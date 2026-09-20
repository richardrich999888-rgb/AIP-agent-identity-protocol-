#!/usr/bin/env bash
# S1 — stand up SPIRE and prove a workload is identified by its binary's SHA-256.
#
# WHAT THIS ESTABLISHES
#   A registration entry is created selecting on `unix:sha256:<digest>`. If the
#   workload receives an SVID for that entry, SPIRE has independently measured
#   that digest from /proc/<pid>/exe and matched it. The SVID's existence IS
#   SPIRE's assertion about the workload's code.
#
#   That digest is the join for the whole cross-check: AIP measures the same
#   quantity for the same process, from the kernel, and the two are compared.
#
# WHAT THIS DOES NOT ESTABLISH
#   Nothing about which system resists a hostile host. SPIRE's unix attestor
#   reads /proc/<pid>/exe, which is the same source AIP measures from, so the
#   two share that attack surface. Node compromise is outside SPIFFE's trust
#   model by its own documentation, and outside AIP's by ours. No claim here
#   depends on the September 2026 Unit 42 technique, which is post-exploitation
#   with root and is neither a CVE nor a protocol break.
#
# Usage: validation/external/spiffe/run.sh [outdir]
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
OUT="${1:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}"
W="$OUT/work"
mkdir -p "$W"

step() { printf '\n\033[36m== %s\033[0m\n' "$*" | tee -a "$OUT/transcript.txt"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*" | tee -a "$OUT/transcript.txt"; }
info() { printf '       %s\n' "$*" | tee -a "$OUT/transcript.txt"; }
die()  { printf '  \033[31mFAIL\033[0m %s\n' "$*" | tee -a "$OUT/transcript.txt"; exit 1; }

# Sockets must live under a SHORT path: sun_path is limited to 108 bytes and
# this repo's results directory already exceeds it. When it is exceeded SPIRE's
# UDS listener fails, the endpoint errgroup cancels the TCP listener with it,
# and NOTHING is logged -- the server just starts and stops its APIs in the same
# second. Evidence still lands in $OUT; only sockets and working data live here.
RUN="/run/aip-spiffe-$$"
mkdir -p "$RUN/server-data" "$RUN/agent-data"

SERVER_PID=""; AGENT_PID=""
cleanup() {
  [ -n "$AGENT_PID" ]  && kill "$AGENT_PID"  2>/dev/null
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$RUN"
}
trap cleanup EXIT

SPIRE_SERVER="${SPIRE_SERVER:-/root/go/bin/spire-server}"
SPIRE_AGENT="${SPIRE_AGENT:-/root/go/bin/spire-agent}"

step "Preconditions"
[ "$(id -u)" -eq 0 ] || die "needs root (the agent reads /proc/<pid>/exe of workloads)"
[ -x "$SPIRE_SERVER" ] || die "spire-server not found at $SPIRE_SERVER"
[ -x "$SPIRE_AGENT" ]  || die "spire-agent not found at $SPIRE_AGENT"
command -v go >/dev/null || die "go toolchain required to build the workload"
info "$($SPIRE_SERVER --version 2>&1 | head -1)  |  $($SPIRE_AGENT --version 2>&1 | head -1)"
{ uname -a; "$SPIRE_SERVER" --version 2>&1 | head -1; go version; } > "$OUT/host.txt"

step "Build the workload (it is the process SPIRE will measure)"
( cd "$HERE/workload" && GOFLAGS=-mod=mod go build -o "$W/aip-spiffe-workload" . ) 2>&1 \
  | tee -a "$OUT/build.log"
[ -x "$W/aip-spiffe-workload" ] || { cat "$OUT/build.log"; die "workload build failed"; }
WL_SHA=$(sha256sum "$W/aip-spiffe-workload" | cut -d' ' -f1)
ok "workload built; its binary SHA-256 is ${WL_SHA:0:16}..."
echo "workload_sha256=$WL_SHA" >> "$OUT/host.txt"

step "Configure and start the SPIRE server"
PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
sed -e "s|__WORK__|$W|g" -e "s|__RUN__|$RUN|g" -e "s|__PORT__|$PORT|g" "$HERE/conf/server.conf" > "$W/server.conf"
info "socket path length: $(echo -n "$RUN/server-api.sock" | wc -c) bytes (sun_path limit is 108)"
"$SPIRE_SERVER" run -config "$W/server.conf" > "$W/server.log" 2>&1 &
SERVER_PID=$!
SRV_SOCK="$RUN/server-api.sock"
for _ in $(seq 1 60); do [ -S "$SRV_SOCK" ] && break; sleep 0.5; done
[ -S "$SRV_SOCK" ] || { tail -20 "$W/server.log"; die "server socket never appeared"; }
ok "server up on 127.0.0.1:$PORT (trust domain aip.local, self-minted CA)"

step "Export the trust bundle and mint a node join token"
"$SPIRE_SERVER" bundle show -socketPath "$SRV_SOCK" > "$RUN/bundle.crt" 2>"$W/bundle.err"
[ -s "$RUN/bundle.crt" ] || { cat "$W/bundle.err"; die "could not export the trust bundle"; }
TOKEN=$("$SPIRE_SERVER" token generate -socketPath "$SRV_SOCK" \
          -spiffeID spiffe://aip.local/node/lab 2>/dev/null | sed -n 's/^Token: //p')
[ -n "$TOKEN" ] || die "could not mint a join token"
ok "trust bundle exported ($(wc -l < "$RUN/bundle.crt") lines); join token minted"

step "Start the SPIRE agent (unix attestor, discover_workload_path = true)"
sed -e "s|__WORK__|$W|g" -e "s|__RUN__|$RUN|g" -e "s|__PORT__|$PORT|g" "$HERE/conf/agent.conf" > "$W/agent.conf"
"$SPIRE_AGENT" run -config "$W/agent.conf" -joinToken "$TOKEN" > "$W/agent.log" 2>&1 &
AGENT_PID=$!
AG_SOCK="$RUN/agent-api.sock"
for _ in $(seq 1 60); do [ -S "$AG_SOCK" ] && break; sleep 0.5; done
[ -S "$AG_SOCK" ] || { tail -25 "$W/agent.log"; die "agent socket never appeared"; }
ok "agent attested to the server and is serving the Workload API"

step "Register the workload BY ITS BINARY DIGEST"
AGENT_ID="spiffe://aip.local/spire/agent/join_token/$TOKEN"
info "agent SPIFFE ID (parent for the workload entry): $AGENT_ID"
"$SPIRE_SERVER" entry create -socketPath "$SRV_SOCK" \
  -parentID "$AGENT_ID" \
  -spiffeID spiffe://aip.local/workload/demo \
  -selector "unix:uid:0" \
  -selector "unix:sha256:$WL_SHA" \
  > "$W/entry.txt" 2>&1
grep -q "Entry ID" "$W/entry.txt" || { cat "$W/entry.txt"; die "entry creation failed"; }
cp "$W/entry.txt" "$OUT/registration_entry.txt"
info "selector: unix:sha256:$WL_SHA"
ok "entry registered: spiffe://aip.local/workload/demo selected on its SHA-256"
step "The workload asks SPIRE who it is"
# The agent syncs entries from the server on an interval, so the first ask can
# legitimately precede the entry reaching the agent. Retry, then fail loudly.
WRC=1
for attempt in $(seq 1 10); do
  "$W/aip-spiffe-workload" -socket "$AG_SOCK" > "$OUT/svid.json" 2>"$W/workload.err"
  WRC=$?
  [ "$WRC" -eq 0 ] && { info "SVID obtained on attempt $attempt"; break; }
  sleep 3
done
if [ "$WRC" -ne 0 ]; then
  echo "--- workload stderr ---";              cat "$W/workload.err"
  echo "--- registered entries ---";           "$SPIRE_SERVER" entry show -socketPath "$SRV_SOCK" 2>&1 | head -30
  echo "--- agent: attestation / selectors ---"
  grep -iE "selector|attest|workload|no identity" "$W/agent.log" | tail -25
  die "workload got no SVID after $attempt attempts (exit $WRC)"
fi
GOT_ID=$(python3 -c "import json;print(json.load(open('$OUT/svid.json'))['spiffe_id'])")
[ "$GOT_ID" = "spiffe://aip.local/workload/demo" ] \
  || die "SPIRE named it '$GOT_ID', expected spiffe://aip.local/workload/demo"
python3 - "$OUT/svid.json" <<'PY' | tee -a "$OUT/transcript.txt"
import json,sys
d=json.load(open(sys.argv[1]))
print(f"       SPIFFE ID   : {d['spiffe_id']}")
print(f"       pid         : {d['pid']}")
print(f"       serial      : {d['serial']}")
print(f"       valid (ms)  : {d['not_before_ms']} .. {d['not_after_ms']}")
print(f"       SVID chain  : {len(d['svid_chain_pem'].split('-----BEGIN CERTIFICATE-----'))-1} cert(s)")
print(f"       trust bundle: {len(d['bundle_pem'].split('-----BEGIN CERTIFICATE-----'))-1} CA cert(s)")
PY
ok "SPIRE issued an SVID for an entry selected on the binary's SHA-256"

step "NEGATIVE CONTROL: is the digest actually doing the work?"
# Without this the whole exercise is unsound. The entry carries two selectors,
# `unix:uid:0` and `unix:sha256:<digest>`. If SPIRE were matching on uid alone,
# any root process would receive this identity and the digest would be
# decoration. So: take a byte-for-byte copy of the SAME program, change one
# byte so its digest differs, and run it as the SAME uid from the same place.
# It must be REFUSED. If it is issued an SVID, the S1 result above is void.
cp "$W/aip-spiffe-workload" "$W/imposter"
printf '\0' >> "$W/imposter"          # changes the digest, leaves the ELF runnable
IMP_SHA=$(sha256sum "$W/imposter" | cut -d' ' -f1)
info "imposter digest: ${IMP_SHA:0:16}...  (registered: ${WL_SHA:0:16}...)"
[ "$IMP_SHA" != "$WL_SHA" ] || die "imposter digest unchanged; the control is vacuous"

"$W/imposter" -socket "$AG_SOCK" > "$W/imposter.json" 2>"$W/imposter.err"
IRC=$?
if [ "$IRC" -eq 0 ]; then
  IMP_ID=$(python3 -c "import json;print(json.load(open('$W/imposter.json'))['spiffe_id'])" 2>/dev/null)
  cp "$W/imposter.json" "$OUT/NEGATIVE_CONTROL_FAILED.json"
  die "UNSOUND: a different binary received '$IMP_ID'. The sha256 selector is not load-bearing."
fi
grep -q "no identity issued" "$W/imposter.err" \
  || info "note: refused with: $(head -1 "$W/imposter.err")"
cp "$W/imposter.err" "$OUT/negative_control.txt"
echo "imposter_sha256=$IMP_SHA" >> "$OUT/host.txt"
ok "the same program with one byte changed was REFUSED — the digest is load-bearing"

# Keep the evidence; leave the throwaway keys and sockets behind.
cp "$RUN/bundle.crt" "$OUT/trust_bundle.pem" 2>/dev/null
cp "$W/server.log" "$W/agent.log" "$OUT/" 2>/dev/null

step "S1 EXIT GATE MET"
printf 'A real workload holds a real SVID, and the registration it matched was\n'
printf 'selected on unix:sha256 — so SPIRE independently measured that binary\n'
printf 'digest from /proc/<pid>/exe and bound an identity to it.\n\n'
printf 'That digest is the join for S2: AIP measures the same quantity for the\n'
printf 'same process instance, from the kernel, and the two get compared.\n'
