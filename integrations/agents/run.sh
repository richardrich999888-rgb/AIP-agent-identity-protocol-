#!/usr/bin/env bash
#
# run.sh — Phase 1: observe a REAL LangGraph agent with the two-daemon pair.
#
# WHAT THIS PROVES
# ----------------
# The Phase 1 exit gate: a real agent process is observed; its batch is signed
# by a collector in a separate process holding the only key; the verifier
# accepts it offline, given nothing but the published observer.pub.
#
# The observed subject is a genuine LangGraph agent (integrations/agents/
# agent_subject.py): a parent graph node spawns a child sub-agent as a real
# process that writes a marked file and opens one outbound TCP connection.
# aip-probe (no key) watches from the kernel and ships to aip-collector (holds
# the only key) over the authenticated, confidential Noise_NK transport. The
# evidence examined at the end is the collector's own signed attested-batch
# archive, verified by aip-observe-verify with no network and no trust in the
# daemon.
#
# WHAT IT DOES NOT PROVE
# ----------------------
# The VERIFIED_EXECUTION reconciler verdict, which additionally needs a signed
# ExpectedExecution from a decision point joined to the observation. That is
# Phase 3; this harness stops at "the real agent's execution is in the signed
# evidence and verifies offline". The reconciliation verdict against a real
# agent is the Phase 3 deliverable.
#
# REQUIREMENTS: root (or CAP_BPF+CAP_PERFMON+CAP_NET_ADMIN), tracefs, and the
# pinned venv in integrations/agents/.venv (see requirements.lock).
#
# Usage:  integrations/agents/run.sh [outdir]
# Exit:   0 only if the agent's execution was observed AND the archive verified.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT="${1:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}"
VENV="$HERE/.venv/bin/python"
mkdir -p "$OUT"

step() { printf '\n\033[36m== %s\033[0m\n' "$*" | tee -a "$OUT/transcript.txt"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*" | tee -a "$OUT/transcript.txt"; }
info() { printf '       %s\n' "$*" | tee -a "$OUT/transcript.txt"; }
die()  { printf '  \033[31mFAIL\033[0m %s\n' "$*" | tee -a "$OUT/transcript.txt"; exit 1; }

COLLECTOR_PID=""; PROBE_PID=""
cleanup() {
  [ -n "$PROBE_PID" ]     && kill "$PROBE_PID"     2>/dev/null
  [ -n "$COLLECTOR_PID" ] && kill "$COLLECTOR_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

step "Preconditions"
[ "$(id -u)" -eq 0 ] || die "needs root (or CAP_BPF+CAP_PERFMON+CAP_NET_ADMIN)"
[ -x "$VENV" ] || die "pinned venv missing; create it: python3 -m venv $HERE/.venv && $HERE/.venv/bin/pip install -r $HERE/requirements.lock"
if [ ! -r /sys/kernel/tracing/available_events ]; then
  mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null
fi
[ -r /sys/kernel/tracing/available_events ] || die "tracefs unavailable; the perf sensors cannot open"
"$VENV" -c "import langgraph" 2>/dev/null || die "langgraph not importable in the venv"
LG_VER=$("$VENV" -c "import importlib.metadata as m; print(m.version('langgraph'))")
info "kernel $(uname -r), tracefs mounted, langgraph $LG_VER"
uname -a > "$OUT/host.txt"; echo "langgraph=$LG_VER" >> "$OUT/host.txt"

step "Build the daemons and the offline verifier"
# Select each package's binary explicitly. A lone --bin aip-lineage filters
# out the daemons and its owning package must also be selected. Use the build
# status, not diagnostic wording, so stale binaries never earn a PASS.
if ! ( cd "$REPO" && CARGO_INCREMENTAL=0 cargo build --locked -q \
    -p aip-probe --bin aip-probe \
    -p aip-collector --bin aip-collector \
    -p aip-observe-verify --bin aip-observe-verify \
    -p aip-reconcile --bin aip-lineage ) >> "$OUT/build.log" 2>&1; then
  die "build failed; see build.log"
fi
for binary in aip-probe aip-collector aip-observe-verify aip-lineage; do
  [ -x "$REPO/target/debug/$binary" ] || die "built binary missing: $binary"
done
ok "aip-probe, aip-collector, aip-observe-verify, aip-lineage built"

W="$OUT/work"; mkdir -p "$W/state"
PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
echo -n "phase1-passphrase" > "$W/pass"

step "Generate the probe's transport key (the probe holds no evidence key)"
env AIP_PROBE_ID=probe.phase1 AIP_PROBE_COLLECTOR_ENDPOINT="127.0.0.1:1" \
    AIP_PROBE_COLLECTOR_NOISE_PUBKEY="$(printf '0%.0s' $(seq 1 64))" \
    AIP_PROBE_KEY_PATH="$W/probe.key.json" AIP_PROBE_SENSORS=sched \
    timeout 4 "$REPO/target/debug/aip-probe" > "$W/probe.keygen.log" 2>&1
[ -s "$W/probe.key.json" ] || { cat "$W/probe.keygen.log"; die "probe did not generate a key"; }
PROBE_PUB=$(python3 -c "import json;print(json.load(open('$W/probe.key.json'))['public_hex'])")
printf '[{"probe_id":"probe.phase1","transport_pubkey_hex":"%s"}]\n' "$PROBE_PUB" > "$W/probes.json"
ok "probe key ${PROBE_PUB:0:16}... written to the allow-list"

step "Start the collector (holds the only evidence key, wrapped at rest)"
env AIP_COLLECTOR_OBSERVER_ID=collector.phase1 AIP_COLLECTOR_KEY_VERSION=1 \
    AIP_COLLECTOR_KEY_PATH="$W/collector.key.wrapped" \
    AIP_COLLECTOR_PASSPHRASE_FILE="$W/pass" AIP_COLLECTOR_STATE_DIR="$W/state" \
    AIP_COLLECTOR_LISTEN="127.0.0.1:$PORT" AIP_COLLECTOR_PROBES_PATH="$W/probes.json" \
    AIP_COLLECTOR_NOISE_KEY_PATH="$W/noise.key.json" \
    AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=1 \
    "$REPO/target/debug/aip-collector" > "$W/collector.log" 2>&1 &
COLLECTOR_PID=$!
for _ in $(seq 1 40); do [ -s "$W/state/noise.pub" ] && break; sleep 0.25; done
NOISE_PUB=$(cat "$W/state/noise.pub" 2>/dev/null)
[ -n "$NOISE_PUB" ] || { cat "$W/collector.log"; die "collector did not publish noise.pub"; }
[ -s "$W/state/observer.pub" ] || { cat "$W/collector.log"; die "collector did not publish observer.pub"; }
kill -0 "$COLLECTOR_PID" 2>/dev/null || { cat "$W/collector.log"; die "collector died"; }
ok "collector up on 127.0.0.1:$PORT; observer.pub and noise.pub published"

step "Start the probe with the kernel sensors"
env AIP_PROBE_ID=probe.phase1 AIP_PROBE_COLLECTOR_ENDPOINT="127.0.0.1:$PORT" \
    AIP_PROBE_COLLECTOR_NOISE_PUBKEY="$NOISE_PUB" \
    AIP_PROBE_KEY_PATH="$W/probe.key.json" \
    AIP_PROBE_SENSORS=sched,sockstate,socksend,connector \
    AIP_PROBE_BATCH_INTERVAL_MS=1000 \
    "$REPO/target/debug/aip-probe" > "$W/probe.log" 2>&1 &
PROBE_PID=$!
sleep 3
kill -0 "$PROBE_PID" 2>/dev/null || { cat "$W/probe.log"; die "probe died"; }
grep -q "connected" "$W/probe.log" || { cat "$W/probe.log"; die "probe never connected"; }
ok "probe up, four kernel sensors open, connected over the confidential transport"

step "Run the REAL LangGraph agent as the observed workload"
: > "$OUT/agent.log"
for i in $(seq 1 8); do
  "$VENV" "$HERE/agent_subject.py" "/tmp/aip_phase1_marker_$i" >> "$OUT/agent.log" 2>&1
  sleep 0.4
done
AGENT_PIDS=$(grep -oE "parent_pid=[0-9]+ child_pid=[0-9]+" "$OUT/agent.log" | tr ' ' '\n' | grep -oE "[0-9]+" | sort -u | tr '\n' ' ')
RUNS=$(grep -c "AGENT_RESULT" "$OUT/agent.log")
info "ran the agent $RUNS times; observed pids: $AGENT_PIDS"
[ "$RUNS" -ge 1 ] || die "the agent produced no result line"
ok "the LangGraph agent executed: parent graph spawned a child that wrote a file and connected"

step "Wait for the collector to attest and archive the observation"
ARCHIVE="$W/state/attested.archive.jsonl"
for _ in $(seq 1 30); do
  [ -s "$ARCHIVE" ] && [ "$(wc -l < "$ARCHIVE")" -ge 2 ] && break
  sleep 1
done
[ -s "$ARCHIVE" ] || { cat "$W/collector.log"; die "no attested batches were archived"; }
BATCHES=$(wc -l < "$ARCHIVE")
info "attested batches on disk: $BATCHES"

# Close the writers before verifying/exporting, as the RBI harness does. A
# partial JSONL write or a new health head after the batch read must not make
# this validation depend on teardown timing.
kill "$PROBE_PID" 2>/dev/null || true
wait "$PROBE_PID" 2>/dev/null || true
PROBE_PID=""
kill "$COLLECTOR_PID" 2>/dev/null || true
wait "$COLLECTOR_PID" 2>/dev/null || true
COLLECTOR_PID=""

# The agent's execution must actually be in the signed evidence: count kernel
# exec events across the archive. Absence here would mean the observer never
# saw the agent, which is a failure of the observation, not of verification.
EXECS=$("$VENV" - "$ARCHIVE" <<'PY'
import json, sys
n = 0
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    b = json.loads(line)["batch"]
    for e in b.get("kernel_events", []):
        k = e.get("kind", {})
        if isinstance(k, dict) and ("Exec" in k or "Fork" in k):
            n += 1
print(n)
PY
)
info "process exec/fork events captured in the signed archive: $EXECS"
[ "$EXECS" -ge 1 ] || { cat "$W/probe.log"; die "the agent ran but no exec/fork reached the signed evidence"; }
ok "the real agent's execution is inside the collector-signed evidence ($EXECS exec/fork events)"

step "Verify the archive OFFLINE — separate process, two files and a public key"
VERIFY="$REPO/target/debug/aip-observe-verify"
"$VERIFY" --observer-id collector.phase1 --key-version 1 \
          --pubkey-file "$W/state/observer.pub" \
          --batches "$ARCHIVE" \
          --health "$W/state/health.archive.jsonl" \
  > "$OUT/offline_verify.txt" 2>&1
VRC=$?
sed 's/^/       /' "$OUT/offline_verify.txt"
cat "$OUT/offline_verify.txt" >> "$OUT/transcript.txt"
[ "$VRC" -eq 0 ] || die "the offline verifier rejected the collector's own archive (exit $VRC)"
grep -q "^VERIFIED" "$OUT/offline_verify.txt" || die "verifier did not report VERIFIED"
ok "offline: the real agent's attested batches verify under the published key alone"

step "Derive the delegation chain from the SAME archive (Phase 3)"
# aip-lineage re-verifies the archive under the anchor FIRST, then derives
# start-verified parent->child edges. It fails closed: an archive that does
# not verify derives nothing. This is observed lineage only — attribution to
# an authorised identity is a reconciler verdict against a signed
# ExpectedExecution, not claimed by this tool.
LINEAGE="$REPO/target/debug/aip-lineage"
"$LINEAGE" --observer-id collector.phase1 --key-version 1 \
           --pubkey-file "$W/state/observer.pub" \
           --batches "$ARCHIVE" \
  > "$OUT/delegation_chain.txt" 2>&1
LRC=$?
sed 's/^/       /' "$OUT/delegation_chain.txt"
cat "$OUT/delegation_chain.txt" >> "$OUT/transcript.txt"
[ "$LRC" -eq 0 ] || die "aip-lineage refused the collector's own archive (exit $LRC)"
EDGES=$(sed -n 's/^edges derived    : //p' "$OUT/delegation_chain.txt")
[ "${EDGES:-0}" -ge 1 ] || die "no delegation edges derived from the real agent run"
ok "delegation chain derived from the verified archive ($EDGES start-verified edges)"

# Keep the evidence; drop the throwaway key material.
cp "$W/state/attested.archive.jsonl" "$W/state/health.archive.jsonl" \
   "$W/state/observer.pub" "$W/collector.log" "$W/probe.log" "$OUT/" 2>/dev/null

step "DEMONSTRATED (Phases 1 and 3)"
printf 'A real LangGraph agent -- a parent graph node spawning a child sub-agent\n'
printf 'that wrote a file and opened a TCP connection -- was observed from the\n'
printf 'kernel by a probe holding no key, attested by a collector in a separate\n'
printf 'process holding the only key, and the resulting archive verified OFFLINE\n'
printf 'by a separate binary given two files and the published public key.\n'
printf '\nPhase 3: the delegation chain (start-verified parent->child edges) was\n'
printf 'derived from that same archive, after re-verifying it under the anchor.\n'
printf 'The derivation is observed lineage only; it fabricates no edge when a\n'
printf 'fork is dropped, and attributes to the kernel-bound forking instance.\n'
printf '\nThe VERIFIED_EXECUTION reconciler verdict (join of this lineage against\n'
printf 'a signed ExpectedExecution) is exercised in aip-reconcile'"'"'s test suite\n'
printf '(lineage_violation.rs, delegation_attribution.rs), not by this script.\n'
