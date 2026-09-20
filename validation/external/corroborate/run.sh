#!/usr/bin/env bash
# Independent-observer corroboration — the evidence behind subsection 10a of
# the RBI technical brief.
#
# Runs AIP's two daemons and TWO independently built runtime observers over the
# same kernel, over the same window, and compares what each recorded:
#
#   bpftrace  an independent eBPF implementation attached to the SAME
#             sched:sched_process_exec tracepoint AIP's perf sensor reads.
#             Corroborates AIP's reporting fidelity. A gate on that tracepoint
#             would blind both, so this is the weaker independence class.
#   auditd    the kernel audit subsystem — a DIFFERENT mechanism. A tracepoint
#             gate does not blind it, so this is the stronger class.
#
# Falco and Tetragon are the first-choice observers named in the brief; their
# distribution repositories are not reachable from this build environment
# (the egress proxy denies download.falco.org and github.com), so they are not
# used here. The comparison core is source-agnostic and carries a Falco variant
# so the adapter is the only missing piece.
#
# This script does NOT grade itself. It prints what the two observers recorded
# and where they disagree. A disagreement is a finding to explain, never a
# threshold to tune away.
#
# Usage: validation/external/corroborate/run.sh [outdir]
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
OUT="${1:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"

step() { printf '\n\033[36m== %s\033[0m\n' "$*" | tee -a "$OUT/transcript.txt"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*" | tee -a "$OUT/transcript.txt"; }
info() { printf '       %s\n' "$*" | tee -a "$OUT/transcript.txt"; }
die()  { printf '  \033[31mFAIL\033[0m %s\n' "$*" | tee -a "$OUT/transcript.txt"; exit 1; }

COLLECTOR_PID=""; PROBE_PID=""; BPF_PID=""
cleanup() {
  [ -n "$BPF_PID" ]       && kill "$BPF_PID"       2>/dev/null
  [ -n "$PROBE_PID" ]     && kill "$PROBE_PID"     2>/dev/null
  [ -n "$COLLECTOR_PID" ] && kill "$COLLECTOR_PID" 2>/dev/null
  auditctl -D >/dev/null 2>&1
  wait 2>/dev/null
}
trap cleanup EXIT

now_ms() { date +%s%3N; }

step "Preconditions"
[ "$(id -u)" -eq 0 ] || die "needs root (kernel sensors, bpftrace, auditctl)"
command -v bpftrace >/dev/null || die "bpftrace not installed"
command -v auditctl >/dev/null || die "auditctl not installed (package: auditd)"
if [ ! -r /sys/kernel/tracing/available_events ]; then
  mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null
fi
[ -r /sys/kernel/tracing/available_events ] || die "tracefs unavailable"
info "kernel $(uname -r); bpftrace $(bpftrace --version 2>&1 | head -1); $(auditctl -v 2>&1 | head -1)"
uname -a > "$OUT/host.txt"
{ bpftrace --version 2>&1 | head -1; auditctl -v 2>&1 | head -1; } >> "$OUT/host.txt"

step "Build"
( cd "$REPO" && CARGO_INCREMENTAL=0 cargo build -q -p aip-probe -p aip-collector \
    -p aip-observe-verify -p aip-corroborate 2>&1 ) | tee -a "$OUT/build.log" \
  | grep -E "^error" && die "build failed"
ok "aip-probe, aip-collector, aip-observe-verify, aip-corroborate built"

W="$OUT/work"; mkdir -p "$W/state"
PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
echo -n "corroborate-passphrase" > "$W/pass"

step "Start AIP: collector (holds the only key) and probe (holds none)"
env AIP_PROBE_ID=probe.corr AIP_PROBE_COLLECTOR_ENDPOINT="127.0.0.1:1" \
    AIP_PROBE_COLLECTOR_NOISE_PUBKEY="$(printf '0%.0s' $(seq 1 64))" \
    AIP_PROBE_KEY_PATH="$W/probe.key.json" AIP_PROBE_SENSORS=sched \
    timeout 4 "$REPO/target/debug/aip-probe" > "$W/probe.keygen.log" 2>&1
[ -s "$W/probe.key.json" ] || die "probe did not generate a transport key"
PROBE_PUB=$(python3 -c "import json;print(json.load(open('$W/probe.key.json'))['public_hex'])")
printf '[{"probe_id":"probe.corr","transport_pubkey_hex":"%s"}]\n' "$PROBE_PUB" > "$W/probes.json"

env AIP_COLLECTOR_OBSERVER_ID=collector.corr AIP_COLLECTOR_KEY_VERSION=1 \
    AIP_COLLECTOR_KEY_PATH="$W/collector.key.wrapped" \
    AIP_COLLECTOR_PASSPHRASE_FILE="$W/pass" AIP_COLLECTOR_STATE_DIR="$W/state" \
    AIP_COLLECTOR_LISTEN="127.0.0.1:$PORT" AIP_COLLECTOR_PROBES_PATH="$W/probes.json" \
    AIP_COLLECTOR_NOISE_KEY_PATH="$W/noise.key.json" \
    AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0 \
    "$REPO/target/debug/aip-collector" > "$W/collector.log" 2>&1 &
COLLECTOR_PID=$!
for _ in $(seq 1 40); do [ -s "$W/state/noise.pub" ] && break; sleep 0.25; done
NOISE_PUB=$(cat "$W/state/noise.pub" 2>/dev/null)
[ -n "$NOISE_PUB" ] || { cat "$W/collector.log"; die "collector did not publish noise.pub"; }

env AIP_PROBE_ID=probe.corr AIP_PROBE_COLLECTOR_ENDPOINT="127.0.0.1:$PORT" \
    AIP_PROBE_COLLECTOR_NOISE_PUBKEY="$NOISE_PUB" \
    AIP_PROBE_KEY_PATH="$W/probe.key.json" \
    AIP_PROBE_SENSORS=sched,connector AIP_PROBE_BATCH_INTERVAL_MS=1000 \
    "$REPO/target/debug/aip-probe" > "$W/probe.log" 2>&1 &
PROBE_PID=$!
sleep 3
kill -0 "$PROBE_PID" 2>/dev/null || { cat "$W/probe.log"; die "probe died"; }
grep -q "connected" "$W/probe.log" || { cat "$W/probe.log"; die "probe never connected"; }
ok "collector on 127.0.0.1:$PORT; probe connected over the confidential transport"

step "Start the two INDEPENDENT observers"
auditctl -D >/dev/null 2>&1
auditctl -a always,exit -F arch=b64 -S execve -k aipxcheck >/dev/null 2>&1 \
  || die "could not install the auditd execve rule"
AUDIT_MARK=$(now_ms)
bpftrace -e 'tracepoint:sched:sched_process_exec { printf("AIPX %llu %d %s\n", nsecs, pid, str(args.filename)); }' \
  > "$W/bpftrace.out" 2> "$W/bpftrace.err" &
BPF_PID=$!
for _ in $(seq 1 60); do grep -q "Attaching" "$W/bpftrace.out" 2>/dev/null && break; sleep 0.25; done
grep -q "Attaching" "$W/bpftrace.out" || { cat "$W/bpftrace.err"; die "bpftrace never attached"; }
sleep 1
# Only from here is BOTH independent observers demonstrably watching.
EXT_FROM_MS=$(now_ms)
ok "bpftrace attached and auditd execve rule active (window opens at $EXT_FROM_MS)"

step "Run the observed workload"
: > "$OUT/workload.log"
for i in $(seq 1 25); do
  /bin/echo "corr-$i" >> "$OUT/workload.log"
  /usr/bin/env true
  /bin/true
done
VENV="$REPO/integrations/agents/.venv/bin/python"
if [ -x "$VENV" ] && "$VENV" -c "import langgraph" 2>/dev/null; then
  for i in 1 2 3; do
    "$VENV" "$REPO/integrations/agents/agent_subject.py" "/tmp/aip_corr_marker_$i" \
      >> "$OUT/workload.log" 2>&1
  done
  info "workload: 75 plain execs + 3 runs of the real LangGraph agent"
  echo "langgraph=yes" >> "$OUT/host.txt"
else
  info "workload: 75 plain execs (LangGraph venv absent; plain execs only)"
  echo "langgraph=no" >> "$OUT/host.txt"
fi
# Close the comparison window at the END OF THE WORKLOAD, before any teardown.
# Two reasons, both found by the first live run:
#   1. AIP batches on an interval, so an execution it received milliseconds
#      before the probe stops has not necessarily reached an attested batch.
#      Comparing up to the instant of teardown measures a flush race, not
#      observer disagreement.
#   2. The teardown itself execs (`sleep`, `kill`). Those are not the workload.
# The first run reported exactly one "AIP gap": a /usr/bin/sleep recorded by
# auditd 3 ms before the window closed. bpftrace missed it too, which is what
# identified it as a boundary artefact rather than a gap. Both independent
# observers keep running through the settle period below, so nothing inside
# the window can be missed by them.
EXT_TO_MS=$(now_ms)
sleep 4
kill "$BPF_PID" 2>/dev/null; BPF_PID=""
sleep 1
ok "workload complete; observer window $EXT_FROM_MS .. $EXT_TO_MS (settled 4s before teardown)"

step "Wait for the collector to attest and archive"
ARCHIVE="$W/state/attested.archive.jsonl"
for _ in $(seq 1 40); do
  [ -s "$ARCHIVE" ] && [ "$(wc -l < "$ARCHIVE")" -ge 2 ] && break
  sleep 0.5
done
[ -s "$ARCHIVE" ] || { cat "$W/probe.log"; die "no attested batch reached disk"; }
info "attested batches: $(wc -l < "$ARCHIVE")"
kill "$PROBE_PID" 2>/dev/null; PROBE_PID=""
sleep 1

step "Collect the independent observers' output"
grep -c '^AIPX' "$W/bpftrace.out" > /dev/null 2>&1 || true
BPF_N=$(grep -c '^AIPX' "$W/bpftrace.out" 2>/dev/null || echo 0)
ausearch -k aipxcheck -ts recent --raw > "$W/auditd.log" 2>/dev/null \
  || cp /var/log/audit/audit.log "$W/auditd.log" 2>/dev/null || true
AUD_N=$(grep -c '^type=SYSCALL' "$W/auditd.log" 2>/dev/null || echo 0)
auditctl -D >/dev/null 2>&1
info "bpftrace exec records: $BPF_N   |   auditd SYSCALL records: $AUD_N"
[ "$BPF_N" -ge 1 ] || die "bpftrace recorded nothing; comparison would be vacuous"
[ "$AUD_N" -ge 1 ] || die "auditd recorded nothing; comparison would be vacuous"

CORR="$REPO/target/debug/aip-corroborate"
ARGS="--observer-id collector.corr --key-version 1 --pubkey-file $W/state/observer.pub
      --batches $ARCHIVE --from-ms $EXT_FROM_MS --to-ms $EXT_TO_MS"

step "Corroborate against bpftrace (independent implementation, same mechanism)"
# shellcheck disable=SC2086
"$CORR" $ARGS --external "$W/bpftrace.out" --source bpftrace \
  | tee "$OUT/corroboration_bpftrace.txt" | sed 's/^/       /'
# shellcheck disable=SC2086
"$CORR" $ARGS --external "$W/bpftrace.out" --source bpftrace --json \
  > "$OUT/corroboration_bpftrace.json" 2>/dev/null

step "Corroborate against auditd (different kernel mechanism — the stronger class)"
# shellcheck disable=SC2086
"$CORR" $ARGS --external "$W/auditd.log" --source auditd \
  | tee "$OUT/corroboration_auditd.txt" | sed 's/^/       /'
# shellcheck disable=SC2086
"$CORR" $ARGS --external "$W/auditd.log" --source auditd --json \
  > "$OUT/corroboration_auditd.json" 2>/dev/null

cp "$W/state/attested.archive.jsonl" "$W/state/observer.pub" \
   "$W/bpftrace.out" "$W/auditd.log" "$OUT/" 2>/dev/null

step "RESULT"
printf 'Two independently built runtime observers watched the same kernel over the\n'
printf 'same window as AIP. The two reports above state, for each, how many\n'
printf 'executions both recorded, how many only AIP recorded, and -- the finding\n'
printf 'that costs us something -- how many the independent observer recorded that\n'
printf 'AIP did not.\n\n'
printf 'This does not make the host kernel trustworthy. Where both observers read\n'
printf 'the same kernel mechanism, one gate blinds both; auditd is carried\n'
printf 'precisely because it does not share that mechanism.\n'
