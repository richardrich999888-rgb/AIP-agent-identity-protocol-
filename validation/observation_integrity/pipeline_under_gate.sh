#!/usr/bin/env bash
#
# pipeline_under_gate.sh — the observation-integrity attack against the REAL
# pipeline, not the instrument driver.
#
# reproduce_interference.sh proves the mechanism with the exp01 recorder (one
# tracer, no collector). This runs a ghost-demo live scenario — controlled
# agent, real tracepoints, real CollectorSigner, real reconciler — with a
# no-op BPF gate held on ONE named tracepoint, and records verbatim what the
# reconciler emitted. The question it answers is the one the recorder cannot:
#
#   with this tracepoint gated, what does the signed observer state say, and
#   what availability does the reconciler derive from it?
#
# A blinded observer that signs Active and lets the reconciler report the
# window as covered is the finding (MISSED). One that signs IntegrityUnknown
# so the reconciler reports Unavailable{ObserverIntegrityUnknown} is the fix
# (DETECTED). The arm names below are what docs/security/ADVERSARIAL_RESULTS.md
# cites.
#
# Usage:
#   pipeline_under_gate.sh <arm> <tracepoint|none> <test-binary> <test-filter>
#   e.g.  pipeline_under_gate.sh tp_gated sock/inet_sock_set_state live_transition t_p_
#         pipeline_under_gate.sh tp_control none live_transition t_p_
#
# RUN_ID selects the results directory so several arms seal into one run.
# Observe-only: the gate suppresses a perf submission and touches nothing else.

set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
INTERFERER="$HERE/tracepoint_interferer"
ARM=${1:?arm}; TP=${2:?tracepoint or none}; TBIN=${3:?test binary}; TFILTER=${4:?test filter}
RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
RUN="$HERE/results/$RUN_ID"
mkdir -p "$RUN"
die() { echo "pipeline_under_gate: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -x "$INTERFERER" ] || (cd "$HERE" && gcc -O2 -o tracepoint_interferer tracepoint_interferer.c) || die "interferer build failed"

intf_pid=""
if [ "$TP" != none ]; then
  TP_ID=$(cat "/sys/kernel/tracing/events/$TP/id") || die "no tracepoint $TP"
  "$INTERFERER" "$TP_ID" > "$RUN/${ARM}_interferer.log" 2>&1 &
  intf_pid=$!
  for _ in $(seq 1 100); do
    grep -q INTERFERER_ATTACHED "$RUN/${ARM}_interferer.log" 2>/dev/null && break
    kill -0 "$intf_pid" 2>/dev/null || break
    sleep 0.05
  done
  grep -q INTERFERER_ATTACHED "$RUN/${ARM}_interferer.log" || die "interferer failed to attach on $TP"
fi

{
  echo "arm: $ARM"; echo "utc: $(date -u +%FT%TZ)"; echo "kernel: $(uname -r)"
  echo "gated_tracepoint: $TP${TP_ID:+ (id=$TP_ID)}"
  echo "pipeline: ghost-demo live test '$TFILTER' in tests/$TBIN.rs (real agent, tracepoints, CollectorSigner, reconciler)"
  echo "aip-observe commit: $(git -C "$REPO" rev-parse --short HEAD)$(git -C "$REPO" diff --quiet -- aip-standalone/aip-observe || echo ' +uncommitted')"
} > "$RUN/${ARM}_environment.txt"

# --nocapture so the test's own `{r:?}` (the full Reconciliation) lands in
# the log verbatim; --test-threads=1 so live scenarios never share the rings.
( cd "$REPO" && cargo test -q -p ghost-demo --test "$TBIN" "$TFILTER" -- --nocapture --test-threads=1 ) \
  > "$RUN/${ARM}_pipeline.log" 2>&1
RC=$?
echo "exit_code: $RC" >> "$RUN/${ARM}_environment.txt"

[ -n "$intf_pid" ] && { kill "$intf_pid" 2>/dev/null; wait "$intf_pid" 2>/dev/null; }

# Pull the one line a reader needs: the reconciler's availability and reason.
python3 - "$RUN/${ARM}_pipeline.log" "$ARM" "$TP" "$RC" "$RUN/${ARM}_summary.json" <<'PY'
import json, re, sys
log, arm, tp, rc, out = sys.argv[1:6]
text = open(log, errors="replace").read()
def grab(pat):
    m = re.search(pat, text, re.S)
    return m.group(1) if m else None
summary = {
    "arm": arm, "gated_tracepoint": tp, "test_exit_code": int(rc),
    "test_passed": int(rc) == 0,
    "result": grab(r"result: (\w+)"),
    "reason": grab(r"reason: (\w+)"),
    "availability": grab(r"availability: (\w+(?: \{[^}]*\})?)"),
    "observer_state_in_log": grab(r"state: (\w+)"),
}
open(out, "w").write(json.dumps(summary, indent=2))
print(f"  {arm:14} gate={tp:26} passed={summary['test_passed']} result={summary['result']} reason={summary['reason']} availability={summary['availability']}")
PY
