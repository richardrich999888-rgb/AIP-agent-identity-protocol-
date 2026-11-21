#!/usr/bin/env bash
# The live parts of the demo that exist on this branch: observer kill (3.4b), shadow AI (2.3a),
# native gate and approvals (3.1b, 3.2). Every run executes even if an earlier one fails, so one
# failure cannot hide another; the script exits non-zero if any run failed.
source "$(dirname "$0")/lib.sh"
ts=$(date -u +%Y%m%dT%H%M%SZ)
fails=0
live() { # name, command...
  local name=$1; shift
  local out="$RUNS/$name-$ts"
  if "$@" "$out"; then log "PASS $name ($out)"; else log "FAIL $name ($out)"; fails=$((fails+1)); fi
  ln -sfn "$out" "$RUNS/$name-latest"
}
mkdir -p "$RUNS"
live live-kill python3 "$REPO/command-center/lab/live_observer_kill.py"
live live-shadow python3 "$REPO/command-center/lab/live_shadow_ai.py"
gate_live() {
  unshare -n sh -c "python3 '$SERVER/netns_lo_up.py' >/dev/null && VANIAN_OPA_BIN='$BIN/opa' PYTHONDONTWRITEBYTECODE=1 '$GATE_VENV/bin/python' '$REPO/command-center/lab/live_gate.py' '$1'"
}
live live-gate gate_live
log "live runs failed: $fails"
[ "$fails" -eq 0 ]
