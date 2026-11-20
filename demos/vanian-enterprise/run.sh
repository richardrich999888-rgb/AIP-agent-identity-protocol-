#!/usr/bin/env bash
# The live parts of the demo that exist on this branch: the observer-kill run (3.4b) and shadow AI (2.3a).
source "$(dirname "$0")/lib.sh"
ts=$(date -u +%Y%m%dT%H%M%SZ)
out="$RUNS/live-kill-$ts"
python3 "$REPO/command-center/lab/live_observer_kill.py" "$out"
ln -sfn "$out" "$RUNS/live-kill-latest"
log "run output: $out"
shadow="$RUNS/live-shadow-$ts"
python3 "$REPO/command-center/lab/live_shadow_ai.py" "$shadow"
ln -sfn "$shadow" "$RUNS/live-shadow-latest"
log "run output: $shadow"
