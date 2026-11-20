#!/usr/bin/env bash
# The live part of the demo that exists on this branch: the observer-kill run (3.4b).
source "$(dirname "$0")/lib.sh"
ts=$(date -u +%Y%m%dT%H%M%SZ)
out="$RUNS/live-kill-$ts"
python3 "$REPO/command-center/lab/live_observer_kill.py" "$out"
ln -sfn "$out" "$RUNS/live-kill-latest"
log "run output: $out"
