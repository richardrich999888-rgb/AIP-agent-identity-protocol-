#!/usr/bin/env bash
#
# repeat_pilot.sh — run validation/pilot_e2e/run.sh N times under one
# configuration and judge every run with the RBI rehearsal's own control
# check (validation/rbi_demo/check_control.py) and the divergence replay.
#
# Pre-registered pass rule for one run, fixed before any result is read:
#   pilot_exit == 0  AND  check_control_exit == 0
# and, reported beside it (not folded in): counted sensor loss per sensor
# (AIP_SENSOR_LOSS lines), divergences in the control phase whose counterpart
# sits in an adjacent batch (boundary artefacts), and divergences with no
# counterpart anywhere (the attack signal).
#
# Usage: repeat_pilot.sh <outdir> <N> <label>
# Env:   passed through unchanged to the pilot, e.g.
#        AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0
#        AIP_PROBE_CONNECTOR_RCVBUF_BYTES=0   (kernel default: the old behavior)
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
OUT=$(mkdir -p "$1" && cd "$1" && pwd); N=$2; LABEL=$3
SUM="$OUT/summary.csv"
{ echo "commit=$(git -C "$REPO" rev-parse HEAD) dirty=$(git -C "$REPO" status --porcelain -- aip-standalone | wc -l)"
  echo "label=$LABEL n=$N kernel=$(uname -r)"
  echo "AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=${AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK:-<unset>}"
  echo "AIP_PROBE_CONNECTOR_RCVBUF_BYTES=${AIP_PROBE_CONNECTOR_RCVBUF_BYTES:-<unset: production default>}"
} > "$OUT/params.txt"
echo "run,pilot_exit,check_control_exit,control_states,loss_lines,loss_by_sensor,rcvbuf_line,replay_total,replay_boundary,replay_no_counterpart" > "$SUM"
for i in $(seq 1 "$N"); do
  R="$OUT/run_$i"
  timeout 900 bash "$REPO/validation/pilot_e2e/run.sh" "$R" > "$R.log" 2>&1; PE=$?
  python3 "$REPO/validation/rbi_demo/check_control.py" "$R/health.A.control.jsonl" \
      "$R/work/state/health.archive.jsonl" "$R/work/state/attested.archive.jsonl" > "$R/check_control.log" 2>&1; CC=$?
  STATES=$(python3 -c "import json,sys;print('|'.join(json.loads(l)['health']['state'] for l in open(sys.argv[1]) if l.strip()))" "$R/health.A.control.jsonl" 2>/dev/null)
  LOSS=$(grep -c AIP_SENSOR_LOSS "$R/probe.log" 2>/dev/null); LOSS=${LOSS:-0}
  BYS=$(grep -o 'AIP_SENSOR_LOSS sensor=[a-z_]*' "$R/probe.log" 2>/dev/null | sort | uniq -c | awk '{print $3"x"$1}' | tr '\n' ' ')
  RB=$(grep -o 'connector receive buffer.*' "$R/probe.log" 2>/dev/null | head -1)
  python3 "$HERE/divergence_replay.py" "$R/attested.archive.jsonl" > "$R/divergence_replay.txt" 2>&1
  T=$(grep -o 'TOTAL divergent=[0-9]* boundary_artefact=[0-9]* no_counterpart=[0-9]*' "$R/divergence_replay.txt" | tr -dc '0-9 =' | awk -F'[ =]+' '{print $2","$3","$4}')
  echo "$i,$PE,$CC,$STATES,$LOSS,\"$BYS\",\"$RB\",${T:-,,}" >> "$SUM"
  rm -rf "$R/work"   # throwaway keys; the archives the checks read were copied out by the pilot
  echo "[$LABEL] run $i pilot=$PE control=$CC loss=$LOSS"
done
cat "$SUM"
