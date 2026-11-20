#!/usr/bin/env bash
# Rehearsals (item 7.1): N consecutive reset → run → verify on a clean tree.
#   ./rehearse.sh N [LABEL]
# Refuses to start on a dirty tree (git status --porcelain must be empty).
# Writes $RUNS/../rehearsals-<ts>.json with each run's exit codes, timings and
# verify statuses. Exit 0 only if every run.sh AND every verify.sh exited 0.
source "$(dirname "$0")/lib.sh"
N=${1:?usage: rehearse.sh N [LABEL]}
LABEL=${2:-rehearsal}
[[ "$N" =~ ^[1-9][0-9]*$ ]] || die "N must be a positive integer"
dirty=$(git -C "$REPO" status --porcelain)
[ -z "$dirty" ] || die "tree is not clean; commit or stash first:
$dirty"
head=$(git -C "$REPO" rev-parse HEAD)
ts=$(date -u +%Y%m%dT%H%M%SZ)
out="$LAB/rehearsals-$ts.json"
rows=()
all_ok=1
for i in $(seq 1 "$N"); do
  "$HERE/reset.sh" > /dev/null
  mkdir -p "$RUNS"
  t_rc=0; "$HERE/test.sh" > "$LAB/rehearsal-$ts-$i-test.log" 2>&1 || t_rc=$?   # set -e safe
  t0=$(date +%s%N)
  r_rc=0; "$HERE/run.sh" > "$LAB/rehearsal-$ts-$i-run.log" 2>&1 || r_rc=$?   # set -e safe
  t1=$(date +%s%N)
  v_rc=0; "$HERE/verify.sh" > "$LAB/rehearsal-$ts-$i-verify.log" 2>&1 || v_rc=$?   # set -e safe
  cp "$RUNS/verify-summary.json" "$LAB/rehearsal-$ts-$i-verify-summary.json" 2>/dev/null || true
  [ "$t_rc" -eq 0 ] && [ "$r_rc" -eq 0 ] && [ "$v_rc" -eq 0 ] || all_ok=0
  rows+=("{\"run\":$i,\"test_exit\":$t_rc,\"run_exit\":$r_rc,\"verify_exit\":$v_rc,\"run_ms\":$(( (t1-t0)/1000000 ))}")
  log "rehearsal $i/$N: test=$t_rc run=$r_rc verify=$v_rc"
done
dirty_after=$(git -C "$REPO" status --porcelain)
printf '{"label":"%s","head":"%s","n":%s,"tree_clean_after":%s,"all_passed":%s,"runs":[%s]}\n' \
  "$LABEL" "$head" "$N" "$([ -z "$dirty_after" ] && echo true || echo false)" \
  "$([ "$all_ok" = 1 ] && echo true || echo false)" "$(IFS=,; echo "${rows[*]}")" > "$out"
python3 -m json.tool "$out" > /dev/null || die "summary is not valid JSON"
log "summary: $out"
[ "$all_ok" = 1 ] && [ -z "$dirty_after" ]
