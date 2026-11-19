#!/usr/bin/env bash
# v0.2 holdout evaluation on tx-tasks-v1 (pipeline frozen at b4371a1). Sequential, offline.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd); cd "$ROOT/research/capability-learning"
OFF="$ROOT/research/compute-memory/bench/offline.sh"; O=results/v02; T=tasks/tx_hutx2.json
# Resolved from the staged bundle (MODELS / SYNTRIASS_BUNDLE / LLAMA_SERVER
# still override, in that order of precedence).
R="$ROOT/deploy/syntriass/resolve_model.py"
M=$(python3 -I "$R" dir) || exit $?; LS=$(python3 -I "$R" server) || exit $?
harness/run_atomic.sh $O/holdout_tx $T
harness/run_atomic.sh $O/holdout_tx_norepair $T --no-repair || true
st=$(python3 -c "import json;print(json.load(open('$O/holdout_tx/triage.json'))['status'])")
if [[ "$st" == CANDIDATE_FOR_EXPERT_VALIDATION ]]; then
  "$OFF" python3 harness/run_task.py $O/deploy_atomic_tx $T $O/holdout_tx/capability.json
elif [[ -f $O/holdout_tx/capability.json ]]; then
  # Not deployable (gate blocked). Measured only as an unapproved dry run, labelled as such.
  mkdir -p $O/dryrun_atomic_tx
  cat data/tx-tasks-v1/test_unseen.jsonl data/tx-tasks-v1/false_activation.jsonl > $O/dryrun_atomic_tx/cases.jsonl
  "$ROOT/target/release/syntriass" cap-check --file $O/holdout_tx/capability.json --cases $O/dryrun_atomic_tx/cases.jsonl > $O/dryrun_atomic_tx/check.jsonl
fi
"$OFF" python3 harness/run_task.py $O/deploy_engineer_tx $T $O/engineer_tx/capability.json
"$OFF" python3 harness/baselines.py $O/baselines_tx --task $T \
  --model "$(python3 -I "$R" path qwen2.5-1.5b-q8)" \
  --model-sha "$(python3 -I "$R" sha qwen2.5-1.5b-q8)" --server $LS
"$OFF" python3 harness/run_task.py $O/deploy_atomic_ir_dev tasks/ir_ep114.json $O/attempt3_ir/capability.json
echo HOLDOUT_DONE
