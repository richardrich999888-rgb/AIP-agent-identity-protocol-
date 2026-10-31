#!/usr/bin/env bash
# v0.2 SECONDARY run after the negative-number parser fix (found by the holdout). Labels unchanged.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd); cd "$ROOT/research/capability-learning"
OFF="$ROOT/research/compute-memory/bench/offline.sh"; O=results/v02/postfix; T=tasks/tx_hutx2.json
mkdir -p $O
harness/run_atomic.sh $O/holdout_tx $T
"$OFF" python3 harness/run_task.py $O/deploy_engineer_tx $T results/v02/engineer_tx/capability.json
st=$(python3 -c "import json;print(json.load(open('$O/holdout_tx/triage.json'))['status'])")
if [[ "$st" == CANDIDATE_FOR_EXPERT_VALIDATION ]]; then
  "$OFF" python3 harness/run_task.py $O/deploy_atomic_tx $T $O/holdout_tx/capability.json
fi
echo POSTFIX_DONE
