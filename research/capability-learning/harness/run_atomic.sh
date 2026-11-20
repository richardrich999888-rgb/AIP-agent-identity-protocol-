#!/usr/bin/env bash
# usage: run_atomic.sh OUT_ROOT TASK [extra propose_atomic args]   (runs offline)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
# Paths and digests come from deploy/syntriass/models.manifest.json, so the
# hashes are not duplicated here and cannot drift from the manifest. SMALL and
# LARGE still override wholesale; MODELS / SYNTRIASS_BUNDLE still move the dir.
RM="$ROOT/deploy/syntriass/resolve_model.py"
M=$(python3 -I "$RM" dir) || exit $?
SMALL=${SMALL:-"$(python3 -I "$RM" path qwen2.5-0.5b-q8):$(python3 -I "$RM" sha qwen2.5-0.5b-q8)"}
LARGE=${LARGE:-"$(python3 -I "$RM" path qwen2.5-1.5b-q8):$(python3 -I "$RM" sha qwen2.5-1.5b-q8)"}
OUT=$1; TASK=$2; shift 2
cd "$ROOT/research/capability-learning"
exec "$ROOT/research/compute-memory/bench/offline.sh" python3 harness/propose_atomic.py "$OUT" --task "$TASK" \
  --bin "$ROOT/target/release/syntriass" --server "$(python3 -I "$RM" server)" \
  --small "$SMALL" --large "$LARGE" "$@"
