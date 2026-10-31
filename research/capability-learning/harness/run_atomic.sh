#!/usr/bin/env bash
# usage: run_atomic.sh OUT_ROOT TASK [extra propose_atomic args]   (runs offline)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
M=${MODELS:-/home/claude/vanian-build/models}
SMALL=${SMALL:-"$M/qwen2.5-0.5b-instruct-q8_0.gguf:ca59ca7f13d0e15a8cfa77bd17e65d24f6844b554a7b6c12e07a5f89ff76844e"}
LARGE=${LARGE:-"$M/qwen2.5-1.5b-instruct-q8_0.gguf:d7efb072e7724d25048a4fda0a3e10b04bdef5d06b1403a1c93bd9f1240a63c8"}
OUT=$1; TASK=$2; shift 2
cd "$ROOT/research/capability-learning"
exec "$ROOT/research/compute-memory/bench/offline.sh" python3 harness/propose_atomic.py "$OUT" --task "$TASK" \
  --bin "$ROOT/target/release/syntriass" --server /home/claude/vanian-build/build-llama-native/bin/llama-server \
  --small "$SMALL" --large "$LARGE" "$@"
