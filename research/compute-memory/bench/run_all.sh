#!/usr/bin/env bash
# All compute/memory experiments, offline, sequential (no concurrent load).
#   usage: bench/run_all.sh OUT_DIR SERVER_BIN [REPS]
# Models are verified against pinned SHA-256 before use.
set -euo pipefail
OUT=$1; S=$2; REPS=${3:-3}; M=${MODELS:-/home/claude/vanian-build/models}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -A SHA=(
  [qwen2.5-0.5b-instruct-q4_k_m.gguf]=74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db
  [qwen2.5-0.5b-instruct-q8_0.gguf]=ca59ca7f13d0e15a8cfa77bd17e65d24f6844b554a7b6c12e07a5f89ff76844e
  [qwen2.5-1.5b-instruct-q8_0.gguf]=d7efb072e7724d25048a4fda0a3e10b04bdef5d06b1403a1c93bd9f1240a63c8
  [qwen2.5-1.5b-instruct-q4_k_m.gguf]=6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e
)
for f in "${!SHA[@]}"; do
  [[ "$(sha256sum "$M/$f" | cut -d' ' -f1)" == "${SHA[$f]}" ]] || { echo "hash mismatch: $f" >&2; exit 1; }
done
mkdir -p "$OUT"
P="$HERE/offline.sh python3 -I $HERE/profile.py"
run() { local e=$1 tag=$2 model=$3; shift 3; [[ -s "$OUT/${e}_${tag}.json" ]] || $P "$e" "$OUT/${e}_${tag}.json" --server "$S" --model "$M/$model" --reps "$REPS" "$@"; }
for tag in 0.5b-q4:qwen2.5-0.5b-instruct-q4_k_m.gguf 0.5b-q8:qwen2.5-0.5b-instruct-q8_0.gguf \
           1.5b-q4:qwen2.5-1.5b-instruct-q4_k_m.gguf 1.5b-q8:qwen2.5-1.5b-instruct-q8_0.gguf; do
  run load "${tag%%:*}" "${tag#*:}"
  run throughput "${tag%%:*}" "${tag#*:}"
done
B15=qwen2.5-1.5b-instruct-q4_k_m.gguf
run prefix 1.5b-q4 $B15
run sidechan 1.5b-q4 $B15
run restore 1.5b-q4 $B15
run shared 1.5b-q4 $B15
run specdec 1.5b-q4 $B15 --draft "$M/qwen2.5-0.5b-instruct-q4_k_m.gguf"
echo RUN_ALL_DONE
