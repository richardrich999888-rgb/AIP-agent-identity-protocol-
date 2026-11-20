#!/usr/bin/env bash
#
# Fresh rerun of the learning benchmark on this machine (W6.1 / W6.3).
#
#   demos/benchmark/rerun.sh OUT_DIR
#
# Calls the teaching-demo session's own harness unchanged; this script only
# supplies the staged models and the llama-server from the offline bundle
# (SYNTRIASS_BUNDLE, checked with deploy/syntriass/resolve_model.py):
#   run1/        run_learning.py   phases A, C (lifecycle), D, F and baseline 4
#   baselines_q8/ baselines.py     B1-B3 on Qwen2.5-1.5B Q8_0, inside offline.sh
#   phase_e/     phase_e.py        model replacement Q4 -> Q8
# then compares the fresh results with the recorded ones (compare.py) and
# exits 0 only if the comparison could be made; differences are reported,
# never hidden. Phase C's model proposal (the 1.5B model drafting the
# procedure, which failed in the original) is not rerun: it costs ~500 CPU-s
# and its recorded outcome (0 compiling candidates) is not an input to any
# later phase.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=$(mkdir -p "${1:?usage: rerun.sh OUT_DIR}" && cd "$1" && pwd)
H="$REPO/research/capability-learning/harness"
CAP="$REPO/research/capability-learning/results/corrected/capability.json"
RES="$REPO/deploy/syntriass/resolve_model.py"
fail() { echo "NOT READY: $*" >&2; exit 3; }
[ -x "$REPO/target/release/syntriass" ] || fail "cargo build --release --locked -p syntriass-runtime"
for m in qwen2.5-1.5b-q4 qwen2.5-1.5b-q8; do python3 "$RES" path "$m" --verify >/dev/null || fail "model $m not staged"; done
Q8=$(python3 "$RES" path qwen2.5-1.5b-q8); Q8_SHA=$(python3 "$RES" sha qwen2.5-1.5b-q8); LLAMA=$(python3 "$RES" server)
ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }
T="$OUT/timings.txt"; : > "$T"
echo "machine: $(python3 "$REPO/demos/common/harness.py" hardware)" | tee "$OUT/machine.txt"
echo "llama-server: $("$LLAMA" --version 2>&1 | head -1)" | tee -a "$OUT/machine.txt"

t=$(date +%s%N); python3 "$H/run_learning.py" "$OUT/run1" "$CAP" > "$OUT/run1.log" 2>&1; echo "run1_ms=$(ms $t)" | tee -a "$T"
t=$(date +%s%N); "$REPO/research/compute-memory/bench/offline.sh" python3 "$H/baselines.py" "$OUT/baselines_q8" \
  --model "$Q8" --model-sha "$Q8_SHA" --server "$LLAMA" > "$OUT/baselines.log" 2>&1; echo "baselines_ms=$(ms $t)" | tee -a "$T"
t=$(date +%s%N); python3 "$H/phase_e.py" "$OUT/phase_e" "$CAP" > "$OUT/phase_e.log" 2>&1; echo "phase_e_ms=$(ms $t)" | tee -a "$T"
python3 "$HERE/compare.py" "$REPO/research/capability-learning/results" "$OUT" | tee "$OUT/comparison.md"
