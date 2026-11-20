#!/usr/bin/env bash
#
# Pull the plug — the demo run (W1.4).
#
#   demos/pull-the-plug/run.sh [OUT_DIR] [--questions FILE] [--corpus DIR]...
#
# 1. checks the offline bundle (SYNTRIASS_BUNDLE): pinned models and
#    llama-server verified by deploy/syntriass/resolve_model.py;
# 2. writes a fresh runtime config and ingests the corpus (default: the
#    synthetic plant corpus; --corpus adds or replaces it);
# 3. inside a network namespace with no route out, asks every question to
#    the local runtime and to the cloud-API app, metering both;
# 4. judges the answers against the questions file (accept.py).
# The cloud side uses CLOUD_API_URL / CLOUD_API_KEY as the operator sets
# them. Unset, it is pointed at cloud.example.invalid and the screen says so:
# offline it cannot connect either way. No model API is ever reached.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=${1:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}; [ $# -gt 0 ] && shift
QUESTIONS="$HERE/questions.json"; CORPORA=(); MODEL=qwen2.5-1.5b-q4
while [ $# -gt 0 ]; do
  case "$1" in
    --questions) QUESTIONS=$(cd "$(dirname "$2")" && pwd)/$(basename "$2"); shift 2 ;;
    --corpus) CORPORA+=(--corpus "$(cd "$2" && pwd)"); shift 2 ;;
    --model) MODEL=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
fail() { echo "NOT READY: $*" >&2; exit 3; }
BIN="$REPO/target/release/syntriass"
[ -x "$BIN" ] || fail "build the runtime: cargo build --release --locked -p syntriass-runtime"
[ -x "$REPO/deploy/syntriass/venv/bin/python" ] || fail "run deploy/syntriass/setup_env.sh (pinned sidecar environment)"
for m in qwen2.5-1.5b-q4 qwen2.5-1.5b-q8; do
  python3 "$REPO/deploy/syntriass/resolve_model.py" path "$m" --verify >/dev/null \
    || fail "model $m not staged or not the pinned bytes (demos/models/stage.py, SYNTRIASS_BUNDLE)"
done
python3 "$REPO/deploy/syntriass/resolve_model.py" server >/dev/null || fail "llama-server not in the bundle"

export CLOUD_API_URL=${CLOUD_API_URL:-https://cloud.example.invalid/v1/chat/completions}
# A laptop running this demo has no proxy; this sandbox does, and inside the
# offline namespace that proxy is unreachable, which would make the cloud side
# fail as "connection_refused via proxy". Clear proxy variables for the run so
# the failure is the real one; DEMO_KEEP_PROXY=1 keeps them.
if [ "${DEMO_KEEP_PROXY:-0}" != 1 ]; then unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy; fi
case "$CLOUD_API_URL" in *example.invalid*) echo "note: cloud side not configured by the operator; pointed at $CLOUD_API_URL (a placeholder)";; esac

python3 "$REPO/research/intelligence-runtime/harness/mkconfig.py" "$OUT/state" balanced "${CORPORA[@]}" > "$OUT/mkconfig.json"
CFG="$OUT/state/config.json"
# --model: the serving slot (balanced profile = one model, slot "q4") takes
# another staged model. Its bytes are re-verified here against the pin in
# demos/models/extra-models.json; the runtime checks the hash again at load.
if [ "$MODEL" != qwen2.5-1.5b-q4 ]; then
  python3 - "$CFG" "$MODEL" "$REPO" <<'PY' || fail "model $MODEL is not staged with its pinned bytes"
import hashlib, json, os, sys
cfg, name, repo = sys.argv[1:]
extra = {m["logical_name"]: m for m in json.load(open(f"{repo}/demos/models/extra-models.json"))["models"]}
m = extra[name]
path = os.path.join(os.environ["SYNTRIASS_BUNDLE"], "models", m["file"])
h = hashlib.sha256(open(path, "rb").read()).hexdigest()
if h != m["sha256"]:
    sys.exit(f"{path}: sha256 {h} != pinned {m['sha256']}")
c = json.load(open(cfg)); c["q4"] = {"path": path, "sha256": h}; json.dump(c, open(cfg, "w"), indent=1)
PY
fi
echo "serving model: $MODEL"
echo "PULL THE PLUG   [LIVE]   measured on: $(python3 "$REPO/demos/common/harness.py" hardware | python3 -c 'import json,sys; print(json.load(sys.stdin)["label"])')"
python3 "$REPO/demos/common/harness.py" run-offline -- bash -c "
  python3 '$REPO/demos/common/harness.py' offline-check > '$OUT/offline-check.json' || true
  echo \"network: \$(cat '$OUT/offline-check.json')\"
  python3 '$HERE/run_questions.py' '$QUESTIONS' '$OUT/answers.jsonl' -- '$BIN' serve --eval --config '$CFG'
"
python3 "$HERE/accept.py" "$QUESTIONS" "$OUT/answers.jsonl" "$OUT/offline-check.json" | tee "$OUT/acceptance.txt" | tail -1
grep -q "ACCEPTANCE: PASS" "$OUT/acceptance.txt"
