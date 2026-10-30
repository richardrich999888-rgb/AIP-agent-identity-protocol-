#!/usr/bin/env bash
# Grounded-QA evaluation for one local model, run inside a loopback-only
# user+net namespace (no route off the host).
#   usage: run_eval.sh VANIAN_BIN LLAMA_SERVER MODEL_GGUF MODEL_SHA256 OUT_DIR [QA_JSONL] [CORPUS_DIR]
# Defaults: QA = grounded_qa_v2.jsonl (44 questions), CORPUS = ./corpus.
# Outputs: OUT_DIR/results.jsonl (per question), OUT_DIR/summary.json.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${VANIAN_IN_NETNS:-0}" != "1" ]]; then
  exec env VANIAN_IN_NETNS=1 unshare --user --map-root-user --net -- "$0" "$@"
fi
BIN=$1; LLAMA=$2; MODEL=$3; SHA=$4; OUT=$5
QA=${6:-$HERE/grounded_qa_v2.jsonl}; CORPUS=${7:-$HERE/corpus}
rm -rf "$OUT"; mkdir -p "$OUT/state"
[[ "$(sha256sum "$MODEL" | cut -d' ' -f1)" == "$SHA" ]] || { echo "model hash mismatch" >&2; exit 1; }
python3 -I -c 'import fcntl,socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
f=struct.unpack("16sH14x",fcntl.ioctl(s,0x8913,struct.pack("16sH14x",b"lo",0)))[1]
fcntl.ioctl(s,0x8914,struct.pack("16sH14x",b"lo",f|0x41))'
# Ready means GET /health == 200. llama-server listens before the model is
# loaded and answers 503 until then; a log line is not readiness.
wait_ready() {
  for _ in $(seq 1 300); do
    python3 -I -c "import urllib.request,sys
try: sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:$1/health',timeout=2).status==200 else 1)
except Exception: sys.exit(1)" && return 0
    sleep 1
  done
  echo "llama-server not ready after 300 s" >&2; return 1
}
PORT=8089
"$LLAMA" -m "$MODEL" --host 127.0.0.1 --port $PORT -c 4096 -t "$(nproc)" --no-webui > "$OUT/llama.log" 2>&1 &
LP=$!; trap 'kill $LP 2>/dev/null || true' EXIT
wait_ready $PORT
echo '[{"id":"noop","program":"/bin/true","program_sha256":"'"$(sha256sum /bin/true | cut -d' ' -f1)"'","fixed_args":[],"timeout_ms":1000}]' > "$OUT/tools.json"
"$BIN" init --state "$OUT/state" --tools "$OUT/tools.json" --grant noop --model-sha256 "$SHA" >/dev/null
echo '{"0":{"tenant":"plant-alpha","clearance":"internal"}}' > "$OUT/state/principals.json"
"$BIN" ingest --state "$OUT/state" "$CORPUS"/*.txt >/dev/null
python3 -I "$HERE/grade.py" "$BIN" "$OUT/state" "127.0.0.1:$PORT" "$QA" "$CORPUS" "$OUT" "$MODEL" "$LP"
