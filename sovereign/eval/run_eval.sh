#!/usr/bin/env bash
# Grounded-QA evaluation for one local model, run inside a loopback-only
# user+net namespace. Writes one JSON line per question to $OUT/results.jsonl
# and a summary to $OUT/summary.json. Grading is substring-based and stated
# as such: it measures fact presence, not full answer correctness.
#   usage: run_eval.sh VANIAN_BIN LLAMA_SERVER MODEL_GGUF MODEL_SHA256 OUT_DIR
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${VANIAN_IN_NETNS:-0}" != "1" ]]; then
  exec env VANIAN_IN_NETNS=1 unshare --user --map-root-user --net -- "$0" "$@"
fi
BIN=$1; LLAMA=$2; MODEL=$3; SHA=$4; OUT=$5
rm -rf "$OUT"; mkdir -p "$OUT/state"
[[ "$(sha256sum "$MODEL" | cut -d' ' -f1)" == "$SHA" ]] || { echo "model hash mismatch" >&2; exit 1; }
python3 -I -c 'import fcntl,socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
f=struct.unpack("16sH14x",fcntl.ioctl(s,0x8913,struct.pack("16sH14x",b"lo",0)))[1]
fcntl.ioctl(s,0x8914,struct.pack("16sH14x",b"lo",f|0x41))'
PORT=8089
"$LLAMA" -m "$MODEL" --host 127.0.0.1 --port $PORT -c 4096 -t "$(nproc)" --no-webui > "$OUT/llama.log" 2>&1 &
LP=$!; trap 'kill $LP 2>/dev/null || true' EXIT
for _ in $(seq 1 180); do grep -q 'server is listening' "$OUT/llama.log" && break; sleep 1; done
echo '[{"id":"noop","program":"/bin/true","program_sha256":"'"$(sha256sum /bin/true | cut -d' ' -f1)"'","fixed_args":[],"timeout_ms":1000}]' > "$OUT/tools.json"
"$BIN" init --state "$OUT/state" --tools "$OUT/tools.json" --grant noop --model-sha256 "$SHA" >/dev/null
echo '{"0":{"tenant":"plant-alpha","clearance":"internal"}}' > "$OUT/state/principals.json"
"$BIN" ingest --state "$OUT/state" "$HERE"/../demo/corpus/*.txt >/dev/null
python3 -I "$HERE/grade.py" "$BIN" "$OUT/state" "127.0.0.1:$PORT" "$HERE/grounded_qa.jsonl" "$OUT" "$MODEL"
