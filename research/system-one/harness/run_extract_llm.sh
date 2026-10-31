#!/usr/bin/env bash
# LLM extraction (v2, with abstention) for one model inside a loopback-only namespace.
#   usage: run_extract_llm.sh LLAMA_SERVER MODEL_GGUF MODEL_SHA256 OUT_DIR [V2_LIMIT]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${VANIAN_IN_NETNS:-0}" != "1" ]]; then
  exec env VANIAN_IN_NETNS=1 unshare --user --map-root-user --net -- "$0" "$@"
fi
LLAMA=$1; MODEL=$2; SHA=$3; OUT=$4; export V2_LIMIT=${5:-100}
[[ "$(sha256sum "$MODEL" | cut -d' ' -f1)" == "$SHA" ]] || { echo "model hash mismatch" >&2; exit 1; }
python3 -I -c 'import fcntl,socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
f=struct.unpack("16sH14x",fcntl.ioctl(s,0x8913,struct.pack("16sH14x",b"lo",0)))[1]
fcntl.ioctl(s,0x8914,struct.pack("16sH14x",b"lo",f|0x41))'
if python3 -I -c 'import socket; socket.create_connection(("1.1.1.1",443),timeout=2)' 2>/dev/null; then echo "external route present" >&2; exit 1; fi
PORT=8098; EP=127.0.0.1:$PORT; mkdir -p "$OUT"
"$LLAMA" -m "$MODEL" --host 127.0.0.1 --port $PORT -c 2048 -t "$(nproc)" --no-webui ${LLAMA_EXTRA:-} > "$OUT.llama.log" 2>&1 &
LP=$!; trap 'kill $LP 2>/dev/null || true' EXIT
for _ in $(seq 1 300); do python3 -I -c "import urllib.request,sys
try: sys.exit(0 if urllib.request.urlopen('http://$EP/health',timeout=2).status==200 else 1)
except Exception: sys.exit(1)" && break; sleep 1; done
cd "$HERE/.."
python3 harness/extract_eval.py llm_json_v2 "$OUT" --endpoint $EP --server-pid $LP --model "$(basename "$MODEL")" | tail -c 200; echo
echo EXTRACT-DONE
