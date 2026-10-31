#!/usr/bin/env bash
# Online staging only. Benchmark runtime uses loopback; do not run staging in an air gap.
set -euo pipefail
mkdir -p .local/runtime
python3 - <<'PY'
import urllib.request,pathlib,hashlib,tarfile
r=pathlib.Path('.local/runtime')
p=r/'llama.tar.gz'
if not p.exists(): urllib.request.urlretrieve('https://files.pythonhosted.org/packages/e4/b4/c8cd17629ced0b9644a71d399a91145aedef109c0333443bef015e45b704/llama_cpp_python-0.3.16.tar.gz',p)
assert hashlib.sha256(p.read_bytes()).hexdigest()=='34ed0f9bd9431af045bb63d9324ae620ad0536653740e9bb163a2e1fcb973be6'
if not (r/'llama_cpp_python-0.3.16').exists():
 with tarfile.open(p) as t:t.extractall(r,filter='data')
p=r/'qwen3-4b.gguf'
if not p.exists():urllib.request.urlretrieve('https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/bc640142c66e1fdd12af0bd68f40445458f3869b/Qwen3-4B-Q4_K_M.gguf',p)
assert hashlib.file_digest(p.open('rb'),'sha256').hexdigest()=='7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5'
print('Pinned model hash verified')
PY
cmake -S .local/runtime/llama_cpp_python-0.3.16/vendor/llama.cpp -B .local/runtime/build -DCMAKE_BUILD_TYPE=Release -DGGML_CUDA=OFF -DLLAMA_CURL=OFF -DLLAMA_BUILD_SERVER=ON
cmake --build .local/runtime/build --target llama-server -j 8
