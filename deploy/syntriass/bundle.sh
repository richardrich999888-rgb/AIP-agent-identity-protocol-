#!/usr/bin/env bash
# Build an offline installation bundle for SYNTRIASS (single node).
#
#   usage: bundle.sh OUT_DIR LLAMA_BIN_DIR MODEL.gguf:SHA256 [MODEL.gguf:SHA256 ...]
#
# Runs on a STAGING host that has the Rust toolchain and a populated cargo
# cache; it performs no network access itself (cargo --offline). The bundle
# is then carried to the air-gapped host (removable media, or the optional
# BitTorrent distribution in research/bittorrent-p2p — never required).
#
# Contents: bin/syntriass, bin/llama-server (wrapper) + lib/ (llama.cpp
# shared objects), share/ (retrieval/interpretation sidecar sources and its
# training file), models/ (hard links, or copies across filesystems),
# MANIFEST.json (versions, model hashes) and SHA256SUMS over every file.
# A model whose hash does not match its declared SHA-256 aborts the bundle.
set -euo pipefail
[[ $# -ge 3 ]] || { sed -n 2,4p "$0" >&2; exit 2; }
OUT=$1; LLAMA_DIR=$2; shift 2
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
[[ ! -e "$OUT" ]] || { echo "bundle: $OUT exists; refusing to overwrite" >&2; exit 2; }
mkdir -p "$OUT"/{bin,lib,models,share/research}

cargo build --offline --release -p syntriass-runtime --manifest-path "$ROOT/Cargo.toml" >&2
install -m 0755 "$ROOT/target/release/syntriass" "$OUT/bin/syntriass"
install -m 0755 "$LLAMA_DIR/llama-server" "$OUT/lib/llama-server.real"
for so in "$LLAMA_DIR"/*.so*; do install -m 0644 "$so" "$OUT/lib/"; done
cat > "$OUT/bin/llama-server" <<'EOF'
#!/bin/sh
# llama.cpp's RUNPATH points at its build directory; resolve the bundled libraries instead.
HERE=$(cd "$(dirname "$0")/../lib" && pwd)
LD_LIBRARY_PATH="$HERE${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" exec "$HERE/llama-server.real" "$@"
EOF
chmod 0755 "$OUT/bin/llama-server"

# Sidecar: exactly the directory layout sidecar.py resolves at import time.
S1=share/research/system-one
mkdir -p "$OUT/$S1"/{harness,methods,datasets,data/maintenance-priority-v2} "$OUT/share/research/compute-memory/tools"
install -m 0644 "$ROOT/research/system-one/harness/sidecar.py" "$OUT/$S1/harness/"
install -m 0644 "$ROOT"/research/system-one/methods/*.py "$OUT/$S1/methods/"
install -m 0644 "$ROOT"/research/system-one/datasets/*.py "$OUT/$S1/datasets/"
install -m 0644 "$ROOT/research/system-one/data/maintenance-priority-v2/train.jsonl" "$OUT/$S1/data/maintenance-priority-v2/"
install -m 0644 "$ROOT/research/compute-memory/tools/cascade.py" "$OUT/share/research/compute-memory/tools/"
install -m 0755 "$ROOT/deploy/syntriass/install.sh" "$OUT/install.sh"

models_json=""
for spec in "$@"; do
  path=${spec%%:*}; sha=${spec##*:}
  got=$(sha256sum "$path" | cut -d' ' -f1)
  [[ "$got" == "$sha" ]] || { echo "bundle: $path sha256 $got != declared $sha" >&2; exit 1; }
  name=$(basename "$path")
  ln "$path" "$OUT/models/$name" 2>/dev/null || cp "$path" "$OUT/models/$name"
  models_json+="${models_json:+,}{\"file\":\"models/$name\",\"sha256\":\"$sha\",\"bytes\":$(stat -c %s "$path")}"
done

git_sha=$(git -C "$ROOT" rev-parse HEAD)
llama_ver=$("$OUT/bin/llama-server" --version 2>&1 | head -1)
cat > "$OUT/MANIFEST.json" <<EOF
{"product": "SYNTRIASS runtime (research build)", "git_commit": "$git_sha",
 "rustc": "$(rustc --version)", "llama_server": "$llama_ver",
 "python_required": ">=3.10 with numpy (sidecar)", "python_seen_at_build": "$(python3 --version 2>&1)",
 "numpy_seen_at_build": "$(python3 -c 'import numpy; print(numpy.__version__)' 2>/dev/null || echo absent)",
 "system_libraries": ["libc.so.6", "libm.so.6", "libgcc_s.so.1", "libstdc++.so.6", "libgomp.so.1"],
 "models": [$models_json],
 "gpu": "not used", "network": "none required at runtime"}
EOF
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
echo "{\"bundle\": \"$OUT\", \"files\": $(wc -l < "$OUT/SHA256SUMS"), \"commit\": \"$git_sha\"}"
