#!/usr/bin/env bash
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo="$(cd -- "$here/../.." && pwd -P)"
assets="${VANIAN_DEMO_ASSETS:-/private/tmp/vanian-local-evidence-agent-assets}"
cd "$repo"
python3.12 "$here/model_runtime.py" prepare --root "$assets"
cargo build --locked -p airon-aip -p aip-observe-verify -p aip-corroborate -p aip-mcp-gateway --bin airon-aip --bin aip-observe-verify --bin aip-corroborate --bin aip-execution-assurance
exec "$assets/venv/bin/python" "$here/demo.py" --assets "$assets" "$@"
