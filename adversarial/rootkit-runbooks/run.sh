#!/usr/bin/env bash
# Phase 5 harness. Runs NO rootkit. Validates the output-parser against the
# fixtures in fixtures/. Swap a fixture for a real VM capture (per README.md)
# to turn a row from a rehearsal into evidence.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$HERE/parse_health.py" "$HERE/manifest.tsv"
