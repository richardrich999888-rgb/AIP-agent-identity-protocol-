#!/usr/bin/env bash
# Phase 4 reproducer — regenerate the ATT&CK Navigator layer and verify it is
# byte-identical to the committed artefact. Runs NO atomic and loads nothing.
#
# The coverage map (coverage.tsv) is a capability statement, not a run log.
# This script proves the artefact is reproducible from the map and that the
# generator's own tests pass; it never executes an attack technique. Executing
# destructive atomics (T1070, T1222, ...) is out of scope on this host per the
# adversarial safety rules — reproduce those from atomics/<ID>/ in the pinned
# corpus, in your own controlled environment.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

echo "== generator unit tests"
python3 gen_layer_test.py

echo "== regenerate the layer and check for drift"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
python3 gen_layer.py > "$tmp"
if ! diff -u aip-attack-coverage.layer.json "$tmp"; then
  echo "DRIFT: the committed layer does not match the map. Regenerate and commit." >&2
  exit 1
fi
n=$(python3 -c "import json;print(len(json.load(open('aip-attack-coverage.layer.json'))['techniques']))")
echo "OK: layer reproducible from coverage.tsv ($n techniques)"
