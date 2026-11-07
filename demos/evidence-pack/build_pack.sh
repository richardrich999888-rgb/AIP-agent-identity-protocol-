#!/usr/bin/env bash
#
# Regenerate the machine-readable part of the buyer evidence pack (W8.2).
#
#   demos/evidence-pack/build_pack.sh KIT.tar.gz OUT_DIR
#
# Writes into OUT_DIR, from clean AIP and OVERLAY trees and the kit archive:
#   sbom-aip.cdx.json, sbom-aip.licences.json        cargo tree of the 3 AIP kit binaries
#   sbom-overlay.cdx.json, sbom-overlay.licences.json cargo tree of the overlay crate (cbom,compliance)
#   cbom-kit-files.cdx.json   syntriass-cbom scan of the extracted kit (config/key/cert files)
#   cbom-kit-binaries.cdx.json syntriass-cbom binscan of the kit's 6 binaries (constants only)
#   cbom-overlay-self.cdx.json syntriass-cbom self-inventory (the overlay's declared algorithms)
#   aibom-scripted-agent.{txt,json}  aibom assess of the kit's only agent, the scripted test agent
#   PROVENANCE.json           commits, kit sha256, tool versions, timestamp
# Paths inside the scans are rewritten relative to the kit (kit/...), so no
# host path leaks into the pack. Nothing is downloaded.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AIP=$(cd "$HERE/../.." && pwd)
OVL=$(cd "${SYNTRIASS_OVERLAY:-$AIP/../overlay}" && pwd)
KIT=$(cd "$(dirname "${1:?usage: build_pack.sh KIT.tar.gz OUT_DIR}")" && pwd)/$(basename "$1")
OUT=$(mkdir -p "${2:?OUT_DIR}" && cd "$2" && pwd)
CBOM="$OVL/target/release/syntriass-cbom"; AIBOM="$AIP/target/release/aibom"
for r in "$AIP" "$OVL"; do
  [ -z "$(git -C "$r" status --porcelain --untracked-files=no)" ] || { echo "REFUSED: $r is dirty" >&2; exit 2; }
done
[ -x "$CBOM" ] && [ -x "$AIBOM" ] || { echo "build syntriass-cbom (overlay) and aibom (cargo build --release -p aip-aibom --bin aibom)" >&2; exit 2; }

python3 "$HERE/sbom_tree.py" aip-kit-binaries "$AIP" "$OUT/sbom-aip" -- -p aip-probe -p aip-collector -p aip-observe-verify
python3 "$HERE/sbom_tree.py" syntriass-overlay "$OVL" "$OUT/sbom-overlay" -- -p syntriass-overlay --features cbom,compliance

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
tar -xzf "$KIT" -C "$W"; (cd "$W" && kit/verify.sh)
"$CBOM" scan --root "$W/kit" --out "$OUT/cbom-kit-files.cdx.json" --no-timestamp 2>&1 | tail -1
"$CBOM" binscan --root "$W/kit/aip/target/release" --root "$W/kit/overlay/target/release" --out "$OUT/cbom-kit-binaries.cdx.json" 2>&1 | head -1
"$CBOM" self-inventory --out "$OUT/cbom-overlay-self.cdx.json" --deterministic 2>&1 | tail -1
sed -i "s#$W/##g" "$OUT/cbom-kit-files.cdx.json" "$OUT/cbom-kit-binaries.cdx.json"

NOW=$(date +%s%3N)
"$AIBOM" assess --manifest "$HERE/scripted-agent.manifest.json" --now-ms "$NOW" --format text > "$OUT/aibom-scripted-agent.txt"
"$AIBOM" assess --manifest "$HERE/scripted-agent.manifest.json" --now-ms "$NOW" --format json > "$OUT/aibom-scripted-agent.json"

python3 - "$OUT" "$AIP" "$OVL" "$KIT" <<'PY'
import hashlib, json, subprocess, sys, datetime
out, aip, ovl, kit = sys.argv[1:]
g = lambda r: subprocess.run(["git", "-C", r, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
json.dump({"generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "aip_commit": g(aip), "overlay_commit": g(ovl),
           "kit": kit.rsplit("/", 1)[-1], "kit_sha256": hashlib.sha256(open(kit, "rb").read()).hexdigest(),
           "cargo": subprocess.run(["cargo", "--version"], capture_output=True, text=True).stdout.strip()},
          open(out + "/PROVENANCE.json", "w"), indent=1)
PY
grep -rl "/tmp/\|/home/" "$OUT" && { echo "REFUSED: a host path leaked into the pack" >&2; exit 1; } || true
echo "pack: $OUT"
