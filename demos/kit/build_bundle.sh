#!/usr/bin/env bash
#
# Build the offline demo kit (W7.1).
#
#   demos/kit/build_bundle.sh OUT_DIR
#
# Writes OUT_DIR/syntriass-demo-kit-<aip>-<overlay>.tar.gz and a .sha256 beside
# it. Inside the archive:
#   kit/aip/      demos/, docs/demos/, and the release binaries the demos call
#   kit/overlay/  demos/, and the release binaries the OVERLAY demos call
#   kit/MANIFEST.json  both commits (refused if either tree is dirty), every
#                 binary's sha256, and the host tools the demos still need
#   kit/SHA256SUMS     every file in kit/
#   kit/verify.sh      checks SHA256SUMS; run it before anything else
# Only files tracked by git (git archive) plus the listed binaries go in: no
# results, no keys, no model weights. Nothing is downloaded.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AIP=$(cd "$HERE/../.." && pwd)
OVL=$(cd "${SYNTRIASS_OVERLAY:-$AIP/../overlay}" && pwd)
OUT=$(mkdir -p "${1:?usage: build_bundle.sh OUT_DIR}" && cd "$1" && pwd)
AIP_BINS=(aip-probe aip-collector aip-observe-verify)
OVL_BINS=(libsyntriass_overlay.so syntriass-identity syntriass-cbom)

for r in "$AIP" "$OVL"; do
  [ -z "$(git -C "$r" status --porcelain --untracked-files=no)" ] \
    || { echo "REFUSED: $r has uncommitted changes; a kit must name exact commits" >&2; exit 2; }
done
for b in "${AIP_BINS[@]}"; do [ -x "$AIP/target/release/$b" ] || { echo "missing $AIP/target/release/$b" >&2; exit 2; }; done
for b in "${OVL_BINS[@]}"; do [ -f "$OVL/target/release/$b" ] || { echo "missing $OVL/target/release/$b" >&2; exit 2; }; done

A=$(git -C "$AIP" rev-parse --short HEAD); O=$(git -C "$OVL" rev-parse --short HEAD)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mkdir -p "$W/kit/aip/target/release" "$W/kit/overlay/target/release"
git -C "$AIP" archive HEAD demos docs/demos | tar -x -C "$W/kit/aip"
git -C "$OVL" archive HEAD demos | tar -x -C "$W/kit/overlay"
for b in "${AIP_BINS[@]}"; do cp "$AIP/target/release/$b" "$W/kit/aip/target/release/"; done
for b in "${OVL_BINS[@]}"; do cp "$OVL/target/release/$b" "$W/kit/overlay/target/release/"; done

python3 - "$W/kit" "$AIP" "$OVL" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
kit, aip, ovl = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
git = lambda r, *a: subprocess.run(["git", "-C", r, *a], capture_output=True, text=True, check=True).stdout.strip()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
m = {"schema": "syntriass.demo.kit/v1",
     "commits": {"aip": git(aip, "rev-parse", "HEAD"), "overlay": git(ovl, "rev-parse", "HEAD")},
     "binaries": {str(p.relative_to(kit)): sha(p) for p in sorted(kit.glob("*/target/release/*"))},
     "host_needs": {
         "all": "Linux, root, python3 (stdlib only), bash",
         "security": "auditd + auditctl, tracefs, kernel with the sched/sockstate/connector/fanotify sensors",
         "quantum": "docker daemon, openssl, gcc with static libc (builds the sample's 'hold' program)",
         "pq": "docker daemon, nsenter, openssl, the host's own /usr/bin/nc (copied into the image unmodified)"},
     "not_in_kit": "model weights (W0.3), so customer-<sector> and investor-3min stay NOT READY; "
                   "the teach mode belongs to the teaching-demo loop"}
(kit / "MANIFEST.json").write_text(json.dumps(m, indent=2) + "\n")
PY
cat > "$W/kit/verify.sh" <<'EOF'
#!/usr/bin/env bash
# Check every file in the kit against SHA256SUMS. Exit non-zero on any mismatch.
cd "$(dirname "${BASH_SOURCE[0]}")" && sha256sum --quiet -c SHA256SUMS && echo "kit verified: $(wc -l < SHA256SUMS) files"
EOF
chmod +x "$W/kit/verify.sh"
(cd "$W/kit" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum > SHA256SUMS)
NAME="syntriass-demo-kit-$A-$O.tar.gz"
tar -C "$W" --owner=0 --group=0 --sort=name -czf "$OUT/$NAME" kit
(cd "$OUT" && sha256sum "$NAME" > "$NAME.sha256")
echo "$OUT/$NAME ($(du -h "$OUT/$NAME" | cut -f1), $(wc -l < "$W/kit/SHA256SUMS") files)"
