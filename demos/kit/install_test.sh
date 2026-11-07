#!/usr/bin/env bash
#
# No-network install test for the demo kit (W7.1).
#
#   sudo demos/kit/install_test.sh KIT.tar.gz OUT_DIR [MODE ...]
#
# Inside a new network namespace with no interface but loopback (checked, not
# assumed), in a fresh empty directory:
#   1. the archive's own .sha256 is checked, then it is extracted;
#   2. kit/verify.sh checks every file; one flipped byte must then make it fail
#      (on a copy, so the real kit is untouched);
#   3. launch.py check runs from the kit;
#   4. each MODE given (default: every mode check reports READY) runs from the
#      kit, not from the repository.
# Exception: `security` runs from the same extracted kit but in the host's
# network namespace, after the rest. Its kernel sensor (the netlink process
# connector) only works in the initial network namespace; the probe refuses
# to start anywhere else, and that is not weakened to make this test pass. So
# this test does not show the security mode working without a network.
# Honest scope: same host, fresh directory, no network namespace. It is not a
# clean machine: host tools (docker, auditd, openssl, gcc) are this host's.
set -euo pipefail
KIT=$(cd "$(dirname "${1:?usage: install_test.sh KIT.tar.gz OUT_DIR [MODE ...]}")" && pwd)/$(basename "$1")
OUT=$(mkdir -p "${2:?OUT_DIR}" && cd "$2" && pwd); shift 2
[ "$(id -u)" -eq 0 ] || { echo "NOT READY: run as root" >&2; exit 2; }
HARNESS=$(cd "$(dirname "${BASH_SOURCE[0]}")/../common" && pwd)/harness.py
HOST_NS_MODES=(security)
D=$(mktemp -d)
NS_MODES=() HOST_MODES=()
for m in "$@"; do if [[ " ${HOST_NS_MODES[*]} " == *" $m "* ]]; then HOST_MODES+=("$m"); else NS_MODES+=("$m"); fi; done
SEL=list; [ $# -gt 0 ] || { SEL=auto; HOST_MODES=(AUTO); }

rc=0
unshare --net bash -s -- "$KIT" "$OUT" "$HARNESS" "$D" "${HOST_NS_MODES[*]}" "$SEL" "${NS_MODES[@]}" <<'INNER' || rc=1
set -euo pipefail
KIT=$1 OUT=$2 HARNESS=$3 D=$4 SKIP=$5 SEL=$6; shift 6
# A new namespace starts with loopback down; the demos use loopback, nothing else.
python3 -c "import sys; sys.path.insert(0, '$(dirname "$HARNESS")'); import harness; harness._loopback_up()"
python3 "$HARNESS" offline-check > "$OUT/offline-check.json" \
  || { echo "FAIL: this namespace has a route out"; cat "$OUT/offline-check.json"; exit 1; }
echo "offline: $(cat "$OUT/offline-check.json")"
cd "$D"
(cd "$(dirname "$KIT")" && sha256sum -c "$(basename "$KIT").sha256") | tee "$OUT/archive-check.txt"
tar -xzf "$KIT"
kit/verify.sh | tee "$OUT/verify.txt"
cp -a kit "$D/tampered"; f=$(sed -n '1p' "$D/tampered/SHA256SUMS" | cut -d' ' -f3-)
printf '\x00' | dd of="$D/tampered/$f" bs=1 seek=0 conv=notrunc status=none
if "$D/tampered/verify.sh" > "$OUT/tamper-verify.txt" 2>&1; then echo "FAIL: a flipped byte in $f was not detected"; exit 1; fi
echo "tamper check: flipped byte in $f -> verify.sh refused" | tee -a "$OUT/verify.txt"
rm -rf "$D/tampered"
export SYNTRIASS_OVERLAY="$D/kit/overlay"
python3 kit/aip/demos/launch.py check | tee "$OUT/check.txt"
MODES=("$@")
if [ "$SEL" = auto ]; then
  mapfile -t MODES < <(awk '$1=="READY"{print $2}' "$OUT/check.txt" | grep -vxF -f <(tr ' ' '\n' <<< "$SKIP"))
fi
rc=0
for m in "${MODES[@]}"; do
  python3 kit/aip/demos/launch.py run "$m" --out "$OUT/$m" | tail -1 | tee -a "$OUT/runs.txt" || rc=1
  grep -q "^PASS" <(tail -1 "$OUT/runs.txt") || rc=1
done
exit $rc
INNER

# Host-namespace modes, from the same extracted kit — only if the kit installed and verified.
[ -s "$OUT/check.txt" ] || { echo "INSTALL TEST: FAIL (kit did not install and verify)" | tee -a "$OUT/runs.txt"; exit 1; }
if [ "${HOST_MODES[*]:-}" = AUTO ]; then
  mapfile -t HOST_MODES < <(awk '$1=="READY"{print $2}' "$OUT/check.txt" | grep -xF -f <(printf '%s\n' "${HOST_NS_MODES[@]}") || true)
fi
for m in "${HOST_MODES[@]}"; do
  echo "[host network namespace — offline not shown by this test] $m" | tee -a "$OUT/runs.txt"
  SYNTRIASS_OVERLAY="$D/kit/overlay" python3 "$D/kit/aip/demos/launch.py" run "$m" --out "$OUT/$m" | tail -1 | tee -a "$OUT/runs.txt"
  grep -q "^PASS" <(tail -1 "$OUT/runs.txt") || rc=1
done
echo "kit dir: $D (kept for inspection)"
echo "INSTALL TEST: $([ $rc -eq 0 ] && echo PASS || echo FAIL)" | tee -a "$OUT/runs.txt"
exit $rc
