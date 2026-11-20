#!/usr/bin/env bash
#
# Catch the lying agent — the 5-minute demo (W2.3).
#
#   sudo demos/lying-agent/run.sh [OUT_DIR] [--with-control]
#
# Runs the scripted test agent once under Sniffer Dog and auditd, prints the
# story (its own log, the signed observation, the independent cross-check,
# offline verification and a rejected one-byte tamper) and exits 0 only if
# the pre-registered acceptance holds. --with-control also runs the honest
# agent and requires that nothing is reported for it.
#
# Prerequisites are checked, never silently changed: root, release binaries,
# tracefs, and a running auditd. On a host without NTP sync, set
# AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0; the collector then signs its
# worst-case clock error into the evidence and the screen says so.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT="${1:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}"
CONTROL=0; [ "${2:-}" = "--with-control" ] && CONTROL=1
fail() { echo "NOT READY: $*" >&2; exit 2; }

[ "$(id -u)" -eq 0 ] || fail "run as root (kernel sensors, auditctl)"
for b in aip-probe aip-collector aip-observe-verify; do
  [ -x "$REPO/target/release/$b" ] || fail "build first: cargo build --release --locked -p aip-probe -p aip-collector -p aip-observe-verify"
done
[ -r /sys/kernel/tracing/available_events ] || mount -t tracefs nodev /sys/kernel/tracing \
  || fail "tracefs unavailable"
command -v auditctl >/dev/null || fail "install auditd (independent cross-check)"
auditctl -s | grep -q '^enabled 1' || fail "auditd is not running; start it with: auditd && auditctl -e 1"

mkdir -p "$OUT"
python3 "$HERE/observe.py" "$OUT/scripted-agent" --mode lying > "$OUT/lying.json"
python3 "$HERE/show.py" "$(ls "$OUT"/scripted-agent/lying-agent-*.json)" | tee "$OUT/screen.txt"
if [ "$CONTROL" -eq 1 ]; then
  python3 "$HERE/observe.py" "$OUT/control-agent" --mode honest > "$OUT/honest.json"
  echo; echo "--- control: the same agent without the hidden step ---"
  python3 "$HERE/show.py" "$(ls "$OUT"/control-agent/lying-agent-*.json)" | tee "$OUT/control-screen.txt"
fi
python3 "$HERE/acceptance.py" check "$OUT"
