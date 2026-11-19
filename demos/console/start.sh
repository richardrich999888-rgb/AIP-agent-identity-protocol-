#!/usr/bin/env bash
# Start the SYNTRIASS demo console:  sudo SYNTRIASS_BUNDLE=/path/to/bundle demos/console/start.sh [PORT]
# Checks what the demos need and says what is missing; it changes nothing on the
# system except starting auditd/dockerd when they are installed but stopped.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run as root (kernel sensors, containers)"; exit 2; }
[ -n "${SYNTRIASS_BUNDLE:-}" ] || echo "note: SYNTRIASS_BUNDLE not set; Pull the plug will say NOT READY (demos/models/README.md)"
if command -v auditctl >/dev/null && ! auditctl -s | grep -q 'enabled 1'; then mkdir -p /var/log/audit; pgrep -x auditd >/dev/null || auditd; auditctl -e 1 >/dev/null; fi
if command -v dockerd >/dev/null && ! docker info >/dev/null 2>&1; then (dockerd >/var/log/syntriass-dockerd.log 2>&1 &); for i in $(seq 30); do docker info >/dev/null 2>&1 && break; sleep 1; done; fi
export AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=${AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK:-1}
python3 "$HERE/../launch.py" check
exec python3 "$HERE/server.py" "${1:-8770}"
