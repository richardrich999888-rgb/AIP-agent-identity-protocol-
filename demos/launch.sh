#!/usr/bin/env bash
# demos/launch.sh MODE  — see demos/launch.py for the modes. `launch.sh check` lists readiness.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-}" in
  ""|-h|--help) exec python3 "$HERE/launch.py" --help ;;
  check|run|rehearse) exec python3 "$HERE/launch.py" "$@" ;;
  *) exec python3 "$HERE/launch.py" run "$@" ;;
esac
