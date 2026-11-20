#!/usr/bin/env bash
#
# Recording kit (W9.1): real terminal recordings and screenshot sequences.
#
#   sudo demos/recording/record.sh OUT_DIR [MODE ...]     (default: every READY mode)
#
# For each mode:
#   OUT/<mode>/terminal.log + terminal.timing   the live run, recorded by util-linux
#                                               `script`; replay with
#                                               scriptreplay -t terminal.timing terminal.log
#   OUT/<mode>/run/...                          the launcher's own result file and outputs
#   OUT/<mode>/shots/NN-*.png                   screenshots of the run's real outputs
#                                               (screenshots.js), never of a mock-up
# Nothing here generates voice or video of any person. Anything replayed from
# these files must be labelled RECORDED on screen; only a fresh `launch.py run`
# is live.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEMOS=$(cd "$HERE/.." && pwd)
OUT=$(mkdir -p "${1:?usage: record.sh OUT_DIR [MODE ...]}" && cd "$1" && pwd); shift
MODES=("$@")
[ ${#MODES[@]} -gt 0 ] || mapfile -t MODES < <(python3 "$DEMOS/launch.py" check | awk '$1=="READY"{print $2}')
rc=0
for m in "${MODES[@]}"; do
  D="$OUT/$m"; mkdir -p "$D"
  echo "== recording $m"
  script -q -e --log-out "$D/terminal.log" --log-timing "$D/terminal.timing" \
    -c "python3 '$DEMOS/launch.py' run '$m' --out '$D/run'" >/dev/null || rc=1
  grep -q "^PASS" "$D/terminal.log" && echo "   live run PASS" || { echo "   live run did not pass; recording kept, marked FAIL"; rc=1; }
  node "$HERE/screenshots.js" "$m" "$D" || rc=1
  ls "$D/shots"
done
exit $rc
