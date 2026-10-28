#!/bin/sh
set -eu
mkdir -p "$HOME" /tmp/framework /tmp/framework-logs
if [ "$FRAMEWORK" = deerflow ]; then
  exec /opt/framework/backend/.venv/bin/python /opt/snifferdog/launch.py
fi
exec /opt/framework/.venv/bin/python /opt/snifferdog/launch.py
