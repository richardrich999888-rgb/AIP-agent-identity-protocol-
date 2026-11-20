#!/usr/bin/env bash
# Remove run outputs and stop lab processes. Keeps the built tools.
source "$(dirname "$0")/lib.sh"
for p in aip-collector aip-probe; do pkill -f "$RELEASE/$p" 2>/dev/null && log "stopped $p" || true; done
rm -rf "$RUNS" && log "removed $RUNS"
