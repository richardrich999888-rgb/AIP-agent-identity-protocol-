#!/usr/bin/env bash
# Preflight: reports what this host has. Changes nothing. Exit 1 if a required item is missing.
source "$(dirname "$0")/lib.sh"
missing=0
need() { if eval "$2" >/dev/null 2>&1; then log "ok       $1"; else log "MISSING  $1"; missing=$((missing+1)); fi; }
have() { if eval "$2" >/dev/null 2>&1; then log "ok       $1"; else log "absent   $1 ($3)"; fi; }
need "root (sensors and network namespaces)" '[ "$(id -u)" = 0 ]'
need "cargo" 'command -v cargo'
need "go (builds the pinned OPA)" 'command -v go'
need "python3 >= 3.11" 'python3 -c "import sys; assert sys.version_info >= (3, 11)"'
need "unshare (offline test runs)" 'command -v unshare'
have "tracefs mounted" '[ -e /sys/kernel/tracing/trace_pipe ]' "setup.sh mounts it"
have "docker daemon" 'docker info' "only compose.yaml needs it"
have "CAP_SYS_RESOURCE (Falco)" 'python3 -c "import sys; c=int([l for l in open(\"/proc/self/status\") if l.startswith(\"CapEff\")][0].split()[1],16); sys.exit(0 if c>>24&1 else 1)"' "Falco cannot run; not on the demo path"
have "tools built" '[ -x "$BIN/opa" ] && [ -x "$VENV/bin/python" ] && [ -x "$RELEASE/aip-observe-verify" ]' "run setup.sh"
log "required missing: $missing"
[ "$missing" -eq 0 ]
