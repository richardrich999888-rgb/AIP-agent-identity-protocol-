#!/usr/bin/env bash
# Shared paths and pins for the VANIAN enterprise lab scripts. Sourced, not run.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
LAB=${VANIAN_LAB_DIR:-$HERE/.lab}          # tools and runs; git-ignored
BIN=$LAB/bin
VENV=$LAB/venv-litellm
GATE_VENV=$LAB/venv-gate
RUNS=$LAB/runs
RELEASE=$REPO/target/release
# Pins (items 1.2, 1.3). Each is checked at setup; a mismatch stops setup.
OPA_VERSION=v1.22.4
OPA_MODULE_H1='h1:/sKtqt7GVSvXQn1sML2PSzl8tD/mTHF2pzQC3x1CV8k='   # = sum.golang.org entry
LITELLM_LOCK=$REPO/research/oss/litellm/requirements-core.lock.txt
GATE_LOCK=$REPO/command-center/server/requirements-gate.lock.txt
SERVER=$REPO/command-center/server
POLICY=$REPO/command-center/policy
log() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
