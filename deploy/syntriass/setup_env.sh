#!/usr/bin/env bash
# Install the pinned Python environment the sidecar and harness need.
#
#   usage: setup_env.sh [--wheels DIR] [--venv DIR] [--python PY] [--skip-data]
#
# Installs into a virtual environment, NOT the system interpreter. That is not
# tidiness: the lock pins exact versions of packages a distribution may also
# manage, and pip cannot replace a Debian-installed package that ships no
# RECORD file. Installing system-wide fails outright on such a package
# (observed with `packaging`), and a pinned environment that fights the
# distribution is not pinned at all.
#
# Prefers wheels from the offline bundle and only falls back to PyPI when no
# wheel directory is present, so an air-gapped install never silently needs
# the network. Either way `pip install --require-hashes` is used, so a file
# that does not match deploy/syntriass/requirements.lock is refused rather
# than installed.
#
# Prints the interpreter path at the end. That is the value the runtime config
# needs in its "python" field; mkconfig.py finds this venv automatically.
#
# Also runs the dataset generate-and-verify step, because a Python
# environment without the sidecar's training data still cannot start the
# sidecar — the two failures look identical to an operator and are easier to
# fix together. --skip-data separates them when only packages are wanted.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
LOCK="$HERE/requirements.lock"
# Default wheel directory: where bundle.sh would place it inside a bundle.
WHEELS="${SYNTRIASS_WHEELS:-$HERE/wheels}"
PYTHON=""
VENV="${SYNTRIASS_VENV:-$HERE/venv}"
RUN_DATA=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wheels) WHEELS=$2; shift 2 ;;
    --venv) VENV=$2; shift 2 ;;
    # Escape hatch: install into an interpreter you nominate, venv and all.
    # The caller then owns any conflict with distribution-managed packages.
    --python) PYTHON=$2; shift 2 ;;
    --skip-data) RUN_DATA=0; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "setup_env: unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -f "$LOCK" ]] || { echo "setup_env: missing lock file: $LOCK" >&2; exit 2; }

if [[ -z "$PYTHON" ]]; then
  BASE=${SYNTRIASS_BASE_PYTHON:-python3}
  command -v "$BASE" >/dev/null || { echo "setup_env: no such interpreter: $BASE" >&2; exit 2; }
  if [[ ! -x "$VENV/bin/python" ]]; then
    echo "setup_env: creating the virtual environment at $VENV"
    "$BASE" -m venv "$VENV" || { echo "setup_env: could not create a venv with $BASE -m venv" >&2; exit 2; }
  else
    echo "setup_env: reusing the virtual environment at $VENV"
  fi
  PYTHON="$VENV/bin/python"
else
  command -v "$PYTHON" >/dev/null || { echo "setup_env: no such interpreter: $PYTHON" >&2; exit 2; }
  echo "setup_env: installing into the nominated interpreter $PYTHON (not a venv)"
fi

# The lock's compiled wheels are built for one interpreter and architecture.
# Say so before pip does, because pip's hash error is hard to read.
TAG=$("$PYTHON" -c 'import sys,sysconfig;print("cp%d%d-%s"%(sys.version_info[0],sys.version_info[1],sysconfig.get_platform()))')
echo "setup_env: interpreter $("$PYTHON" -V 2>&1) ($TAG)"
case "$TAG" in
  cp311-linux-x86_64) ;;
  *) echo "setup_env: WARNING — requirements.lock pins cp311 manylinux x86-64 wheels." >&2
     echo "setup_env:           On $TAG the hash check will fail by design." >&2
     echo "setup_env:           Regenerate the lock on this platform instead of relaxing it." >&2 ;;
esac

if [[ -d "$WHEELS" ]] && compgen -G "$WHEELS/*.whl" > /dev/null; then
  echo "setup_env: installing from the bundle's wheels: $WHEELS (no network)"
  "$PYTHON" -m pip install --quiet --no-index --find-links "$WHEELS" \
      --require-hashes --requirement "$LOCK"
else
  echo "setup_env: no wheel directory at $WHEELS; falling back to PyPI"
  echo "setup_env: an air-gapped install should carry wheels — see deploy/syntriass/README.md"
  "$PYTHON" -m pip install --quiet --require-hashes --requirement "$LOCK"
fi

echo "setup_env: verifying the installed set imports"
"$PYTHON" - <<'PYCHECK'
import importlib, sys
# Import names differ from distribution names; check what the code imports.
for module, distribution in (("numpy", "numpy"), ("sklearn", "scikit-learn"),
                             ("pytest", "pytest")):
    try:
        loaded = importlib.import_module(module)
    except ImportError as error:
        sys.exit(f"setup_env: {distribution} did not install: {error}")
    print(f"setup_env:   {module} {getattr(loaded, '__version__', '?')}")
PYCHECK

if [[ "$RUN_DATA" -eq 1 ]]; then
  echo "setup_env: generating and verifying the seeded datasets"
  "$PYTHON" -I "$HERE/verify_datasets.py" --generate
fi

echo "setup_env: OK"
echo "setup_env: interpreter for the runtime config \"python\" field:"
echo "$("$PYTHON" -c 'import sys; print(sys.executable)')"
