#!/usr/bin/env bash
# Run tests as the caller inside a disposable, delegated cgroup v2 service.
# CI must exercise the freezer, not turn permission failures into skips.
set -euo pipefail

exec sudo systemd-run --quiet --wait --pipe --collect \
  --property=Delegate=yes --property="User=$(id -u)" \
  --property="Group=$(id -g)" --working-directory="$PWD" \
  /usr/bin/env "PATH=$PATH" "HOME=$HOME" \
    "CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}" \
    "RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}" \
    "RUSTFLAGS=${RUSTFLAGS:-}" "CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-0}" \
  bash -euo pipefail -c '
    membership=$(sed -n "s/^0:://p" /proc/self/cgroup)
    test -n "$membership"
    export AIP_TEST_CGROUP_ROOT="/sys/fs/cgroup$membership"
    test "$(stat -fc %T "$AIP_TEST_CGROUP_ROOT")" = cgroup2fs
    test -w "$AIP_TEST_CGROUP_ROOT/cgroup.procs"
    probe="$AIP_TEST_CGROUP_ROOT/aip-freezer-preflight"
    mkdir "$probe"
    echo 0 > "$probe/cgroup.freeze"
    rmdir "$probe"
    echo "Testing with delegated cgroup: $AIP_TEST_CGROUP_ROOT"
    exec "$@"
  ' bash "$@"
