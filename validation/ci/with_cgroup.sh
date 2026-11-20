#!/usr/bin/env bash
# Run tests as the caller inside a disposable, delegated cgroup v2 service.
# CI must exercise the freezer, not turn permission failures into skips.
set -euo pipefail

# ---- User namespaces -------------------------------------------------------
# vanian-sovereign's tool sandbox is built from unprivileged user, net, pid and
# mount namespaces, and its tests deliberately fail rather than skip when the
# kernel refuses them. Ubuntu 24.04 - the current ubuntu-latest image - ships
# kernel.apparmor_restrict_unprivileged_userns=1, which denies exactly that to
# the unprivileged user this script runs the tests as. The result was three
# failing tests and, worse, two that PASSED, because a tool which never runs
# produces no output and a non-zero exit.
#
# Relax the restriction rather than run the tests as root. Root can create the
# namespaces, but it also changes what the sandbox tests measure (file modes,
# capability checks, what a sandboxed process may touch), so a pass as root
# would not be evidence about the unprivileged path the product uses.
USERNS_SYSCTL=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
if [ -e "$USERNS_SYSCTL" ]; then
  userns_before=$(cat "$USERNS_SYSCTL")
  if [ "$userns_before" != "0" ]; then
    echo "Relaxing apparmor_restrict_unprivileged_userns ($userns_before -> 0)"
    sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0
  fi
  echo "apparmor_restrict_unprivileged_userns=$(cat "$USERNS_SYSCTL")"
else
  echo "apparmor_restrict_unprivileged_userns: absent (not an AppArmor kernel)"
fi

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
    # Same discipline as the freezer probe above: prove the sandbox namespaces
    # can be created as THIS user before running anything, so a kernel that
    # refuses them stops the run here with the reason the kernel gave, instead
    # of five confusing assertion failures in agent_execution.rs.
    if ! userns_err=$(unshare --user --map-root-user --net --pid --fork \
        --kill-child --mount --mount-proc -- /bin/true 2>&1); then
      echo "user namespace preflight FAILED as uid $(id -u): $userns_err" >&2
      echo "vanian-sovereign tool sandbox tests cannot run here." >&2
      exit 1
    fi
    echo "User namespace preflight: ok as uid $(id -u)"
    exec "$@"
  ' bash "$@"
