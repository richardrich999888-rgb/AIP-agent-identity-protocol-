#!/usr/bin/env bash
# Run tests as the caller inside a disposable, delegated cgroup v2 service.
# CI must exercise the freezer, not turn permission failures into skips.
set -euo pipefail

# Exercise the product's unprivileged path. Running as root changes the claim.
test "$(id -u)" -ne 0

# Ubuntu restricts unprivileged user namespaces through AppArmor. Keep the
# host-wide sysctl intact and, on disposable GitHub-hosted CI only, grant the
# required operation to /usr/bin/unshare with a temporary application profile.
# No existing profile is replaced. Local/self-hosted operators configure their
# own approved policy; this wrapper never changes it automatically.
USERNS_SYSCTL=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
ci_profile_file=""
ci_profile_loaded=0
userns_before=""
cleanup() {
  ci_status=$?
  trap - EXIT
  if [ "$ci_profile_loaded" = 1 ]; then
    if sudo apparmor_parser -R "$ci_profile_file"; then
      echo "Removed temporary CI userns profile"
    else
      echo "Failed to remove temporary CI userns profile" >&2
      ci_status=1
    fi
  fi
  if [ -n "$ci_profile_file" ]; then rm -f -- "$ci_profile_file"; fi
  if [ -n "$userns_before" ]; then
    if [ "$(cat "$USERNS_SYSCTL")" != "$userns_before" ]; then
      echo "Host userns restriction changed during the test" >&2
      ci_status=1
    else
      echo "Host userns restriction unchanged: $userns_before"
    fi
  fi
  exit "$ci_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ -e "$USERNS_SYSCTL" ]; then
  userns_before=$(cat "$USERNS_SYSCTL")
  if [ "$userns_before" != 0 ]; then
    if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
      echo "Restricted user namespaces: configure an approved local AppArmor profile first" >&2
      exit 1
    fi
    command -v apparmor_parser >/dev/null
    apparmor_parser --version
    ci_profile_file=$(mktemp)
    cat > "$ci_profile_file" <<PROFILE
abi <abi/4.0>,
profile aip-ci-unshare-${BASHPID} /usr/bin/unshare flags=(unconfined) {
  userns,
}
PROFILE
    sudo apparmor_parser -a "$ci_profile_file"
    ci_profile_loaded=1
    echo "Temporary unshare profile loaded; host restriction remains $userns_before"
  fi
fi
unshare --version

sudo systemd-run --quiet --wait --pipe --collect \
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
    if ! userns_err=$(unshare --user --map-root-user --net --pid --fork \
        --kill-child --mount --mount-proc -- /bin/true 2>&1); then
      echo "User namespace preflight FAILED as uid $(id -u): $userns_err" >&2
      exit 1
    fi
    echo "User namespace preflight: ok as uid $(id -u)"
    exec "$@"
  ' bash "$@"
