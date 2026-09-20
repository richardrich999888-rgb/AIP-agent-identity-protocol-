#!/usr/bin/env bash
# Tier-2 rootkit VM setup — DOCUMENT-ONLY provisioning for the disposable VM.
#
# ── READ THIS FIRST ───────────────────────────────────────────────────────
# This script provisions the ONE environment in which the rootkit runbooks may
# run: a dedicated VM, snapshotted before each run, with NO network path to any
# production or development host (safety rule 1). It builds and loads NOTHING
# itself — it installs the toolchain and sets the kernel hardening modes for the
# two passes, so a human can then follow README.md by hand.
#
# It is not run on the machine that built this repository. To prevent exactly
# that, it FAILS CLOSED: it refuses to do anything unless the operator has
# explicitly asserted, in the VM, that this is the disposable, isolated VM by
# exporting AIP_ROOTKIT_VM=1. Absent that, it prints what it would do and exits
# non-zero. It never calls sudo silently; every privileged action is stated and
# requires the operator to already be root in the VM (rule 5).
#
# Kernel capabilities required for the runbook (NOT acquired here): CAP_BPF /
# CAP_SYS_ADMIN to load the modules, CAP_NET_RAW for the AF_PACKET tap. State
# them, stop, and let the human proceed.
set -euo pipefail

confirm_disposable_vm() {
  if [ "${AIP_ROOTKIT_VM:-0}" != "1" ]; then
    cat >&2 <<'MSG'
REFUSED: this is the rootkit VM setup and it will not run outside the
dedicated, snapshotted, network-isolated VM.

If — and only if — you are inside that VM (not a dev host, not CI, not a
container on a shared machine), re-run with:

    AIP_ROOTKIT_VM=1 sudo -E ./vm_setup.sh

What it will then do (and nothing else):
  * install a build toolchain, clang/llvm, libbpf, linux headers, git
  * NOT clone, build, or load any rootkit (that is the human runbook)
  * print the two hardening profiles to apply for the paired passes
MSG
    exit 2
  fi
  if [ "$(id -u)" != "0" ]; then
    echo "REFUSED: run as root inside the VM (privileged installs; rule 5)." >&2
    exit 2
  fi
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then echo apt; return; fi
  if command -v dnf     >/dev/null 2>&1; then echo dnf; return; fi
  echo "unknown package manager; install the toolchain by hand" >&2
  exit 2
}

install_toolchain() {
  local pm; pm="$(detect_pkg_mgr)"
  echo "== installing build toolchain via $pm (no rootkit is fetched)"
  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y --no-install-recommends \
        build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
        pkg-config git bpftool "linux-headers-$(uname -r)"
      ;;
    dnf)
      dnf install -y \
        clang llvm libbpf-devel elfutils-libelf-devel zlib-devel \
        make gcc pkgconf-pkg-config git bpftool "kernel-devel-$(uname -r)"
      ;;
  esac
}

print_hardening_profiles() {
  cat <<'MSG'

== Paired-pass hardening profiles (apply per README's hardening matrix)

Pass 1 — UNHARDENED (Secure Boot OFF; needed to load an unsigned module):
    sysctl -w kernel.unprivileged_bpf_disabled=0
    sysctl -w net.core.bpf_jit_harden=0
    # /sys/kernel/security/lockdown shows "[none]"

Pass 2 — HARDENED (the RBI defensive baseline):
    sysctl -w kernel.unprivileged_bpf_disabled=1
    sysctl -w net.core.bpf_jit_harden=2
    # boot with lockdown=integrity and Secure Boot ON; verify:
    #   cat /sys/kernel/security/lockdown   # expect "[integrity]"
    # Note: lockdown=confidentiality DISABLES the observer's own tracing and
    # is a hard deployment precondition, surfaced to RBI, never hidden.

Then follow README.md per tool. Capture the collector's health.archive.jsonl
out of the VM into fixtures/<tool>.attack.health.jsonl and run ./run.sh.
MSG
}

main() {
  confirm_disposable_vm
  install_toolchain
  print_hardening_profiles
  echo
  echo "VM provisioned. No rootkit was fetched, built, or loaded by this script."
}

main "$@"
