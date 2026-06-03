#!/usr/bin/env bash
set -euo pipefail

AEGIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EBPF_MANIFEST="${AEGIS_DIR}/aegis-quantum-ebpf/Cargo.toml"
EBPF_TARGET="bpfel-unknown-none"

usage() {
  cat <<'EOF'
Usage: scripts/check_ebpf_toolchain.sh [--debug|--release]

Checks that Rust nightly + rust-src are installed, then builds the AEGIS
eBPF/XDP crate for bpfel-unknown-none with build-std=core.

Prerequisites:
  rustup toolchain install nightly --component rust-src

Examples:
  scripts/check_ebpf_toolchain.sh --debug
  scripts/check_ebpf_toolchain.sh --release
EOF
}

mode="--debug"
case "${1:-}" in
  ""|"--debug")
    mode="--debug"
    ;;
  "--release")
    mode="--release"
    ;;
  "-h"|"--help")
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if ! command -v rustup >/dev/null 2>&1; then
  echo "error: rustup is required to build the eBPF target" >&2
  exit 1
fi

if ! rustup toolchain list | grep -Eq '^nightly([ -]|$)'; then
  echo "error: Rust nightly is not installed" >&2
  echo "install with: rustup toolchain install nightly --component rust-src" >&2
  exit 1
fi

if ! rustup component list --toolchain nightly --installed | grep -Eq '^rust-src([ -]|$)'; then
  echo "error: rust-src is not installed for nightly" >&2
  echo "install with: rustup component add rust-src --toolchain nightly" >&2
  exit 1
fi

echo "AEGIS eBPF build"
echo "  manifest: ${EBPF_MANIFEST}"
echo "  target:   ${EBPF_TARGET}"
echo "  mode:     ${mode#--}"

if [[ "${mode}" == "--release" ]]; then
  cargo +nightly build \
    --manifest-path "${EBPF_MANIFEST}" \
    --target "${EBPF_TARGET}" \
    -Z build-std=core \
    --release
else
  cargo +nightly build \
    --manifest-path "${EBPF_MANIFEST}" \
    --target "${EBPF_TARGET}" \
    -Z build-std=core
fi

echo "AEGIS eBPF build completed."
