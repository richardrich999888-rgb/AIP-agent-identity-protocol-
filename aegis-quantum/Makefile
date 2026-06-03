# ── AEGIS-QUANTUM Development Makefile ────────────────────────────────────────
#
# Cross-platform build and test orchestration for macOS + Linux.
#
# USAGE:
#   make check        — Syntax check all workspace crates (macOS-safe)
#   make test         — Run all 17+ unit tests
#   make run          — Run TRL-4 lab validation binary
#   make dry-run      — Run Python dry-run validation (6/6 tests)
#   make bench        — Run Criterion.rs benchmarks
#   make build-ebpf   — Cross-compile eBPF bytecode (requires nightly)
#   make lima-up      — Spin up Lima Linux VM for live-fire testing
#   make lima-shell   — SSH into the Lima VM
#   make lima-fire    — Run live-fire validation inside Lima VM
#   make vagrant-up   — Spin up 2-node Vagrant testbed
#   make clean        — Remove all build artifacts
#   make all          — Full CI pipeline: check → test → run → dry-run

.PHONY: all check test run dry-run bench build-ebpf clean \
        lima-up lima-shell lima-fire lima-down \
        vagrant-up vagrant-down vagrant-ssh-gateway vagrant-ssh-attacker

# ── Configuration ────────────────────────────────────────────────────────────

WORKSPACE       := .
EBPF_CRATE      := aegis-quantum-ebpf
USERSPACE_CRATE := aegis-quantum-userspace
EBPF_TARGET     := bpfel-unknown-none
LIMA_CONFIG     := infra/lima/aegis-kernel.yaml
LIMA_VM_NAME    := aegis-kernel
VAGRANT_DIR     := infra/vagrant

# Colors for terminal output
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
CYAN   := \033[0;36m
RESET  := \033[0m

# ── Primary Targets ──────────────────────────────────────────────────────────

## Run the full CI pipeline: check, test, validation
all: check test run dry-run
	@echo "$(GREEN)═══════════════════════════════════════════════════════$(RESET)"
	@echo "$(GREEN)  AEGIS-QUANTUM CI Pipeline: ALL PASS$(RESET)"
	@echo "$(GREEN)═══════════════════════════════════════════════════════$(RESET)"

## Syntax check all workspace crates (macOS-safe, no Linux deps compiled)
check:
	@echo "$(CYAN)── cargo check --workspace ──$(RESET)"
	cargo check --workspace

## Run all unit tests across the workspace
test:
	@echo "$(CYAN)── cargo test --workspace ──$(RESET)"
	cargo test --workspace

## Run the TRL-4 laboratory validation binary
run:
	@echo "$(CYAN)── AEGIS TRL-4 Lab Validation ──$(RESET)"
	RUST_LOG=info cargo run --package $(USERSPACE_CRATE)

## Run Python dry-run validation (macOS-compatible, 6/6 tests)
dry-run:
	@echo "$(CYAN)── Python Dry-Run Validation ──$(RESET)"
	python3 validation/validate_xdp.py --dry-run

## Run Criterion.rs performance benchmarks
bench:
	@echo "$(CYAN)── Criterion Benchmarks ──$(RESET)"
	cargo bench --package aegis-quantum-benchmarks

# ── eBPF Cross-Compilation (requires Rust nightly) ──────────────────────────

## Cross-compile the eBPF XDP program to BPF bytecode
## This works on macOS because it targets the BPF virtual machine, not host HW
build-ebpf:
	@echo "$(CYAN)── Cross-compiling eBPF to $(EBPF_TARGET) ──$(RESET)"
	@echo "$(YELLOW)Requires: rustup toolchain install nightly --component rust-src$(RESET)"
	cargo +nightly build \
		--manifest-path $(EBPF_CRATE)/Cargo.toml \
		--target $(EBPF_TARGET) \
		-Z build-std=core \
		--release
	@echo "$(GREEN)eBPF bytecode compiled: $(EBPF_CRATE)/target/$(EBPF_TARGET)/release/$(EBPF_CRATE)$(RESET)"

## Build eBPF in debug mode (faster, but may trigger verifier warnings)
build-ebpf-debug:
	cargo +nightly build \
		--manifest-path $(EBPF_CRATE)/Cargo.toml \
		--target $(EBPF_TARGET) \
		-Z build-std=core

# ── Lima VM (Apple Silicon native Linux) ─────────────────────────────────────

## Start the Lima Linux VM for eBPF live-fire testing
lima-up:
	@echo "$(CYAN)── Starting Lima VM: $(LIMA_VM_NAME) ──$(RESET)"
	@echo "$(YELLOW)First boot downloads Ubuntu 24.04 ARM64 (~800MB)$(RESET)"
	limactl start $(LIMA_CONFIG) --name $(LIMA_VM_NAME)
	@echo "$(GREEN)VM ready. Use 'make lima-shell' to enter.$(RESET)"

## SSH into the Lima VM
lima-shell:
	limactl shell $(LIMA_VM_NAME)

## Run live-fire validation inside the Lima VM
lima-fire:
	@echo "$(CYAN)── Live-Fire Validation (via Lima) ──$(RESET)"
	limactl shell $(LIMA_VM_NAME) -- bash -c '\
		cd /Users/richardrich/Desktop/AIP/aegis-quantum && \
		cargo build --workspace && \
		sudo python3 validation/validate_xdp.py --live-fire \
	'

## Stop the Lima VM
lima-down:
	limactl stop $(LIMA_VM_NAME)

## Destroy the Lima VM completely
lima-destroy:
	limactl delete $(LIMA_VM_NAME) --force

# ── Vagrant Multi-Node Testbed ───────────────────────────────────────────────

## Start the 2-node Vagrant testbed (gateway + attacker)
vagrant-up:
	@echo "$(CYAN)── Starting Vagrant Testbed ──$(RESET)"
	cd $(VAGRANT_DIR) && vagrant up

## SSH into the gateway node (XDP host)
vagrant-ssh-gateway:
	cd $(VAGRANT_DIR) && vagrant ssh aegis-gateway

## SSH into the attacker node (Scapy injector)
vagrant-ssh-attacker:
	cd $(VAGRANT_DIR) && vagrant ssh aegis-attacker

## Run live-fire on the gateway via Vagrant
vagrant-fire:
	cd $(VAGRANT_DIR) && vagrant ssh aegis-gateway -- \
		'cd ~/aegis-quantum && cargo build --workspace && sudo python3 validation/validate_xdp.py --live-fire --iface eth1'

## Destroy the Vagrant testbed
vagrant-down:
	cd $(VAGRANT_DIR) && vagrant destroy -f

# ── Cleanup ──────────────────────────────────────────────────────────────────

## Remove all build artifacts
clean:
	cargo clean
	@echo "$(GREEN)Build artifacts cleaned.$(RESET)"

# ── Help ─────────────────────────────────────────────────────────────────────

## Show available targets
help:
	@echo ""
	@echo "$(CYAN)AEGIS-QUANTUM Development Targets$(RESET)"
	@echo "$(CYAN)═════════════════════════════════$(RESET)"
	@echo ""
	@echo "  $(GREEN)Local (macOS)$(RESET)"
	@echo "    make check       — Syntax check (0 warnings target)"
	@echo "    make test        — Run 17+ unit tests"
	@echo "    make run         — TRL-4 lab validation"
	@echo "    make dry-run     — Python validation (6/6 tests)"
	@echo "    make bench       — Criterion benchmarks"
	@echo "    make build-ebpf  — Cross-compile eBPF bytecode"
	@echo "    make all         — Full CI pipeline"
	@echo ""
	@echo "  $(GREEN)Lima VM (Apple Silicon Linux)$(RESET)"
	@echo "    make lima-up     — Start Linux VM"
	@echo "    make lima-shell  — SSH into VM"
	@echo "    make lima-fire   — Run live-fire in VM"
	@echo "    make lima-down   — Stop VM"
	@echo ""
	@echo "  $(GREEN)Vagrant Testbed (Multi-Node)$(RESET)"
	@echo "    make vagrant-up           — Start 2-node cluster"
	@echo "    make vagrant-ssh-gateway  — SSH into XDP host"
	@echo "    make vagrant-ssh-attacker — SSH into injector"
	@echo "    make vagrant-fire         — Run live-fire on gateway"
	@echo "    make vagrant-down         — Destroy cluster"
	@echo ""
