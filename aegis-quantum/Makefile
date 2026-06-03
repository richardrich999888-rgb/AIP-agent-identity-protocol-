# ── AEGIS-QUANTUM Development Makefile ────────────────────────────────────────
#
# Cross-platform build and test orchestration for macOS + Linux.
#
# USAGE:
#   make check        — Syntax check all workspace crates (macOS-safe)
#   make test         — Run all 110 Rust tests
#   make run          — Run TRL-4 lab validation binary
#   make dry-run      — Run Python dry-run validation (6/6 tests)
#   make chaos-local  — Run AEGIS chaos/stress dry-run report
#   make live-fire-readiness — Check bare-metal gateway readiness
#   make bench        — Run Criterion.rs benchmarks
#   make stress-bench — Run Criterion.rs stress benchmarks
#   make build-ebpf   — Cross-compile eBPF bytecode (requires nightly)
#   make lima-up      — Spin up Lima Linux VM for live-fire testing
#   make lima-shell   — SSH into the Lima VM
#   make lima-fire    — Run live-fire validation inside Lima VM
#   make vagrant-up   — Spin up 2-node Vagrant testbed
#   make clean        — Remove all build artifacts
#   make all          — Full CI pipeline: check → test → run → dry-run

.PHONY: all check test run dry-run validation-report bench stress-test stress-bench chaos-local live-fire-readiness check-ebpf-env check-ebpf build-ebpf build-ebpf-debug ci-local clean \
        lima-up lima-shell lima-fire lima-down \
        vagrant-up vagrant-down vagrant-ssh-gateway vagrant-ssh-attacker vagrant-chaos

# ── Configuration ────────────────────────────────────────────────────────────

WORKSPACE       := .
EBPF_CRATE      := aegis-quantum-ebpf
USERSPACE_CRATE := aegis-quantum-userspace
EBPF_TARGET     := bpfel-unknown-none
EBPF_CHECK      := scripts/check_ebpf_toolchain.sh
LIMA_CONFIG     := infra/lima/aegis-kernel.yaml
LIMA_VM_NAME    := aegis-kernel
VAGRANT_DIR     := infra/vagrant
LIVE_FIRE_IFACE ?= eth1

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

## Local CI without starting the lab binary; useful for GitHub Actions and quick checks
ci-local: check test dry-run
	@echo "$(GREEN)AEGIS local validation passed: check + 110 tests + dry-run$(RESET)"

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

## Generate a JSON validation report artifact for funding/CI evidence packs
validation-report:
	@echo "$(CYAN)── Generating validation_report.json ──$(RESET)"
	python3 validation/validate_xdp.py --dry-run --output validation_report.json
	@echo "$(GREEN)Validation report written: validation_report.json$(RESET)"

## Run Criterion.rs performance benchmarks
bench:
	@echo "$(CYAN)── Criterion Benchmarks ──$(RESET)"
	cargo bench --package aegis-quantum-benchmarks

## Run deterministic stress harness tests only
stress-test:
	@echo "$(CYAN)── AEGIS Stress Harness Tests ──$(RESET)"
	cargo test --package aegis-quantum-stress-tests

## Run Criterion.rs stress benchmarks
stress-bench:
	@echo "$(CYAN)── AEGIS Stress Benchmarks ──$(RESET)"
	cargo bench --package aegis-quantum-stress-tests

## Generate the local chaos/stress JSON report
chaos-local:
	@echo "$(CYAN)── AEGIS Chaos Stress Dry-Run ──$(RESET)"
	python3 stress-tests/run_chaos_suite.py --dry-run

## Check whether this host is ready for bare-metal live-fire validation
live-fire-readiness:
	@echo "$(CYAN)── AEGIS Live-Fire Readiness ──$(RESET)"
	python3 stress-tests/run_live_fire_readiness.py --role gateway --iface $(LIVE_FIRE_IFACE)

# ── eBPF Cross-Compilation (requires Rust nightly) ──────────────────────────

## Cross-compile the eBPF XDP program to BPF bytecode
## This works on macOS because it targets the BPF virtual machine, not host HW
check-ebpf-env:
	@echo "$(CYAN)── Checking eBPF toolchain prerequisites ──$(RESET)"
	@$(EBPF_CHECK) --help >/dev/null
	@rustup toolchain list | grep -E '^nightly([ -]|$$)' >/dev/null || \
		( echo "$(RED)nightly missing. Run: rustup toolchain install nightly --component rust-src$(RESET)" && exit 1 )
	@rustup component list --toolchain nightly --installed | grep -E '^rust-src([ -]|$$)' >/dev/null || \
		( echo "$(RED)rust-src missing. Run: rustup component add rust-src --toolchain nightly$(RESET)" && exit 1 )
	@echo "$(GREEN)eBPF toolchain prerequisites present$(RESET)"

## Compile the eBPF XDP program in debug mode through the reproducible script
check-ebpf:
	@echo "$(CYAN)── eBPF debug build check ──$(RESET)"
	$(EBPF_CHECK) --debug

## Compile the eBPF XDP program in release mode through the reproducible script
build-ebpf:
	@echo "$(CYAN)── Cross-compiling eBPF to $(EBPF_TARGET) ──$(RESET)"
	@echo "$(YELLOW)Requires: rustup toolchain install nightly --component rust-src$(RESET)"
	$(EBPF_CHECK) --release
	@echo "$(GREEN)eBPF bytecode compiled: $(EBPF_CRATE)/target/$(EBPF_TARGET)/release/$(EBPF_CRATE)$(RESET)"

## Build eBPF in debug mode (faster, but may trigger verifier warnings)
build-ebpf-debug:
	$(EBPF_CHECK) --debug

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

## Run functional semantic-loop packet injection from the attacker VM
vagrant-chaos:
	cd $(VAGRANT_DIR) && vagrant ssh aegis-attacker -- \
		'cd ~/aegis-quantum && sudo python3 infra/vagrant/semantic_loop_injector.py --target 192.168.56.10 --iface eth1 --count 10000 --legit-count 100'

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
	@echo "    make test        — Run 110 Rust tests"
	@echo "    make run         — TRL-4 lab validation"
	@echo "    make dry-run     — Python validation (6/6 tests)"
	@echo "    make validation-report — Write validation_report.json artifact"
	@echo "    make bench       — Criterion benchmarks"
	@echo "    make stress-test — Run AEGIS stress harness tests"
	@echo "    make stress-bench — Run AEGIS stress benchmarks"
	@echo "    make chaos-local — Write pilot-results/chaos_stress_report.json"
	@echo "    make live-fire-readiness — Check bare-metal gateway readiness"
	@echo "    make ci-local    — cargo check + tests + dry-run"
	@echo "    make check-ebpf  — Debug eBPF build check (requires nightly + rust-src)"
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
	@echo "    make vagrant-chaos        — Inject semantic-loop traffic from attacker"
	@echo "    make vagrant-down         — Destroy cluster"
	@echo ""
