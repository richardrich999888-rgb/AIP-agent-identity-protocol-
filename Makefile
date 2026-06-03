# AIRON Trust Infrastructure validation orchestration.

.PHONY: help aip-check aip-test aip-validation-report aip-ci-local pilot-latency-report

GREEN  := \033[0;32m
CYAN   := \033[0;36m
RESET  := \033[0m

AIP_STANDALONE_MANIFEST := aip-standalone/Cargo.toml
AIP_SERVICE_MANIFEST    := aip-service/Cargo.toml
AIP_REPORT              := aip_validation_report.json

help:
	@echo ""
	@echo "$(CYAN)AIRON Validation Targets$(RESET)"
	@echo ""
	@echo "  $(GREEN)AIP$(RESET)"
	@echo "    make aip-check             - cargo check protocol workspace and service"
	@echo "    make aip-test              - run all AIP protocol and service tests"
	@echo "    make aip-validation-report - write $(AIP_REPORT)"
	@echo "    make aip-ci-local          - check + tests + report"
	@echo ""
	@echo "  $(GREEN)Pilot Evidence$(RESET)"
	@echo "    make pilot-latency-report  - write target-only latency report template"
	@echo ""
	@echo "  $(GREEN)AEGIS$(RESET)"
	@echo "    cd aegis-quantum && make ci-local"
	@echo ""

aip-check:
	@echo "$(CYAN)-- AIP standalone cargo check --$(RESET)"
	cargo check --manifest-path $(AIP_STANDALONE_MANIFEST) --workspace
	@echo "$(CYAN)-- AIP service cargo check --$(RESET)"
	cargo check --manifest-path $(AIP_SERVICE_MANIFEST)

aip-test:
	@echo "$(CYAN)-- AIP standalone cargo test --$(RESET)"
	cargo test --manifest-path $(AIP_STANDALONE_MANIFEST) --workspace
	@echo "$(CYAN)-- AIP service cargo test --$(RESET)"
	cargo test --manifest-path $(AIP_SERVICE_MANIFEST)

aip-validation-report:
	@echo "$(CYAN)-- Generating $(AIP_REPORT) --$(RESET)"
	python3 scripts/generate_aip_validation_report.py --output $(AIP_REPORT)
	@echo "$(GREEN)AIP validation report written: $(AIP_REPORT)$(RESET)"

aip-ci-local: aip-check aip-test aip-validation-report
	@echo "$(GREEN)AIP local validation passed: check + tests + report$(RESET)"

pilot-latency-report:
	@echo "$(CYAN)-- Generating airon_latency_report.json --$(RESET)"
	python3 scripts/generate_airon_latency_histogram.py --output airon_latency_report.json
	@echo "$(GREEN)Pilot latency report written: airon_latency_report.json$(RESET)"
