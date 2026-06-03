# AIRON Trust Infrastructure validation orchestration.

.PHONY: help aip-check aip-test aip-validation-report aip-ci-local aip-sdk-test aip-load-locust dossier-artifacts pilot-latency-report pilot-local

GREEN  := \033[0;32m
CYAN   := \033[0;36m
RESET  := \033[0m

AIP_STANDALONE_MANIFEST := aip-standalone/Cargo.toml
AIP_SERVICE_MANIFEST    := aip-service/Cargo.toml
AIP_REPORT              := aip_validation_report.json
AIP_BASE_URL            ?= http://127.0.0.1:8081
USERS                   ?= 500
SPAWN_RATE              ?= 50
RUN_TIME                ?= 5m

help:
	@echo ""
	@echo "$(CYAN)AIRON Validation Targets$(RESET)"
	@echo ""
	@echo "  $(GREEN)AIP$(RESET)"
	@echo "    make aip-check             - cargo check protocol workspace and service"
	@echo "    make aip-test              - run all AIP protocol and service tests"
	@echo "    make aip-validation-report - write $(AIP_REPORT)"
	@echo "    make aip-ci-local          - check + tests + report"
	@echo "    make aip-sdk-test          - run Python SDK unit tests"
	@echo "    make aip-load-locust       - run Locust HTTP identity load profile"
	@echo ""
	@echo "  $(GREEN)Pilot Evidence$(RESET)"
	@echo "    make dossier-artifacts     - write sanitized EvidencePacket verifier bundle"
	@echo "    make pilot-latency-report  - write target-only latency report template"
	@echo "    make pilot-local           - run local AIRON pilot smoke and latency pass"
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

aip-ci-local: aip-check aip-test aip-sdk-test aip-validation-report
	@echo "$(GREEN)AIP local validation passed: check + tests + Python SDK + report$(RESET)"

aip-sdk-test:
	@echo "$(CYAN)-- AIP Python SDK tests --$(RESET)"
	PYTHONPATH=python/airon-aip-sdk/src python3 -m unittest discover -s python/airon-aip-sdk/tests

aip-load-locust:
	@echo "$(CYAN)-- Running AIP Locust profile against $(AIP_BASE_URL) --$(RESET)"
	mkdir -p pilot-results
	locust -f aip-service/load-tests/locustfile.py \
		--host $(AIP_BASE_URL) \
		--headless \
		-u $(USERS) \
		-r $(SPAWN_RATE) \
		--run-time $(RUN_TIME) \
		--csv pilot-results/aip_locust

dossier-artifacts:
	@echo "$(CYAN)-- Generating AIRON dossier verifier artifacts --$(RESET)"
	cargo run --manifest-path $(AIP_STANDALONE_MANIFEST) --package airon-verify --example generate_dossier_artifacts -- dossier/artifacts
	@echo "$(GREEN)Dossier artifacts written: dossier/artifacts$(RESET)"

pilot-latency-report:
	@echo "$(CYAN)-- Generating airon_latency_report.json --$(RESET)"
	python3 scripts/generate_airon_latency_histogram.py --output airon_latency_report.json
	@echo "$(GREEN)Pilot latency report written: airon_latency_report.json$(RESET)"

pilot-local:
	@echo "$(CYAN)-- Running local AIRON pilot --$(RESET)"
	python3 scripts/run_airon_local_pilot.py
	@echo "$(GREEN)Local AIRON pilot complete: pilot-results/local_pilot_summary.json$(RESET)"
