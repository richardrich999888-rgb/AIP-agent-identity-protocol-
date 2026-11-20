#!/usr/bin/env bash
# Every automated suite the lab depends on, with live dependencies, offline where possible.
source "$(dirname "$0")/lib.sh"
fails=0
run() { local name=$1; shift; if "$@" > "$RUNS/test-$name.log" 2>&1; then log "PASS $name"; else log "FAIL $name (see $RUNS/test-$name.log)"; fails=$((fails+1)); fi; }
mkdir -p "$RUNS"
run policy "$BIN/opa" test "$POLICY"
run server-suite unshare -n sh -c "cd '$SERVER' && python3 netns_lo_up.py && \
  VANIAN_OPA_BIN='$BIN/opa' VANIAN_OBSERVE_VERIFY_BIN='$RELEASE/aip-observe-verify' \
  LITELLM_LOCAL_MODEL_COST_MAP=True PYTHONDONTWRITEBYTECODE=1 '$VENV/bin/python' -m unittest \
  test_eventstore test_opa_gate test_llm_capture test_finops_events test_llm_store_logger test_observer_ingest test_shadow_ai test_finops_report"
run litellm-acceptance unshare -n sh -c "cd '$REPO/research/oss/litellm' && python3 '$SERVER/netns_lo_up.py' && \
  env -u DATABASE_URL LITELLM_LOCAL_MODEL_COST_MAP=True '$VENV/bin/python' acceptance.py '$RUNS/litellm-records.jsonl' --isolated"
run revocation-gap bash -c "cd '$REPO' && cargo test -q --locked -p aip-authorize --test revocation_gap"
run delegation-findings bash -c "cd '$REPO' && cargo test -q --locked -p aip-authorize --test delegation_identity_findings"
run live-sensors bash -c "cd '$REPO' && cargo test -q --locked -p aip-probe --test live_sensors"
if grep -q 'skipped=' "$RUNS/test-server-suite.log"; then log "FAIL server-suite has SKIPPED tests: a live dependency is missing"; fails=$((fails+1)); fi
log "suites failed: $fails"
[ "$fails" -eq 0 ]
