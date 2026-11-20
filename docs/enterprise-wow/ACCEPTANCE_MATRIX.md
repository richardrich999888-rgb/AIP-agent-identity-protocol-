# Acceptance matrix (enterprise WOW loop, item 6.4a)

Generated from `docs/enterprise-wow/evidence/6.1a/verify-summary.json`, which `demos/vanian-enterprise/verify.sh` wrote after `test.sh` and `run.sh` on 21 Nov 2026 (cloud session container).
**Result: 0/12 VERIFIED, 0 FAIL; verify.sh exit 1** (re-run after 2.5a). Status and limitation are copied from `verify.py`, not restated.

| Capability | Status | Source | Execution path | Test | Evidence | Limitation |
|---|---|---|---|---|---|---|
| 1 Agent inventory | **NOT_AVAILABLE** | P0-059 (absent) | — | — | — | P0-059 commits are not on this branch (item 0.1) |
| 2 Shadow AI | **PARTIAL** | `command-center/server/shadow_ai.py` | kernel SYN_SENT to a declared model endpoint, unregistered → HEURISTIC | `test_shadow_ai` 10/0/0; `live_shadow_ai.py` 7/7 | `evidence/2.3a-shadow-ai/`, `evidence/6.1a/live-shadow-result.json` | HEURISTIC class passes live with 0 false positives; CONFIRMED class and registry are P0-059 (2.3b) |
| 3 Ghost AI | **NOT_AVAILABLE** | P0-059 (absent) | — | — | — | P0-059 commits are not on this branch (item 0.1) |
| 4 Orphan AI | **NOT_AVAILABLE** | P0-059 (absent) | — | — | — | P0-059 commits are not on this branch (item 0.1) |
| 5 Parent-child | **NOT_AVAILABLE** | P0-059 (absent) | — | — | — | P0-059 commits are not on this branch (item 0.1) |
| 6 Governance enforcement | **PARTIAL** | `command-center/server/opa_gate.py`, `command-center/policy/gate.rego` | `opa eval` once per decision on a hashed bundle snapshot; fail closed | `opa test` 17/17; `test_opa_gate` 23/0/0 live | `evidence/6.1a/test-policy.log`, `test-server-suite.log` | the OPA decision is tested but not wired into the gate: ADVISORY (3.1b) |
| 7 Human approval | **NOT_IMPLEMENTED** | none | — | — | — | 3.2 needs the gateway |
| 8 Activity and observer coverage | **PARTIAL** | `aip-probe`, `aip-collector`, `aip-observe-verify`, `command-center/server/observer_ingest.py` | probe → collector (signed archive) → verifier → event store → coverage() | `test_observer_ingest` 22/0/0; `live_sensors` 6/0/0; `live_observer_kill.py` 7/7 | `evidence/3.4b-live-kill/`, `evidence/6.1a/live-kill-result.json` | coverage, gaps and the kill run pass live; per-event rows and console are 3.4c |
| 9 Human vs agent attribution | **NOT_IMPLEMENTED** | none | — | — | — | 4.3 needs the gateway |
| 10 FinOps | **PARTIAL** | `llm_capture.py`, `finops_events.py`, `llm_store_logger.py`, `eventstore.py` | LiteLLM SDK hook → UsageRecord → `llm.usage` event (None never stored as 0) | LiteLLM acceptance 16/16 offline; server suite 70/0/0 | `evidence/6.1a/test-litellm-acceptance.log`, `research/oss/litellm/` | capture and persistence pass against the TEST DATA mock; console 4.2 and agents 4.1b missing |
| 11 AIP identity | **PARTIAL** | `aip-authorize`, `aip-core` | DecisionPoint::authorize_at → signed ExpectedExecution | `aip-authorize` 108/0/0; `revocation_gap` 3/0/0; `delegation_identity_findings` 5/0/0 | `evidence/6.1a/test-revocation-gap.log`, `test-delegation-findings.log`, ADR-001, ADR-002 | crates tested; console is P0-059; findings pinned: DecisionPoint ignores revocation (ADR-001), Delegate scope not enforced and no proof of possession (ADR-002) |
| 12 Evidence verification | **PARTIAL** | `aip-observe-verify`; `command-center/server/eventstore.py` verify() | offline verifier over signed archives; store hash chain | `test_observer_ingest` tamper/delete/wrong-key; `test_eventstore` Tamper | `evidence/6.1a/test-server-suite.log` | observer archives verified offline; bundle v2 and vcc-verify are P0-059 |

To reach VERIFIED, each capability needs an automated test and a live run on the demo path. For 1–5 that means the P0-059 commits (0.1). For 6, 7 and 9 it means the gateway (3.1b, 3.2, 4.3). For 8, 10, 11 and 12 it means the console and bundle work named in each limitation.
