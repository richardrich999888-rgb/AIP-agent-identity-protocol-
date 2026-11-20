# Adversarial results (enterprise WOW loop, item 6.3a)

As of 21 Nov 2026, 00:3x IST, branch `claude/vanian-enterprise-wow`.

Each row says what was run and what it showed. **RUN** means an automated
test or live run on this branch exercised the attack. **PARTIAL** means part
of the attack path ran; the row says which part. **NOT RUN** gives the
reason. Nothing is counted from P0-059, whose results are not reachable here
(item 0.1).

| # | Test | Status | Command → result | False positives | Coverage | Unresolved |
|---|---|---|---|---|---|---|
| 1 | Unregistered workload | **RUN** | `live_shadow_ai.py` ×3: the unregistered client of the model port is HEURISTIC_AI_WORKLOAD (7/7 each) | — | heuristic class only | CONFIRMED and registry are P0-059 (2.3b); "no binding" in every run |
| 2 | False-positive control | **RUN** | `live_shadow_ai.py` ×3: http.server, its client and `sort` are observed and UNCLASSIFIED; 3.4b archives give 0 HEURISTIC out of 154–160 processes | **0** | ordinary loopback web traffic and exec | only these workloads were tried |
| 3 | Missing ownership | NOT RUN | — | — | — | needs 2.4 (P0-059 registry) |
| 4 | Revoked authorization | **PARTIAL** | (a) `test_opa_gate` live `test_revoked_denied`: a revoked hop gives DENY with "authority revoked". (b) `cargo test -p aip-authorize --test revocation_gap` 3/0/0: **DecisionPoint still authorizes under a revoked root or hop.** | none observed | (a) the OPA decision only; (b) the DecisionPoint gap is pinned | not enforced at a gate (3.1b); DecisionPoint fix is ADR-001; the P0-059 gateway re-run is blocked |
| 5 | Unauthorized child delegation | **RUN — attack NOT refused** | `cargo test -p aip-authorize --test delegation_identity_findings`: a holder without Delegate sub-delegates; the chain verifies and the grandchild is **Authorized** (ADR-002) | — | protocol layer (aip-core + DecisionPoint) | the fix is proposed in ADR-002, not made this weekend; the process-spawn half (`vcc-agent --spawn`) is P0-059 |
| 6 | Forged identity | **RUN — attack NOT refused at DecisionPoint** | same test file: a request naming another agent, with none of its key material, is **Authorized**, because there is no proof of possession. Controls: a forged key derives a different id, and the chain leaf must match. | — | DecisionPoint | the gateway's signed requests (P0-059) are not re-verified; fix in ADR-002 |
| 7 | Attribution ambiguity | NOT RUN | — | — | — | needs 4.3 and the gateway |
| 8 | Self-report contradicts observation | NOT RUN | — | — | — | P0-059 lying agent |
| 9 | Tampered evidence | **PARTIAL** | `test_observer_ingest` live: an edited batch, a deleted batch and the wrong key are each refused by `aip-observe-verify`, and nothing is ingested. `test_eventstore` Tamper: edits made with the triggers dropped are reported by `verify()`. | none observed | observer archives and the event store | bundle v2 and `vcc-verify` (6.2) are P0-059; deleting the store's newest rows is detected only against a held head |
| 10 | Missing observer coverage | **RUN** | `test_observer_ingest` on the repo's qualified `same-run-interruption` archive: the task window is DEGRADED, not covered. `live_observer_kill.py` ×3: 7/7 each. | none: the healthy `same-run` task window is COVERED, with 0 gaps | probe killed (archive) and collector killed (live) | state lag of about 10.5 s (max_silence); same host; no synced clock |
| 11 | Policy-denied tool | **PARTIAL** | `opa test command-center/policy` 17/17, including an explicit deny that beats the allowlist; `test_opa_gate` live `test_explicit_deny`. | `test_allow` stays ALLOW | the decision only | the call is not refused at a gate (3.1b) → ADVISORY |
| 12 | Missing cost telemetry | **PARTIAL** | LiteLLM: `raw-zeros.txt` shows LiteLLM itself logging cost 0 and tokens 0; `acceptance.py` 16/16 shows `llm_capture` storing None with a reason. OpenLIT reports `gen_ai.usage.cost = "0"` (1.4). | a genuine declared price of 0 stays 0 (`test_genuine_zero_cost_is_kept`) | the capture layer | the console's "no telemetry" display (4.2) is not built |
| 13 | Restart and persistence | **PARTIAL** | `test_eventstore` Restart 2/2: reopen, and a second OS process; `test_llm_store_logger` replay-and-restart. | — | the store | BFF restart (P0-059) |
| 14 | Duplicate events | **RUN** | `test_eventstore` Duplicates 4/4; a redelivered LiteLLM hook is a no-op (`stored` 1 of `seen` 2); re-polling an archive inserts 0. | different events are never merged (`test_any_field_change_is_a_new_event`) | the store and both ingest paths | — |
| 15 | Interrupted collector | **RUN** | `command-center/lab/live_observer_kill.py`, 3 runs: 7/7 checks each (`evidence/3.4b-live-kill/`) | — | live SIGKILL of the real `aip-collector` | same as #10 |

Totals (updated after 2.5a): **RUN 7** (#1, #2, #5, #6, #10, #14, #15), of which **#5 and #6 found the attack NOT refused**; **PARTIAL 5** (#4, #9, #11, #12, #13); **NOT RUN 3** (#3, #7, #8). 7 + 5 + 3 = 15.
