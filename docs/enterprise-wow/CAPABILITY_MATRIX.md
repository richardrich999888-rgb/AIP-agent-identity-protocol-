# Capability matrix (enterprise WOW loop, item 0.3a)

As of 21 Nov 2026, 00:3x IST, branch `claude/vanian-enterprise-wow`.

Classes, from the brief:

- **IT** independently tested: an automated test, and where stated a live run, on this branch;
- **II** integration incomplete: the part works, but it is not wired into the demo path;
- **P** partial;
- **S** simulated: works only against TEST DATA or a mock;
- **NI** not implemented on this branch.

A row whose evidence lives only in P0-059 is **NV** (not verifiable here),
because the P0-059 commits are not on the remote (0.1). NV is not a claim
that the capability is absent. It means nothing on this branch can show it.

PREVENTION or ADVISORY is stated wherever enforcement is in question. No row
here is PREVENTION, because no enforcement point is wired (3.1b is blocked).

## Built or verified in this loop

| Capability | Module | Class | Evidence (command → result) | Limit |
|---|---|---|---|---|
| Kernel sensors open | `aip-probe` `SensorSet::open` | **IT** | `sensor_matrix` 3/7 as found, 7/7 with tracefs; `live_sensors` 6/0/0 (0.4) | sched, cgroup, sockstate and socksend opened but were not exercised for events |
| Signed observer archive verified offline | `aip-collector` + `aip-observe-verify` | **IT** | `observer_ingest` live tests 22/0/0 on the repo's qualified archives; tamper, delete and wrong-key all refused (3.4a) | — |
| Observer coverage and kill gap | `command-center/server/observer_ingest.py` | **IT** | `live_observer_kill.py` 3/3 runs, 7/7 checks (3.4b) | summary state lags about 10.5 s; same host; no synced clock |
| Persistent event store (#13, #14) | `command-center/server/eventstore.py` | **IT** | `test_eventstore` 24/0/0; 7/7 mutations (2.1a) | deleting the newest rows is detected only against a held head; P0-059 ingestion is 2.1b |
| Policy decision (OPA) | `command-center/server/opa_gate.py` + `command-center/policy/` | **IT + II** | `opa test` 17/17; `test_opa_gate` 23/0/0 with the pinned OPA; 6/6 mutations (3.1a) | a decision component only; not at the gate → **ADVISORY** until 3.1b |
| LLM usage and cost capture | `llm_capture.py`, `finops_events.py`, `llm_store_logger.py` | **IT + S + II** | 1.3 acceptance 16/16 offline; command-center suite 70/0/0 (4.1a) | mock model and test prices (TEST DATA); agent metadata asserted by the caller; agents not wired (4.1b) |
| OTel export pipe | `otelcorecol` v0.165.0 (pinned build) | **IT + S** | `openlit-otel/chain.py` 3/3 offline (1.4) | not on the demo path |
| Falco second witness | Falco 0.45.2 | **NI here** | BLOCKED_BY_INFRASTRUCTURE: no CAP_SYS_RESOURCE (1.4) | final for this host |
| Revocation at DecisionPoint | `aip-authorize` `DecisionPoint` | **NI** (gap) | `revocation_gap` 3/0/0 pins that revoked authority is still authorized (2.6) | ADR-001 proposed; not implemented this weekend by rule |
| Delegate-scope enforcement and proof of possession | `aip-core` delegation, `aip-authorize` `DecisionPoint` | **NI** (findings) | `delegation_identity_findings` 5/0/0 pins that a holder without Delegate can sub-delegate and the grandchild is authorized (#5), and that a request naming another agent without its key is authorized (#6) (2.5a) | ADR-002 proposed; not changed this weekend |

## Existing crates (own tests only)

| Capability | Crate | Class | Evidence | Limit |
|---|---|---|---|---|
| Reconciliation, CANNOT_PROVE by default | `aip-reconcile` | **IT + II** | `cargo test --locked -p aip-reconcile` 224/0/0 (0.2a) | not called by the demo path on this branch |
| Warrants | `aip-warrant` | **IT + II** | 23/0/0 | as above |
| Containment boundary | `aip-containment` | **IT + II** | 31/0/0 | as above; no actuation was demonstrated |
| NEXORA commitments | `aip-nexora` | **IT + II** | 196/0/0 | as above |
| Sentinel effect log | `aip-sentinel-feed` | **IT + II** | 34/0/0 | as above |
| Decision point and ExpectedExecution | `aip-authorize` | **IT + II** | 103/0/0 (2.6) | revocation gap above |

## The 12 demo capabilities (brief), at this branch

| # | Capability | Class | Why |
|---|---|---|---|
| 1 | Agent inventory | **IT / native** | 21 Nov 18:20 IST: `inventory.py` over the registry and the store's gate records (2.2, native, not P0-059). Unit 11/0/0; live 12/12. Kernel-only processes are not joined. |
| 2 | Shadow AI | **NV** | P0-059 |
| 3 | Ghost AI | **NV** | P0-059 |
| 4 | Orphan AI | **NV** | P0-059 |
| 5 | Parent-child | **NV** | P0-059 |
| 6 | Governance enforcement | **II** | The decision component is tested (3.1a); the gate wiring is blocked (3.1b) → ADVISORY |
| 7 | Human approval | **NI** | 3.2 not started; it needs the gateway |
| 8 | Activity and observer coverage | **IT + II** | 3.4a/b live; per-event rows and the console are 3.4c |
| 9 | Human vs agent attribution | **NI** | 4.3 not started; it needs the gateway |
| 10 | FinOps | **IT + S + II** | capture and persistence tested (4.1a); console is 4.2 |
| 11 | AIP identity | **IT** (crates) / **NV** (console) | the AIP crates are tested in the repo; the console view is P0-059 |
| 12 | Evidence verification | **IT** (observer archives) / **NV** (bundle v2) | `aip-observe-verify` live; `vcc-verify` and the bundle are P0-059 |

**0.3b (blocked on 0.1):** classify P0-059's modules once their commits are
reachable: the gateway, lineage, discovery, the lying agent, the bundle,
`vcc-verify`, the BFF and the console.
