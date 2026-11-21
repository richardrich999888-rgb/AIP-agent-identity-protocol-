# VANIAN Enterprise AI-Security WOW Demo — completion loop

**Deadline:** Monday 23 Nov 2026, 09:00 IST. **Freeze:** Monday 06:00 IST.
**Brief:** the P0 "Enterprise AI Security WOW Demo" prompt (12 capabilities, console, lab, 15 adversarial tests, 5-min recording).
**Path in repo:** `docs/enterprise-wow/COMPLETION_LOOP.md` (this file is the loop's only memory between iterations).

Rules (inherited from `docs/release/COMPLETION_LOOP.md`):

- One item per iteration. An item is ticked only with a commit SHA, the exact test command and its counts (passed / failed / skipped).
- `BLOCKED_BY_INFRASTRUCTURE`, `BLOCKED_BY_EXTERNAL_APPROVAL` and `CUT_FOR_DEADLINE` are final states. Do not hide them.
- Never weaken a test, never relabel a failed run, and never show synthetic data without a label. A feature with no enforcement point is ADVISORY, not PREVENTION.
- Do not touch SYNTRIASS branches or demos (`claude/syntriass-*`). Do not merge to `main`. Do not force-push. Do not deploy externally.
- Every capability needs: source, real execution path, test scenario, reproducible output, verification evidence, explicit limitation.

---

## Loop prompt (paste this as the instruction for every iteration)

```
You are continuing the VANIAN Enterprise WOW Demo completion loop.
1. git fetch; check out claude/vanian-enterprise-wow and pull. Read docs/enterprise-wow/COMPLETION_LOOP.md in full.
2. If the current IST time is past a checkpoint in "Schedule", apply that checkpoint's decision rule first.
3. Take the FIRST unticked item, in priority order, whose dependencies are ticked. Do only that item. Timebox: 75 minutes.
4. Implement in small commits. Run the item's acceptance command and every suite it touches. A test that needs an unavailable environment is SKIPPED, not passed.
5. Commit and push. Tick the item with: SHA, command, counts, and one line of limitations. Append a row to "Iteration log". Update "Progress report".
6. If the item cannot be finished, record why, set a final state or split it into smaller items, push, and stop.
Never fabricate output. Never mark a capability VERIFIED unless an automated test and a live run both show it.
```

---

## Ground truth (verified 20 Nov 2026, 19:30 IST)

| Fact | Status |
|---|---|
| P0-059 Command Center (`ef466db9`, `6a6b31dc`, `8d85354d`) | **Not on GitHub.** It exists only as `p0-059-command-center.bundle` (base `6d9cd1ad`). |
| `feature/wow-demos` head | `f665cab2`: 2 documentation commits past the bundle base, so cherry-picks should apply cleanly. |
| Remote refs | 88, including `claude/*` loop branches and `claude/syntriass-airgap-intelligence` (do not touch the last one). |
| Sandbox | 2 vCPU, 7 GB, root, kernel 6.18, no NTP. Sniffer Dog and auditd work live. Package registries and GitHub are reachable; most other hosts are blocked. |
| Docker | Client 29.10 installed; **daemon not running** (`/var/run/docker.sock` absent). |
| Push access from the cloud sandbox | **Refused on 20 Nov.** Each scheduled iteration starts with a fresh disk, so **without push access nothing persists between iterations.** |

Carried forward from P0-059 (re-verify in the 0.x items, don't assume):

- Governed MCP gateway: SO_PEERCRED binding, signed requests, revocation, exact-call allowlist, DecisionPoint.
- Lineage classification (VALID, REVOKED, ORPHANED, UNREGISTERED, …).
- Discovery joined to Sniffer Dog by (pid, start ticks, exe hash).
- The lying agent with auditd cross-check.
- Signed bundle with out-of-band anchors; `vcc-verify` passes the original and rejects a tampered copy.
- Stdlib BFF with tenant-scoped keys, and the React console.
- 10/10 rehearsals. 45 + 441 Rust, 40 Python, 7 vitest and 10 Playwright tests passing.
- Known gap: `DecisionPoint` does not consult revocation.

---

## Prerequisites (human, before the loop starts)

- [ ] **P1. Push access.** Pick one of these:
  - **(a, recommended)** Grant Claude write access to `richardrich999888-rgb/AIP-agent-identity-protocol-` (GitHub connector or app authorization). The loop then runs as cloud scheduled iterations.
  - **(b)** Run Claude Code on your own Linux machine (Ubuntu 22.04/24.04, root, x86_64) as one long session with `/loop` against this file.
- [ ] **P2.** Import the P0-059 bundle (iteration 0.1 does this if P1 is granted).
- [ ] **P3.** Confirm the iteration cadence: every 90 min Fri 21:00 → Mon 06:00 is about 37 iterations.

---

## Schedule and checkpoints (IST)

| Checkpoint | Must be ticked | Decision rule if not |
|---|---|---|
| Sat 06:00 | Phase 0 + Phase 1 | Cut Phase 1 to OPA + LiteLLM only; mark the other candidates `NOT_EVALUATED`. |
| Sun 06:00 | All P0 items (2.x, 3.1–3.3) | Freeze the scope of 4.x. FinOps is reduced to the LiteLLM usage capture only. |
| Sun 18:00 | P1 items + console navigation | Cut cost trends and budgets to `CUT_FOR_DEADLINE`. Cut attribution case (d) to a labelled preview if it is not working. |
| Mon 02:00 | Lab scripts + 15 adversarial tests run | Stop features. Only fixes, rehearsals and recording from here on. |
| Mon 06:00 | **Freeze.** 10 rehearsals, recording, final report | Ship what passes. Everything else is listed in "Known limitations". |
| Mon 08:30 | Handoff message: branch, SHA, links | — |

Cut order when behind: P2 polish → cost trends and budgets → Activity Explorer live updates → attribution case (d) UI. **Never cut:** evidence verification, Sniffer Dog, governance enforcement, inventory, identity graph.

---

## Phase 0 — audit and baseline (P0)

- [ ] **0.1** Create `claude/vanian-enterprise-wow` from `origin/feature/wow-demos`. Cherry-pick the three P0-059 commits from the bundle. Build with `cargo build --release --locked -p aip-probe -p aip-collector -p aip-observe-verify -p vanian-command-center`. Run the P0-059 test table (`command-center/README.md`). Record real counts and failures.
- [ ] **0.2** Inventory the branches, recent Claude commits and PRs (GitHub API needs P1). Output: `docs/enterprise-wow/AUDIT.md`. Re-use `command-center/docs/REPOSITORY_AUDIT.md` and extend it to sentinel, containment and NEXORA. Split on 21 Nov: 0.2a (inventory) and 0.2b (P0-059 audit re-use).
  - [x] **0.2a** `docs/enterprise-wow/AUDIT.md`. **Done** `e8410425`. Covers 44 branches and 23 PRs (21 open, 15 drafts; main has had no merge since 19 Jun). `cargo test --locked -p` for aip-sentinel-feed, aip-containment, aip-nexora, aip-warrant and aip-reconcile: 508 passed / 0 failed / 0 ignored. Limit: test counts show the crates pass their own tests, not that the demo uses them.
  - [ ] **0.2b** Merge in `command-center/docs/REPOSITORY_AUDIT.md` from P0-059. **Blocked on 0.1.**
- [ ] **0.3** Write the capability matrix using the brief's five classes (independently tested / integration incomplete / partial / simulated / not implemented) for every module named in Phase 0. Output: `docs/enterprise-wow/CAPABILITY_MATRIX.md`. Split on 21 Nov: 0.3a (this branch) and 0.3b (P0-059 modules).
  - [x] **0.3a** `docs/enterprise-wow/CAPABILITY_MATRIX.md`. **Done** `94337fc6`. Every module reachable here is classified, citing the loop's own commands and counts. No row is PREVENTION. Of the 12 demo capabilities: 5 are NV (P0-059), 2 NI (approval, attribution), 1 II (governance, ADVISORY), and 4 tested in part.
  - [ ] **0.3b** Classify the P0-059 modules (gateway, lineage, discovery, lying agent, bundle and `vcc-verify`, BFF, console). **Blocked on 0.1.**
- [x] **0.4** Lab feasibility check. Try `dockerd &` as root and record whether Compose runs. If not, mark `BLOCKED_BY_INFRASTRUCTURE` and run every service as a native process with a `compose.yaml` kept for real hosts. Record kernel sensor availability per sensor.
  - **Done** `24379741`. Compose runs: `dockerd &`, `docker run --rm hello-world` exit 0, two-service `docker compose up` probe exit 0 and host curl exit 0. Not BLOCKED_BY_INFRASTRUCTURE.
  - Sensors: `cargo run --release --locked -p aip-probe --example sensor_matrix` gave 3/7 open as found (connector, fanotify, afpacket). After `mount -t tracefs nodev /sys/kernel/tracing` it gave 7/7. `cargo test --locked -p aip-probe --test live_sensors -- --nocapture` gave 6 passed / 0 failed / 0 skipped, with no SKIPPED line.
  - Limits: dockerd and tracefs are manual and must be scripted in 6.1. cgroup v1. The four tracer sensors opened but were not exercised. Evidence: `docs/enterprise-wow/evidence/0.4/`.

## Phase 1 — open-source R&D (P0 for OPA and LiteLLM, P2 for the rest)

The brief's claims about each project are hypotheses. Verify the license file in each repository at a pinned commit.

- [x] **1.1** Write `docs/research/OPEN_SOURCE_INTEGRATION_MATRIX.md` covering every candidate the brief lists:
  - OpenLIT, LiteLLM, OPA, Falco, OpenTelemetry Collector, OpenLoop, Langfuse, Arize Phoenix, SPIFFE/SPIRE and OpenFGA;
  - plus MCP gateway and agent-instrumentation projects.

  For each one record: repository, release, license and its obligations (including any directories under separate enterprise licenses), architecture, security model, dependencies, local requirements, effort, maintenance risk, tests run, verdict. Rank them. Use web research and do not answer from memory.
  - "OpenLoop": identify the actual project first. If it cannot be identified unambiguously, record that.
  - **Done** `58a69d2b`. `python3 -I research/oss/survey.py research/oss/survey.json`: exit 0, 17/17 candidates pinned to commits with license files hashed. `python3 -m unittest test_survey`: 15 passed / 0 failed / 0 skipped. Verdicts: ADOPT OPA (`v1.22.4`) and LiteLLM core (`1.110.2`, no `enterprise/`); the rest DEFER, REFERENCE ONLY or REJECT. OpenLoop is AMBIGUOUS (two unrelated projects).
  - Limits: github.com pages and api.github.com are blocked (403), so release notes and stars were not read; tags were cross-checked with PyPI. No project's own tests were run (1.2–1.4). License classes are signature matches, not legal advice.
- [x] **1.2** Clone **OPA** into `research/oss/opa` at a pinned commit, or use the pinned release binary with its checksum. Run its tests or a smoke test. Record the results.
  - **Done** `fc8a686e`. Pinned `v1.22.4` / `ba39415db4b3`, built via proxy.golang.org (module hash = sum.golang.org entry; the release binary is unreachable). `opa test -v policy/*.rego` 10 passed / 0 failed / 0 skipped. Four mutations all caught. `research/oss/opa/smoke.sh` (live server) 5/5 decisions, exit 0. OPA's own `go test ./v1/ast/... ./v1/rego/...`: 6 packages ok / 0 fail, exit 0.
  - **Finding:** the default OPA server accepts unauthenticated PUTs. Clearing `inventory/revoked` returned 204, and the revoked agent was then allowed. Any OPA-backed control stays ADVISORY until a gateway enforces OPA's decision and a test shows the management API refusing writes.
  - Limits: a local build, not the release binary (the file hash differs from upstream). Only the ast and rego subset of OPA's own suite was run. OPA ran as root.
- [x] **1.3** Install **LiteLLM** (pinned version) in a venv. Test it against the mock model (4.1). Establish whether usage and cost capture work **without Postgres**, through the SDK callback or the proxy custom logger. Record the results.
  - **Done** `af2df27c`. Answer: yes, via the SDK CustomLogger path, with no Postgres. Core `litellm==1.110.2` (no `[proxy]` extra); mock model and prices are TEST DATA. `unshare -n … acceptance.py --isolated`: 16 passed / 0 failed checks, exit 0. `python3 -m unittest test_capture test_mock_openai`: 23 passed / 0 failed / 0 skipped. Three mutations all caught.
  - Findings: LiteLLM logs cost and tokens of 0 for an unpriced model, a missing provider usage and a failed call; `capture.py` maps these to None with a reason. Callback exceptions are swallowed. The `[proxy]` extra installs `litellm-enterprise` (LicenseRef-Proprietary), which `import litellm` then loads.
  - Limits: the proxy path was not tested (license). Sync `completion()` only. Metadata is caller-asserted, not verified. Records go to JSONL, not the event store (2.1 is blocked by 0.1). The mock was written here; 4.1 reuses it. Evidence: `research/oss/litellm/`.
- [x] **1.4** (P2) Evaluate Falco, the OTel Collector and OpenLIT only if Phase 1 finishes by the Sat 06:00 checkpoint. Otherwise mark them `NOT_EVALUATED`.
  - **Done** `9ac0671c`. OTel Collector v0.165.0: USABLE (built from the pinned commit). OpenLIT 1.45.0: INSTRUMENTATION ONLY. `chain.py` passes 3/3 offline, but OpenLIT phones home for pricing and reports a cost of 0 when it has no price. Falco 0.45.2: **BLOCKED_BY_INFRASTRUCTURE** (no CAP_SYS_RESOURCE, memlock hard limit 8,192 KiB; final for this host). Evidence: `research/oss/openlit-otel/`.

## Phase 2 — P0 capabilities

| # | Capability | Exists (P0-059) | Gap this loop closes |
|---|---|---|---|
| 1 | Agent inventory | per-run JSON | persistent store, framework, host, credentials metadata, last seen, risk |
| 2 | Shadow AI | unregistered agent runtime (CONFIRMED) | a HEURISTIC class kept separate from CONFIRMED; false-positive control |
| 3 | Ghost AI | unknown-worker refused + observed | explicit `attribution_missing_reason` field; a forged identity case |
| 4 | Orphan AI | ancestor revoked → ORPHANED | **owner** removal case; orphan **actively executing** after revocation, observed live |
| 5 | Parent-child | signed chain + gateway actions | parent **process** spawns children; unauthorized delegation detected |
| 11 | AIP identity | done | verification failure shown live in the console |

- [ ] **2.1 Persistent event store.** Split on 20 Nov: 2.1a (the store) and 2.1b (ingestion and queries).
  - `command-center/server/eventstore.py` (stdlib `sqlite3`): append-only, with an idempotency key = SHA-256 of the canonical event.
  - Each run's records are ingested into it.
  - Inventory, last-observed time and risk become queries over the store.
  - Tests: duplicate ingestion is a no-op (adversarial #14); the BFF restart preserves state (adversarial #13).
  - [x] **2.1a** The store: `command-center/server/eventstore.py`. **Done** `815f5d3a`. `python3 -m unittest -v test_eventstore`: 22 passed / 0 failed / 0 skipped. Covers adversarial #13 (restart, including a second OS process) and #14 (duplicate is a no-op). Five mutations all caught. Limit: deleting the newest rows is detectable only against a held `head()` (pinned by a test).
  - [ ] **2.1b** Ingest each P0-059 run's records. Inventory, last-observed time and risk become store queries. BFF restart test (#13 at the BFF level). **Blocked on 0.1** (the P0-059 commits are not on the remote).
- [ ] **2.2 Inventory fields.** Add framework (`scripted-test-agent` / `langgraph` if 4.x adds one), host, runtime, credential metadata (key fingerprint and token expiry, never secrets), parent, owner, responsible human, and risk/governance status derived from findings.
- [ ] **2.3 Shadow and ghost.** Split on 21 Nov: 2.3a (heuristic class, live) and 2.3b (P0-059 classes).
  - Add a `HEURISTIC_AI_WORKLOAD` class: a process that connects to the LLM proxy or model port with no identity. Keep it separate from CONFIRMED.
  - Add a false-positive control: a normal process (e.g. `python3 -m http.server`, `sort`) must stay `UNCLASSIFIED` (adversarial #2).
  - Every ghost row carries `attribution_missing_reason` (one of: no registry row / signature invalid / no gateway session / no binding).
  - [x] **2.3a** `command-center/server/shadow_ai.py`: HEURISTIC_AI_WORKLOAD from kernel events, kept separate from CONFIRMED. False-positive control. `attribution_missing_reason` on heuristic rows. **Done** `ee497446`. `python3 command-center/lab/live_shadow_ai.py OUT`: 3/3 runs, 7 passed / 0 failed checks each (#1, #2). `test_shadow_ai` 10/0/0; four mutations all caught. Old 3.4b archives: 0 HEURISTIC out of 154–160 processes. Limits: A's reason was "no binding" in every run (no start time bound, so pid reuse is not excluded); the model endpoint is operator-declared; the registry is empty.
  - [ ] **2.3b** Merge with P0-059's CONFIRMED class and registry. Ghost rows with "signature invalid" and "no gateway session". **Blocked on 0.1.**
- [ ] **2.4 Orphan, live.** The orphaned grandchild must keep running after revocation and attempt a call: it is observed by Sniffer Dog and refused by the gateway. Add an owner-removal case (principal removed from the registry → UNKNOWN_OWNER). Test both.
- [ ] **2.5 Real parent-child processes.** Split on 21 Nov: 2.5a (protocol-layer #5/#6) and 2.5b (process spawn).
  - `vcc-agent --spawn` lets the orchestrator process launch its children, so the inferred fork edge and the signed edge coincide.
  - Unauthorized delegation case: `recon-reporter` (no Delegate scope) tries to sub-delegate → the chain is rejected and recorded (adversarial #5).
  - Forged identity case: a request signed with a key that does not derive the claimed id (adversarial #6).
  - [x] **2.5a** #5 and #6 at the protocol layer. **Done** `f2353c6c`, with **two findings**: a holder without Delegate can sub-delegate and the grandchild is authorized; DecisionPoint has no proof of possession. `cargo test --locked -p aip-authorize --test delegation_identity_findings`: 5 passed / 0 failed / 0 skipped; crate 108/0/0. Fixes are proposed in ADR-002 and not applied (core unchanged this weekend). The plan's "chain is rejected" is therefore **not** met.
  - [ ] **2.5b** `vcc-agent --spawn` (orchestrator launches its children, so the inferred fork edge and the signed edge coincide). The forged-identity case at the gateway. **Blocked on 0.1.**
- [x] **2.6 Close the revocation gap.** Keep the gateway check. Add `docs/enterprise-wow/ADR-001-decisionpoint-revocation.md` recommending a `DecisionPoint` change. **Do not change `DecisionPoint` this weekend.**
  - **Done (ADR part)** `b5143a7f`. `cargo test --locked -p aip-authorize --test revocation_gap`: 3 passed / 0 failed / 0 skipped. These tests pin that `DecisionPoint::authorize_at` authorizes under a revoked root and under a revoked hop, while `RevocationLog` reports both as revoked. The whole crate: 103 passed / 0 failed. ADR: `docs/enterprise-wow/ADR-001-decisionpoint-revocation.md`. `DecisionPoint` is unchanged.
  - Limits: "keep the gateway check" is **not verified**: the gateway is in P0-059 (0.1 blocked). Also recorded, from reading the code only: `RevocationLog::revoke` discards save errors (`revocation.rs:127`), which fails open. A tracking issue is not filed yet.

## Phase 3 — governance (P0) and monitoring

- [ ] **3.1 OPA at the enforcement point.** Split on 20 Nov: 3.1a (decision component) and 3.1b (wiring and parity).
  - Gate step 7 calls OPA: pinned binary, `opa eval` or a localhost server, with a Rego bundle in `command-center/policy/`.
  - Every decision records the bundle hash.
  - Rules: allowed and denied tools, delegation restrictions, sensitive actions, revoked authority (input from signed revocations).
  - If OPA is unreachable, the gate **denies** (fail closed).
  - Tests: parity with the old allowlist on all P0-059 cases, plus OPA-down → DENY.
  - [x] **3.1a** OPA decision adapter `command-center/server/opa_gate.py` and bundle `command-center/policy/`. **Done** `141a11e9`. Bundle hash and input hash recorded per decision. Every engine failure is DENY. PENDING_APPROVAL is not forwarded. `opa test command-center/policy`: 17/17. `VANIAN_OPA_BIN=… python3 -m unittest test_opa_gate`: 23 passed / 0 failed / 0 skipped (16 passed / 7 skipped without the binary). Six mutations all caught. Uses `opa eval` per call, not a server (the 1.2 finding).
  - [ ] **3.1b** Gate step 7 calls `OpaGate.decide`. `revoked_jtis` comes from signature-verified revocations. Parity tests against all P0-059 allowlist cases, plus an OPA-down test at the gate (call not forwarded). **Blocked on 0.1.** Until then 3.1a is a decision component, not PREVENTION.
- [ ] **3.2 Human approval with real enforcement.**
  - A sensitive call (`payments.settle_batch` above a threshold) returns `PENDING_APPROVAL`, and the gateway holds it.
  - An operator approves in the console. The approval is signed with the operator's principal key; the agent retries with the approval id, and the call is ALLOWED and forwarded.
  - Test: no approval means no forwarding.
- [ ] **3.3 Policy console.** Show the current Rego, its version, a test "evaluate this request" form that calls OPA for real, and the violations and audit log. Label each result **PREVENTION** (gateway) or **ADVISORY** (detection only).
- [ ] **3.4 Activity pipeline.** Split on 21 Nov: 3.4a (verified ingestion and coverage) and 3.4b (live run and console).
  - Continuous ingestion of Sniffer Dog batches into the event store while a run is active.
  - The Activity Explorer shows process, file, socket and tool events with evidence strength.
  - Degraded-observer state: collector down → banner and coverage gap (adversarial #10, #15: kill the collector mid-window and confirm the gap is reported and that nothing is shown as clean).
  - [x] **3.4a** `command-center/server/observer_ingest.py`. **Done** `ea405018`. It ingests only batches that the real `aip-observe-verify` accepts. Coverage, gaps, restarts, losses and DEGRADED come from signed windows. `VANIAN_OBSERVE_VERIFY_BIN=target/release/aip-observe-verify python3 -m unittest test_observer_ingest`: 22 passed / 0 failed / 0 skipped (15 passed / 7 skipped without the binary). Six mutations all caught. On the repo's qualified `same-run-interruption` archive (probe killed), the agent task window is reported DEGRADED, not clean. The healthy `same-run` task window is COVERED.
  - [x] **3.4b** Live run: probe and collector on this host, continuous verified polling while a workload runs, and the collector SIGKILLed mid-window (adversarial #15, #10). **Done** `a078c7cf`. `python3 command-center/lab/live_observer_kill.py OUT`: 3/3 runs, 7 passed / 0 failed checks each. The full task window is not covered; the state is DEGRADED; the gap starts before the kill. Limits: the summary state lags the kill by about 10.5 s (max_silence), while `window_covered` stays exact. No synced clock (no NTP; the control is off). Same host. Evidence: `docs/enterprise-wow/evidence/3.4b-live-kill/`.
  - [ ] **3.4c** Per-event rows (process, file, socket) for the Activity Explorer, and the console degraded banner showing "covered to <time>". **Blocked on 0.1** (P0-059 console).

## Phase 4 — P1 capabilities

- [ ] **4.1 Mock model + FinOps.** Split on 20 Nov: 4.1a (capture into the store) and 4.1b (the P0-059 agents use it).
  - A local OpenAI-compatible mock model returns deterministic text and `usage` token counts, labelled **TEST DATA** everywhere.
  - Agents call it through LiteLLM with per-agent metadata (agent id, workflow, owner).
  - Usage and cost are captured into the event store: tokens, model/provider, agent, workflow, owner, cost at a declared **test price** (labelled "estimated").
  - [x] **4.1a** LiteLLM → `StoreUsageLogger` → `EventStore` as `llm.usage` events. Mock model and prices are TEST DATA. **Done** `fb6da331`. Event-store thread fix `07652616`: LiteLLM runs hooks on its own thread; the live test caught 3 of 4 events silently lost. Offline suite (`unshare -n`, with the pinned LiteLLM and OPA): 70 passed / 0 failed / 0 skipped. With stdlib Python only: 61 passed / 9 skipped. Missing telemetry is stored as null, never 0. Unattributed usage gets no subject. A redelivered hook event is a no-op.
  - [ ] **4.1b** The P0-059 agents call the mock through LiteLLM with their real agent id, workflow and owner, and agent metadata is bound to the verified identity rather than caller-asserted. **Blocked on 0.1.**
- [ ] **4.2 FinOps console.** Split on 21 Nov: 4.2a (backend aggregation) and 4.2b (console and roll-up).
  - Tokens and cost per agent, workflow and owner; parent→child roll-up; budget per owner with a usage bar; trend across runs.
  - Missing telemetry is shown as **"no telemetry"**, never as 0 (adversarial #12).
  - [x] **4.2a** `command-center/server/finops_report.py`: per agent, workflow and owner; owner budgets (TEST USD) with a lower-bound flag; trend buckets; NO_TELEMETRY and PARTIAL states (None never 0, adversarial #12). **Done** `48ba91cf`. `test_finops_report` 13/0/0, plus the live `test_finops_report_over_live_events` (LiteLLM to store, offline), 16 passed in that run; four mutations all caught.
  - [ ] **4.2b** The console page, and the parent→child roll-up (needs P0-059 lineage). **Blocked on 0.1.**
- [ ] **4.3 Human-versus-agent attribution, four cases**, each from signatures and sessions, never from process names or user-agent strings:
  - **(a) Human initiated:** the operator signs the action with the principal key in a console session.
  - **(b) Agent authorized:** existing ALLOW.
  - **(c) Agent under human delegation:** the human signs a task-scoped grant; the record links the human session → task grant → agent → action.
  - **(d) Unattributed:** an action Sniffer Dog observes with no gateway record and no identity (e.g. a shell `curl` to the tool port).
  - Ambiguity test (adversarial #7): a process running as the human's uid but without a session signature → `AMBIGUOUS`, not `HUMAN`.

## Phase 5 — console (P0 navigation, P2 polish)

- [ ] **5.1** Change the navigation to exactly: Overview | Discovery | Agent Inventory | Identity Graph | Activity Explorer | Governance | FinOps | Evidence Vault.
  - Fold the existing P0-059 pages under these.
  - Loading, error, empty and **degraded-observer** states on every page.
  - "Live" means polling or SSE from the event store, with a visible last-event time.
- [ ] **5.2** Extend the Playwright E2E to all 8 pages and the new flows (approval, attribution, FinOps "no telemetry" state).
- [ ] **5.3** (P2) Visual polish. Only after Sun 18:00, and only if everything above is ticked.

## Phase 6 — lab, adversarial tests, evidence

- [ ] **6.1** `demos/vanian-enterprise/` containing (split on 21 Nov: 6.1a scripts, 6.1b guides and full coverage):
  - `README.md`, `setup.sh`, `check.sh`, `run.sh`, `reset.sh`, `verify.sh`, `test.sh`;
  - `RECORDING_GUIDE.md`, `NARRATION.md`;
  - `compose.yaml` for OPA, LiteLLM and the mock model (with a native fallback).

  `setup.sh && run.sh` initialises the demo; `verify.sh` checks all 12 capabilities and exits non-zero on any failure.
  - [x] **6.1a** check, setup, test, run, verify and reset scripts, plus `compose.yaml` (the mock only; OPA and LiteLLM deliberately not services, see the file). **Done** `efc1d5b1`. setup exit 0; `test.sh` 5/5 suites; `run.sh` 7/7 checks; `verify.sh` **0/12 VERIFIED, 0 FAIL, exit 1** (5 NOT_AVAILABLE, 2 NOT_IMPLEMENTED, 5 PARTIAL); `test_verify` 6/6. Evidence: `docs/enterprise-wow/evidence/6.1a/`. Limit: the Docker Hub pull returned 429, so the image comes from mirror.gcr.io, pinned by digest.
  - [ ] **6.1b** `RECORDING_GUIDE.md` and `NARRATION.md` (with 7.2). verify.sh coverage for capabilities 1–5, 7 and 9. **Blocked on 0.1** for 1–5; on the gateway for 7 and 9.

- [ ] **6.2** Write the evidence bundle v2. It covers policy decisions with the OPA bundle hash, approvals, attribution records and FinOps usage.
  - Add `vcc-verify` checks: `POLICY` (decision ↔ bundle hash ↔ receipt), `APPROVAL` (operator signature) and `ATTRIBUTION` (signatures). Each check must have a test that tampers its input and fails.
- [ ] **6.3** Run all 15 adversarial tests. Output: `docs/enterprise-wow/ADVERSARIAL_RESULTS.md`, with per test: command, result, false positives, coverage, unresolved limitations. Split on 21 Nov: 6.3a (what runs on this branch) and 6.3b (the rest).
  - [x] **6.3a** `docs/enterprise-wow/ADVERSARIAL_RESULTS.md`. **Done** `471ff1f1`. RUN 3 (#10, #14, #15), PARTIAL 5 (#4, #9, #11, #12, #13), NOT RUN 7. Every row cites its command and count.
  - [ ] **6.3b** Run #1, #2, #3, #5, #6, #7 and #8, and complete the PARTIAL rows. **Blocked on 0.1 and the gateway.**

| # | Test | Item |
|---|---|---|
| 1 | Unregistered workload | 2.3 |
| 2 | False-positive control | 2.3 |
| 3 | Missing ownership | 2.4 |
| 4 | Revoked authorization | P0-059, re-run |
| 5 | Unauthorized child delegation | 2.5 |
| 6 | Forged identity | 2.5 |
| 7 | Attribution ambiguity | 4.3 |
| 8 | Self-report contradicts observation | P0-059 |
| 9 | Tampered evidence | 6.2 |
| 10 | Missing observer coverage | 3.4 |
| 11 | Policy-denied tool | 3.1 |
| 12 | Missing cost telemetry | 4.2 |
| 13 | Restart and persistence | 2.1 |
| 14 | Duplicate events | 2.1 |
| 15 | Interrupted collector | 3.4 |

- [ ] **6.4** Write the 12-capability acceptance matrix: `demos/vanian-enterprise/verify.sh` output + `docs/enterprise-wow/ACCEPTANCE_MATRIX.md`, giving source, execution path, test, output, evidence and limitation for each capability. Split on 21 Nov: 6.4a (current) and 6.4b (final).
  - [x] **6.4a** `docs/enterprise-wow/ACCEPTANCE_MATRIX.md`, generated from the recorded `verify.sh` run. **Done** `96e59b4d`. 0/12 VERIFIED, 0 FAIL.
  - [ ] **6.4b** Regenerate after 0.1, 3.1b, 3.2 and 4.3 land, and at freeze.

## Phase 7 — recording and handoff

- [ ] **7.1** 10 consecutive `run.sh` + `verify.sh` rehearsals on a **clean tree**. Keep the summary JSON. Split on 21 Nov: 7.1a (harness, dry run) and 7.1b (the 10 qualifying rehearsals).
  - [x] **7.1a** `demos/vanian-enterprise/rehearse.sh N`: refuses a dirty tree; writes a summary JSON with the head commit, every exit code and the timings. **Done** `a01f3606`, fix `c69b7cbf` (set -e had cut it short), evidence `ee03b7bf`. Dry run, 2 cycles: test 0, run 0, verify 1 each; tree clean afterwards; all_passed false. Labelled DRY RUN, not counted.
  - [ ] **7.1b** 10 qualifying rehearsals at freeze (after the last feature commit). They pass only when verify exits 0.
- [ ] **7.2** Record the 5-minute video with the recorder (scenes per brief Phase 6: 0:00 overview, 0:40 shadow/ghost/orphan launched live, 1:20 parent-child, 2:10 lying agent, 3:00 governance + attribution, 3:50 FinOps, 4:25 evidence). Produce 300.000 s, 1920×1080, 30 fps; captions + SRT; no cutting away from failures. Add the full technical demonstration as a second, longer cut.
- [ ] **7.3** Write `docs/enterprise-wow/FINAL_REPORT.md`:
  - branch and SHA; test counts; the matrices;
  - known limitations and unresolved blockers;
  - which items are VERIFIED, PARTIAL, CUT or BLOCKED.

---

## Definition of done (Monday 09:00)

A skeptical engineer runs `demos/vanian-enterprise/setup.sh && run.sh && verify.sh` on a supported Linux host and gets:

- a pass for every capability that the matrix marks VERIFIED;
- an explicit FAIL, SKIP or PREVIEW for everything else.

The console reads only persisted backend data. The video shows that same run.

## Progress report

| When (IST) | Milestone | Status | Notes |
|---|---|---|---|
| Fri 20 Nov 19:30 | Plan seeded | — | waiting on P1 (push access) |
| Fri 20 Nov 19:25 | Plan committed to `claude/vanian-enterprise-wow` | — | P1 met in this session (see verification below); P2 open: the bundle is not reachable here |
| Fri 20 Nov 19:44 | 0.4 lab feasibility | Done | Docker + Compose work in the cloud container; 0.1 still waits on P0-059 commits |
| Fri 20 Nov 20:05 | 1.1 integration matrix | Done | OpenLoop ambiguous; LiteLLM enterprise/ and Langfuse ee/ excluded by license |
| Fri 20 Nov 20:09 | 1.2 OPA | Done | default REST API writable without auth: must be locked down or embedded |
| Fri 20 Nov 20:20 | 1.3 LiteLLM | Done | proxy extra pulls proprietary litellm-enterprise; use core SDK only |
| Fri 20 Nov 20:23 | 2.6 revocation ADR | Done | gateway half unverifiable until P0-059 lands |
| Fri 20 Nov 20:25 | 2.1a event store | Done | 2.1b (ingestion) blocked on 0.1 |
| Fri 20 Nov 20:28 | 3.1a OPA adapter | Done | 3.1b (gate wiring, parity) blocked on 0.1 |
| Fri 20 Nov 20:32 | 4.1a FinOps capture | Done | 4.1b blocked on 0.1 |
| Sat 21 Nov 00:12 | 3.4a observer ingestion | Done | 3.4b live kill run next; console part blocked on 0.1 |
| Sat 21 Nov 00:16 | 3.4b live kill | Done | state lag ~10.5 s measured; 3.4c blocked on 0.1 |
| Sat 21 Nov 00:21 | 1.4 P2 evaluations | Done | Phase 1 complete before Sat 06:00; Falco blocked here |
| Sat 21 Nov 00:24 | 0.2a audit | Done | 0.2b blocked on 0.1 |
| Sat 21 Nov 00:25 | 0.3a matrix | Done | 5 of 12 capabilities NV until P0-059 lands |
| Sat 21 Nov 00:30 | 6.1a lab scripts | Done | verify exit 1: 0/12 VERIFIED until P0-059 and the gateway land |
| Sat 21 Nov 00:31 | 6.3a adversarial results | Done | 7 tests wait on P0-059 and the gateway |
| Sat 21 Nov 00:32 | 6.4a acceptance matrix | Done | everything left is blocked on 0.1 or the gateway |
| Sat 21 Nov 00:36 | 2.3a shadow AI | Done | adversarial #1 and #2 now RUN; 2.3b blocked on 0.1 |
| Sat 21 Nov 00:40 | 2.5a delegation/identity | Done (findings) | #5 and #6 attacks not refused; ADR-002 |
| Sat 21 Nov 00:43 | 4.2a FinOps aggregation | Done | 4.2b console blocked on 0.1 |
| Sat 21 Nov 01:29 | ADR-002 impact, ADR-001 measured, 7.1a | Done | 279 tests depend on non-Delegate delegation; lost-revocation finding measured |
| Sat 21 Nov 06:08 | **Checkpoint Sat 06:00** | Evaluated | Phase 1: 1.1–1.4 all ticked, so the cut rule does not apply. Phase 0: 0.2a, 0.3a and 0.4 ticked; 0.1, 0.2b and 0.3b are open, blocked because the P0-059 commits are still not on the remote (checked at Sat 21 Nov 06:08 IST). The plan has no cut rule for Phase 0. Risk for Sun 06:00: of the P0 items, only 2.1a, 2.3a, 2.5a, 2.6 and 3.1a are done; the rest need P0-059. If they are still open at Sun 06:00, the rule freezes 4.x (FinOps = LiteLLM capture only; 4.1a and 4.2a already exist). |
| Sat 21 Nov 11:00 | Findings tracked; cadence reduced | Done | Security findings filed as issues #27–#30. The :30 scheduled task is disabled, so the loop checks every 3 h, at :00. Every open item waits on P0-059 or on freeze, and idle runs were only polling. `feature/vanian-accountability-console` is not used as a source: it is not P0-059, and the plan names P0-059. |

## Iteration log

| # | Item | Result | SHA | Tests (pass/fail/skip) |
|---|---|---|---|---|
| 1 | 0.4 | Done: Compose runs; sensors 3/7 as found, 7/7 with tracefs | `24379741` | live_sensors 6/0/0; sensor_matrix 7/7 open |
| 2 | 1.1 | Done: 17 candidates pinned, ranked; OPA + LiteLLM core adopted | `58a69d2b` | test_survey 15/0/0; survey 17/17 ok |
| 3 | 1.2 | Done: OPA pinned + verified; finding: unauthenticated REST writes un-revoke an agent | `fc8a686e` | opa test 10/0/0; smoke 5/5; upstream 6 pkgs ok/0 fail |
| 4 | 1.3 | Done: SDK capture works without Postgres; 3 zero-for-unmeasured cases fixed in capture | `af2df27c` | acceptance 16/0; unit 23/0/0 |
| 5 | 2.6 | Done (ADR): gap measured by 3 tests; DecisionPoint untouched | `b5143a7f` | revocation_gap 3/0/0; aip-authorize 103/0/0 |
| 6 | 2.1a | Done: append-only store with dedup, restart, tamper detection | `815f5d3a` | test_eventstore 22/0/0 |
| 7 | 3.1a | Done: OPA adapter, fail-closed, bundle hash per decision | `141a11e9` | rego 17/17; adapter 23/0/0 live (16/0/7 without OPA) |
| 8 | 4.1a | Done: LiteLLM usage persisted; found + fixed store thread bug (`07652616`) | `fb6da331` | command-center suite 70/0/0 offline |
| 9 | 3.4a | Done: verified archive ingestion; interrupted run shows DEGRADED, healthy COVERED | `ea405018` | test_observer_ingest 22/0/0 |
| 10 | 3.4b | Done: live collector kill, gap reported in 3/3 runs | `a078c7cf` | live_observer_kill 7/7 checks x3 |
| 11 | 1.4 | Done: OTel usable; OpenLIT instrumentation only; Falco BLOCKED_BY_INFRASTRUCTURE | `9ac0671c` | chain 3/0 checks |
| 12 | 0.2a | Done: repository audit; 5 Ghost crates 508/0/0 | `e8410425` | cargo test 508/0/0 |
| 13 | 0.3a | Done: capability matrix, no PREVENTION rows | `94337fc6` | doc only; cites prior counts |
| 14 | 6.1a | Done: lab scripts; verify reports 0/12 VERIFIED honestly | `efc1d5b1` | test.sh 5/5; run 7/7; test_verify 6/6 |
| 15 | 6.3a | Done: 3 RUN, 5 PARTIAL, 7 NOT RUN (blocked) | `471ff1f1` | doc; cites prior counts |
| 16 | 6.4a | Done: acceptance matrix (0/12 VERIFIED) | `96e59b4d` | generated from verify-summary.json |
| 17 | 2.3a | Done: heuristic shadow AI live, 0 false positives | `ee497446` | live 7/7 x3; unit 10/0/0 |
| 18 | 2.5a | Done with 2 findings: Delegate not enforced; no proof of possession | `f2353c6c` | 5/0/0; aip-authorize 108/0/0 |
| 19 | 4.2a | Done: FinOps aggregation, no-telemetry never 0 | `48ba91cf` | 13/0/0 + live 16 OK |
| 20 | 7.1a | Done: rehearsal harness; 2-cycle dry run behaves as designed | `ee03b7bf` | dry run: test 0, run 0, verify 1 x2 |

---

## Verification on 20 Nov 2026, 19:22 IST (cloud session `session_019kXhQDbuUN5rVvhHjyo4jq`)

The ground-truth table above is kept as written. This is what a second sandbox found when it checked the same facts; each line names how it was checked.

| Fact | Found | How checked |
|---|---|---|
| Push access | **Works from this session.** It pushed `feature/airon-teach-demo` and `fix/aip-service-drop-chrono` (PR #25) on 19–20 Nov, and this commit. | `git push` results; `git ls-remote` shows the pushed heads. |
| P0-059 commits `ef466db9`, `6a6b31dc`, `8d85354d` | **Not available.** None of the three is in this clone (`git cat-file`: not a valid object). No `*.bundle` or `p0-059*` file exists on this disk. | `git cat-file -t`; `find / -xdev \( -name '*.bundle' -o -name 'p0-059*' \)`. |
| Bundle base `6d9cd1ad` | Present; an ancestor of `feature/wow-demos`. | `git cat-file -t 6d9cd1ad` → commit. |
| `feature/wow-demos` head | `f665cab2`, as stated. It contains no `command-center/` directory. | `git ls-remote`; `git ls-tree`. |
| Sandbox | 4 vCPU, 15 GB RAM, kernel 6.18.44 (differs from the table: a different host). | `nproc`, `free -g`, `uname -r`. |
| Docker | `/var/run/docker.sock` exists, but **no daemon answers**. Compose v5.6.1 is installed. `dockerd` was not started (that is item 0.4). | `docker info` → "Cannot connect to the Docker daemon"; `docker compose version`. |

**Consequence for 0.1:** it cannot cherry-pick until the three P0-059 commits are reachable, for example pushed as a branch from the machine that holds the bundle, or the bundle file added to this session. Items that do not need P0-059 (0.4, 1.1–1.3) can proceed.
