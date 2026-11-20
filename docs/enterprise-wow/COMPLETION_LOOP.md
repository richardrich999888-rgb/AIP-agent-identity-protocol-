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
- [ ] **0.2** Inventory the branches, recent Claude commits and PRs (GitHub API needs P1). Output: `docs/enterprise-wow/AUDIT.md`. Re-use `command-center/docs/REPOSITORY_AUDIT.md` and extend it to sentinel, containment and NEXORA.
- [ ] **0.3** Write the capability matrix using the brief's five classes (independently tested / integration incomplete / partial / simulated / not implemented) for every module named in Phase 0. Output: `docs/enterprise-wow/CAPABILITY_MATRIX.md`.
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
- [ ] **1.4** (P2) Evaluate Falco, the OTel Collector and OpenLIT only if Phase 1 finishes by the Sat 06:00 checkpoint. Otherwise mark them `NOT_EVALUATED`.

## Phase 2 — P0 capabilities

| # | Capability | Exists (P0-059) | Gap this loop closes |
|---|---|---|---|
| 1 | Agent inventory | per-run JSON | persistent store, framework, host, credentials metadata, last seen, risk |
| 2 | Shadow AI | unregistered agent runtime (CONFIRMED) | a HEURISTIC class kept separate from CONFIRMED; false-positive control |
| 3 | Ghost AI | unknown-worker refused + observed | explicit `attribution_missing_reason` field; a forged identity case |
| 4 | Orphan AI | ancestor revoked → ORPHANED | **owner** removal case; orphan **actively executing** after revocation, observed live |
| 5 | Parent-child | signed chain + gateway actions | parent **process** spawns children; unauthorized delegation detected |
| 11 | AIP identity | done | verification failure shown live in the console |

- [ ] **2.1 Persistent event store.**
  - `command-center/server/eventstore.py` (stdlib `sqlite3`): append-only, with an idempotency key = SHA-256 of the canonical event.
  - Each run's records are ingested into it.
  - Inventory, last-observed time and risk become queries over the store.
  - Tests: duplicate ingestion is a no-op (adversarial #14); the BFF restart preserves state (adversarial #13).
- [ ] **2.2 Inventory fields.** Add framework (`scripted-test-agent` / `langgraph` if 4.x adds one), host, runtime, credential metadata (key fingerprint and token expiry, never secrets), parent, owner, responsible human, and risk/governance status derived from findings.
- [ ] **2.3 Shadow and ghost.**
  - Add a `HEURISTIC_AI_WORKLOAD` class: a process that connects to the LLM proxy or model port with no identity. Keep it separate from CONFIRMED.
  - Add a false-positive control: a normal process (e.g. `python3 -m http.server`, `sort`) must stay `UNCLASSIFIED` (adversarial #2).
  - Every ghost row carries `attribution_missing_reason` (one of: no registry row / signature invalid / no gateway session / no binding).
- [ ] **2.4 Orphan, live.** The orphaned grandchild must keep running after revocation and attempt a call: it is observed by Sniffer Dog and refused by the gateway. Add an owner-removal case (principal removed from the registry → UNKNOWN_OWNER). Test both.
- [ ] **2.5 Real parent-child processes.**
  - `vcc-agent --spawn` lets the orchestrator process launch its children, so the inferred fork edge and the signed edge coincide.
  - Unauthorized delegation case: `recon-reporter` (no Delegate scope) tries to sub-delegate → the chain is rejected and recorded (adversarial #5).
  - Forged identity case: a request signed with a key that does not derive the claimed id (adversarial #6).
- [x] **2.6 Close the revocation gap.** Keep the gateway check. Add `docs/enterprise-wow/ADR-001-decisionpoint-revocation.md` recommending a `DecisionPoint` change. **Do not change `DecisionPoint` this weekend.**
  - **Done (ADR part)** `b5143a7f`. `cargo test --locked -p aip-authorize --test revocation_gap`: 3 passed / 0 failed / 0 skipped. These tests pin that `DecisionPoint::authorize_at` authorizes under a revoked root and under a revoked hop, while `RevocationLog` reports both as revoked. The whole crate: 103 passed / 0 failed. ADR: `docs/enterprise-wow/ADR-001-decisionpoint-revocation.md`. `DecisionPoint` is unchanged.
  - Limits: "keep the gateway check" is **not verified**: the gateway is in P0-059 (0.1 blocked). Also recorded, from reading the code only: `RevocationLog::revoke` discards save errors (`revocation.rs:127`), which fails open. A tracking issue is not filed yet.

## Phase 3 — governance (P0) and monitoring

- [ ] **3.1 OPA at the enforcement point.**
  - Gate step 7 calls OPA: pinned binary, `opa eval` or a localhost server, with a Rego bundle in `command-center/policy/`.
  - Every decision records the bundle hash.
  - Rules: allowed and denied tools, delegation restrictions, sensitive actions, revoked authority (input from signed revocations).
  - If OPA is unreachable, the gate **denies** (fail closed).
  - Tests: parity with the old allowlist on all P0-059 cases, plus OPA-down → DENY.
- [ ] **3.2 Human approval with real enforcement.**
  - A sensitive call (`payments.settle_batch` above a threshold) returns `PENDING_APPROVAL`, and the gateway holds it.
  - An operator approves in the console. The approval is signed with the operator's principal key; the agent retries with the approval id, and the call is ALLOWED and forwarded.
  - Test: no approval means no forwarding.
- [ ] **3.3 Policy console.** Show the current Rego, its version, a test "evaluate this request" form that calls OPA for real, and the violations and audit log. Label each result **PREVENTION** (gateway) or **ADVISORY** (detection only).
- [ ] **3.4 Activity pipeline.**
  - Continuous ingestion of Sniffer Dog batches into the event store while a run is active.
  - The Activity Explorer shows process, file, socket and tool events with evidence strength.
  - Degraded-observer state: collector down → banner and coverage gap (adversarial #10, #15: kill the collector mid-window and confirm the gap is reported and that nothing is shown as clean).

## Phase 4 — P1 capabilities

- [ ] **4.1 Mock model + FinOps.**
  - A local OpenAI-compatible mock model returns deterministic text and `usage` token counts, labelled **TEST DATA** everywhere.
  - Agents call it through LiteLLM with per-agent metadata (agent id, workflow, owner).
  - Usage and cost are captured into the event store: tokens, model/provider, agent, workflow, owner, cost at a declared **test price** (labelled "estimated").
- [ ] **4.2 FinOps console.**
  - Tokens and cost per agent, workflow and owner; parent→child roll-up; budget per owner with a usage bar; trend across runs.
  - Missing telemetry is shown as **"no telemetry"**, never as 0 (adversarial #12).
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

- [ ] **6.1** `demos/vanian-enterprise/` containing:
  - `README.md`, `setup.sh`, `check.sh`, `run.sh`, `reset.sh`, `verify.sh`, `test.sh`;
  - `RECORDING_GUIDE.md`, `NARRATION.md`;
  - `compose.yaml` for OPA, LiteLLM and the mock model (with a native fallback).

  `setup.sh && run.sh` initialises the demo; `verify.sh` checks all 12 capabilities and exits non-zero on any failure.
- [ ] **6.2** Write the evidence bundle v2. It covers policy decisions with the OPA bundle hash, approvals, attribution records and FinOps usage.
  - Add `vcc-verify` checks: `POLICY` (decision ↔ bundle hash ↔ receipt), `APPROVAL` (operator signature) and `ATTRIBUTION` (signatures). Each check must have a test that tampers its input and fails.
- [ ] **6.3** Run all 15 adversarial tests. Output: `docs/enterprise-wow/ADVERSARIAL_RESULTS.md`, with per test: command, result, false positives, coverage, unresolved limitations.

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

- [ ] **6.4** Write the 12-capability acceptance matrix: `demos/vanian-enterprise/verify.sh` output + `docs/enterprise-wow/ACCEPTANCE_MATRIX.md`, giving source, execution path, test, output, evidence and limitation for each capability.

## Phase 7 — recording and handoff

- [ ] **7.1** 10 consecutive `run.sh` + `verify.sh` rehearsals on a **clean tree**. Keep the summary JSON.
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

## Iteration log

| # | Item | Result | SHA | Tests (pass/fail/skip) |
|---|---|---|---|---|
| 1 | 0.4 | Done: Compose runs; sensors 3/7 as found, 7/7 with tracefs | `24379741` | live_sensors 6/0/0; sensor_matrix 7/7 open |
| 2 | 1.1 | Done: 17 candidates pinned, ranked; OPA + LiteLLM core adopted | `58a69d2b` | test_survey 15/0/0; survey 17/17 ok |
| 3 | 1.2 | Done: OPA pinned + verified; finding: unauthenticated REST writes un-revoke an agent | `fc8a686e` | opa test 10/0/0; smoke 5/5; upstream 6 pkgs ok/0 fail |
| 4 | 1.3 | Done: SDK capture works without Postgres; 3 zero-for-unmeasured cases fixed in capture | `af2df27c` | acceptance 16/0; unit 23/0/0 |
| 5 | 2.6 | Done (ADR): gap measured by 3 tests; DecisionPoint untouched | `b5143a7f` | revocation_gap 3/0/0; aip-authorize 103/0/0 |

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
