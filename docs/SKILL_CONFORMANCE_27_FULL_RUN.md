# Skill Conformance — Full Repository Run

**HEAD at start** `8fe9ff4b9b777a3de2baf8b13f8751fdee3f2344`
**Branch** `claude/skill-25-implementation-xbz0t3`
**Working tree at start** clean
**Date of run** 2026-09-07
**Scope** every skill installed under `.claude/skills/`, exercised once against
this HEAD. No production code was changed to obtain any result in this document.

This is a verification run. Where this report and any earlier audit report
disagree, this report is the current one — several earlier limitations have
since been closed by later work, and at least one earlier limitation is now
stale (§9.1). Where this report and the code disagree, the code wins.

---

## 1. Executive verdict

**27-skill conformance run completed: 0 failures; 2 partial; 1 blocked.
2,192 validation tests executed with 0 failures; 84/84 mutations killed;
zero cross-skill architectural invariant violations.**

Nothing in this repository failed. Two skills are PARTIAL because evidence
they require was not produced, one is BLOCKED because the hardware it needs
does not exist here, and neither condition is a defect in the code.

### 1.1 Scope — and a discrepancy in the count

**The repository does not contain 27 skills. It contains 36 skill
specifications, of which 30 are numbered.** The stated count of 27 is
reconstructible and is used as the audit scope, but the discrepancy is stated
first because a conformance report that silently accepted a wrong denominator
would be worthless.

Recovered from `git log --diff-filter=A -- .claude/skills/`:

| Group | Count | Numbering |
|---|---|---|
| Named skills, numbered by their own commit messages | 10 | Skills 1–10 |
| Numbered directories `11-…` – `15-…` | 5 | Skills 11–15 |
| Numbered directories `16-…` – `30-…` | 15 | Skills 16–30 |
| Unnumbered engineering-role skills | 6 | — |
| Bundle README (no `SKILL.md`) | 1 | — |
| **Total directories** | **37** | |

**Skills 1–27 are the 27 in scope, and they are the whole denominator.**
Skills 28, 29 and 30 exist as specifications, are explicitly out of scope for
this run (the instruction was *"Do not implement Skill 28 or any future
skill"*), and are **excluded from the 27-skill conformance result** — they are
reported in §3 as SPEC-ONLY so that nothing is hidden, and nowhere counted.
The six unnumbered role skills are process guidance for a human or agent
operator, not deliverable specifications, and have no acceptance gate to run.

### 1.2 Skill status — in-scope (Skills 1–27)

| Status | Count |
|---|---:|
| PASS | 24 |
| PARTIAL | 2 |
| BLOCKED | 1 |
| **FAIL** | **0** |

Read that table with these four facts attached; without them it is misleading:

- **Skills 1 and 2 are process/N/A classifications counted inside the 24.**
  Neither is a deliverable specification — Skill 1 is an architectural
  gatekeeper, Skill 2 an implementation methodology — so neither states an
  acceptance gate over repository state and neither can strictly PASS or FAIL.
  They are counted as PASS-equivalent because their governing rules are upheld
  throughout, not because either was independently validated. **22 skills were
  validated against a gate and passed it; 2 had no gate to validate.**
- **Skill 15 is PARTIAL** because 6 of 16 external AIRI validation scenarios
  are recorded NOT_RUN (§3, §11.4). It is not upgraded to PASS.
- **Skill 16 is PARTIAL** because blocker **B-3 remains OPEN** (§3, §11.6).
  It is not upgraded to PASS.
- **Skill 25's physical-AI extension is BLOCKED** by unavailable physical
  hardware and environment — no camera, no ROS, no PX4, no independent
  physical observer (§12). Skill 25's core profile passes on its own gate;
  the extension is blocked, not failed.

### 1.3 Measured results

| Measure | Result |
|---|---|
| Validation performed against | `8fe9ff4b9b777a3de2baf8b13f8751fdee3f2344` |
| Rust workspace | **2,064 passed · 0 failed · 6 ignored** (two independent passes, identical) |
| External validation adapter | **66 passed · 0 failed** |
| Python SDK (clean virtualenv) | **62 passed · 0 failed** |
| **Total tests / total failures** | **2,192 / 0** |
| Adversarial + structural checks | **498 passing** |
| Mutations | **84 total · 84 killed · 0 survivors** |
| Cross-skill architectural violations | **0** |
| `cargo fmt` / `cargo clippy -D warnings` | clean / clean |
| Production files changed by this run | **0** |

### 1.4 What this run does not establish

Zero failures in a test suite is a statement about the test suite. It is not
a statement about production readiness, and it is not physical validation.
Specifically, this run establishes **none** of the following:

- **No physical validation of any kind.** No physical quantity was measured by
  any independent mechanism. This remains BLOCKED (§12), not pending.
- **No spacecraft or orbital validation.** Skill 26 is **SIMULATION-PROVEN**:
  the onboard execution is real, the link, contact windows, light-time and
  ground station are simulated.
- **No production readiness.** No deployment, no operational evidence, no
  measured latency, CPU, memory, event loss or recovery time (§13).
- **No customer, defence or TRL claim.** Skill 30's gate is not approached.

The accountability core is architecturally sound and self-consistent — one
core, one reconciler, one verifier, one evidence hierarchy, one
`ObservationClass`/`EvidenceCeiling` model, one keypair primitive, no
vertical-specific signing authority, no second source of truth, and no
wire/protocol change during this run (§8). That is what was verified. It is
not a substitute for any of the four items above.

---

## 2. The 27 skills in scope

| # | Canonical path | Purpose (as stated by the spec) |
|---|---|---|
| 1 | `.claude/skills/ghost-architecture-orchestrator/SKILL.md` | Architectural gatekeeper; enforces stage order |
| 2 | `.claude/skills/syntriass-ghost-implementation/SKILL.md` | Implementation methodology; evidence-first ordering |
| 3 | `.claude/skills/syntriass-aip-correctness/SKILL.md` | AIP cryptographic correctness; signed expiry, injective encoding |
| 4 | `.claude/skills/syntriass-execution-binding/SKILL.md` | Process-instance execution identity |
| 5 | `.claude/skills/syntriass-decision-point/SKILL.md` | Independent decision boundary; ExpectedExecution |
| 6 | `.claude/skills/syntriass-observer-attestation/SKILL.md` | Independent observation with its own trust root |
| 7 | `.claude/skills/syntriass-reconciliation/SKILL.md` | The single reconciliation engine |
| 8 | `.claude/skills/syntriass-ghost-warrant/SKILL.md` | Warrant as a decision gate, not an actuator |
| 9 | `.claude/skills/syntriass-ghost-containment/SKILL.md` | Containment behind the warrant gate |
| 10 | `.claude/skills/syntriass-nexora-integration/SKILL.md` | Continuity and provenance; offline verification |
| 11 | `.claude/skills/11-ai-runtime-integration/SKILL.md` | AIRI: framework-neutral AI runtime interface |
| 12 | `.claude/skills/12-python-observation-boundary/SKILL.md` | Python agent boundary and SDK |
| 13 | `.claude/skills/13-model-framework-provenance/SKILL.md` | Model/accelerator execution provenance |
| 14 | `.claude/skills/14-tool-invocation-and-effect/SKILL.md` | Tool invocation vs runtime execution vs external effect |
| 15 | `.claude/skills/15-ai-stack-end-to-end/SKILL.md` | End-to-end AI stack accountability |
| 16 | `.claude/skills/16-production-boundary-and-blocker-closure/SKILL.md` | Close forensic blockers B-1a … B-10 |
| 17 | `.claude/skills/17-autonomous-system-model/SKILL.md` | Environment-neutral autonomous-system model |
| 18 | `.claude/skills/18-autonomy-execution-profile/SKILL.md` | Environment-neutral execution model |
| 19 | `.claude/skills/19-edge-hardware-identity-and-binding/SKILL.md` | Bind execution to compute substrate |
| 20 | `.claude/skills/20-autonomous-observation-profile/SKILL.md` | Generalised independent observation contract |
| 21 | `.claude/skills/21-effect-boundary-and-actuation/SKILL.md` | Intent vs command vs external effect |
| 22 | `.claude/skills/22-linux-autonomous-edge-reference/SKILL.md` | Linux reference implementation |
| 23 | `.claude/skills/23-uas-accountability-profile/SKILL.md` | UAS vertical profile |
| 24 | `.claude/skills/24-robotics-autonomy-profile/SKILL.md` | Robotics/UGV vertical profile |
| 25 | `.claude/skills/25-industrial-critical-edge-accountability-profile/SKILL.md` | Industrial/critical-edge vertical profile |
| 26 | `.claude/skills/26-disconnected-space-autonomy-profile/SKILL.md` | Disconnected/space vertical profile |
| 27 | `.claude/skills/27-enterprise-autonomy-profile/SKILL.md` | Enterprise vertical profile |

Out of scope, reported for completeness: **28** `28-autonomous-system-conformance`,
**29** `29-autonomous-edge-threat-model`, **30** `30-defence-reference-deployment`
— all three SPEC-ONLY. Six unnumbered role skills: `aip-protocol-change-guard`,
`aip-service-hardening`, `execution-binding-engineer`, `ghost-adversarial-tester`,
`ghost-architecture-engineer`, `ghost-reconciliation-engineer`.

---

## 3. Per-skill status

Every status below was decided against the skill's **own** acceptance gate,
read from its `SKILL.md` at this HEAD, and against executed tests — never
against the existence of a specification or a document.

### Skills 1–2 — process skills, NOT APPLICABLE

Neither is a deliverable specification. Skill 1 is an architectural gatekeeper
that decides what may be built and in what order; Skill 2 is an implementation
methodology. Neither states an acceptance gate over repository state, so
neither can PASS or FAIL. Their governing rules — stage ordering, no capability
claimed from a primitive, no design document treated as implementation — are
audited *through* the other 25 skills and are upheld: the stage order
AIP → ExecutionBinding → Decision Point → Observer → Reconciliation → Warrant →
Containment → NEXORA is reflected exactly in the crate dependency graph.

### Skill 3 — AIP correctness · **PASS**

Gate: signed expiry on `ScopedToken` and `DelegationToken`, injective authority
encoding, domain separation, no raw-concatenation signed encoder, malformed
AIP-ID cannot panic, no caller-supplied trust anchor mistaken for authorization.

Evidence: `aip-types` 5, `aip-crypto` 9, `aip-core` 158, `aip-authorize` 39
tests, all passing. `aip-authorize/tests/adversarial.rs` carries 32 adversarial
tests. Artifact `docs/architecture/AIP_CORRECTNESS_REPORT.md` present.
Canonical encoders live in one place (`aip_types::canonical`) and are used by
every signed structure in the repository.
**TEST-PROVEN.**

### Skill 4 — Execution binding · **PASS**

Gate: process identity is not PID-only; PID reuse tested; boot context and
start time addressed; executable content hashed; injective canonical encoding;
domain separation; transplantation rejected; failure does not fabricate identity.

Evidence: `ExecutionBinding::identity_bytes()` = agent AIP-ID +
`ProcessInstance{pid, pid_start_time_ticks, boot_id}` + `exe_content_sha256`.
`EXECUTION_BINDING_VERSION = 1`. `aip-protocol` 79 tests, `aip-execution` 43
tests including `tests/boundary_attacks.rs` (29 adversarial). Artifact
`EXECUTION_BINDING_IMPLEMENTATION_REPORT.md` present.
**TEST-PROVEN**, with the live-process portions **EXECUTION-PROVEN** via
`aip-edge`.

### Skill 5 — Decision point · **PASS**

Gate: independent decision boundary; agent cannot be its own decision point;
`ExpectedExecution` exists; `decision_id` is the correlation key; `issued_at`
and `valid_until` signed; expiry mutation rejected; ExpectedExecution never
represented as execution proof.

Evidence: `aip-authorize` 39 tests, 32 of them adversarial. Decision-point key
is separate from agent authority (enforced structurally — `aip-authorize` does
not depend on `aip-agent`). Artifact `DECISION_POINT_IMPLEMENTATION_REPORT.md`.
**TEST-PROVEN.**

### Skill 6 — Observer attestation · **PASS**

Gate: independent trust root; signed `ObservedExecution`; continuity explicit;
degradation explicit; replay addressed; **no authorization, containment or
NEXORA logic inside the observer.**

Evidence: `aip-observe` 170 tests, 26 adversarial. `ObserverLedger` with
`ContinuityFault{Replay, Fork, Rollback, Gap, HeadMismatch, UnverifiableEpoch}`
and sticky `ContinuityStatus::GapObserved`. The ledger is held **at the
collector**, off the observed host — the architectural point of the skill.
`ObserverState::IntegrityUnknown` and `SignedSensorHealth` close the
foreign-BPF interference boundary (`12767ea`). Structural check: `aip-observe`
contains no authorization, warrant, containment or proof-tree logic.
Artifact `OBSERVER_IMPLEMENTATION_REPORT.md`.
**TEST-PROVEN**, with kernel-facility paths **EXECUTION-PROVEN** where the
facility is available on this host (6 tests remain ignored for want of root).

### Skill 7 — Reconciliation · **PASS**

Gate: `CANNOT_PROVE` is the default; all result preconditions enforced;
evidence strength independent of severity; deterministic output; **no
authorization, warrant, containment or NEXORA logic introduced.**

Evidence: `aip-reconcile` 173 tests, 32 adversarial, plus eight dedicated
evidence-class suites (`action_evidence`, `exec_evidence`, `file_evidence`,
`send_evidence`, `transition_evidence`, `wire_corroboration`, `lineage_edges`,
`lineage_violation`). `ReconciliationResult` is constructed only through
sealed constructors (B-9). Artifact `RECONCILIATION_IMPLEMENTATION_REPORT.md`.
**TEST-PROVEN.**

### Skill 8 — Warrant · **PASS**

Gate: a warrant is a decision boundary, not an actuator; containment never
granted to `CANNOT_PROVE`; `Attested` never automatically grants containment;
severity never substitutes for strength.

Evidence: `aip-warrant` 23 tests. `aip-warrant` does not depend on
`aip-containment` (checked in the manifest). Artifact
`WARRANT_IMPLEMENTATION_REPORT.md`.
**TEST-PROVEN.**

### Skill 9 — Containment · **PASS**

Gate: containment sits behind the warrant gate; predecessor PASS artifacts
verified; smallest coherent containment boundary.

Evidence: `aip-containment` 31 tests, including
`tests/engine_to_containment.rs` (5 tests) which drives a real `DecisionPoint`,
a real `CollectorSigner`, the real engine, `evaluate`, and `contain()` against
a **live process**. Artifact `CONTAINMENT_IMPLEMENTATION_REPORT.md`.
**EXECUTION-PROVEN** for the crossing; see Skill 16 for the open finding about
what that crossing terminates in.

### Skill 10 — NEXORA integration · **PASS**

Gate: NEXORA provides identity, provenance, continuity, version binding,
replay resistance and cross-layer integrity **without becoming a governance
authority**; offline verification; verifier must not trust a serialized
verdict.

Evidence: `aip-nexora` 178 tests, 22 adversarial. `LeafKind::ALL` is frozen at
9 members. `VerifiedProof` deliberately implements `Serialize` but **not**
`Deserialize` — a capability that could be read out of bytes would be a
capability an attacker could write. `verify_proof` is defined exactly once in
the repository. Artifact `NEXORA_IMPLEMENTATION_REPORT.md`.
**TEST-PROVEN.**

### Skill 11 — AI runtime integration (AIRI) · **PASS**

Gate: one framework adapter emits an AIRI execution trace; the same schema
represents multiple frameworks; cross-framework substitution fails; adapter-only
evidence cannot escalate `CANNOT_PROVE` to `Proven`; execution-instance binding
survives process/worker transitions.

Evidence: `aip-airi` 67 tests, 23 adversarial — including
`a_claim_relabelled_to_another_framework_fails_verification`,
`no_framework_is_a_trust_anchor`,
`a_forged_event_signed_by_a_key_the_verifier_does_not_anchor_fails`,
`a_handoff_binds_parent_and_child_executions`. `FrameworkIdentity` is
documented in-code as "Not a trust input".
**TEST-PROVEN.**

### Skill 12 — Python observation boundary · **PASS**

Gate: a sample Python agent obtains an AIP identity, receives an
ExpectedExecution, executes a tool request through AIRI, propagates execution
identity, produces an event **clearly classified as self-report**, is
reconciled against independent evidence, and never gains `Proven` because the
SDK said so.

Evidence: `sdk/python/vanian_airi` with `tests/` — **62 tests, 62 passing.**
Suites: `test_boundary.py`, `test_context.py`, `test_canonical_parity.py`,
`test_adapters_e2e.py`, `test_schema_conformance.py`. Cross-language canonical
parity is pinned by `parity_vectors.json`, consumed on the Rust side by
`aip-airi/tests/parity_vectors.rs` and `tests/python_interop.rs`.

Environmental note recorded rather than hidden: under this container's
**system** `python3-cryptography` 41.0.7, 16 of the 62 tests error with
`pyo3_runtime.PanicException` at `cryptography.hazmat.bindings._rust` import.
Zero assertion failures — all 16 are the same broken system package. Re-run in
a clean virtualenv with `cryptography` 50.0.1: **62 passed, 0 failed.** The
defect is in the container image, not the repository.
**TEST-PROVEN.**

### Skill 13 — Model / framework provenance · **PASS**

Gate: model metadata cryptographically bound to the execution event;
framework/model substitution detectable; a model event cannot be transplanted
between agent identities or executions; offline verification does not need the
original LLM call; missing model/accelerator evidence never becomes implicit
success.

Evidence: `aip-airi/src/provenance.rs` (`ModelProvenance`); adversarial
coverage includes `an_event_signed_for_a_different_agent_id_is_refused`,
`a_malformed_commitment_cannot_be_smuggled_in_as_a_foreign_digest`,
`a_model_invocation_is_never_corroborated_by_a_host_observer` — the last is
the accelerator boundary stated as a refusal rather than a caveat.
**TEST-PROVEN.**

### Skill 14 — Tool invocation and effect · **PASS**

Gate: parameter substitution detectable; tool-call transplantation across
agent/execution identities fails; replay detectable; **a tool response cannot
by itself prove the side effect occurred.**

Evidence: `aip-airi` `ToolInvocation` + `aip-effect` 27 tests, all 27
adversarial. `a_successful_tool_response_is_not_evidence_of_the_external_effect`
is a named test. `EffectAssessment` separates `ObservedStance` from
`EffectFinding`, and `NotObservedReason` prevents absence collapsing into
non-occurrence.
**TEST-PROVEN.**

### Skill 15 — AI stack end-to-end · **PARTIAL**

Gate: the 20-case test matrix; `CANNOT_PROVE` default; NEXORA packages
sufficient for offline re-derivation.

What passes: the matrix is covered in-repo. Every one of the 20 named cases
maps to at least one executing adversarial test across `aip-airi` (23),
`aip-reconcile` (32), `aip-observe` (26) and `aip-nexora` (22). Offline
re-derivation is proven by `aip-edge/tests/nexora.rs` and the NEXORA suite.

**Why PARTIAL:** the skill's own out-of-tree validation matrix
(`validation/reports/AIRI_VALIDATION_MATRIX.csv`, 16 scenarios) records
**10 PASS and 6 NOT_RUN**, and all 16 rows record the external observers
(Tetragon, OBI) as `BLOCKED (no kprobes)` and Langfuse as
`UNAVAILABLE (registries blocked)`. The six not run are `s07_telemetry_delayed`,
`s08_telemetry_duplicated`, `s09_telemetry_reordered`, `s10_evidence_replayed`,
`s14_observer_unavailable`, `s15_conflicting_external_evidence`. Five need a
live telemetry pipeline or two disagreeing mechanism-independent sources; one
(`s10`) belongs to the verifier the harness deliberately does not invoke.

The in-repo semantics are TEST-PROVEN. The cross-tool validation is
incomplete, by a margin the repository states accurately. Marking this PASS
would treat 10/16 as 16/16.
Mutation evidence: `validation/airi/MUTATION_RESULTS.json` — **9 mutations,
9 KILLED, 0 survivors, `patch_applied: true` on all 9.**
**TEST-PROVEN in-repo; TOOLING-EXECUTION-PROVEN partially; 6 scenarios UNKNOWN.**

### Skill 16 — Production boundary and blocker closure · **PARTIAL**

Gate, five criteria:

| Criterion | Status |
|---|---|
| No open P0 findings under the central accountability claim | **NOT ESTABLISHED** — B-3 is recorded OPEN in the skill's own register |
| All P1 production blockers have code-backed closure evidence | **MET** — B-1a, B-4, B-5, B-6, B-7, B-8, B-9, B-10 all CLOSED with commits |
| Service and standalone verification agree on temporal semantics | **MET** (B-1a, `283c473`) |
| ≥1 test crosses reconcile → warrant → containment on engine-produced reconciliation | **MET** — `engine_to_containment.rs`, 5 tests, live process |
| Primary CI command compiles and tests the service tier | **MET** — `airon-aip` is workspace member; CI runs `cargo test --all --all-features`; **87 tests, 0 failed** |

**Why PARTIAL:** B-3's *observation* gap is closed — the crossing exists and
executes — but the finding stays open, and the reason is architecturally
significant rather than cosmetic:

> **Actuation is unreachable from genuine reconciliation.**

Three independent closures, each sufficient alone: `contain()` gate 5 requires
`Proven`, and every workload-violation class the engine draws
(`PhantomClaim`, `UnattributedEffect`, `IdentityDivergence`,
`LineageViolation`) is capped at `Attested` because its content is read from
the observed host and is root-forgeable; gate 6 requires a workload violation
and refuses the one class the engine draws at `Proven`
(`SensorIntegrityFailure`); and a `SensorIntegrityFailure` necessarily carries
`Unavailable` availability, which `evaluate` caps at `Alert` and gate 7
refuses independently.

The cgroup freezer is therefore reachable only from a fixture. This is
**correct fail-closed behaviour**, not a defect — but whether full closure is
the intended end state is an unresolved architectural decision, and a
conformance report should not resolve it by relabelling it PASS.
No `Proven` `PhantomClaim` was manufactured to make the actuator fire, which
is the right call.
**CODE-PROVEN and EXECUTION-PROVEN for the closures; the open question is
DOCUMENTED.**

### Skill 17 — Autonomous system model · **PASS**

Gate, four criteria, all **MET** and each pinned by a named test:
nine system types encode distinctly with no per-vertical field
(`every_environment_is_representable_without_a_schema_fork`); identity/
authority/execution/hardware relationships non-confusable (S17-1/2/3/9);
parent-child creation never implies authority (S17-5, mutation-checked); no
existing artifact modified.

Evidence: `aip-system` 32 tests including `tests/identity_separation.rs`
(25 tests) and `tests/compatibility.rs`. **6 mutations, 6 killed.**
See §9.1 for the required-work naming delta and §11.2 for the live gap.
**TEST-PROVEN.**

### Skill 18 — Autonomy execution profile · **PASS**

Gate: the same execution semantics support an enterprise API call and a drone
navigation command without duplicating the reconciler; a model event cannot
masquerade as an observed effect; cross-agent/execution/platform
transplantation rejected.

Evidence: `aip-execution` 43 tests including `tests/boundary_attacks.rs`
(29 adversarial). The first gate criterion is now demonstrated *empirically*
rather than by design argument: `aip-enterprise` (API call) and `aip-uas`
(navigation command) both reach the reconciler through the same
`ExecutionProfile` with zero reconciler branches. **5 mutations, 5 killed**
(including "a 200 response confirms the effect" → 3 tests fail).
**TEST-PROVEN.**

### Skill 19 — Edge hardware identity and binding · **PASS**

Gate, three criteria, all **MET**: the verifier distinguishes agent identity
from physical compute identity; a process replayed on another host cannot
inherit the original hardware binding; **unsupported hardware attestation
remains `CANNOT_PROVE`/`NotEvaluated` rather than silently trusted.**

Evidence: `aip-platform` 44 tests, 27 adversarial. `ObservedBoot` has a
private field whose only constructors verify an `AttestedBatch` against the
verifier's anchors first — no `from_bytes`, no `new`, no `From<[u8;16]>`.
**5 mutations, 5 killed.**

One mutation originally survived — adding a public `from_bytes` escape hatch
was caught by nothing, an honest limit of a type-system invariant. **Verified
closed at this HEAD:** a structural guard now exists
(`aip-platform/tests/compatibility.rs:198` forbids the literal
`"pub fn from_bytes"`), and no `pub fn from_bytes` exists in `aip-platform` or
`aip-observation`.

ADR-002 (device attestation) is **PROPOSED / NOT IMPLEMENTED** and gap G1 (no
durable hardware identity across reboots) is OPEN. This is deferral by design,
not a shortfall: the gate's third criterion *requires* unsupported attestation
to stay `CANNOT_PROVE`, which is exactly what was done. Implementing it would
introduce a new trust anchor — a STOP condition.
**TEST-PROVEN.**

### Skill 20 — Autonomous observation profile · **PASS**

Gate: every profile states its evidentiary ceiling; a compromised actor cannot
manufacture an observer assertion through the normal SDK path; observation
gaps produce explicit uncertainty rather than false negatives.

Evidence: `aip-observation` 40 tests — 18 adversarial, 9 `anti_collapse`,
9 `guards`, 4 `ceiling`. `EvidenceCeiling` is **declared per
`ObservationClass`, never computed from a record**, and a profile cannot raise
one. **6 mutations, 6 killed**, including "`PhysicalEffect` declares a `Proven`
ceiling" → 7 tests fail, and "`NotObservable` collapses into `NotObserved`" →
2 fail.
**TEST-PROVEN.**

### Skill 21 — Effect boundary and actuation · **PASS**

Gate: the system can state a command was executed **without** claiming its
external effect occurred; a physical-effect claim is traceable to a specific
evidence source and observation boundary.

Evidence: `aip-effect` 27 tests, all 27 adversarial. `EffectAssessment`,
`EffectCorrelation`, `EffectObservation`, `EffectWindow`, `EffectBinding`,
`ObservedStance`, `NotObservedReason`, `EffectFinding`. ADR-004 records the
binding-granularity decision.

Naming delta (§9.1): the spec's required-work list names `RequestedEffect`,
`ExecutedCommand`, `ObservedEffect`, `EffectConfirmation`, `EffectUncertainty`.
`RequestedEffect` exists in `aip-execution`; the other four exist under
different names carrying the same semantics. The gate is behavioural and is
met; the naming divergence is undocumented and is recorded as a gap.
**TEST-PROVEN.**

### Skill 22 — Linux autonomous edge reference · **PASS**

Gate: a single Linux reference workload demonstrates the end-to-end chain from
identity through proof; the reference runs without cloud connectivity; all
unsupported claims surfaced as limitations.

Evidence: four crates, and **the split is the deliverable** — the workload
cannot link the observer's crate and the observer cannot link the workload's,
enforced by `aip-edge/tests/dependency_isolation.rs` (8 tests).
`aip-edge` 69 tests: `adversarial.rs` (12), `no_second_engine.rs` (6),
`end_to_end.rs` (14), `lifecycle.rs`, `nexora.rs`. `Scenario` covers Honest,
SelfReportOnly, ObserverLost, WorkloadExitsFirst, WrongBoot, WrongPlatform,
CrossExecutionInjection, ReplayedObservation. Verification runs offline.
**EXECUTION-PROVEN** — these are real processes on this host, observed by a
separate process.

### Skill 23 — UAS accountability profile · **PASS**

Gate: a simulated UAS mission produces identity-bound, expected-execution-bound
and observation-correlated evidence; **the same reconciler and proof pipeline**
as the Linux reference.

Evidence: `aip-uas` 126 tests — 20 adversarial, 10 `no_second_architecture`,
plus `integration.rs` running live companion-computer processes through
`aip_edge::orchestrate`. Test names carry the epistemics:
`a_live_companion_computer_establishes_its_own_execution_and_nothing_about_an_aircraft`,
`a_verified_autonomy_execution_does_not_make_a_mission_complete`,
`a_geofence_question_cannot_be_answered_by_a_live_companion_run`.
ADR-005 records the telemetry evidence boundary.
**EXECUTION-PROVEN for the compute layer. Nothing is claimed about an aircraft.**

### Skill 24 — Robotics autonomy profile · **PASS**

Gate: a reference robot/UGV simulation uses the same core pipeline as UAS;
framework-specific events remain claims unless independently corroborated.

Evidence: `aip-robotics` 131 tests — 18 adversarial, 10
`no_second_architecture`, 9 `cross_vertical`, plus live `integration.rs`.
`a_safety_stop_command_leaving_the_autonomy_stack_is_not_a_machine_stopping`
and `the_profile_needs_no_change_to_nexora_or_to_the_reconciler` are the two
load-bearing tests. ADR-006 records the embodied evidence boundary.
**EXECUTION-PROVEN for the compute layer. Nothing is claimed about a robot.**

### Skill 25 — Industrial / critical-edge profile · **PASS** (core)  ·  physical extension **BLOCKED**

Gate: industrial/critical-edge deployments modelled **without modifying core
reconciliation semantics**; the verifier distinguishes command execution from
physical process confirmation.

Evidence: `aip-industrial` 172 tests — 23 adversarial, 12
`no_second_architecture`, 12 `cross_vertical`. **12 mutations, 12 killed,
0 survivors.** ADR-008 records the process-evidence boundary. Zero lines of
`aip-reconcile` or `aip-nexora` changed.
**TEST-PROVEN**, with live-process portions **EXECUTION-PROVEN.**

The physical-AI validation extension is reported separately in §12 and is
**BLOCKED**, not failed: `validation/physical_ai/preflight.sh` executed here
returns **STATUS PARTIAL — 3 ready, 3 partial, 22 blocked**, and states
plainly that the physical-observation milestone is unreachable in this
environment because it needs a camera. Confirmed independently: no
`/dev/video*` exists, and OpenCV is not installed in this container. The
external adapter itself builds and passes **66 tests**.

### Skill 26 — Disconnected and space autonomy profile · **PASS**

Gate: a simulated disconnected mission executes, collects evidence locally and
is verified later without cloud dependence; **continuity failures are explicit
and do not silently downgrade into success.**

Evidence: `aip-space` 102 tests — 15 adversarial, 12 `no_second_architecture`,
4 `mission.rs` (the gate itself: real onboard execution through
`aip_edge::orchestrate` reaching `VERIFIED_EXECUTION`, bundling, transfer,
ground-side reconstruction, offline NEXORA verification, plus a negative test
proving the proof does **not** verify against wrong anchors).
`completeness_claimable()` is `late.is_empty() && continuity_status() ==
Verified`; `gap_observed` is sticky; `non_occurrence_admissible()` returns
`false` unconditionally. **16 mutations, 16 killed, 0 survivors.**
**SIMULATION-PROVEN.** The onboard execution is real; the disconnection,
contact windows, light-time delay and ground link are simulated. **No
spacecraft or orbital-hardware validation is claimed or implied.**

### Skill 27 — Enterprise autonomy profile · **PASS**

Gate: enterprise workloads map into the same accountability core used by edge
systems; **no enterprise-specific branch of reconciliation exists.**

Evidence: `aip-enterprise` 99 tests — 14 adversarial, 12
`no_second_architecture`, 11 `cross_vertical` (a five-way guard across
robotics/uas/industrial/space/enterprise), 6 `integration.rs` running real
execution through the unmodified shared engine. `IdentityKind::may_substitute_for`
returns `false` for all pairs; `framework_grants_authority()` is
non-overridable and returns `false`; `establishes_remote_outcome()` returns
`false`. **14 mutations, 14 killed, 0 survivors.** ADR-013.
**EXECUTION-PROVEN** for local execution and local filesystem effect;
**remote outcome is structurally unreachable by design.**
**Production readiness is NOT claimed** — no deployment exists.

### Skills 28–30 — **SPEC-ONLY** (out of scope, reported for completeness)

| # | Skill | State | What is missing |
|---|---|---|---|
| 28 | Autonomous system conformance | SPEC-ONLY | No machine-readable conformance matrix, no audit-artifact generator, no cross-domain substitution suite as a first-class program. Substantial *material* exists (`cross_vertical.rs` ×3, `no_second_architecture.rs` ×5) but it is not the normative matrix the spec requires. **This document is a manual precursor, not that generator.** |
| 29 | Autonomous edge threat model | SPEC-ONLY | `AUTONOMOUS_EXECUTION_THREAT_MODEL.md` and `AIRI_THREAT_MODEL.md` exist and are substantial, but no threat-to-response mapping spanning all verticals, and no scenario suite across UAS/robotics/industrial/disconnected as one program. |
| 30 | Defence reference deployment | SPEC-ONLY | No representative deployment, no measured latency/CPU/memory/event-loss/recovery figures from a mission run, no operator procedures, no customer pilot package. **No TRL claim is supportable from this HEAD.** |

---

## 4. Test counts

### Runner 1 — Rust workspace (`cargo test --workspace`)

`TEST1_EXIT=0` · **2,064 passed · 0 failed · 6 ignored** · 182 result blocks ·
0 `test result: FAILED` blocks. Confirmed by a second independent pass.

| Crate | Passed | Failed | Ignored | Primary skill |
|---|---:|---:|---:|---|
| aip-types | 5 | 0 | 0 | 3, 4 |
| aip-crypto | 9 | 0 | 0 | 3 |
| aip-core | 158 | 0 | 0 | 3 |
| aip-protocol | 79 | 0 | 1 | 4 |
| aip-authorize | 39 | 0 | 0 | 5 |
| aip-observe | 170 | 0 | 0 | 6 |
| aip-airi | 67 | 0 | 1 | 11, 13, 14, 15 |
| aip-system | 32 | 0 | 0 | 17 |
| aip-execution | 43 | 0 | 1 | 18 |
| aip-platform | 44 | 0 | 0 | 19 |
| aip-observation | 40 | 0 | 0 | 20 |
| aip-effect | 27 | 0 | 0 | 21 |
| aip-reconcile | 173 | 0 | 0 | 7 |
| aip-agent | 39 | 0 | 0 | 3 |
| aip-warrant | 23 | 0 | 0 | 8 |
| aip-nexora | 178 | 0 | 0 | 10 |
| aip-containment | 31 | 0 | 0 | 9 |
| aip-edge-contract | 3 | 0 | 0 | 22 |
| aip-edge-workload | 0 | 0 | 0 | 22 (binary) |
| aip-edge-observer | 0 | 0 | 0 | 22 (binary) |
| aip-edge | 69 | 0 | 0 | 22 |
| aip-uas | 126 | 0 | 0 | 23 |
| aip-robotics | 131 | 0 | 0 | 24 |
| aip-industrial | 172 | 0 | 0 | 25 |
| aip-space | 102 | 0 | 0 | 26 |
| aip-enterprise | 99 | 0 | 0 | 27 |
| airon-aip (service) | 87 | 0 | 0 | 16 |
| aip-real-tests | 67 | 0 | 2 | 3–10 |
| aip-test | 16 | 0 | 0 | harness |
| ghost-demo | 35 | 0 | 0 | demo |
| banking-demo, aip-cli, aip-verify | 0 | 0 | 0 | binaries |
| **Total** | **2,064** | **0** | **6** | |

The per-crate attribution sums to exactly 2,064, matching the workspace total —
no test is double-counted or unattributed.

The 6 ignored: 1 `aip-protocol`, 1 `aip-airi`, 1 `aip-execution`, 2
`aip-real-tests` (wall-clock throughput gates meaningful only under
`--release`), 1 `aip-space` (`bundle`). All pre-existing; none is a skipped
security assertion.

### Runner 2 — External validation adapter (separate Cargo workspace)

`validation/physical_ai/adapters/vanian-external-adapter` — **66 passed,
0 failed.** Not a workspace member by design (it must not become a production
dependency), so `cargo test --workspace` does **not** reach it. Running it is
part of a complete pass.

### Runner 3 — Python SDK

`sdk/python` — **62 passed, 0 failed** (clean virtualenv, `cryptography` 50.0.1).
Under the container's broken system `cryptography` 41.0.7: 46 passed,
16 errored, **0 assertion failures** — all 16 the same
`pyo3_runtime.PanicException` at module import.

### Grand total

**2,192 tests executed across three runners. 0 failures. 6 ignored.**

---

## 5. Adversarial results

324 tests live in files explicitly named `adversarial`, plus 174 in dedicated
structural/attack suites. All pass.

| Suite | Tests |
|---|---:|
| aip-reconcile / adversarial | 32 |
| aip-authorize / adversarial | 32 |
| aip-platform / adversarial | 27 |
| aip-effect / adversarial | 27 |
| aip-observe / adversarial | 26 |
| aip-industrial / adversarial | 23 |
| aip-airi / adversarial | 23 |
| aip-nexora / adversarial | 22 |
| aip-uas / adversarial | 20 |
| aip-robotics / adversarial | 18 |
| aip-observation / adversarial | 18 |
| aip-space / adversarial | 15 |
| aip-real-tests / adversarial | 15 |
| aip-enterprise / adversarial | 14 |
| aip-edge / adversarial | 12 |
| **Subtotal, adversarial-named** | **324** |
| aip-execution / boundary_attacks | 29 |
| aip-system / identity_separation | 25 |
| no_second_architecture ×5 (uas 10, robotics 10, industrial 12, space 12, enterprise 12) | 56 |
| cross_vertical ×3 (robotics 9, industrial 12, enterprise 11) | 32 |
| aip-observation / anti_collapse | 9 |
| aip-observation / guards | 9 |
| aip-edge / dependency_isolation | 8 |
| aip-edge / no_second_engine | 6 |
| **Subtotal, structural/attack** | **174** |
| **Total** | **498** |

Coverage classes represented: substitution, transplantation (cross-agent,
cross-execution, cross-tenant, cross-framework, cross-platform, cross-vertical),
replay, fork, rollback, gap, truncation, staleness, omission, malformed input,
oversized input, wrong identity, wrong binding, wrong authority, wrong boot,
wrong platform, observer loss, observer integrity failure, and
absence-vs-non-occurrence.

**No adversarial test asserts a verdict upgrade.** Every one asserts a
refusal, an `Unknown`, a `CannotProve`, or a degradation.

---

## 6. Mutation results

Mutation evidence exists for 9 of the 27 skills. Where it exists, every
mutation carries proof it was actually applied before its result was
interpreted.

| Skill | Mutations | Killed | Survivors | Applied-proof |
|---|---:|---:|---:|---|
| 11–15 (AIRI) | 9 | 9 | 0 | `MUTATION_RESULTS.json`: `patch_applied: true` ×9, `sha256_before`/`sha256_after` per mutation |
| 17 | 6 | 6 | 0 | documented per-mutation with the failing test named |
| 18 | 5 | 5 | 0 | documented |
| 19 | 5 | 5 | 0 (1 closed) | documented; the original survivor is closed at this HEAD by a structural guard — verified |
| 20 | 6 | 6 | 0 | documented |
| 25 | 12 | 12 | 0 | PATCH APPLIED 12/12; sources verified byte-identical after the run |
| 25 (physical-AI adapter) | 11 | 11 | 0 | documented |
| 26 | 16 | 16 | 0 | REQUIRED 16 · APPLIED 16 · PATCH APPLIED 16/16 · KILLED 16 · SURVIVORS 0 |
| 27 | 14 | 14 | 0 | REQUIRED 14 · APPLIED 14 · PATCH APPLIED 14/14 · KILLED 14 · SURVIVORS 0 |
| **Total** | **84** | **84** | **0** | |

Two of Skill 26's mutations survived their first run (S8, S11) and both were
**fixed in the code, not in the tests** — unreachable defensive branches
shadowed by earlier checks were removed, and `completeness_claimable` was
reduced to two independently-killable conjuncts.

**84/84 is not system-wide mutation coverage, and must not be read as such.**
It is a complete result for the nine skills that have mutation evidence.
**Skills 3–10, 16, 21, 22, 23 and 24 have none**; they are covered by
adversarial tests whose non-vacuity has never been established.

Skills 7 (the reconciler) and 10 (the verifier) are the two that matter most:
they are the sole authorities for their questions, they carry 351 tests between
them, and **nothing establishes that those tests would fail if the
reconciliation or verification logic were broken.** Ranked as the
highest-priority remaining gap in §11.1.

---

## 7. Evidence classification

| Class | What holds it |
|---|---|
| **EXECUTION-PROVEN** | Real processes on this Linux host observed by a separate process: `aip-edge` (69), `aip-uas` integration, `aip-robotics` integration, `aip-enterprise` integration, `aip-containment/engine_to_containment.rs` against a live process, `aip-observe` kernel-facility paths where the facility exists |
| **TEST-PROVEN** | The 2,192 executed tests, including all 498 adversarial/structural tests |
| **CODE-PROVEN** | Single-definition invariants verified by inspection at this HEAD: one `EvidenceCeiling`, one `ObservationClass`, one `ReconciliationResult`, one `verify_proof`, one keypair generator, `LeafKind::ALL` frozen at 9, `VerifiedProof` not `Deserialize` |
| **SIMULATION-PROVEN** | Skill 26's disconnected mission — real onboard execution, simulated link/contact/light-time/ground station |
| **TOOLING-EXECUTION-PROVEN** | `preflight.sh` executed here and correctly reporting BLOCKED; the external adapter's 66 tests; the AIRI validation harness's 10 PASS scenarios and 9 killed mutations |
| **DOCUMENTED** | 13 ADRs, 8 skill evidence reports, AIRI specification/threat model/limitations/migration, `SKILL26_27_PLAN_AND_INVARIANTS.md`, `SKILL25_PLAN_AND_INVARIANTS.md` |
| **INFERRED** | That the five-vertical composition pattern will generalise to a sixth. Nothing depends on this |
| **UNKNOWN** | Every physical quantity. Real spacecraft, real aircraft, real robot, real industrial process, real cloud deployment, real tenant isolation under load, device attestation (ADR-002), 6 AIRI validation scenarios, and every behaviour of the 18 external frameworks the preflight reports as absent |

---

## 8. Cross-skill architectural findings

**Zero architecture violations detected.** Verified at this HEAD, by
inspection and by executing structural guard tests:

- **One authoritative reconciler** — `aip-reconcile`. `pub fn reconcile_*` is
  defined in exactly one file in the repository.
- **One authoritative verifier** — NEXORA. `pub fn verify_proof` is defined
  exactly once, and NEXORA has not become a governance authority.
- **One evidence hierarchy** — no duplicated or conflicting evidence semantics.
- **One `ObservationClass` / `EvidenceCeiling` model** — each defined once, in
  `aip-observation/src/class.rs`; a ceiling is declared per class and never
  computed from a record.
- **One crypto/keypair primitive** — `aip-crypto::generate_ed25519_keypair`.
- **No vertical-specific signing authority** — zero signing references in all
  five vertical profile crates.
- **No second source of truth** — adapters and profile crates carry no security
  semantics of their own.
- **No wire/protocol change during this conformance run** — and none by the
  work that preceded it: `AIP_VERSION 0x0004`, `PACKET_VERSION 2`,
  `EXECUTION_BINDING_VERSION 1`, `LeafKind::ALL` = 9, all last modified at
  `12767ea`.

The subsections below are the evidence for each.

### A. ONE CORE — **UPHELD**

One accountability architecture. The five vertical profiles
(`aip-uas`, `aip-robotics`, `aip-industrial`, `aip-space`, `aip-enterprise`)
are one-way consumers of the core: nothing in the core depends on any of them.
Verified by manifest inspection and by `no_second_architecture.rs` ×5 (56 tests).

### B. ONE RECONCILER — **UPHELD**

`pub fn reconcile_*` is defined in exactly one file in the repository:
`aip-standalone/aip-reconcile/src/reconcile.rs`
(`reconcile_expectation`, `reconcile_observation`, `reconcile_lineage`).
`aip-reconcile` appears in all five vertical manifests **only under
`[dev-dependencies]`** — enforced by Cargo, asserted by a manifest-reading
test. A vertical *cannot* call the reconciler in production code.

### C. ONE VERIFIER — **UPHELD**

`pub fn verify_proof` is defined exactly once, in
`aip-nexora/src/commitment.rs`. `aip-nexora` is likewise dev-dependency-only in
all five verticals. NEXORA remains the authoritative verifier and has not
become a governance authority: it decides no `AuthorityStanding` it was not
given.

### D. ONE EVIDENCE HIERARCHY — **UPHELD, with one deliberate distinction**

`enum EvidenceCeiling` is defined once (`aip-observation/src/class.rs`) and
`enum ObservationClass` once, alongside it.

Three verdict-shaped enums exist. They are **different questions**, not a
duplicated hierarchy, and the distinction is load-bearing:

- `ReconciliationResult` (aip-reconcile) — the accountability verdict about a
  workload. **Sole authority.**
- `ProofVerdict` / `ComponentVerdict` / `ContinuityStanding` (aip-nexora) —
  what a *verifier* could establish about a *proof package*. About the
  package, never about the workload.
- `GroundConclusion` (aip-space) — whether a *bundle transfer* is complete.
  `asserts_non_occurrence()` returns `false` for every variant, by construction.

Collapsing any pair would be the defect. Keeping them separate is correct.

### E. ONE OBSERVATION MODEL — **UPHELD**

No vertical defines a private truth model. `ObservationClass` has 9 members and
one `class_of(SourceMechanism)` mapping. No vertical adds a `SourceMechanism`.
Ceiling raises are refused (`CeilingRaised`), asserted per vertical.

### F. NO NEW TRUST ANCHORS — **UPHELD**

Complete inventory of key generation in production code:

| Site | Purpose |
|---|---|
| `aip-crypto/src/lib.rs:10` `generate_ed25519_keypair` | the one keypair primitive |
| `aip-crypto/src/custody.rs:176` `generate` | custody wrapper over the above |
| `aip-core/src/wellknown.rs` `generate_jwks` / `generate_aip_configuration` | publishes an existing public key; generates no key |

**Signing references in the five vertical profile crates: 0, 0, 0, 0, 0.**
No vertical, adapter or profile introduces a signer, observer authority or
verification authority. `framework_commitment()` records a framework's name and
version as *data*; `framework_grants_authority()` is non-overridable and
returns `false`.

### G. NO SECOND SOURCE OF TRUTH — **UPHELD**

Adapters and profile crates carry no security semantics of their own. The
`EnterpriseAdapter` trait's `source()`, `ceiling()` and
`framework_grants_authority()` are non-overridable. The external validation
adapter preserves RAW / NORMALIZED / CLASSIFICATION as separate layers and
never auto-constructs an `ObservationRecord`.

### H. NO FALSE PHYSICAL CLAIMS — **UPHELD**

`ObservationClass::PhysicalEffect` is declared and **unreachable**:
`has_mechanism()` returns `false` for it, its documented mechanism list reads
*"anything: no mechanism implements this class"*, and a mutation that gave it a
`Proven` ceiling fails 7 tests. Its ceiling is `Attested`, never `Proven`,
because a sensor reading is content read from a device and is root-forgeable on
the observed host exactly as procfs is (ADR-003 §2).

A repository-wide scan for overclaiming language
(`proves the physical`, `physically proven`, `REAL_WORLD_VALIDATION_PROVEN`,
`TRL 6/7 achieved`, `flight-proven`) across `docs/` and `validation/` returns
**zero non-negated matches.** The synthetic-scene collector labels its output
`SimulatorGroundTruth` and the adapter refuses every such record as a physical
claim — asserted by
`every_synthetic_record_is_refused_as_a_physical_claim`.

### I. FAILURE SEMANTICS — **UPHELD**

`CANNOT_PROVE` is the reconciler's default and is first-class in every layer.
`gap_observed` is sticky and is never cleared by later good traffic
(`gap_status_is_not_silently_upgraded_by_later_contiguity`). A fork quarantines
permanently and cannot be un-proven by well-formed traffic
(`fork_at_one_sequence_quarantines_permanently`). `non_occurrence_admissible()`
returns `false` unconditionally. `GroundConclusion::asserts_non_occurrence()`
returns `false` for every variant. `establishes_remote_outcome()` returns
`false`. Monotonicity holds.

### J. VERTICAL CONFORMANCE — **NO DRIFT**

| Vertical | Domain tag | Profile id | ProfileKind | Signers | reconcile/nexora |
|---|---|---|---|---:|---|
| Edge (reference) | `SYNTRIASS/AUTONOMY/EDGE_REFERENCE_PARAMETERS/v1` | — | — | 0 | isolated by crate split |
| UAS | `SYNTRIASS/AUTONOMY/UAS_PROFILE/v1` | `vanian.uas.v1` | Environment | 0 | dev-only |
| Robotics | `SYNTRIASS/AUTONOMY/ROBOTICS_PROFILE/v1` | `vanian.robotics.v1` | Environment | 0 | dev-only |
| Industrial | `SYNTRIASS/AUTONOMY/INDUSTRIAL_PROFILE/v1` | `vanian.industrial.v1` | Environment | 0 | dev-only |
| Space | `SYNTRIASS/AUTONOMY/SPACE_PROFILE/v1` | `vanian.space.v1` | Environment | 0 | dev-only |
| Enterprise | `SYNTRIASS/AUTONOMY/ENTERPRISE_PROFILE/v1` | `vanian.enterprise.v1` | Environment | 0 | dev-only |

Identical composition pattern, identical namespace shape, distinct ids, one
`ProfileKind`. **No semantic drift between verticals.**

One asymmetry, deliberate and documented in ADR-011: enterprise's top evidence
tier (`LocalEffectObserved`) **is** reachable, because a local file write is
observable by `Fanotify`, whereas the four embodied verticals' top tiers are
not. "The top tier is unreachable" is embodiment-specific and false for
enterprise. Naming enterprise's tier `PhysicallyObserved` for symmetry was
considered and rejected.

---

## 9. Duplicated semantics

**None found that constitute a second architecture.** Two items are recorded
as naming/consistency debt rather than semantic duplication.

### 9.1 Required-work object names not present as specified

Skills 17, 18, 19 and 21 name specific objects in their required-work lists.
Several do not exist under those names anywhere in the repository:

| Skill | Named in spec | State at HEAD |
|---|---|---|
| 17 | `SystemIdentity`, `PlatformIdentity`, `HardwareIdentity`, `SoftwareIdentity`, `ExecutionIdentity` | Not defined under these names. Semantics carried by `NamespacedId`, `SystemId`, `PlatformId`, `HardwareId`, `ExecutionBinding`, `SystemExecution` |
| 18 | `ExecutionUnit`, `ExecutionTransition`, `ParameterCommitment`, `EffectBoundary` | Not defined. Semantics carried by `RuntimeAction`, `ExecutionStage`, `ExpectedExecution`'s commitments, `EffectDisposition`/`EffectOutcome` |
| 19 | `EdgeNodeIdentity`, `DeviceAttestationReference` | Not defined. Deferred to ADR-002 (PROPOSED / NOT IMPLEMENTED) |
| 21 | `ExecutedCommand`, `ObservedEffect`, `EffectConfirmation`, `EffectUncertainty` | Not defined. Semantics carried by `RuntimeAction`, `EffectObservation`, `EffectAssessment`, `NotObservedReason` |

The acceptance gates are behavioural and are met by executing tests. The
implementations' names are arguably better than the specs'. **But the mapping
is nowhere written down**, so a reviewer reading a spec against the code cannot
confirm the correspondence without doing what this section just did. That is a
documentation defect, not an architectural one, and it should be closed by a
name-mapping table in each evidence report rather than by renaming shipped types.

### 9.2 Three profile rules duplicated five times

ADR-011 already records this: profile-ref construction, ceiling-raise refusal
and dev-dependency direction are now written out independently in all five
vertical crates. The ADR-007/ADR-009 profile-kit extraction trigger has fired.
This is duplication of *code*, not of *semantics* — the five copies agree — but
five copies of a security rule is five places for them to stop agreeing.

---

## 10. Regressions

**None.** Compared against the state recorded at the end of the previous
session:

| Check | Then | Now |
|---|---|---|
| `cargo fmt --all -- --check` | clean | clean (`FMT_EXIT=0`) |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean | clean (`CLIPPY_EXIT=0`) |
| `cargo test --workspace` | 2064 / 0 / 6 | 2064 / 0 / 6 (`TEST1_EXIT=0`) |
| Mutation survivors | 0 | 0 |
| Wire constants | `AIP_VERSION 0x0004`, `PACKET_VERSION 2`, `EXECUTION_BINDING_VERSION 1`, `LeafKind::ALL` = 9 | identical |

The wire-critical files were last modified at `12767ea` (the
observation-integrity mitigation). Skills 25, 26, 27 and the physical-AI
validation work changed **no** wire-bearing file.

One environmental difference from the previous session, recorded because it
changes what this run could execute: `preflight.sh` reported *8 ready / 2
partial / 18 blocked* previously and reports *3 ready / 3 partial / 22
blocked* now. Cause: this container has no OpenCV and no ROS toolchain. The
preflight is correctly environment-sensitive and did not substitute fake
tooling — which is the behaviour its specification demands.

---

## 11. Remaining gaps

Ranked by engineering priority. The first three are the ones that matter; the
rest are real but subordinate.

### 11.1 No mutation evidence for the authoritative reconciler and verifier

**This is the highest-priority remaining assurance gap.**

84 of 84 existing mutations were killed, with 0 survivors — but that figure
describes the skills that *have* mutation evidence, and it must not be read as
coverage of the system as a whole. **14 of the 27 in-scope skills have no
mutation evidence at all**: skills 3, 4, 5, 6, 7, 8, 9, 10, 16, 21, 22, 23, 24,
plus skills 1–2 which cannot have any.

Two of those fourteen are the ones that matter:

- **Skill 7 — `aip-reconcile`**, the single authoritative reconciler, 173 tests.
- **Skill 10 — `aip-nexora`**, the single authoritative verifier, 178 tests.

They are the sole authorities for their questions, they carry 351 tests between
them, and **nothing establishes that those tests would fail if the reconciliation
or verification logic underneath them were broken.** Every other gap in this
section concerns a capability the system honestly states it lacks. This one
concerns whether a capability the system *claims* is genuinely tested, which is
why it ranks first. Mutation coverage of the authoritative reconciliation and
verification logic is the single highest-value next piece of assurance work.

### 11.2 `AutonomousSystem` aggregate descriptor has no production consumer *(current, verified at this HEAD)*

Skill 17's evidence report states as limitation §9.5: *"No integration with the
accountability core yet. By D17-6 nothing consumes `AutonomousSystem`."*

**That statement is now partly stale and partly still true**, and this run
checked rather than inherited it. Ten crates depend on `aip-system` and consume
its identifier types in production code — `SystemId` (59 uses), `MissionId`
(43), `PlatformId` (7), `SystemExecution` (2), `AuthorityContext` (2),
`HardwareId` (1). But the aggregate descriptor `AutonomousSystem` itself is
referenced outside its own crate in exactly **one file, a test**
(`aip-execution/tests/binding.rs`). The universal abstraction the skill was
written to produce is still not read by anything that ships.

### 11.3 No physical validation

**Software and runtime validation are not physical observation, and this run
produced only the former.**

What *was* established: real processes executing on a real Linux host, observed
by a separate process that does not share the workload's crate — genuine
independent observation **of computation**. That is EXECUTION-PROVEN and it is
not nothing.

What was **not** established, and is not approached: any measurement of any
physical quantity by any independent physical mechanism. No camera, no fiducial
detection, no external tracking, no observer machine separate from the subject
holding its own key. Every physical claim the architecture could make remains
mechanically unreachable — `ObservationClass::PhysicalEffect` is declared and
`has_mechanism()` returns `false` for it.

This is **BLOCKED**, not pending and not partial: the hardware does not exist
in this environment, and the repository refuses to substitute anything for it.
See §12 for the executed preflight and the exact missing infrastructure.

### 11.4 Six AIRI validation scenarios not run

`s07`, `s08`, `s09` need a live telemetry pipeline; `s14` was observed by
accident rather than by design; `s15` needs two mechanism-independent sources
that disagree; `s10` belongs to a verifier the harness deliberately does not
invoke. All 16 rows also record the external observers as `BLOCKED (no
kprobes)`.

### 11.5 Device attestation is unimplemented

ADR-002 is PROPOSED. Gap G1 — no durable hardware identity across reboots —
is OPEN. Correct as deferral; still a gap.

### 11.6 B-3 — containment actuation is unreachable from genuine reconciliation *(runner-up: an architectural decision, not a hidden failure)*

**B-3 is OPEN. It is not fixed, and nothing in this run fixed it.** It is
recorded here, and in §3 as the reason Skill 16 is PARTIAL, so that it is
visible rather than buried.

What the evidence establishes: the reconcile → warrant → containment crossing
exists and executes on engine-produced reconciliation against a live process
(`engine_to_containment.rs`, 5 tests). It terminates in a refusal, by three
independent closures each sufficient alone (§3, Skill 16).

What the evidence does **not** establish: that containment is reachable from
genuine reconciliation. On the contrary — the cgroup freezer fires only from a
`fixture_default()` record. This report makes no claim that actuation works
end to end on real evidence, because it does not.

Whether that full closure is the intended end state is an unresolved
architectural decision that has now been deferred through four skills. It is a
decision to make deliberately, not a bug to patch, and not a result to
relabel.

### 11.7 The profile-kit extraction is owed

ADR-011. Scoped to Skill 28 and deliberately not done here.

### 11.8 Skills 21–24 have no evidence report

`docs/audit/` holds reports for 16, 17, 18, 19, 20, 25, 26, 27. Skills 21, 22,
23 and 24 have architecture documents (`ADR-004`, `LINUX_EDGE_REFERENCE.md`,
`UAS_ACCOUNTABILITY_PROFILE.md`, `ROBOTICS_ACCOUNTABILITY_PROFILE.md`,
ADR-005, ADR-006) but no evidence report classifying their claims. Each of
those four skills' `## Required workflow` step 6 requires one.

---

## 12. Physical-validation limitations

**No physical validation exists in this repository, and none is claimed.**

`validation/physical_ai/preflight.sh`, executed at this HEAD:

```
Summary: 3 ready, 3 partial, 22 blocked

What can be executed here
  - nothing in this tree

STATUS PARTIAL — the physical-observation milestone is NOT reachable in this
environment, because it requires a camera that is not present.
```

Independently confirmed during this run: **no `/dev/video*` device exists**,
and OpenCV is not importable. ROS 2, modern Gazebo, `ros2_control`, Nav2,
MoveIt 2, `rosbag2`, `ros2_tracing`, PX4 SITL, MAVSDK, pymavlink, `asyncua`,
4diac FORTE and open62541 are all absent.

What this means, stated as prohibitions the repository already enforces:

- **A simulator does not prove a physical event.** Gazebo ground truth is the
  simulator's own record of what it drew.
- **Telemetry does not prove physical effect.** A MAVLink message is a claim by
  the actor about the actor.
- **A controller acknowledgement does not prove actuation.** A PLC ACK is a
  protocol response.
- **A rendered scene is not an observation of any world.** The collector labels
  such runs `SimulatorGroundTruth` and the adapter refuses them.
- **UAS hardware is disabled by construction.** `ARM = DISABLED`,
  `TAKEOFF = DISABLED`, `MISSION EXECUTION = DISABLED`. No script in this tree
  may arm a vehicle.

The physical-observation milestone — *one physical quantity + external
mechanism + valid observation path + reaches `FROM_ATTESTED`* — is **not met
and not approached.** It needs a camera, an observer machine separate from the
robot, and that observer's own key.

`ObservationClass::PhysicalEffect` remains declared and mechanically
unreachable. That is the correct state until the hardware exists.

---

## 13. Production-readiness assessment

**Not production-ready. The architecture is sound; the deployment evidence
does not exist.**

| Dimension | State |
|---|---|
| Architectural integrity | **Strong.** One core, one reconciler, one verifier, one evidence hierarchy, one observation model, one key primitive, zero new trust anchors across five verticals |
| Correctness under adversarial input | **Strong for what is tested.** 498 adversarial/structural tests, 0 failures, 0 mutation survivors where mutation testing exists |
| Epistemic discipline | **Strong.** `CANNOT_PROVE` fail-closed throughout; no overclaiming language anywhere in `docs/` or `validation/`; unreachable evidence tiers are declared unreachable rather than quietly reachable |
| Test non-vacuity | **Partial.** 14 of 27 skills have no mutation evidence, including the reconciler and the verifier |
| Service tier | **In the build boundary** (B-10 closed), 87 tests passing, CI runs it |
| Key custody | **Documented** (`KEY_CUSTODY_INVENTORY.md`, ADR-KEY-CUSTODY, B-5/B-6/B-7 closed). Operational custody remains a deployment obligation |
| Containment | **Fail-closed to the point of being unreachable** from genuine reconciliation. Unresolved |
| Hardware attestation | **Not implemented.** ADR-002 PROPOSED |
| Physical validation | **None.** Blocked on hardware |
| Deployment evidence | **None.** No measured latency, CPU, memory, event loss or recovery time from any representative mission |
| Customer/defence evaluation | **None.** No pilot package, no operator procedures, no TRL basis |

**No TRL claim is supportable from this HEAD.** Skill 30's gate — a
representative autonomous defence workload demonstrating the integrated chain,
with reproducible operational evidence — is not approached.

---

## 14. Recommended next action

In priority order. The first is the one that changes what the rest of this
report is worth.

1. **Mutation-test the reconciler and the verifier (Skills 7 and 10).**
   351 tests whose non-vacuity is unestablished, guarding the two sole
   authorities in the system. Every other gap here is about capability the
   system honestly says it lacks; this one is about whether the capability it
   claims is actually tested. Do this before Skill 28.
2. **Run Skill 28.** The conformance program it specifies would replace this
   manually-assembled document with a machine-readable, regenerable artifact,
   and would close §11.8 (missing evidence reports for 21–24) and §9.1 (the
   spec-name-to-type mapping) as a by-product.
3. **Extract the profile kit** (ADR-011 / ADR-007 / ADR-009) as part of
   Skill 28 — five copies of three security rules is the highest-probability
   source of future drift.
4. **Resolve B-3 deliberately.** Decide whether containment actuation *should*
   be reachable from genuine reconciliation. It is an architectural decision,
   not a bug fix, and it has been deferred through four skills.
5. **Do not attempt Skill 30.** Its gate needs hardware, a deployment and
   measured operational evidence. Attempting it from this environment would
   produce exactly the overclaiming every other skill in this repository is
   built to prevent.

---

## 15. Compact final matrix

| Skill | Status | Tests | Adversarial | Mutation | Evidence | Notes |
|---|---|---:|---:|---|---|---|
| 1 Orchestrator | N/A | — | — | — | DOCUMENTED | Process skill; no gate over repo state |
| 2 Ghost implementation | N/A | — | — | — | DOCUMENTED | Process skill; no gate over repo state |
| 3 AIP correctness | PASS | 211 | 32 | none | TEST-PROVEN | types+crypto+core+authorize |
| 4 Execution binding | PASS | 122 | 29 | none | TEST/EXECUTION-PROVEN | protocol+execution |
| 5 Decision point | PASS | 39 | 32 | none | TEST-PROVEN | shares aip-authorize with S3 |
| 6 Observer attestation | PASS | 170 | 26 | none | TEST/EXECUTION-PROVEN | ledger held at collector |
| 7 Reconciliation | PASS | 173 | 32 | **none** | TEST-PROVEN | sole reconciler; non-vacuity unproven |
| 8 Warrant | PASS | 23 | — | none | TEST-PROVEN | decision gate, not actuator |
| 9 Containment | PASS | 31 | 5 | none | EXECUTION-PROVEN | live-process crossing |
| 10 NEXORA | PASS | 178 | 22 | **none** | TEST-PROVEN | sole verifier; non-vacuity unproven |
| 11 AI runtime (AIRI) | PASS | 67 | 23 | 9/9 | TEST-PROVEN | shared aip-airi |
| 12 Python boundary | PASS | 62 | — | — | TEST-PROVEN | separate runner; system `cryptography` broken here |
| 13 Model provenance | PASS | (in 67) | (in 23) | (in 9) | TEST-PROVEN | accelerator boundary is a refusal |
| 14 Tool + effect | PASS | 27 | 27 | (in 9) | TEST-PROVEN | aip-effect |
| 15 AI stack e2e | **PARTIAL** | 103 | 103 | 9/9 | TEST-PROVEN in-repo | 6/16 external scenarios NOT_RUN |
| 16 Production boundary | **PARTIAL** | 87 | 5 | none | CODE/EXECUTION-PROVEN | B-3 finding OPEN: actuation unreachable |
| 17 System model | PASS | 32 | 25 | 6/6 | TEST-PROVEN | `AutonomousSystem` has no prod consumer |
| 18 Execution profile | PASS | 43 | 29 | 5/5 | TEST-PROVEN | gate now proven by 2 verticals |
| 19 Hardware identity | PASS | 44 | 27 | 5/5 | TEST-PROVEN | ADR-002 NOT IMPLEMENTED by design |
| 20 Observation profile | PASS | 40 | 40 | 6/6 | TEST-PROVEN | ceiling declared, never computed |
| 21 Effect boundary | PASS | 27 | 27 | none | TEST-PROVEN | no evidence report |
| 22 Linux edge reference | PASS | 72 | 26 | none | EXECUTION-PROVEN | crate split is the deliverable |
| 23 UAS profile | PASS | 126 | 30 | none | EXECUTION-PROVEN | compute only; nothing about an aircraft |
| 24 Robotics profile | PASS | 131 | 37 | none | EXECUTION-PROVEN | compute only; nothing about a robot |
| 25 Industrial profile | PASS | 172 | 47 | 12/12 | TEST/EXECUTION-PROVEN | core profile |
| 25 physical-AI extension | **BLOCKED** | 66 | — | 11/11 | TOOLING-EXECUTION-PROVEN | no camera, no ROS/PX4; preflight says so |
| 26 Space profile | PASS | 102 | 27 | 16/16 | **SIMULATION-PROVEN** | no spacecraft validation claimed |
| 27 Enterprise profile | PASS | 99 | 37 | 14/14 | EXECUTION-PROVEN | production readiness NOT claimed |
| 28 Conformance | SPEC-ONLY | — | — | — | — | out of scope; not implemented |
| 29 Threat model | SPEC-ONLY | — | — | — | — | out of scope; docs exist, program does not |
| 30 Defence deployment | SPEC-ONLY | — | — | — | — | out of scope; no TRL basis |

Test counts in this matrix attribute crates to their primary skill; several
skills share a crate (3/5 share `aip-authorize`; 11/13/14/15 share `aip-airi`),
so the column sums to more than 2,192 by design. The authoritative
non-overlapping totals are in §4.

---

## 16. Run integrity

| | |
|---|---|
| HEAD at start | `8fe9ff4b9b777a3de2baf8b13f8751fdee3f2344` |
| HEAD at end | `8fe9ff4b9b777a3de2baf8b13f8751fdee3f2344` (unchanged) |
| Branch | `claude/skill-25-implementation-xbz0t3` |
| `git status --short` at start | empty |
| Production files changed by this run | **0** |
| Files added by this run | 1 — this document |
| Documentation commit | `0ef70d6` — this report, first version |
| Subsequent commits | reporting corrections to this document only |

No production code, test, manifest or configuration file was modified to obtain
any result in this report, and none has been modified since. The only
environment change was creating a throwaway virtualenv **outside the
repository** to work around the container's broken system `cryptography`
package.

**Measured results are frozen.** Every figure in this document was measured
against `8fe9ff4` and is unchanged by any later edit: 2,192 tests / 0 failures,
84/84 mutations killed, 0 architecture violations, 0 production files changed.
Later revisions correct classification and reporting language only — no test
was re-run to produce a different number, no result was reinterpreted, and no
history was rewritten.

