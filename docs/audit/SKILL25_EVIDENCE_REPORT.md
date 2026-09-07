# Skill 25 — Evidence Report

**Specification** `.claude/skills/25-industrial-critical-edge-accountability-profile/SKILL.md`
**Baseline** `12767ea`
**Branch** `claude/skill-25-implementation-xbz0t3`
**Related** ADR-008, ADR-009,
`docs/architecture/INDUSTRIAL_CRITICAL_EDGE_PROFILE.md`,
`docs/architecture/SKILL25_PLAN_AND_INVARIANTS.md`

This report states what is CODE-PROVEN, TEST-PROVEN, EXECUTION-PROVEN,
DOCUMENTED, INFERRED and UNKNOWN. Nothing is promoted to a stronger class
because a fixture was constructed to demonstrate it.

---

## 1. Specification provenance

One Skill 25 document exists in the repository. It is byte-identical on
`claude/codebase-production-readiness-wm6idp` and
`claude/autonomous-accountability-skills-16-30` (`git diff` between the two
paths is empty). No reconciliation between competing specifications was
required, and none was performed.

## 2. Acceptance criteria

| # | criterion (verbatim from the specification) | status | where |
|---|---|---|---|
| R1 | Define `IndustrialCommand` | met | `command.rs` — 18 commands, `ics.` namespace |
| R2 | Define `ControlLoopExecution` | met | `controlloop.rs` — committed document + freshness |
| R3 | Define `ProtocolInteraction` | met | `protocol.rs` |
| R4 | Define `SafetyBoundary` | met | `safety.rs` — signed document, own key |
| R5 | Define `PhysicalProcessEffect` | met | `process.rs` |
| R6 | Adapters for representative edge protocols without hard-coding a protocol as trusted | met | `ProtocolAdapter` + Modbus/TCP, DNP3, OPC UA; `no_protocol_is_marked_trusted_anywhere_in_the_library` |
| R7 | Observation coverage for compute, network and process-state evidence | met | `coverage.rs` — three domains, `class_domain` total |
| R8 | Operator/manual override semantics and lineage appearance | met | `operator.rs` — 7 kinds, `Completeness` per kind |
| R9 | Replay, stale-command, sensor-gap and observer-outage scenarios | met | `adversarial.rs` a1–a9; `integration.rs` replay + observer loss on live evidence |
| N1 | Safety boundaries and process effects are distinct commitments and observations | met | distinct types, keys, discriminants; `a11` |
| N2 | Industrial protocol messages are not automatically proof of physical process change | met | `establishes_process_change()` false, computed; `a12`, `a20` |
| N3 | Containment actions remain warrant-controlled and fail-safe | met | `containment.rs`; live warrant-path test |
| G1 | Industrial/critical-edge deployments modelled without modifying core reconciliation semantics | met | zero production files changed outside the new crate |
| G2 | The verifier distinguishes command execution from physical process confirmation | met | `execution_versus_confirmation()`; asserted on a live `VERIFIED_EXECUTION` run |

**14 of 14.**

## 3. Evidence classes

### CODE-PROVEN

Facts a reader establishes from the source without running anything.

- The crate defines no identifier, no observation record, no verdict class, no
  evidence strength, no key, no leaf kind, no reconciler and no verifier. Its
  dependency list contains no crate on the verdict path at runtime.
- `establishes_process_change()`, `establishable_from_measurement()`,
  `enforcement_establishable()`, `effect_observable()` and
  `ProcessEvidence::is_reachable()` are all **computed from
  `ObservationClass::PhysicalEffect.is_implemented()` or from the source table**,
  never written as literal `false`. Implementing a physical mechanism flips them
  and fails the tests, which is the intended way to find out.
- `excuses_divergence()` and `restores_process_safe_state()` are literal
  `false` — deliberately, because there is no future table entry that should
  change them.
- `class_domain` is exhaustive over `ObservationClass`; the compiler enforces
  that a class added later cannot silently join a domain.
- No signed core structure gains, loses or reinterprets a byte.

### TEST-PROVEN

162 tests over constructed values: 115 unit, 23 adversarial, 12 structural, 12
cross-vertical.

- The 25 invariants in `SKILL25_PLAN_AND_INVARIANTS.md` §3.
- The adversarial matrix: replay (protocol and commitment), stale command,
  sensor gap, observer outage, observer integrity, tamper, substitution,
  omission, transplant, wrong identity, wrong binding, wrong authority.
- Three-vertical consistency: UAS, robotics and industrial answer the three
  shared questions identically, their evidence ladders match rung for rung,
  their action namespaces are disjoint, and their four commitment parameter keys
  are distinct.

### EXECUTION-PROVEN

10 tests running the Skill 22 three-process reference as a critical-edge node,
on real kernel evidence — real processes, real procfs and socket-table
measurement, a real off-process collector, the real verdict engine. Six
scenarios: honest, cross-execution injection, replayed observation, observer
loss, wrong boot, wrong platform.

What these runs establish, on evidence rather than on fixtures:

- A live, observed edge node reaches `VERIFIED_EXECUTION`, and the profile
  simultaneously reports every process claim unestablished, `SHUTDOWN_COMPLETE`
  as `Unknown`, an emergency shutdown as commanded-but-not-performed, and the
  process-state domain as unobservable. **The acceptance gate's second clause is
  demonstrated on a passing verdict, not on a failing one.**
- A replayed batch is detected by the existing engine and does not inflate the
  record count; the profile's answer about the plant is identical either way.
- Observer loss yields `CANNOT_PROVE` and no non-occurrence assertion.
- An observation of a different process instance does not become evidence about
  this edge node.
- The existing warrant engine evaluates an industrial run unchanged, over the
  reconciliation record it produced, with the warrant's digest matching that
  record byte for byte.
- The existing proof path verifies an industrial run, and `LeafKind::ALL` is
  still 9.

**What is not execution-proven:** everything about a plant. No PLC, no protocol
stack, no instrument and no process equipment was involved. The live runs
exercise a Linux host, which is genuinely half the chain and is not the half
anyone worries about.

### DOCUMENTED

- ADR-008 — the industrial process evidence boundary: six decisions, six
  rejected alternatives, three open questions.
- ADR-009 — why the ADR-007 extraction is deferred again, with the per-rule
  evidence the third vertical produced and a revised trigger.
- `INDUSTRIAL_CRITICAL_EDGE_PROFILE.md` — the profile, its sources, its
  protocols, its semantic boundary, its coverage model, its migration and
  versioning notes and eight known gaps.
- `SKILL25_PLAN_AND_INVARIANTS.md` — the implementation map and the 25-row
  invariant matrix with its mutation column.

### INFERRED

Stated as engineering judgement, not established by anything here:

- That the eight-rung chain is the right decomposition for a control loop. It
  matches how the failures are described in the field and it is not derived
  from a standard.
- That eight of nine protocols cannot distinguish a replay. This follows from
  the protocol facts as declared in `protocol.rs`; those facts were written
  from knowledge of the standards and were **not** checked against the standards
  documents in this session.
- That the classification of the safety instrumented system as *inside the
  control system* is right. The argument is given in `sensing.rs`; a deployment
  with a genuinely air-gapped, separately-attested SIS could reasonably disagree,
  and would still get no evidence out of it here, because the source has no
  mechanism either way.
- That a two-out-of-three transmitter vote adds nothing. The argument is
  common-cause failure plus controller-computed voting; it is not measured.

### UNKNOWN

- Whether any real industrial deployment's instrument set maps cleanly onto the
  seventeen sources. Nothing has been tried against one.
- Whether the protocol facts (`message_authentication`, `replay_defence`,
  `transport`) match every version and profile of each standard. They are
  declared per protocol and are used only to say what cannot be established, so
  an error in them cannot raise a ceiling — but it could understate a
  deployment's replay posture, which is the direction that matters less and is
  still an error.
- Whether the coverage domains are the right three for deployments that are
  neither compute-heavy nor network-heavy — a serial-only site, for instance.
- Whether an anchored external plant sensor is feasible at all. It is named as
  the shortest path to real industrial evidence and nothing has been built.
- The behaviour of any of this on a host where the observer is running under an
  adversary with kernel access. That boundary is `aip-observe`'s and the
  observation-integrity work characterised part of it; this profile inherits
  whatever it establishes and adds nothing.

## 4. Mutation testing

Twelve mutations, each targeting one security-relevant rule. For every one the
harness asserted the source fragment was present, wrote the mutated file,
confirmed the file changed, confirmed the crate still compiled, and only then
ran the suite. A mutation that did not apply would have been reported
`NOT_APPLIED`, never `KILLED`.

| mutation | target | outcome | killed by |
|---|---|---|---|
| M1 | protocol interaction establishes a process change | KILLED | `no_protocol_interaction_establishes_a_process_change` |
| M2 | agreement raises the ceiling at three sources | KILLED | `agreement_never_raises_the_ceiling` |
| M3 | `LoopState::assertable` echoes unconditionally | KILLED | 3 state tests |
| M4 | coverage ignores observer health | KILLED | 2 coverage tests (the observation-integrity guard) |
| M5 | an attributed override excuses a divergence | KILLED | `no_override_ever_excuses_a_divergence` |
| M6 | a stale command is admitted | KILLED | `a_stale_command_is_refused_rather_than_weakened` |
| M7 | a safety boundary establishes enforcement when no bypass is declared | KILLED | 2 safety tests |
| M8 | an unmechanised source reaches `Attested` | KILLED | 2 sensing tests |
| M9 | an adapter claims authentication the protocol does not define | KILLED | `an_adapter_cannot_claim_authentication_a_protocol_does_not_define` |
| M10 | compute containment restores a safe process state | KILLED | `containment_never_establishes_a_safe_process_state` |
| M11 | the process-state domain supports non-occurrence | KILLED | `process_state_is_never_observable_however_the_plant_is_instrumented` |
| M12 | a plant claim is establishable from an unanchored independent source | KILLED | `no_process_claim_is_establishable_from_measurement_in_this_build` |

**MUTATIONS REQUIRED 12 · APPLIED 12 · PATCH APPLIED 12/12 · KILLED 12 ·
SURVIVORS 0.** Sources verified byte-identical after the run.

## 5. Regression check

| metric | before (`12767ea`) | after | note |
|---|---|---|---|
| workspace members | 30 | 31 | one new vertical |
| production files changed outside the new crate | — | 0 | `Cargo.toml` member list and `Cargo.lock` only |
| public API changes to shipped crates | — | none | |
| protocol / wire version changes | — | none | six version constants unchanged |
| signed field changes | — | none | |
| new trust anchors | — | 0 | |
| new signers | — | 0 | |
| new keys | — | 0 | |
| new identifiers | — | 0 | `MissionId`, `SystemId`, `PlatformId` reused |
| new evidence classes | — | 0 | `ObservationClass` untouched |
| reconcilers | 1 | 1 | `aip-reconcile` |
| verifiers | unchanged | unchanged | |
| proof trees | 1 | 1 | `LeafKind::ALL.len() == 9`, asserted in a live test |
| new domain tags | — | 1 | `SYNTRIASS/AUTONOMY/INDUSTRIAL_PROFILE/v1`, with 3 structure discriminants |
| new parameter keys | — | 2 | both versioned in the key |
| observation-integrity behaviour | — | inherited, not re-derived | delegates to `covered_by_kernel_pushed_source` |

Explicitly checked and absent: duplicate architecture, trust-boundary bypass,
evidence escalation, self-attested "independent" evidence, a second
reconciliation path, verifier bypass, silent protocol drift.

## 6. Validation

| check | result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| full workspace suite, run 1 | 1863 passed, 0 failed, 6 ignored |
| full workspace suite, run 2 | 1863 passed, 0 failed, 6 ignored |
| full workspace suite, run 3 | 1863 passed, 0 failed, 6 ignored |
| baseline for comparison (`12767ea`) | 1691 passed, 0 failed, 6 ignored |

The delta of 172 is exactly this crate's suite. No existing test changed
behaviour, and none was modified.

## 7. Production readiness

**Not claimed, and the profile's own status line says so:
`PROFILE — NOT_PRODUCTION_CAPABILITY`.**

What is production-shaped: the code is deterministic, has no randomness, no
unsafe, no new dependency, bounded inputs on every constructor, fail-closed
defaults on every predicate, and a structural guard over its own source.

What is not: no plant, no PLC, no protocol stack and no instrument has been
involved at any point. This is a model of what could be established about an
industrial deployment, validated against a Linux host. Calling it production
readiness for industrial control would be exactly the error the profile exists
to prevent.
