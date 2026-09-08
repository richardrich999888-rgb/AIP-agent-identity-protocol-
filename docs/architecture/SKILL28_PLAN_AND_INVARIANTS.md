# Skill 28 — Implementation Plan and Invariant Matrix

**Written before implementation**, per the skill's required workflow step 2.

**Baseline** `b5c401a` · **Branch** `claude/skill-25-implementation-xbz0t3`
**Specification** `.claude/skills/28-autonomous-system-conformance/SKILL.md`
**Related** ADR-007, ADR-009, ADR-011 (the profile-kit trigger)

---

## 1. What Skill 28 asks for

| # | Required work | Where it lands |
|---|---|---|
| R1 | The universal invariant set — identity, authority, expected execution, execution binding, AIRI claim, observation, attribution, continuity, reconciliation, warrant, containment, proof | `aip-conformance/src/invariant.rs` |
| R2 | A machine-readable domain conformance matrix for Enterprise, UAS, UGV, Robotics, Industrial, Critical Edge, Space | `aip-conformance/src/{domain,matrix}.rs` + emitted artifact |
| R3 | Cross-domain substitution tests — identity, execution, model, framework, parameter, observer evidence | `aip-conformance/tests/substitution.rs` |
| R4 | Version and compatibility tests for adapters and proof packages | `aip-conformance/tests/versioning.rs` |
| R5 | An audit artifact generator labelling claims CODE-PROVEN / TEST-PROVEN / EXECUTION-PROVEN / DOCUMENTED / INFERRED / UNKNOWN | `aip-conformance/src/bin/emit-conformance.rs` |

Acceptance gate: all supported domains pass the same core invariants; a new
domain cannot silently weaken the central semantics; output is independently
reviewable.

## 2. Discovery findings that shape the design

### 2.1 Seven named domains, five crates

The specification names seven domains. The repository has five profile crates
plus the Linux edge reference. The mapping is **not** one-to-one, and the
matrix will say so rather than invent crates:

| Named domain | Realised by | Note |
|---|---|---|
| Enterprise | `aip-enterprise` | Skill 27 |
| UAS | `aip-uas` | Skill 23 |
| UGV | `aip-robotics` | Skill 24 covers UGV **and** robotics in one profile |
| Robotics | `aip-robotics` | same crate as UGV |
| Industrial | `aip-industrial` | Skill 25 |
| Critical Edge | `aip-industrial` | Skill 25 is "Industrial **and Critical-Edge**" |
| Space | `aip-space` | Skill 26 |

Two pairs share a crate. Reporting seven independent domains would overstate
coverage by two; the matrix carries `realised_by` so a reviewer sees it.

`aip-edge` is the Linux **reference implementation** (Skill 22), not a domain.
It is the execution substrate the domains are demonstrated on, and appears in
the matrix as the substrate rather than as an eighth row.

### 2.2 The five profiles already share a shape

Every profile exposes the same four-part surface, under its own names:

| | UAS | Robotics | Industrial | Space | Enterprise |
|---|---|---|---|---|---|
| agreement enum | `Agreement` | `Agreement` | `Agreement` | `Agreement` | `Agreement` |
| agreement struct | `SensorAgreement` | `SensorAgreement` | `InstrumentAgreement` | `SourceAgreement` | `SourceAgreement` |
| evidence ladder | `StateEvidence` | `TaskEvidence` | `ProcessEvidence` | `SpaceEvidence` | `EnterpriseEvidence` |
| state model | `MissionState` | `TaskState` | `LoopState` | `WorkloadState` | `WorkloadState` |

This is what makes a universal matrix possible at all. It is also the
duplication ADR-011 recorded.

### 2.3 What already exists, and must not be duplicated

- Five `no_second_architecture.rs` suites (10–12 tests each) asserting local
  structural invariants over each crate's own source.
- `aip-enterprise/tests/cross_vertical.rs` — an eleven-test five-way guard.
- `aip-industrial/tests/cross_vertical.rs` — the earlier three-way guard.
- `aip-edge/tests/no_second_engine.rs` and `dependency_isolation.rs`.

The conformance program **consolidates the normative statement** of these
rules; it does not replace the local suites. ADR-011 already rejected deleting
them ("redundant is not wrong").

## 3. Architecture

One new crate, `aip-conformance`, last in the dependency order.

```
aip-conformance
  ├── depends on: the core, all five profiles, aip-edge, aip-reconcile, aip-nexora
  └── depended on by: NOTHING
```

**It must not become a second source of truth.** It states no security
semantics of its own: every invariant is a question it *asks of the core*, by
calling the core. It defines no verdict, no ceiling, no observation class, no
identifier, holds no key and signs nothing. A structural guard asserts this,
and a manifest guard asserts nothing in the workspace depends on it.

### 3.1 Why not extract the profile kit here

ADR-011 §Decision 2 assigned the production profile-kit extraction to Skill 28.
**This milestone does not perform it**, and the reasoning is recorded in a new
ADR rather than left implicit:

- Skill 28's required work (§1) does not include it, and its acceptance gate is
  about conformance, not de-duplication.
- The extraction edits five shipped crates and their validated suites; Skill
  28's governing discipline carries the same *"implement the smallest
  compatible change"* rule ADR-011 invoked to defer it.
- The *purpose* of the extraction — one normative statement of the universal
  rules — is served better by the conformance program, which states each
  invariant **once** and applies it to **every** domain from one place.

The production extraction therefore remains owed, and after this milestone has
no assigned skill. That is a decision for the repository's owner, and the ADR
says so plainly instead of quietly discharging the debt.

## 4. The universal invariant set

Twelve invariants, the twelve the specification names. Each carries a stable
code so the emitted matrix is diffable, a statement of what it requires, and
the boundary at which it stops.

| code | invariant | what it requires | stops at |
|---|---|---|---|
| `I01` | Identity | an AIP-ID is derived from a key and provenance and validates; a malformed id cannot panic a consumer | says nothing about who holds the key |
| `I02` | Authority | a delegation chain verifies under the verifier's issuer anchors; a parent-child relation confers nothing by itself | says nothing about whether authority *should* have been granted |
| `I03` | ExpectedExecution | an expectation is decision-point signed, expiry is inside the signature, and the agent may not be its own decision point | is never evidence that anything executed |
| `I04` | ExecutionBinding | execution identity is the process instance plus the executable's content, not a PID | a binding cannot be transplanted to another host or execution |
| `I05` | AiriClaim | a framework event is a claim bound to an agent and an execution; no framework name grants anything | a claim is never independent observation |
| `I06` | Observation | an observation carries its class, and a class's evidence ceiling is declared, never computed from the record | a profile may not raise a ceiling |
| `I07` | Attribution | an effect is attributed only through an attested complete expected side | insufficient evidence is `CANNOT_PROVE`, never an accusation |
| `I08` | Continuity | a gap, fork, rollback or replay in the observer's own record is explicit and sticky | later good traffic never erases a recorded gap |
| `I09` | Reconciliation | one engine draws every verdict; `CANNOT_PROVE` is the default | strength is fixed by result kind, never by severity |
| `I10` | Warrant | a warrant is a decision boundary; containment is never granted to `CANNOT_PROVE` or to `Attested` automatically | a warrant is permission to act on proof, not proof |
| `I11` | Containment | containment consumes an independently produced warrant and manufactures no evidence | fail-closed |
| `I12` | Proof | a proof package is re-derived by the verifier, never trusted; a refused package establishes nothing | NEXORA is provenance and continuity, not authority |

### 4.1 Per-domain conformance vocabulary

For each (domain, invariant) pair the matrix records exactly one of:

- **Satisfied** — the invariant holds for this domain, with an evidence class
  and a named test or code site.
- **NotApplicable** — the invariant is not reachable in this domain, with the
  reason. *Not* a pass: it is recorded and counted separately.
- **Unknown** — the invariant is not established for this domain.

There is deliberately **no `Waived`**. The specification's second
non-negotiable rule is that a green adapter suite cannot waive a failed core
invariant; the way to guarantee that is to give the vocabulary no word for it.

## 5. Test plan

| suite | covers | shape |
|---|---|---|
| `tests/universal.rs` | R1 — the twelve invariants, every domain | executed against the core where execution is available; API-level where it is not |
| `tests/substitution.rs` | R3 — identity, execution, model, framework, parameter, observer evidence, each transplanted across domains | every one must be refused |
| `tests/versioning.rs` | R4 — profile versions, wire constants, `LeafKind::ALL`, proof-package version handling | a version bump must be visible, not silent |
| `tests/no_second_architecture.rs` | the crate's own discipline | no engine, no key, no identifier, and nothing depends on it |
| `tests/matrix.rs` | R2, R5 | the matrix is total, self-consistent, and re-emits byte-identically |

## 6. What this milestone will not claim

- **Not** that seven independent domains were validated. Five crates realise
  seven names; the matrix carries the mapping.
- **Not** that the profile-kit extraction is done (§3.1).
- **Not** any physical validation, deployment, or TRL position.
- **Not** that a `NotApplicable` cell is a pass.
