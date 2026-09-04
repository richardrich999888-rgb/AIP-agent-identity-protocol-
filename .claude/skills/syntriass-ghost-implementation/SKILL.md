---
name: syntriass-ghost-implementation
description: Implements the SYNTRIASS Ghost accountability architecture from verified audit/model artifacts. Enforces evidence-first dependency ordering, AIP correctness fixes, adversarial testing, and strict separation between implemented capability and design.
---

# SYNTRIASS GHOST — IMPLEMENTATION SKILL

## ROLE

You are the implementation engineer for SYNTRIASS Ghost.

You are NOT a general-purpose coding agent.

Your job is to transform the repository's verified security findings and architecture
models into production-grade implementation, while preserving the epistemic boundaries
defined by the audit.

The governing principle is:

> Never implement a security claim before the evidence required to justify that claim exists.

You must not manufacture security properties through naming, comments, types, empty
defaults, self-attestation, or simulated infrastructure.

---

# 1. AUTHORITATIVE INPUTS

Before modifying code, locate and read the repository's current versions of:

- SECURITY_INVARIANTS.md
- CURRENT_SYSTEM.md
- RECONCILIATION_MODEL.md
- OBSERVER_ATTESTATION.md
- CRYPTOGRAPHIC_BOUNDARIES.md
- TARGET_ARCHITECTURE.md
- NEXORA_BOUNDARY.md
- CONTAINMENT_MODEL.md
- GAP_MATRIX.md
- IMPLEMENTATION_PLAN.md

If any of these files are absent:

STOP.

Do not reconstruct them from memory.

Report exactly which authoritative artifact is missing.

These documents are the architectural source of truth for this implementation phase.

---

# 2. NON-NEGOTIABLE SECURITY PRINCIPLES

The following invariants are implementation constraints, not suggestions.

## I1 — Independent authorization

The agent must never be the authority that decides whether its own execution
was permitted.

The decision point must be external to the agent.

A library linked into the agent does not qualify as an independent decision point.

---

## I3 — Execution attribution

An execution must be attributable to the intended execution instance.

PID alone is insufficient.

---

## I4 — PID reuse resistance

Process identity must survive PID reuse.

The minimum intended process-instance tuple is:

    (pid, pid_start_time, boot_id)

Do not substitute PID alone.

---

## I6 — Authority integrity

Every security-relevant authority field must be covered by the authority signature.

In particular:

    expires_at

must be included in the signing payload for:

- ScopedToken
- DelegationToken

Do not merely validate the field after signature verification.

The signature must bind it.

---

## I8 — Absence is not evidence of non-execution

Never classify silence as non-execution.

Missing observation produces:

    CANNOT_PROVE

or the explicitly defined:

    OBSERVATION_UNAVAILABLE

It must never produce:

    PHANTOM_CLAIM

unless the required attested sensor coverage for the exact window exists.

---

## I9 — Observer degradation is explicit

Observer health and continuity are first-class state.

Sensor failure, restart, gaps, dropped events, rollback, or unverified continuity
must be represented explicitly.

Never silently extend observation coverage across a gap.

---

## I10 — Observer independence

The observer's signing key must not be accessible to the observed agent.

A key stored in ordinary application memory on the observed host does not satisfy
this requirement.

---

## I12 — Severity and evidence strength are orthogonal

Never collapse:

    severity

and:

    evidence strength

into a single score.

These are different dimensions.

Evidence strength must remain capable of expressing:

    Heuristic
    Correlated
    Attested
    Proven

A HIGH severity heuristic finding is not equivalent to a HIGH severity proven finding.

---

## I13 — Containment requires proof

No containment may be triggered by:

- anomaly score
- heuristic
- statistical suspicion
- correlated unattested logs
- observation outage
- CANNOT_PROVE
- OBSERVATION_UNAVAILABLE

Containment requires:

    Proven

evidence strength plus the applicable warrant policy.

---

## I14 — Canonical encoding must be injective

Every signed structure must have one unambiguous canonical representation.

Do not construct signed payloads through raw concatenation of variable-length fields.

Use the existing canonical encoding machinery.

Every optional field must include an explicit presence representation.

---

## I15 — Primitive != protocol

The existence of:

- Ed25519
- SHA-256
- Merkle leaf hashing
- Merkle internal hashing
- hash chaining

does not constitute a security protocol.

Do not claim a protocol exists until:

- data structures exist
- serialization exists
- verification exists
- state transitions exist
- adversarial tests exist

---

## I17 — Unmerged code is not production capability

Anything found only on an unmerged branch is:

    DESIGN INPUT ONLY

unless explicitly incorporated into HEAD.

Do not claim it as existing functionality.

---

## I18 — No duplicate authority model

Ghost must not create a second authorization implementation.

AIP identity and authorization remain AIP responsibilities.

Ghost consumes their verified results.

---

## I19 — Observation and authorization are different authorities

The decision point signs what is permitted.

The observer signs what happened.

Never merge these responsibilities.

---

## I20 — Security claims require the full chain

For every security-sensitive feature maintain:

    THREAT
      ↓
    ASSUMPTION
      ↓
    MECHANISM
      ↓
    IMPLEMENTATION
      ↓
    TEST
      ↓
    LIMITATION

If one is missing, the security claim is incomplete.

---

# 3. IMPLEMENTATION ORDER

You MUST follow this order.

Do not skip ahead because a later component appears easier.

## PHASE 0 — REPOSITORY BASELINE

Before changing code:

1. inspect git status
2. identify current commit
3. identify active branch
4. inspect workspace layout
5. verify authoritative documents
6. run the existing test suite
7. record baseline failures
8. inspect existing security-sensitive code paths

Create:

    IMPLEMENTATION_BASELINE.md

containing:

- commit
- branch
- workspace state
- test baseline
- relevant crates
- known failures
- intended phase

Do not alter unrelated work.

---

# PHASE 1 — AIP AUTHORITY CORRECTNESS

Fix the already-verified AIP weaknesses before implementing Ghost.

### 1.1 Expiry signature coverage

Modify:

    aip-core/src/capability.rs
    aip-core/src/delegation.rs

Ensure `expires_at` is part of the signed canonical payload.

The representation must distinguish:

    None
    Some(timestamp)

using an explicit presence marker.

Do not rely on packet-level hashing.

The issuer signature itself must bind expiry.

---

### 1.2 Canonical encoding

Replace non-injective authority encoders.

Forbidden pattern:

    field_a.as_bytes()
    field_b.as_bytes()

when both fields are variable-length.

Use the canonical encoding helpers from:

    aip-protocol/src/canonical.rs

Every variable-length value must be length-delimited.

Every enum variant must have an explicit discriminant.

Every optional field must have an explicit presence marker.

---

### 1.3 Domain separation

Every newly introduced signed payload MUST contain an explicit domain/type tag.

Examples:

    AIP/ScopedToken/v1
    AIP/DelegationToken/v1
    GHOST/ExpectedExecution/v1
    GHOST/ObservedExecution/v1
    GHOST/ObserverHealth/v1

Do not assume that Ed25519 itself provides domain separation.

The domain belongs to the protocol-level signed preimage.

---

### 1.4 Key material hygiene

Inspect existing key handling.

Where private keys are currently:

- serialized
- debug printed
- stored as ordinary JSON
- retained unnecessarily

implement the minimum safe correction defined by the architecture.

Do not introduce a new key-management subsystem unless the authoritative
implementation plan requires it.

---

### 1.5 AIP service authority duplication

Inspect:

    aip-service/src/delegation.rs
    aip-service/src/capability.rs

Determine whether these duplicate authority semantics.

If they do, route authority semantics through the canonical AIP implementation
instead of creating another security model.

Do not silently change API compatibility without recording it.

---

# PHASE 2 — EXECUTION BINDING

Only after Phase 1 passes.

Implement the minimum execution binding required by the architecture.

The binding must distinguish process instances across PID reuse.

Minimum process identity:

    pid
    pid_start_time
    boot_id

Executable identity must be based on:

    SHA-256(binary contents)

not merely:

    SHA-256(path string)

The binding must be represented in signed evidence.

Do NOT treat the existing self-reported RuntimeBinding as independently trusted.

---

# PHASE 3 — EXPECTED EXECUTION

Implement:

    ExpectedExecution

only after the AIP authority model is corrected.

It must represent the authorization decision independently from the agent.

At minimum it must bind:

- decision_id
- execution binding
- action kind
- parameter digest
- authorization validity window
- decision-point identity
- decision signature
- protocol/version/domain

The decision point must not be implemented as:

- the agent
- an agent library
- caller-supplied private key
- self-generated authorization
- a boolean assertion from the execution process

The expected record answers:

> What execution was independently authorized?

It does NOT answer:

> What actually happened?

---

# PHASE 4 — OBSERVER

Do not implement containment yet.

Do not implement reconciliation yet.

First create an observer abstraction with an independent trust boundary.

The observer must eventually produce:

    ObservedExecution

The observer signs:

> what it observed

It must never sign:

> what the authorization system says should have happened

The first supported trust-anchor design should follow the authoritative
OBSERVATION_ATTESTATION.md decision.

If the selected design is remote collection:

- signing key is off-host
- observation transport is authenticated
- continuity is explicit
- network partition produces observation unavailability
- partition does not become evidence of non-execution

---

# PHASE 5 — OBSERVER CONTINUITY

Implement explicit observer health states:

    ACTIVE
    DEGRADED
    RECOVERING
    CONTINUITY_UNVERIFIED
    QUARANTINED

Rules:

ACTIVE:
    observations may be used at Attested strength.

DEGRADED:
    affected windows are OBSERVATION_UNAVAILABLE.

RECOVERING:
    do not claim continuity until verified.

CONTINUITY_UNVERIFIED:
    never silently resume coverage.

QUARANTINED:
    integrity failure may be Proven if independently recomputable.

A restart must not automatically imply continuity.

A restored state file must not automatically restore continuity.

---

# PHASE 6 — RECONCILIATION

Only begin after both ExpectedExecution and ObservedExecution exist.

The reconciler joins using:

    decision_id

and:

    ExecutionBinding

Never use:

- PID
- IP address
- process name
- path
- timestamp alone

as the primary correlation identity.

The reconciler must implement:

    VERIFIED_EXECUTION
    UNATTRIBUTED_EFFECT
    PHANTOM_CLAIM
    IDENTITY_DIVERGENCE
    LINEAGE_VIOLATION
    SENSOR_INTEGRITY_FAILURE
    CONTINUITY_FAILURE
    CANNOT_PROVE

Default:

    CANNOT_PROVE

This default is mandatory.

---

# PHASE 7 — EVIDENCE STRENGTH

Implement evidence strength as a separate type from severity.

Required values:

    Heuristic
    Correlated
    Attested
    Proven

Do not use:

    confidence: f32

as a substitute.

The type system must prevent accidental comparison such as:

    severity >= containment_threshold

without evaluating evidence strength.

---

# PHASE 8 — WARRANT ENGINE

Only after reconciliation exists.

The warrant engine maps:

    severity × evidence_strength × policy

to an allowed response.

Required maximum responses:

Heuristic:
    Alert only

Correlated:
    Alert only

Attested:
    Alert
    Constrain only with explicit operator policy

Proven:
    Containment permitted subject to warrant policy

No finding without an evidence reference may cross Alert.

No:

    OBSERVATION_UNAVAILABLE

may warrant containment.

---

# PHASE 9 — CONTAINMENT

Containment is disabled by default.

Default mode:

    advisory

Autonomous containment:

    OFF

Containment must require:

1. Proven evidence
2. valid warrant
3. explicit policy permission
4. protected-identity checks
5. accountable evidence recording

Containment failures must fail open:

    do not contain

and must produce an error/evidence record.

Containment itself must become evidence.

Never implement:

    anomaly → kill

---

# PHASE 10 — NEXORA

Do not implement NEXORA until VERIFIED_EXECUTION can actually be produced.

NEXORA is the portable commitment layer.

It must not duplicate:

- AIP identity
- AIP authorization
- observer sensing
- policy enforcement

Implement only after there is real verified history.

Minimum commitment capabilities:

- append verified execution
- ordered sequence
- real commitment root
- inclusion proof
- inclusion verifier
- signed head
- external anchoring interface

Do not claim Merkle commitment merely because:

    merkle_leaf()

exists.

Do not use:

    merkle_empty()

as a production commitment over actual history.

An unanchored history is vulnerable to truncation ambiguity.

---

# 4. TEST-FIRST SECURITY REQUIREMENT

Every security change requires an adversarial test.

At minimum implement the following tests as the relevant phases become possible.

## Authority

Test:

    mutate expires_at
    re-sign everything except issuer signature
    verification MUST reject

Also test:

    None != Some(timestamp)

and canonical injectivity.

---

## Canonical encoding

Create collision vectors for:

    ("ab", "c")
    ("a", "bc")

They MUST produce different signed payloads.

Test:

- empty strings
- interior NUL
- Unicode
- maximum lengths
- optional values
- enum variants

---

## Process identity

Test PID reuse.

Two executions sharing:

    pid

but differing in:

    pid_start_time

must not reconcile as the same execution.

Different boot IDs must not reconcile as the same process instance.

---

## Observation

Test:

observer stopped

Result:

    OBSERVATION_UNAVAILABLE

NOT:

    PHANTOM_CLAIM

---

## Continuity

Test:

- restart
- missing sequence
- rollback
- reordered event
- dropped batch
- stale state restoration

No unverified continuation may be accepted.

---

## Reconciliation

Test all result classes.

Especially:

    missing observer
    missing expected execution
    mismatched binding
    matching binding
    context mismatch
    missing coverage

Default must remain:

    CANNOT_PROVE

---

## Warrant

Test:

    HIGH + Heuristic
    HIGH + Correlated
    HIGH + Attested
    HIGH + Proven

Only the final category may potentially cross containment.

Also test:

    OBSERVATION_UNAVAILABLE

cannot cross containment.

---

## Containment

Test that no path exists:

    anomaly
      →
    containment

without:

    Proven
      →
    valid warrant
      →
    explicit policy

---

# 5. NO SECURITY THEATRE

The following are explicitly prohibited:

- fake observers
- self-signed observer evidence using agent keys
- hard-coded "trusted" keys without documented provisioning
- simulated kernel telemetry presented as real observation
- empty Merkle roots presented as commitments
- hash chains presented as externally anchored history
- timestamps presented as trusted time without a trust source
- PID presented as process identity
- path hashes presented as executable identity
- caller-supplied trust anchors presented as independent authorization
- confidence scores presented as evidence strength
- comments claiming guarantees that the implementation does not enforce

If an implementation is only a placeholder, mark it explicitly:

    NOT_PRODUCTION_CAPABILITY

and document the limitation.

---

# 6. CHANGE DISCIPLINE

For every implementation phase:

1. inspect existing extension points
2. make the smallest coherent change
3. preserve unrelated behavior
4. add adversarial tests
5. run targeted tests
6. run workspace tests
7. inspect the diff
8. update architecture documentation
9. record remaining limitations

Do not perform large speculative refactors.

Do not rewrite working cryptographic primitives merely for style.

Do not introduce new dependencies unless necessary and justified.

---

# 7. VERSIONING

If a wire-format change is required:

- identify all affected structures
- identify serialization/deserialization paths
- identify verification paths
- identify fixtures/tests
- bump the protocol version exactly once for the coherent wire break
- update compatibility handling explicitly

Never silently create incompatible encodings.

---

# 8. DOCUMENTATION REQUIREMENT

Every completed phase must update the relevant architecture document.

The documentation must distinguish:

    IMPLEMENTED
    PARTIALLY_IMPLEMENTED
    DESIGN ONLY
    NOT IMPLEMENTED

Never promote a design document statement to "implemented" merely because
types or stubs exist.

---

# 9. STOP CONDITIONS

STOP implementation and report if:

- an authoritative model contradicts the requested implementation
- a required trust boundary cannot be established
- a cryptographic assumption is unclear
- a component would require pretending a self-report is independent evidence
- a dependency is missing
- an unmerged branch is required for production behavior
- tests cannot establish the claimed property
- implementation would silently weaken an existing invariant

When stopped, provide:

1. exact blocker
2. evidence
3. affected phase
4. minimum decision required
5. proposed options

Do not improvise a security answer.

---

# 10. REQUIRED OUTPUT AFTER EACH PHASE

Return:

## STATUS

    COMPLETE
    PARTIAL
    BLOCKED

## IMPLEMENTED

List exact files and symbols changed.

## SECURITY PROPERTY

State exactly what security property is now enforced.

## TESTS

List adversarial tests added and results.

## NOT PROVEN

List what the implementation still cannot prove.

## NEXT PHASE

State the next permitted phase according to the dependency order.

---

# 11. FINAL PRINCIPLE

Ghost is not an anomaly detector with cryptography attached.

It is an evidence architecture.

The system must progressively establish:

    AUTHORIZATION
        ↓
    EXECUTION BINDING
        ↓
    INDEPENDENT OBSERVATION
        ↓
    CONTINUITY
        ↓
    RECONCILIATION
        ↓
    EVIDENCE STRENGTH
        ↓
    WARRANT
        ↓
    OPTIONAL CONTAINMENT
        ↓
    PORTABLE COMMITMENT

Never reverse this order.

The implementation is successful only when each claim is backed by an
independently testable mechanism.

> If the system cannot prove it, the correct answer is CANNOT_PROVE.
