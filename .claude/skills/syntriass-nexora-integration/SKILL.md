---
name: syntriass-nexora-integration
description: Final Ghost Architecture 2.0 integration gate for NEXORA identity, cryptographic anchors, continuity, provenance, and cross-layer integrity. Prevents NEXORA from becoming an authority bypass, identity shortcut, or substitute for independent execution evidence. Requires all preceding Ghost gates to pass before implementation and verifies that NEXORA strengthens provenance and continuity without collapsing authorization, observation, reconciliation, warrant, or containment boundaries.
---

# SYNTRIASS NEXORA INTEGRATION

## Skill 10 — Cryptographic Identity, Provenance & Continuity Gate

You are the final architectural and implementation gate for Ghost Architecture 2.0.

You are NOT a generic cryptography engineer.

You are responsible for integrating NEXORA into Ghost Architecture 2.0 without weakening any previously established security boundary.

NEXORA must strengthen:

- identity continuity
- provenance
- cryptographic linkage
- replay resistance
- state continuity
- key/protocol version tracking
- evidence-chain integrity
- cross-component traceability

NEXORA MUST NOT become:

- an authorization engine
- an observation engine
- a substitute for Sentinel
- a substitute for reconciliation
- a warrant issuer
- a containment authority
- a source of inferred execution
- a mechanism for manufacturing missing evidence
- an identity shortcut based on PID, IP, port, process name, path, or similar mutable runtime attributes

The final system must remain capable of saying:

> "This identity is cryptographically linked."

without incorrectly saying:

> "Therefore this execution was authorized."

And it must remain capable of saying:

> "This event is cryptographically anchored."

without incorrectly saying:

> "Therefore this event actually occurred."

---

# 1. ABSOLUTE PRECONDITION

DO NOT begin implementation until the required predecessor gates have passed.

Required predecessor reports:

1. AIP correctness
2. Execution Binding
3. Decision Point
4. Observer
5. Reconciliation
6. Warrant
7. Containment

Expected report locations:

`docs/architecture/AIP_CORRECTNESS_REPORT.md`
`docs/architecture/EXECUTION_BINDING_IMPLEMENTATION_REPORT.md`
`docs/architecture/DECISION_POINT_IMPLEMENTATION_REPORT.md`
`docs/architecture/OBSERVER_IMPLEMENTATION_REPORT.md`
`docs/architecture/RECONCILIATION_IMPLEMENTATION_REPORT.md`
`docs/architecture/WARRANT_IMPLEMENTATION_REPORT.md`
`docs/architecture/CONTAINMENT_IMPLEMENTATION_REPORT.md`

If any required predecessor is missing, stale, ambiguous, or failed:

**HARD STOP.**

Do not compensate for a failed predecessor by modifying NEXORA.

NEXORA is the final integration layer, not an escape hatch.

---

# 2. AUTHORITATIVE INPUTS

Before making any implementation change, inspect:

- `docs/architecture/SECURITY_INVARIANTS.md`
- `docs/architecture/TRUST_BOUNDARIES.md`
- `docs/architecture/EXECUTION_BINDING.md`
- `docs/architecture/OBSERVATION_MODEL.md`
- `docs/architecture/RECONCILIATION_MODEL.md`
- `docs/architecture/DECISION_POINT.md`
- `docs/architecture/GAP_MATRIX.md`
- `docs/architecture/IMPLEMENTATION_PLAN.md`
- all predecessor implementation reports
- existing AIP cryptographic code
- existing identity structures
- existing evidence structures
- existing hash-chain structures
- existing key/version structures

Search the repository before inventing new primitives or duplicate identity systems.

If an existing NEXORA implementation already exists, understand it before modifying it.

---

# 3. CORE NEXORA MODEL

A NEXORA Anchor is a compact cryptographic proof object binding a semantic payload to cryptographic and protocol context.

At minimum, determine how the implementation represents:

- issuer identity
- context
- semantic payload digest
- issuance sequence
- previous anchor
- protocol version
- key version

Optional fields must remain explicitly optional.

Do not silently add fields that alter the security meaning of an Anchor.

The Anchor must be deterministic over its canonical representation.

Canonical serialization is part of the security boundary.

---

# 4. NEXORA IS NOT AUTHORITY

NEXORA identity MUST NOT itself grant permission.

Never implement:

```text
valid NEXORA identity
    =
authorized execution
```

Never implement:

```text
valid anchor
    =
valid warrant
```

Never implement:

```text
valid anchor
    =
independent observation
```

Never implement:

```text
valid anchor
    =
proof that an action physically occurred
```

Identity, authority, observation, reconciliation, warrant, and containment remain separate security domains.

---

# 5. IDENTITY BOUNDARY

NEXORA may establish cryptographic continuity of an identity.

It MUST NOT establish identity using:

- PID alone
- IP address
- network port
- process name
- executable path
- container ID alone
- hostname alone
- mutable metadata
- self-declared identity

Runtime identifiers may be included as contextual metadata where appropriate, but they MUST NOT become the root of cryptographic identity.

PID reuse MUST NOT transfer identity continuity.

Process restart MUST NOT silently create continuity with a previous execution instance.

Identity continuity and execution-instance identity are different concepts.

---

# 6. ANCHOR SEMANTICS

Every Anchor MUST have an unambiguous semantic meaning.

Define precisely:

```text
Anchor =
    canonical payload
    +
    issuer
    +
    context
    +
    sequence
    +
    previous-anchor relation
    +
    protocol version
    +
    key version
    +
    cryptographic binding
```

Do not allow two semantically different objects to produce indistinguishable Anchors.

Do not allow two canonical encodings of the same semantic object unless the protocol explicitly defines them as equivalent.

---

# 7. CANONICALIZATION

Canonicalization MUST be specified before cryptographic hashing/signing.

Verify:

- field ordering
- field types
- integer representation
- byte/string encoding
- null handling
- optional-field representation
- length encoding
- nested-object representation
- version representation

The following MUST NOT produce different digests merely because of serialization ambiguity:

```text
same semantic object
        ↓
different serializer
        ↓
different hash
```

Likewise, attacker-controlled alternative serialization MUST NOT produce the same security-sensitive semantic object unexpectedly.

---

# 8. HASH BOUNDARY

Determine exactly what is hashed.

Do not use vague statements such as:

"hash the object."

Specify:

```text
digest = H(canonical_encoding(payload))
```

or the exact protocol-defined equivalent.

If an Anchor contains a digest of another object, identify:

- the object
- canonical encoding
- hash function
- domain separator
- version
- digest size

Do not introduce ad-hoc hashing.

Do not truncate security-critical digests without explicit protocol justification.

---

# 9. DOMAIN SEPARATION

Different semantic objects MUST NOT accidentally share the same cryptographic namespace.

Where appropriate, use explicit domain separation.

For example:

```text
NEXORA_ANCHOR
NEXORA_EXECUTION
NEXORA_EVIDENCE
NEXORA_OBSERVATION
NEXORA_WARRANT
```

Do not assume that identical hash primitives imply identical security domains.

The same primitive may be safely reused only when the protocol domain is explicitly separated.

---

# 10. SEQUENCE AND REPLAY RESISTANCE

NEXORA sequence semantics MUST be explicit.

Determine:

- who allocates sequence numbers
- whether sequence numbers are monotonic
- whether gaps are legal
- whether reuse is legal
- how rollback is detected
- how restart is handled
- how concurrent issuance is handled
- how forks are represented
- how conflicting successors are detected

A replayed Anchor MUST NOT silently become a fresh security event.

Test:

```text
Anchor A
  ↓
replay Anchor A
  ↓
system must detect or reject replay
```

---

# 11. PREVIOUS-ANCHOR LINKAGE

If an Anchor references a previous Anchor, the relationship MUST be cryptographically meaningful.

Verify:

```text
A(n)
  ↓
previous = digest(A(n-1))
```

or the exact protocol-defined equivalent.

Test:

- previous-anchor mutation
- sequence mutation
- payload mutation
- issuer mutation
- context mutation
- protocol-version mutation
- key-version mutation

Every security-sensitive mutation MUST invalidate the appropriate cryptographic verification.

---

# 12. FORK DETECTION

Determine what happens when:

```text
Anchor A
   ├── Anchor B
   └── Anchor C
```

is created where B and C both claim to be the valid successor.

NEXORA MUST NOT silently choose one based on:

- arrival order
- wall-clock time
- process preference
- network ordering
- local state

Fork semantics MUST be explicit.

If the protocol cannot resolve a conflict, the result must remain bounded:

```text
CONFLICT
```

or an equivalent protocol-defined state.

Do not convert uncertainty into validity.

---

# 13. KEY VERSIONING

Key version MUST be cryptographically and semantically unambiguous.

Determine:

- key identifier
- key version
- algorithm
- algorithm parameters
- trust root
- rotation semantics
- revocation semantics
- historical verification semantics

A key rotation MUST NOT retroactively alter the meaning of an existing Anchor.

Old Anchors must remain verifiable according to the protocol's historical verification rules.

---

# 14. PROTOCOL VERSIONING

Protocol version MUST NOT be decorative metadata.

It must determine which canonicalization and verification rules apply.

A future protocol version MUST NOT silently reinterpret an old Anchor.

Test:

```text
Anchor(version = V1)
        ↓
verify using V2
```

The system must follow explicitly defined compatibility rules.

Never silently downgrade verification semantics.

---

# 15. POST-QUANTUM BOUNDARY

Where NEXORA uses post-quantum signatures, verify the exact algorithm and parameter set already approved by the architecture.

Do not casually replace a protocol-approved primitive.

Do not claim:

"post-quantum"

without identifying the actual cryptographic mechanism and parameterization.

Do not mix:

- hash security
- signature security
- protocol security
- identity security

into one generic "PQC secure" claim.

PQC protects a cryptographic boundary.

It does not automatically prove execution.

---

# 16. NEXORA AND AIP

AIP remains responsible for its defined authority semantics.

NEXORA may anchor AIP objects.

It MUST NOT redefine them.

For example:

```text
AIP authorization
        ↓
NEXORA Anchor
```

is valid architectural composition.

But:

```text
NEXORA Anchor
        ↓
therefore authorization exists
```

is prohibited unless an independently defined authorization protocol explicitly establishes that relationship.

---

# 17. NEXORA AND EXECUTION BINDING

Execution Binding answers:

```text
Which execution instance does this authority/evidence refer to?
```

NEXORA answers:

```text
How is the relevant identity/state/provenance cryptographically linked?
```

Do not collapse them.

An Anchor containing:

```text
PID = 1234
```

does not prove that PID 1234 is the same process across restart.

An Anchor containing:

```text
execution_id = X
```

may cryptographically bind to X, but the existence of X must still be established by the appropriate execution-binding mechanism.

---

# 18. NEXORA AND SENTINEL

Sentinel is an independent observer.

NEXORA MUST NOT replace Sentinel.

A NEXORA Anchor may bind or reference an ObserverAttestation, but it must not manufacture one.

Never implement:

```text
no ObserverAttestation
        ↓
create NEXORA Anchor
        ↓
therefore observed
```

That is prohibited.

The system must preserve:

```text
agent evidence
        ≠
independent observation
```

---

# 19. NEXORA AND RECONCILIATION

Reconciliation compares independently established facts.

NEXORA may provide cryptographic linkage between records.

It must not determine the reconciliation result merely because one record has a valid Anchor.

For example:

```text
valid anchor
+
agent claim
≠
verified execution
```

Verification still requires the required evidence sources.

Do not allow cryptographic presence to substitute for semantic evidence.

---

# 20. NEXORA AND WARRANTS

NEXORA MUST NOT issue warrants.

A valid Anchor is not a warrant.

A valid NEXORA identity is not a warrant.

A valid cryptographic chain is not automatically a warrant.

Warrant issuance remains governed by Skill 8.

---

# 21. NEXORA AND CONTAINMENT

NEXORA MUST NOT directly actuate containment.

It must never directly call or trigger:

- kill
- SIGKILL
- cgroup freeze
- firewall mutation
- iptables
- nftables
- XDP_DROP
- process isolation

unless such actuation is explicitly part of the already-approved containment architecture and invoked through its authorized warrant-controlled boundary.

NEXORA itself MUST NOT become the authority for containment.

---

# 22. CRYPTOGRAPHIC CONTINUITY

If NEXORA provides continuity across events, define exactly what continuity means.

Distinguish:

```text
identity continuity
state continuity
execution continuity
evidence continuity
observer continuity
protocol continuity
```

These are not interchangeable.

A restart MUST NOT automatically imply:

```text
same execution
```

A valid previous Anchor MUST NOT automatically imply:

```text
same live process
```

A valid chain MUST NOT automatically imply:

```text
continuous observation
```

---

# 23. CRASH / RESTART SEMANTICS

Test:

1. normal restart
2. abnormal termination
3. process crash
4. machine reboot
5. power loss
6. partial persistence
7. corrupted local state
8. rollback to older state
9. duplicated state
10. forked state

Determine whether the system:

- resumes
- starts a new identity epoch
- detects discontinuity
- rejects continuation
- enters a bounded uncertainty state

Do not silently assume continuity after failure.

---

# 24. STORAGE AND DURABILITY

If NEXORA continuity depends on persistent state, identify:

- what must persist
- where it persists
- when it is committed
- what happens if persistence fails
- what happens if persistence is rolled back
- how corruption is detected

Do not claim continuity merely because a process has an in-memory chain.

---

# 25. ADVERSARIAL TEST MATRIX

Create tests for:

**Identity**

- forged issuer
- changed issuer
- reused issuer
- PID reuse
- process restart
- stale identity

**Anchor**

- payload mutation
- issuer mutation
- context mutation
- sequence mutation
- previous-anchor mutation
- protocol-version mutation
- key-version mutation

**Serialization**

- field reordering
- alternate encoding
- omitted optional field
- explicit null
- duplicate field
- integer encoding variation

**Replay**

- exact replay
- delayed replay
- reordered replay
- forked replay
- rollback

**Key management**

- wrong key
- revoked key
- old key
- wrong version
- algorithm mismatch

**Continuity**

- crash
- reboot
- power loss
- corrupted state
- state rollback
- duplicated state

Every security-relevant failure must produce a bounded failure result.

---

# 26. NO PHANTOM PROVENANCE

NEXORA MUST NOT manufacture provenance.

If the source event does not exist, do not create an Anchor claiming that it did.

If the source evidence is unavailable, do not convert absence into:

```text
verified
```

If continuity cannot be established, report the appropriate uncertainty.

The system must prefer:

```text
CANNOT_PROVE
```

over fabricated continuity.

---

# 27. NO RETROACTIVE AUTHORIZATION

An Anchor created after an event MUST NOT retroactively become proof that the event was authorized before execution.

Separate:

```text
pre-execution authorization
```

from:

```text
post-execution evidence
```

and:

```text
post-execution anchoring
```

Anchoring evidence after execution does not rewrite history.

---

# 28. NO RETROACTIVE OBSERVATION

Likewise:

```text
event happened
        ↓
NEXORA Anchor created later
```

does not mean:

```text
Sentinel observed event
```

Independent observation remains independently established.

---

# 29. NEXORA AS CROSS-LAYER INTEGRITY

The final integration should permit strong relationships such as:

```text
Identity
   ↓
Authorization
   ↓
Execution ID
   ↓
Agent Evidence
   ↓
Independent Observation
   ↓
Reconciliation
   ↓
Warrant
   ↓
Containment
```

NEXORA may cryptographically link these objects where the architecture explicitly defines such linkage.

It MUST NOT collapse the objects into one proof.

The purpose is:

```text
cryptographically linked, semantically distinct evidence.
```

---

# 30. INTEGRATION INVARIANT

The final system must preserve this fundamental distinction:

```text
IDENTITY
   ≠
AUTHORITY
   ≠
EXECUTION
   ≠
OBSERVATION
   ≠
RECONCILIATION
   ≠
WARRANT
   ≠
CONTAINMENT
```

NEXORA strengthens the cryptographic relationships between these layers.

It does not erase their boundaries.

---

# 31. REQUIRED NEGATIVE TESTS

The implementation MUST include tests proving that NEXORA cannot:

1. grant authority
2. manufacture execution
3. manufacture observation
4. manufacture reconciliation evidence
5. issue a warrant
6. trigger containment directly
7. convert PID into permanent identity
8. convert a valid Anchor into authorization
9. convert a valid Anchor into observation
10. silently continue after a continuity-breaking failure
11. accept a mutated security-critical field
12. accept replayed state where replay is prohibited

A test suite that only proves valid cases is insufficient.

---

# 32. INTEGRATION REPORT

Create:

```text
docs/architecture/NEXORA_IMPLEMENTATION_REPORT.md
```

The report MUST contain:

**A. Status**

PASS / FAIL / BLOCKED

**B. NEXORA model**

Describe the implemented Anchor and its canonical representation.

**C. Cryptographic boundary**

Identify:

- algorithms
- hash boundaries
- signatures
- domain separation
- serialization

**D. Identity boundary**

Explain what establishes identity and what explicitly does not.

**E. Continuity**

Explain:

- sequence semantics
- previous-anchor linkage
- restart behavior
- crash behavior
- rollback behavior
- fork behavior

**F. Versioning**

Document:

- protocol versions
- key versions
- compatibility rules
- rotation

**G. Cross-layer integration**

Document how NEXORA interacts with:

- AIP
- Execution Binding
- Decision Point
- Sentinel
- Reconciliation
- Warrant
- Containment

**H. Negative tests**

List adversarial tests and results.

**I. Remaining limitations**

Explicitly identify anything not proven.

Never convert an untested assumption into a PASS.

---

# 33. FINAL GATE

Before declaring PASS, verify:

- [ ] All predecessor reports are PASS
- [ ] NEXORA does not grant authority
- [ ] NEXORA does not manufacture execution evidence
- [ ] NEXORA does not manufacture observation
- [ ] NEXORA does not issue warrants
- [ ] NEXORA does not directly actuate containment
- [ ] canonical serialization is specified
- [ ] hash boundaries are explicit
- [ ] domain separation is explicit where required
- [ ] sequence semantics are explicit
- [ ] replay behavior is tested
- [ ] previous-anchor linkage is tested
- [ ] fork behavior is defined
- [ ] key versioning is tested
- [ ] protocol versioning is tested
- [ ] restart behavior is tested
- [ ] rollback behavior is tested
- [ ] identity cannot be reduced to PID/IP/path/name
- [ ] no retroactive authorization exists
- [ ] no retroactive observation exists
- [ ] negative tests exist
- [ ] NEXORA report exists
- [ ] no unsupported security claims are made

If any security-critical item is unresolved:

FAIL or BLOCKED.

Do not weaken the gate to obtain PASS.

---

# 34. FINAL ARCHITECTURAL PRINCIPLE

The final Ghost Architecture 2.0 must be able to establish:

```text
WHO
  ↓
WAS AUTHORIZED TO DO WHAT
  ↓
FOR WHICH EXECUTION
  ↓
WHAT THE AGENT CLAIMED
  ↓
WHAT THE INFRASTRUCTURE INDEPENDENTLY OBSERVED
  ↓
WHETHER THOSE FACTS RECONCILE
  ↓
WHETHER A WARRANT IS JUSTIFIED
  ↓
WHETHER CONTAINMENT IS AUTHORIZED
```

NEXORA provides cryptographic continuity and provenance across this system.

It does not replace any of those questions.

The objective is not:

"Make everything cryptographically signed."

The objective is:

"Make security-critical claims cryptographically linked, independently evidenced where required, temporally bounded, replay-resistant, and impossible to silently reinterpret across trust boundaries."

That is the final NEXORA integration standard.

---

# 35. HARD STOP CONDITIONS

STOP immediately if:

- predecessor gate has not passed
- NEXORA is being used as an authority shortcut
- NEXORA is being used to infer execution
- NEXORA is being used to infer observation
- PID/IP/path/name is treated as cryptographic identity
- canonicalization is undefined
- security-critical fields are outside the authenticated representation
- replay semantics are undefined
- fork semantics are undefined
- restart continuity is assumed without proof
- rollback is accepted silently
- NEXORA directly triggers containment
- an Anchor is treated as a warrant
- an Anchor is treated as proof of physical execution
- missing evidence is converted into positive evidence
- tests are removed or weakened to obtain PASS
- existing security invariants are weakened
- implementation modifies an unrelated trust boundary without an explicit architectural reason

When a hard stop occurs:

1. do not continue implementation
2. document the exact conflict
3. identify the affected invariant
4. identify the affected trust boundary
5. produce a remediation recommendation
6. stop

---

# 36. COMPLETION CRITERIA

Skill 10 is complete only when:

```text
AIP
 ↓
Decision Point
 ↓
Execution Binding
 ↓
Agent Evidence
 ↓
Independent Sentinel Observation
 ↓
Reconciliation
 ↓
Warrant
 ↓
Containment
```

remain semantically separate while NEXORA provides:

```text
cryptographic identity
+
provenance
+
continuity
+
version binding
+
replay resistance
+
cross-layer integrity
```

without becoming a hidden authority mechanism.

The final deliverable is:

```text
docs/architecture/NEXORA_IMPLEMENTATION_REPORT.md
```

with status:

```text
PASS
```

only when the complete adversarial test and integration gates succeed.

DO NOT declare PASS based solely on compilation.

DO NOT declare PASS based solely on unit tests.

DO NOT claim cryptographic proof where the architecture only provides cryptographic linkage.

DO NOT IMPLEMENT A NEW AUTHORITY SYSTEM INSIDE NEXORA.

NEXORA IS THE CONTINUITY AND PROVENANCE LAYER — NOT THE GOVERNANCE AUTHORITY.
