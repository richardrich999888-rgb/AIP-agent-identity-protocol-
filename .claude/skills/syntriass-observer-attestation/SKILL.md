---
name: syntriass-observer-attestation
description: Build the independent observation and attestation layer for SYNTRIASS Ghost only after AIP correctness, execution binding, and the decision point have passed. Enforces independent trust, observer continuity, explicit degradation, and evidence honesty.
---

# SYNTRIASS OBSERVER ATTESTATION

## 1. ROLE

You are the Observer Attestation implementation specialist.

Your responsibility is to implement the independent observation layer required by Ghost.

You MUST NOT:

- implement authorization;
- implement ExpectedExecution;
- implement reconciliation;
- implement warrants;
- implement containment;
- implement NEXORA;
- treat agent-generated telemetry as independent observation;
- claim hardware or TEE attestation without actual verification;
- infer non-execution from missing telemetry;
- silently convert observer failure into a security finding.

The observer answers exactly one question:

> "What execution-related event did an independently trusted observer actually observe?"

It does NOT answer:

> "Was that execution permitted?"

Authorization belongs to the decision point.

---

# 2. AUTHORITATIVE INPUTS

Before touching production code, read:

1. `docs/architecture/SECURITY_INVARIANTS.md`
2. `docs/architecture/EXECUTION_BINDING.md`
3. `docs/architecture/OBSERVATION_MODEL.md`
4. `docs/architecture/OBSERVER_ATTESTATION.md`
5. `docs/architecture/RECONCILIATION_MODEL.md`
6. `docs/architecture/TARGET_ARCHITECTURE.md`
7. `docs/architecture/GAP_MATRIX.md`
8. `docs/architecture/TRUST_BOUNDARIES.md`
9. `docs/architecture/IMPLEMENTATION_PLAN.md`

Also inspect the current implementation produced by Skills 1–5.

Do not rely on this skill instead of the repository artifacts.

If terminology, invariant numbering, architecture, or dependency state conflicts:

STOP.

Report the conflict before modifying security-sensitive code.

---

# 3. PRECONDITIONS

Do not begin implementation unless:

- Skill 3 AIP correctness has PASS status;
- `expires_at` integrity is fixed and adversarially tested;
- canonical authority encoding is injective;
- domain separation exists for new signed structures;
- Skill 4 ExecutionBinding has PASS status;
- process-instance identity is not PID-only;
- executable identity is based on binary contents;
- Skill 5 Decision Point has PASS status;
- ExpectedExecution exists and is independently signed.

If any prerequisite is missing:

STOP.

Produce:

`OBSERVER_IMPLEMENTATION_REPORT.md`

with:

- missing prerequisite;
- evidence;
- exact blocking condition;
- no implementation.

---

# 4. THREAT MODEL

Before implementation explicitly document:

## THREAT

Assume an attacker may:

- have root on the observed host;
- inspect processes;
- spawn processes;
- terminate processes;
- modify files;
- modify configuration;
- alter the host clock;
- kill or restart the observer;
- exhaust telemetry buffers;
- reorder locally available events;
- erase local observer state;
- restore stale observer state;
- partition the host from the collector.

## ASSUMPTIONS

State explicitly:

- kernel trust assumptions;
- observer TCB;
- collector TCB;
- network assumptions;
- clock assumptions;
- hardware assumptions;
- what root compromise can and cannot defeat.

Do not silently assume a trustworthy kernel.

Do not claim root-resistance unless the selected architecture actually provides it.

---

# 5. TRUST ROOT

The observer signing key MUST NOT be accessible to the observed agent.

This is mandatory.

The preferred first implementation is:

REMOTE COLLECTOR

Architecture:

```text
Observed Host
    |
    | observation events
    v
Observer transport
    |
    v
Remote Collector
    |
    | independent signing key
    v
ObserverAttestation
```

The signing key lives at the collector, not inside the agent.

Do not substitute:

- plaintext software key on observed host;
- agent private key;
- service signing key;
- caller-supplied private key.

If implementation constraints make the remote collector impossible, STOP and document the decision rather than silently weakening I10.

---

# 6. OBSERVER RESPONSIBILITY

The observer signs:

WHAT IT SAW.

Never:

WHAT IS PERMITTED.

For example:

VALID:

```text
ObservedExecution {
    execution_binding,
    action_kind,
    parameter_digest,
    observed_at,
    observer_sequence,
    observer_id,
    ...
}
```

INVALID:

```text
ObservedExecution {
    permitted: true,
    authorization: ...
}
```

The observer may reference a decision_id for correlation if the architecture requires it, but it MUST NOT derive authorization from that reference.

---

# 7. OBSERVED EXECUTION

Define a canonical signed structure for:

`ObservedExecution`

Minimum semantic fields:

- `decision_id` when available;
- `ExecutionBinding`;
- action kind;
- parameter digest;
- observation timestamp or monotonic observation position;
- observer sequence;
- observer identity/key version;
- observation batch identifier;
- protocol version.

Do not duplicate AIP authorization fields unnecessarily.

Every signed field must be covered by the canonical signed preimage.

Every signed object MUST have explicit domain separation.

Use existing canonical encoding helpers.

Do not create a second ad-hoc encoder.

---

# 8. OBSERVER ATTESTATION

Define:

`ObserverAttestation`

It MUST establish:

1. observer identity;
2. exact observation payload;
3. sequence/continuity information;
4. key version;
5. signature;
6. protocol/domain identifier.

The verifier must independently reconstruct the signed bytes.

Never verify only a hash supplied alongside the signature.

Never trust an unsigned `observer_id`.

---

# 9. DOMAIN SEPARATION

Every new signed payload requires a unique domain tag.

For example:

```text
SYNTRIASS/GHOST/OBSERVED_EXECUTION/v1
SYNTRIASS/GHOST/OBSERVER_HEALTH/v1
SYNTRIASS/GHOST/OBSERVER_HEAD/v1
```

Use the repository's canonical encoding.

Do not invent a second cryptographic primitive.

Do not claim domain separation merely because different Rust structs exist.

The domain tag MUST be inside the signed preimage.

---

# 10. OBSERVER CONTINUITY

Observer continuity is security state, not logging metadata.

Implement explicit states:

```text
ACTIVE
DEGRADED
RECOVERING
CONTINUITY_UNVERIFIED
QUARANTINED
```

Semantics:

**ACTIVE**

Observer is live and continuity is verified.

Observations may reach:

`Attested`

**DEGRADED**

Observer remains alive but has a known gap, dropped event, or coverage defect.

Result:

`OBSERVATION_UNAVAILABLE`

**RECOVERING**

Observer restarted and continuity has not yet been re-established.

Result:

`OBSERVATION_UNAVAILABLE`

**CONTINUITY_UNVERIFIED**

Observer resumed without a verifiable link to prior state.

Result:

`OBSERVATION_UNAVAILABLE`

and emit a continuity finding.

**QUARANTINED**

Observer integrity failure is arithmetically proven.

Result:

`SENSOR_INTEGRITY_FAILURE`

with:

`Proven`

strength.

---

# 11. CONTINUITY MODEL

A local state file controlled by the attacker is insufficient.

Implement a continuity mechanism that prevents the observer from claiming:

"I was continuously observing"

when continuity cannot be established.

At minimum, continuity must bind:

- previous observer sequence;
- previous attested head;
- current sequence;
- observer identity;
- key version;
- observation interval;
- protocol version.

If continuity is broken:

DO NOT reconstruct continuity from attacker-controlled local state.

Represent the break explicitly.

---

# 12. HEALTH ATTESTATION

Implement signed observer health.

Health MUST include enough information to determine:

- observer identity;
- state;
- sequence;
- current observation position;
- last observed event/batch;
- continuity status;
- key version;
- protocol version.

Absence of recent health MUST reduce coverage.

It MUST NOT extend coverage.

This distinction is mandatory.

---

# 13. CLOCKS

Do not use the host wall clock as the sole source of continuity.

Where possible:

- use monotonic sequencing for observer order;
- use wall-clock timestamps only as contextual time;
- bind time windows explicitly;
- do not claim exact timing if the clock is attacker-controlled.

A manipulated clock may affect temporal correlation.

It must not silently create stronger evidence.

---

# 14. SENSOR FAILURE

The following MUST become explicit degraded states:

- observer killed;
- observer restarted;
- buffer overflow;
- telemetry drop;
- collector unavailable;
- network partition;
- state rollback;
- sequence discontinuity;
- signature failure;
- malformed observation;
- unsupported protocol version.

None of these may become:

`PHANTOM_CLAIM`

merely because observation disappeared.

---

# 15. OBSERVATION AVAILABILITY

Define explicit coverage semantics.

A window is covered only if the observer can prove it was observing throughout the relevant interval according to the selected continuity model.

If coverage cannot be established:

```text
OBSERVATION_UNAVAILABLE
```

This is not a malicious execution verdict.

It is an epistemic limitation.

---

# 16. KEY LIFECYCLE

Document and implement:

- key generation;
- provisioning;
- key version;
- rotation;
- expiration;
- revocation;
- collector restart;
- key loss;
- old-key verification.

Do not hard-code a single eternal observer key.

If rotation is deferred from the first implementation, represent that explicitly as a limitation and make the protocol version capable of carrying key identity/version.

---

# 17. REPLAY

Observer attestations MUST NOT be assumed fresh merely because they are signed.

Define replay semantics.

At minimum bind:

- observer sequence;
- observer identity;
- observation batch;
- continuity state.

A replayed valid signature must not automatically become a new observation.

Do not rely on the AIP `Signature.nonce` unless it is actually checked by the relevant verification path.

---

# 18. PROCESS ATTRIBUTION

Observer events MUST use the ExecutionBinding established by Skill 4.

Do not fall back to:

- PID alone;
- IP address;
- source port;
- executable path alone;
- process name alone.

If the observer cannot establish the required binding:

return an attribution failure / unavailable observation.

Do not guess.

---

# 19. WHAT THE OBSERVER MUST NOT CLAIM

Do not implement fields or logic implying:

- "authorized";
- "allowed";
- "policy-compliant";
- "safe";
- "malicious";
- "should be contained".

The observer records execution facts.

The reconciler interprets those facts against authorization.

---

# 20. CRYPTOGRAPHIC IMPLEMENTATION

Reuse:

- existing Ed25519 implementation;
- existing SHA-256 implementation;
- existing canonical encoder;
- existing verification patterns.

Do not add:

- a new signature library;
- homemade cryptography;
- unauthenticated hash chains;
- fake Merkle commitments;
- placeholder PQC.

Do not describe an unsigned hash chain as an attestation.

---

# 21. TEST-FIRST REQUIREMENT

Before modifying security-sensitive production logic, create adversarial tests.

At minimum:

1. observer signature mutation;
2. observed payload mutation;
3. observer identity mutation;
4. sequence rollback;
5. sequence replay;
6. continuity gap;
7. observer restart;
8. stale state restoration;
9. collector partition;
10. observer key unavailable to agent;
11. authorization field cannot be injected into observation;
12. PID reuse cannot alter ExecutionBinding;
13. missing observation does not become PHANTOM_CLAIM;
14. domain-tag confusion fails;
15. canonical encoding mutation fails;
16. key-version mismatch fails.

Tests that merely assert happy-path signatures are insufficient.

---

# 22. SECURITY PROPERTY TESTS

Explicitly prove:

```text
agent controls observation input
        ≠
agent controls observation signature
```

and:

```text
observation absence
        ≠
non-execution
```

and:

```text
observer attestation
        ≠
authorization
```

and:

```text
observer restart
        ≠
continuous coverage
```

---

# 23. NO SILENT DOWNGRADES

If the observer cannot provide Attested evidence:

do not manufacture Attested evidence.

If the signing key is unavailable:

do not emit unsigned observations as if signed.

If continuity is unknown:

do not claim continuity.

If the collector is unreachable:

do not claim remote attestation succeeded.

Every downgrade must be explicit.

---

# 24. PRODUCTION BOUNDARY

Keep observer implementation separated from:

- AIP authorization;
- decision point;
- reconciliation;
- warrant;
- containment;
- NEXORA.

The observer is an evidence producer.

It is not a policy engine.

---

# 25. REQUIRED OUTPUT

Produce:

`OBSERVER_IMPLEMENTATION_REPORT.md`

The report MUST contain:

1. implementation status;
2. architecture;
3. trust root;
4. threat model;
5. assumptions;
6. key lifecycle;
7. continuity model;
8. failure semantics;
9. signed structures;
10. domain separation;
11. test inventory;
12. adversarial test results;
13. known limitations;
14. unresolved risks.

Do not mark PASS unless the tests actually establish the required properties.

---

# 26. HARD STOP CONDITIONS

STOP immediately if:

- observer signing key is accessible to the observed agent;
- observer signs authorization decisions;
- observation is generated solely from agent self-report;
- continuity is inferred from missing data;
- missing telemetry becomes non-execution;
- PID-only attribution is introduced;
- unsigned observations are represented as attested;
- domain separation is omitted;
- an existing canonical encoder is bypassed;
- fake hardware attestation is introduced;
- PQC is introduced as a placeholder;
- containment logic is added;
- reconciliation logic is added;
- NEXORA is added.

---

# 27. DEFINITION OF DONE

Skill 6 is PASS only when:

- observer architecture exists;
- independent trust root exists;
- ObservedExecution is signed;
- signature verification is implemented;
- domain separation exists;
- ExecutionBinding is incorporated;
- continuity is explicit;
- degradation is explicit;
- replay is addressed;
- key identity/version is represented;
- observation availability is explicit;
- adversarial tests pass;
- no authorization logic exists in the observer;
- no containment logic exists;
- no NEXORA implementation exists.

Then produce:

`OBSERVER_IMPLEMENTATION_REPORT.md`

and stop.

Do not proceed to Reconciliation.
