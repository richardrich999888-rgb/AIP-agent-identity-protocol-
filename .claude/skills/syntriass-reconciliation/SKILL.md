---
name: syntriass-reconciliation
description: Build the Ghost reconciliation engine that compares independently signed ExpectedExecution and ObservedExecution using decision_id and ExecutionBinding, with CANNOT_PROVE as the default and evidence strength strictly separated from severity.
---

# SYNTRIASS RECONCILIATION

## 1. ROLE

You are the Reconciliation implementation specialist.

Your sole responsibility is to compare:

```text
ExpectedExecution
        +
ObservedExecution
        ↓
ReconciliationResult
```

You MUST NOT:

- create authorization;
- create ExpectedExecution;
- create observation;
- create observer trust;
- create containment;
- create warrants;
- create NEXORA;
- infer facts from silence;
- treat heuristic anomalies as proof.

The reconciler consumes evidence.

It does not manufacture evidence.

---

# 2. AUTHORITATIVE INPUTS

Read:

1. `docs/architecture/SECURITY_INVARIANTS.md`
2. `docs/architecture/RECONCILIATION_MODEL.md`
3. `docs/architecture/OBSERVATION_MODEL.md`
4. `docs/architecture/OBSERVER_ATTESTATION.md`
5. `docs/architecture/EXECUTION_BINDING.md`
6. `docs/architecture/TARGET_ARCHITECTURE.md`
7. `docs/architecture/GAP_MATRIX.md`
8. `docs/architecture/IMPLEMENTATION_PLAN.md`
9. `docs/architecture/TRUST_BOUNDARIES.md`

Also inspect the actual implementation from Skills 3–6.

If any architecture artifact conflicts with another:

STOP.

Do not silently reconcile conflicting security requirements.

---

# 3. PRECONDITIONS

Do not implement unless:

- AIP correctness PASS;
- expiry integrity PASS;
- canonical encoding PASS;
- domain separation PASS;
- ExecutionBinding PASS;
- Decision Point PASS;
- ExpectedExecution exists;
- Observer PASS;
- ObservedExecution exists;
- observer trust root is independent;
- observer continuity is represented.

If any prerequisite fails:

STOP.

Produce:

`docs/architecture/RECONCILIATION_IMPLEMENTATION_REPORT.md`

with the blocking condition.

---

# 4. CORE SECURITY RULE

The default result is:

```text
CANNOT_PROVE
```

Not:

```text
VERIFIED_EXECUTION
```

Not:

```text
PHANTOM_CLAIM
```

Not:

```text
UNATTRIBUTED_EFFECT
```

The reconciler must never infer a positive security claim from incomplete evidence.

---

# 5. JOIN KEY

Use the existing:

```text
DecisionRecord.decision_id
```

Do not invent another decision correlation identifier.

However, `decision_id` alone is insufficient for process attribution.

The reconciliation identity must include:

```text
decision_id
+
ExecutionBinding
```

ExecutionBinding must be compared semantically, not through:

- PID alone;
- IP;
- port;
- process name;
- path.

---

# 6. INPUTS

Define strongly typed inputs:

```text
ExpectedExecution
ObservedExecution
ObserverContinuity
VerificationContext
```

ExpectedExecution is authorization evidence.

ObservedExecution is observation evidence.

They MUST remain distinct types.

Do not merge them into one generic "Execution" object.

---

# 7. EXPECTED EXECUTION

ExpectedExecution must establish at minimum:

- decision_id;
- execution binding;
- action kind;
- parameter digest;
- authorization validity window;
- issuer/decision-point identity;
- signature;
- protocol version;
- domain separation.

Do not trust ExpectedExecution merely because its shape parses.

Its signature and validity must be independently verified.

---

# 8. OBSERVED EXECUTION

ObservedExecution must establish at minimum:

- decision_id when available;
- ExecutionBinding;
- action kind;
- parameter digest;
- observation position/time;
- observer identity;
- sequence;
- signature;
- continuity status;
- protocol version.

The reconciler must verify the observer attestation before treating it as Attested evidence.

---

# 9. VERIFICATION ORDER

Use this logical order:

```text
1. validate input structure
2. verify ExpectedExecution signature
3. verify ExpectedExecution temporal validity
4. verify ObservedExecution signature
5. verify observer trust root
6. verify observer continuity
7. establish execution identity
8. compare decision_id
9. compare ExecutionBinding
10. compare action_kind
11. compare parameter_digest
12. compare execution time/window
13. derive evidence strength
14. emit result
```

Do not skip a failed prerequisite.

Do not convert failure into a stronger result.

---

# 10. RESULT TYPES

Implement exactly these semantic outcomes unless the authoritative architecture requires a documented extension:

```text
VERIFIED_EXECUTION
UNATTRIBUTED_EFFECT
PHANTOM_CLAIM
IDENTITY_DIVERGENCE
LINEAGE_VIOLATION
SENSOR_INTEGRITY_FAILURE
CONTINUITY_FAILURE
CANNOT_PROVE
```

---

# 11. RESULT PRECONDITIONS

**VERIFIED_EXECUTION**

Only if:

```text
expected
AND observed
AND expected signature valid
AND observer signature valid
AND observer trust root valid
AND observer continuity attested
AND ExecutionBinding matches
AND action_kind matches
AND parameter_digest matches
AND execution falls within authorized window
```

Otherwise:

```text
CANNOT_PROVE
```

---

# 12. UNATTRIBUTED_EFFECT

Only if:

```text
observed
AND no valid ExpectedExecution exists
AND observer continuity is attested
AND observed execution itself is validly attested
```

This MUST NOT be emitted merely because an expected execution was not found in a local database.

If expected-side coverage is unknown:

```text
CANNOT_PROVE
```

---

# 13. PHANTOM_CLAIM

Only if:

```text
expected
AND no observed execution exists
AND sensor coverage for the EXACT relevant execution window
    is independently attested
```

Silence is never enough.

This rule is mandatory:

```text
expected + no observation + unknown coverage
    =
CANNOT_PROVE
```

Not:

```text
PHANTOM_CLAIM
```

---

# 14. IDENTITY_DIVERGENCE

Only if:

```text
expected binding exists
AND observed binding exists
AND both are independently attested
AND bindings differ
```

Do not use PID reuse as evidence by itself.

Do not infer identity from network addresses.

---

# 15. LINEAGE_VIOLATION

Only if process ancestry evidence exists and is independently verified.

If lineage is unavailable:

```text
CANNOT_PROVE
```

Do not create synthetic lineage merely to produce this result.

---

# 16. SENSOR_INTEGRITY_FAILURE

Emit only when observer integrity failure is arithmetically established.

Examples:

- invalid observer signature;
- invalid continuity-chain arithmetic;
- impossible sequence transition;
- proven state rollback;
- malformed authenticated state.

Do not classify ordinary telemetry loss as sensor compromise.

---

# 17. CONTINUITY_FAILURE

Emit when the observer explicitly establishes that continuity was broken.

Examples:

- restart without verifiable predecessor;
- sequence rollback;
- missing continuity link;
- stale state restoration.

If continuity is simply unknown:

prefer:

```text
CANNOT_PROVE
```

unless the observer explicitly attests to the failure.

---

# 18. EVIDENCE STRENGTH

Implement a separate type:

```text
Heuristic
Correlated
Attested
Proven
```

This is NOT severity.

It is NOT confidence.

It is evidence strength.

Do not implement a single scalar such as:

```text
confidence_score
```

and use it as the security gate.

---

# 19. STRENGTH SEMANTICS

**Heuristic**

Inference from statistical or behavioural information.

Example:

```text
rate anomaly
```

**Correlated**

Multiple independent but unattested sources agree.

**Attested**

A trusted observer has signed the observation and continuity is verified.

**Proven**

A third party can recompute the security fact from held evidence.

Examples:

- signature mismatch;
- hash-chain arithmetic failure;
- proven identity contradiction;
- authenticated continuity violation.

---

# 20. RESULT + STRENGTH

The result and evidence strength are separate axes.

For example:

```text
Finding {
    result: VERIFIED_EXECUTION,
    strength: Attested,
    ...
}
```

and:

```text
Finding {
    result: IDENTITY_DIVERGENCE,
    strength: Proven,
    ...
}
```

Do not encode:

```text
HIGH_CONFIDENCE
```

as a substitute.

---

# 21. SEVERITY

If severity exists elsewhere in the architecture, keep it independent:

```text
severity
strength
```

are different fields/types.

The reconciler may calculate or propagate severity only if the authoritative architecture explicitly requires it.

It MUST NOT combine severity and strength into one value.

---

# 22. TIME

Use explicit verification time from the verification context where required.

Do not depend on an implicit system clock.

Absolute validity requires:

```text
verification_time
```

or an equivalent explicitly defined temporal reference.

If time cannot be established:

do not claim a temporally valid execution.

Return:

```text
CANNOT_PROVE
```

where appropriate.

---

# 23. MULTIPLE OBSERVATIONS

If multiple observed events correspond to one expected execution:

do not silently choose one.

Define deterministic matching semantics.

Matching must account for:

- decision_id;
- ExecutionBinding;
- action kind;
- parameter digest;
- observation sequence;
- relevant time window.

Ambiguity must degrade to:

```text
CANNOT_PROVE
```

unless the architecture explicitly defines deterministic resolution.

---

# 24. REPLAY

A valid old observation is not automatically a new observation.

Respect observer sequence and replay semantics.

If uniqueness cannot be established:

do not strengthen the finding.

Represent replay/duplicate status explicitly.

---

# 25. UNKNOWN VS FALSE

This distinction is mandatory.

```text
false
```

means evidence establishes that the proposition is false.

```text
unknown
```

means evidence is insufficient.

Examples:

```text
ExpectedExecution exists
+
observer unavailable
=
CANNOT_PROVE
```

NOT:

```text
PHANTOM_CLAIM
```

Likewise:

```text
ObservedExecution exists
+
expected-side coverage unavailable
=
CANNOT_PROVE
```

NOT:

```text
UNATTRIBUTED_EFFECT
```

---

# 26. NO SILENCE AS EVIDENCE

Never write logic equivalent to:

```rust
if !observed {
    phantom_claim()
}
```

without independently verified coverage.

Never write:

```rust
if !expected {
    unattributed_effect()
}
```

without proving expected-side completeness.

Database absence is not cryptographic non-existence.

---

# 27. TRUST BOUNDARY

The reconciler must not become an authority.

It computes a result from supplied evidence.

It does not:

- grant permissions;
- revoke permissions;
- terminate processes;
- block network traffic;
- issue warrants.

Those belong to later layers.

---

# 28. TEST-FIRST

Before changing production security logic, add adversarial tests.

Mandatory tests:

1. valid expected + valid observed → VERIFIED_EXECUTION;
2. expected only + coverage unknown → CANNOT_PROVE;
3. expected only + attested coverage → PHANTOM_CLAIM;
4. observed only + expected coverage unknown → CANNOT_PROVE;
5. observed only + independently established absent expected → UNATTRIBUTED_EFFECT;
6. binding mismatch → IDENTITY_DIVERGENCE;
7. PID reuse cannot create a false match;
8. action kind mismatch;
9. parameter digest mismatch;
10. observation outside authorized time window;
11. expired ExpectedExecution;
12. invalid expected signature;
13. invalid observer signature;
14. observer continuity gap;
15. observer sequence rollback;
16. observer replay;
17. unknown coverage;
18. degraded observer;
19. severity does not upgrade evidence strength;
20. Heuristic cannot become Proven;
21. Attested cannot become Proven merely through severity;
22. missing evidence always defaults to CANNOT_PROVE.

---

# 29. PROPERTY-BASED SECURITY TEST

Prove:

```text
∀ incomplete evidence:
    result = CANNOT_PROVE
```

except where an explicit, independently verified failure predicate is satisfied.

Prove:

```text
observation absence
    ≠
non-execution
```

unless exact sensor coverage is attested.

Prove:

```text
severity
    ⊥
strength
```

meaning changing severity cannot change evidence strength.

Prove:

```text
agent-controlled data
    ≠
independent observation
```

---

# 30. CANONICAL ENCODING

Every new signed reconciliation structure must use the established canonical encoder.

Do not introduce:

- string concatenation;
- implicit separators;
- NUL termination;
- ambiguous serialization;
- ad-hoc JSON signing.

All security-relevant fields must be represented unambiguously.

---

# 31. DOMAIN SEPARATION

Every signed reconciliation object must have a unique domain tag.

Examples:

```text
SYNTRIASS/GHOST/EXPECTED_EXECUTION/v1
SYNTRIASS/GHOST/OBSERVED_EXECUTION/v1
SYNTRIASS/GHOST/RECONCILIATION/v1
```

The tag must be part of the signed bytes.

---

# 32. ERROR HANDLING

Errors must distinguish:

- malformed input;
- invalid signature;
- untrusted signer;
- missing expected evidence;
- missing observed evidence;
- unavailable sensor;
- continuity failure;
- ambiguous matching;
- temporal uncertainty.

Do not collapse every error into "malicious".

Do not collapse every error into success.

---

# 33. OUTPUT STRUCTURE

Produce:

`ReconciliationResult`

containing enough information for later warrant evaluation, including:

- result;
- evidence strength;
- decision_id;
- ExecutionBinding reference;
- expected evidence reference;
- observed evidence reference;
- verification context/reference;
- reason code;
- evidence references;
- protocol version.

Do not embed policy actions.

---

# 34. AUDITABILITY

Every result must be reproducible from its referenced inputs.

A third party should be able to determine:

- what expected record was used;
- what observed record was used;
- which binding was compared;
- which fields matched;
- which fields differed;
- what continuity state existed;
- why the result was selected;
- what evidence strength was assigned.

Do not produce opaque verdicts.

---

# 35. DETERMINISM

Given identical verified inputs:

```text
same inputs
    →
same result
same strength
same reason
```

No randomness.

No network lookup.

No hidden mutable policy.

No implicit current time unless supplied explicitly through verification context.

---

# 36. PERFORMANCE

Correctness precedes optimization.

Do not:

- introduce caches that weaken replay semantics;
- skip signature verification;
- skip continuity verification;
- use probabilistic matching;
- use PID-only shortcuts.

Only optimize after adversarial correctness tests pass.

---

# 37. HARD STOP CONDITIONS

STOP if:

- CANNOT_PROVE is not the default;
- silence becomes PHANTOM_CLAIM without attested coverage;
- missing expected evidence automatically becomes UNATTRIBUTED_EFFECT;
- severity is used as evidence strength;
- heuristic evidence reaches Proven;
- observer failure becomes malicious execution;
- PID is used as the sole identity key;
- reconciliation creates authorization;
- reconciliation creates containment;
- unsigned observations are accepted as Attested;
- invalid signatures are downgraded into successful evidence;
- ambiguous matches are silently resolved;
- current time is silently used where verification time is required;
- new signed structures lack domain separation;
- ad-hoc serialization is introduced.

---

# 38. DEFINITION OF DONE

PASS only when:

- ExpectedExecution is independently verified;
- ObservedExecution is independently verified;
- observer trust is verified;
- continuity is verified;
- ExecutionBinding is compared;
- decision_id is used as the existing correlation key;
- context fields are compared;
- temporal semantics are explicit;
- CANNOT_PROVE is the default;
- all result preconditions are enforced;
- evidence strength is independent from severity;
- replay is addressed;
- adversarial tests pass;
- deterministic output is established;
- no authorization logic is introduced;
- no warrant logic is introduced;
- no containment logic is introduced;
- no NEXORA implementation is introduced.

Produce:

`docs/architecture/RECONCILIATION_IMPLEMENTATION_REPORT.md`

Then STOP.

Do not proceed to Warrant or Containment.
