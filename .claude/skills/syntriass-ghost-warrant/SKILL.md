---
name: syntriass-ghost-warrant
description: >
  Build and verify the Ghost Warrant Engine only after AIP correctness,
  execution binding, decision point, observer attestation, and reconciliation
  have passed. Enforces strict separation between severity and evidence
  strength, requires Proven evidence for containment authority, defaults to
  Alert/No-Action, and prevents heuristic or degraded observations from
  becoming containment warrants.
---

# SYNTRIASS GHOST — SKILL 8
# WARRANT ENGINE

## 0. ROLE

You are the Warrant Engine implementation and verification specialist for
SYNTRIASS Ghost.

Your job is to transform an already-reconciled security finding into a
policy decision about what response, if any, is permitted.

You are NOT:

- an observer,
- an authorization decision point,
- a reconciler,
- a containment executor,
- an identity authority,
- an evidence generator,
- a replacement for AIP verification,
- NEXORA,
- or a generic anomaly detector.

The Warrant Engine answers exactly one question:

> Given an authenticated reconciliation result, its severity, its evidence
> strength, and explicit response policy, what response class is warranted?

It must never manufacture evidence.

It must never upgrade evidence strength.

It must never turn uncertainty into certainty.

It must never infer execution from observation absence.

It must never directly terminate, isolate, block, kill, revoke, or otherwise
actuate a workload.

Containment belongs to Skill 9.

---

# 1. AUTHORITATIVE INPUTS

Before doing anything, read:

1. `docs/architecture/SECURITY_INVARIANTS.md`
2. `docs/architecture/CURRENT_SYSTEM.md`
3. `docs/architecture/TARGET_ARCHITECTURE.md`
4. `docs/architecture/RECONCILIATION_MODEL.md`
5. `docs/architecture/CONTAINMENT_MODEL.md`
6. `docs/architecture/GAP_MATRIX.md`
7. `docs/architecture/IMPLEMENTATION_PLAN.md`
8. the completed Skill 3 correctness report
9. the completed Skill 4 execution-binding report
10. the completed Skill 5 decision-point report
11. the completed Skill 6 observer implementation report
12. the completed Skill 7 reconciliation implementation report

If any required predecessor report is missing or does not contain an explicit
PASS, STOP.

Do not implement around a failed predecessor.

If invariant numbering, terminology, or authority boundaries conflict between
the documents, STOP and report the conflict before modifying code.

Do not silently reconcile architectural documents.

---

# 2. PRECONDITION GATE

Skill 8 may execute only if all of the following are true:

```text
AIP correctness              PASS
Execution binding            PASS
Decision point               PASS
Observer attestation        PASS
Reconciliation              PASS
```

Additionally:

```text
VERIFIED_EXECUTION           reachable
CANNOT_PROVE                 implemented
Evidence Strength            implemented
OBSERVATION_UNAVAILABLE      represented
Severity                     represented independently
```

If any condition is false:

```text
STATUS: HARD STOP
```

Report:

- missing predecessor,
- failed predecessor,
- missing artifact,
- missing type,
- missing test,
- or unresolved architectural dependency.

Do not create a partial warrant engine.

---

# 3. CORE SECURITY PROPERTY

The central invariant is:

```text
SEVERITY ⊥ EVIDENCE_STRENGTH
```

Severity and evidence strength are independent dimensions.

Severity answers:

How serious would this be if the finding is true?

Evidence strength answers:

How strongly is the finding established?

These dimensions must remain separate in:

- source types,
- constructors,
- policy evaluation,
- serialization,
- logs,
- tests,
- APIs,
- and containment decisions.

Never encode them into a single score.

Never allow:

```text
high confidence
```

to substitute for:

```text
Proven evidence
```

Never allow:

```text
high severity
```

to substitute for:

```text
Proven evidence
```

---

# 4. EVIDENCE STRENGTH

Use the architecture's established four-level model:

```rust
pub enum EvidenceStrength {
    Heuristic,
    Correlated,
    Attested,
    Proven,
}
```

Do not add an implicit fifth level.

Do not introduce:

```text
VeryHigh
Certain
Trusted
Critical
Confirmed
```

as synonyms for `Proven`.

The meaning is:

**Heuristic**

Statistical, behavioural, or inferential evidence.

Examples:

- rate anomaly,
- unusual sequence,
- behavioural deviation.

Maximum response:

```text
Alert
```

**Correlated**

Multiple sources agree but the sources are not independently attested.

Maximum response:

```text
Alert
```

**Attested**

A signed observation from an independent observer whose continuity is
verified over the relevant window.

Possible response:

```text
Alert
```

or:

```text
Constrain
```

only where explicit operator policy permits it.

Attested evidence alone does NOT automatically authorize containment.

**Proven**

Evidence whose conclusion is mechanically reproducible from held evidence.

Examples:

- cryptographic signature mismatch,
- verified hash-chain break,
- an attested execution contradicting an authorization,
- a verified execution against independently attested sensor coverage.

Only `Proven` evidence can cross the containment warrant gate.

---

# 5. RECONCILIATION RESULTS

The Warrant Engine must consume the reconciler's typed result.

Expected results include:

```text
VERIFIED_EXECUTION
UNATTRIBUTED_EFFECT
PHANTOM_CLAIM
IDENTITY_DIVERGENCE
LINEAGE_VIOLATION
SENSOR_INTEGRITY_FAILURE
CONTINUITY_FAILURE
OBSERVATION_UNAVAILABLE
CANNOT_PROVE
```

Do not recreate reconciliation logic here.

Do not independently compare expected and observed executions.

Do not independently inspect process IDs.

Do not independently inspect network addresses.

Do not independently decide whether an action was authorized.

Those decisions belong upstream.

The Warrant Engine consumes the authenticated result.

---

# 6. WARRANT DECISION MODEL

Define a typed response class.

Minimum model:

```rust
pub enum ResponseClass {
    Alert,
    Constrain,
    Contain,
}
```

If the repository already contains an equivalent response type, reuse it
rather than creating a duplicate.

The policy function should conceptually be:

```text
Warrant =
    policy(
        reconciliation_result,
        severity,
        evidence_strength,
        operator_policy,
        protected_identity_state
    )
```

The result must be explicit.

Never return a boolean such as:

```rust
should_kill: bool
```

A boolean destroys the distinction between:

- no warrant,
- alert,
- constrain,
- containment.

---

# 7. HARD WARRANT RULE

The following rule is non-negotiable:

```text
Containment requires EvidenceStrength::Proven.
```

Therefore:

```text
Heuristic + any severity
    → at most Alert

Correlated + any severity
    → at most Alert

Attested + any severity
    → at most Constrain

Proven + policy permits
    → Contain may be warranted
```

The Warrant Engine must enforce this structurally.

Do not rely solely on caller discipline.

A caller must not be able to construct a containment warrant from:

```rust
Severity::Critical
```

alone.

A caller must not be able to construct one from:

```rust
confidence = 0.999
```

alone.

A caller must not be able to bypass the gate by passing:

```text
trusted = true
```

or:

```text
confirmed = true
```

---

# 8. DEFAULT POSTURE

The default policy is:

```text
Mode                    advisory
Autonomous containment  disabled
Uncited finding         Alert maximum
Degraded observer       no escalation
OBSERVATION_UNAVAILABLE Alert maximum
Protected identity      no autonomous containment
```

A newly deployed system must not autonomously destroy or isolate workloads.

The safe default is:

```rust
ResponseClass::Alert
```

not:

```rust
ResponseClass::Contain
```

---

# 9. CANNOT_PROVE

`CANNOT_PROVE` is not maliciousness.

It means:

```text
The available evidence is insufficient to establish the proposition.
```

Therefore:

```text
CANNOT_PROVE
    ≠
PHANTOM_CLAIM
```

and:

```text
CANNOT_PROVE
    ≠
UNATTRIBUTED_EFFECT
```

and:

```text
CANNOT_PROVE
    ≠
ATTACK
```

The warrant engine must never escalate `CANNOT_PROVE` to containment.

Minimum:

```text
CANNOT_PROVE → Alert
```

It may also be represented as:

```text
NoWarrant
```

if that is the repository's established response vocabulary, but it must not
be treated as proof of wrongdoing.

---

# 10. OBSERVATION_UNAVAILABLE

Sensor failure is not execution evidence.

Therefore:

```text
OBSERVATION_UNAVAILABLE
    → never Contain
```

Likewise:

```text
DEGRADED
RECOVERING
CONTINUITY_UNVERIFIED
```

must not independently create containment authority.

A missing observer heartbeat may cause:

```text
Alert
```

for sensor health.

It must not cause:

```text
Contain
```

against the workload.

This enforces the epistemic distinction:

```text
we did not observe it
```

is not:

```text
it did not happen
```

---

# 11. PHANTOM_CLAIM

`PHANTOM_CLAIM` requires the upstream reconciliation precondition:

```text
expected
+
no observed execution
+
independently attested sensor coverage
over the exact execution window
```

The Warrant Engine must trust the reconciler's authenticated result.

It must not independently infer `PHANTOM_CLAIM`.

If the reconciler reports:

```text
PHANTOM_CLAIM
```

but evidence strength is not sufficient for the configured response:

```text
downgrade response
```

Never upgrade the evidence.

In particular:

```text
PHANTOM_CLAIM + missing coverage
```

must never become:

```text
Contain
```

---

# 12. SENSOR_INTEGRITY_FAILURE

A proven observer integrity failure may be:

```text
EvidenceStrength::Proven
```

but this does not automatically mean:

```text
the observed workload is malicious
```

The warrant engine must distinguish:

```text
sensor integrity failure
```

from:

```text
execution violation
```

A sensor may be compromised without the workload being malicious.

Policy may therefore choose:

```text
Alert
```

or:

```text
Constrain observer
```

without granting authority to contain the observed workload.

Do not collapse the two.

---

# 13. CONTINUITY_FAILURE

A continuity failure indicates loss of observation assurance.

It does not establish execution.

Therefore:

```text
CONTINUITY_FAILURE
    → Alert at most
```

unless an independent, mechanically proven fact establishes another
containment-relevant condition.

Do not transform:

```text
observer restarted
```

into:

```text
workload executed maliciously
```

---

# 14. PROTECTED IDENTITIES

The policy must support explicit protected identities.

Protected identities include, at minimum:

- control-plane processes,
- the decision point,
- the observer trust infrastructure,
- the warrant service itself,
- critical operator access paths,
- recovery infrastructure.

If an identity is protected:

```text
autonomous containment = forbidden
```

The protection must be represented in policy, not merely documented.

Do not create an exception such as:

```rust
if critical {
    kill_anyway();
}
```

---

# 15. OPERATOR POLICY

Containment authority must be explicitly configurable.

Minimum conceptual model:

```rust
pub struct WarrantPolicy {
    pub autonomous_containment: bool,
    pub allow_constrain_on_attested: bool,
    pub protected_identities: ProtectedIdentitySet,
}
```

Reuse existing configuration infrastructure where possible.

Do not hide containment enablement in:

- environment-variable magic,
- debug flags,
- test-only switches,
- undocumented constants,
- feature flags that silently change security semantics.

The policy must be inspectable and testable.

---

# 16. WARRANT OBJECT

A containment-capable warrant must itself be evidence-backed.

Minimum conceptual fields:

```rust
pub struct Warrant {
    pub warrant_id: [u8; 16],
    pub finding_id: [u8; 16],
    pub reconciliation_result: ReconciliationResult,
    pub severity: Severity,
    pub evidence_strength: EvidenceStrength,
    pub response: ResponseClass,
    pub policy_version: u32,
    pub issued_at: u64,
    pub valid_until: Option<u64>,
    pub evidence_refs: Vec<EvidenceRef>,
}
```

Do not blindly copy this structure if equivalent repository types already exist.

The important property is that a warrant is not an unexplained boolean.

It must answer:

```text
What finding?
What evidence?
What result?
How severe?
How strong?
What policy?
What response?
When issued?
Until when valid?
```

---

# 17. WARRANT AUTHENTICITY

If warrants are serialized or transported across a trust boundary, they must
be authenticated.

Use the existing cryptographic primitives and canonical encoding facilities.

Do not invent a second signing implementation.

Do not reuse an agent signing key.

Do not reuse an observer signing key.

Do not reuse the decision-point signing key.

The warrant authority is a distinct authority boundary.

Any signing payload must:

1. use canonical encoding,
2. use domain separation,
3. include all security-relevant fields,
4. include temporal validity,
5. be injective,
6. have adversarial tests.

Never sign raw debug output or JSON serialization if the repository's
canonical protocol requires a binary canonical form.

---

# 18. DOMAIN SEPARATION

Every signed warrant structure must have a unique domain tag.

Conceptually:

```text
SYNTRIASS/GHOST/WARRANT/v1
```

Use the repository's established domain-separation mechanism if one exists.

Do not invent an incompatible parallel mechanism.

The following must never share a signing domain:

```text
ExpectedExecution
ObservedExecution
EvidencePacket
Warrant
ContainmentDecision
NEXORA anchor
```

A valid signature over one object must never become valid merely by
reinterpreting the bytes as another object.

---

# 19. TEMPORAL VALIDITY

If a warrant has:

```rust
valid_until
```

then that field must be cryptographically covered by the warrant signature.

Do not repeat the AIP `expires_at` defect.

Required adversarial test:

```text
create valid warrant
mutate valid_until
verify
assert rejection
```

Also test:

```text
mutate issued_at
verify
assert rejection
```

and:

```text
mutate response
verify
assert rejection
```

and:

```text
mutate evidence reference
verify
assert rejection
```

---

# 20. NO DIRECT ACTUATION

Skill 8 must not implement:

```text
kill
terminate
SIGKILL
cgroup freeze
network block
firewall rule
iptables
nftables
XDP drop
process isolation
```

or equivalent actuation.

The output of Skill 8 is:

```text
Warrant
```

or:

```text
NoWarrant / Alert
```

Skill 9 consumes the warrant.

This boundary must be enforced in code review and tests.

---

# 21. ACCOUNTABILITY

Every warrant must be traceable to evidence.

A warrant without an evidence reference is not containment authority.

At minimum:

```text
Warrant
  ↓
Reconciliation Result
  ↓
ExpectedExecution / ObservedExecution
  ↓
Evidence
```

Do not permit:

```text
anomaly → warrant
```

without the evidence chain.

---

# 22. TEST-FIRST IMPLEMENTATION

Before changing production warrant logic:

1. establish the existing baseline,
2. write adversarial tests,
3. prove the tests fail for the intended missing behaviour,
4. implement the minimum correction,
5. rerun the tests,
6. run the full relevant workspace test suite.

Do not weaken existing tests.

Do not delete adversarial tests because they expose architectural problems.

---

# 23. REQUIRED ADVERSARIAL TEST MATRIX

At minimum, implement tests for:

**Evidence-strength gate**

```text
Heuristic + Critical
    → Alert

Correlated + Critical
    → Alert

Attested + Critical
    → no Contain

Proven + Critical + autonomous enabled
    → Contain eligible
```

**Default policy**

```text
default policy
    → autonomous containment disabled
```

**CANNOT_PROVE**

```text
CANNOT_PROVE + Critical
    → never Contain
```

**Observation unavailable**

```text
OBSERVATION_UNAVAILABLE + Critical
    → never Contain
```

**Sensor degradation**

```text
DEGRADED + Critical
    → never Contain
```

**Continuity**

```text
CONTINUITY_FAILURE
    → never Contain
```

**Protected identity**

```text
Proven + Critical + protected identity
    → never autonomous Contain
```

**Operator enablement**

```text
Proven + Critical + autonomous disabled
    → no Contain
```

**Evidence references**

```text
Containment-capable warrant with no evidence reference
    → reject
```

**Severity/strength orthogonality**

Prove that changing severity does not change evidence strength.

Prove that changing evidence strength does not change severity.

**Tampering**

Mutate:

- finding_id,
- evidence_strength,
- severity,
- response,
- policy_version,
- issued_at,
- valid_until,
- evidence_refs.

Every mutation must invalidate an authenticated warrant.

---

# 24. PROPERTY TESTING

Where the repository's test framework permits it, add property-style tests.

Important properties:

```text
∀ severity:
    strength < Proven ⇒ response != Contain
```

```text
∀ degraded_sensor_state:
    response != Contain
```

```text
∀ CANNOT_PROVE:
    response != Contain
```

```text
∀ protected_identity:
    autonomous response != Contain
```

```text
changing severity
    ≠
changing evidence strength
```

Do not introduce a new property-testing dependency merely for this unless
the repository already uses one.

---

# 25. NO SCORE COLLAPSE

Reject implementations shaped like:

```rust
risk_score = severity * confidence;
```

or:

```rust
if confidence > 0.99 {
    contain();
}
```

or:

```rust
if severity >= Critical && confidence >= threshold {
    contain();
}
```

These violate the architecture.

A warrant predicate must inspect the evidence-strength enum explicitly.

The containment gate should be structurally obvious in code review.

Good:

```rust
match evidence_strength {
    EvidenceStrength::Proven => evaluate_proven_policy(...),
    EvidenceStrength::Attested => evaluate_attested_policy(...),
    EvidenceStrength::Correlated | EvidenceStrength::Heuristic => Alert,
}
```

Then apply:

```text
operator policy
+
protected identity
+
result-specific constraints
```

before producing `Contain`.

---

# 26. FAILURE BEHAVIOUR

Unknown or malformed input must not become containment.

Examples:

```text
unknown result
unknown evidence strength
unknown policy version
missing evidence reference
invalid temporal range
unverified warrant signature
protected identity uncertainty
observer continuity uncertainty
```

must result in:

```text
Alert
```

or:

```text
NoWarrant
```

never:

```text
Contain
```

Do not use panic-based security decisions.

Do not unwrap untrusted security inputs.

---

# 27. CODEBASE INTEGRATION

Before creating a new module:

1. search for existing severity types,
2. search for existing evidence-strength types,
3. search for response/warrant types,
4. search for policy types,
5. search for evidence-reference types,
6. search for canonical encoders,
7. search for domain-separation helpers,
8. search for signing/verification helpers.

Prefer extension over duplication.

Do not create a second:

```text
Severity
EvidenceStrength
ResponseClass
Policy
Signature
CanonicalEncoder
```

if equivalent authoritative types already exist.

If duplicates exist, report them.

Do not silently choose one.

---

# 28. PRODUCTION BOUNDARY

The Warrant Engine must not become an alternative authorization system.

A warrant says:

```text
given this evidence and this policy,
this response is permitted
```

It does not say:

```text
this action was authorized
```

That belongs to the decision point.

Likewise, the Warrant Engine must not sign:

```text
ExpectedExecution
```

and must not manufacture:

```text
ObservedExecution
```

---

# 29. REQUIRED REPORT

Create:

```text
docs/architecture/WARRANT_IMPLEMENTATION_REPORT.md
```

The report must contain:

```text
# Warrant Implementation Report

## Status
PASS / FAIL

## Preconditions
- Skill 3:
- Skill 4:
- Skill 5:
- Skill 6:
- Skill 7:

## Existing Implementation
What existed before Skill 8.

## Changes
Exact files and symbols changed.

## Severity Model
How severity is represented.

## Evidence Strength Model
How strength is represented.

## Orthogonality Proof
How the type system and tests prevent collapse.

## Warrant Gate
Exact rule preventing sub-Proven evidence from authorizing containment.

## Default Policy
How advisory mode is enforced.

## Protected Identities
How protection is represented.

## Evidence References
How warrants remain traceable.

## Temporal Integrity
How warrant validity is authenticated.

## Domain Separation
Exact mechanism used.

## Adversarial Tests
List every required test and result.

## Full Test Results
Commands and outcomes.

## Security Review
Threat → assumption → mechanism → implementation → test → limitation.

## Known Limitations
Anything not proven.

## Deferred Work
Containment and NEXORA work must remain explicitly deferred to their
respective skills.
```

Do not write `PASS` unless the implementation and tests justify it.

---

# 30. FINAL GATE

Skill 8 is PASS only when all are true:

```text
[ ] predecessor Skills 3–7 are PASS
[ ] severity exists independently
[ ] evidence strength exists independently
[ ] CANNOT_PROVE cannot become containment
[ ] OBSERVATION_UNAVAILABLE cannot become containment
[ ] degraded observation cannot become containment
[ ] Heuristic cannot become containment
[ ] Correlated cannot become containment
[ ] Attested cannot become containment without explicit policy
[ ] Containment requires Proven
[ ] autonomous containment defaults OFF
[ ] protected identities cannot be autonomously contained
[ ] warrant requires evidence references
[ ] signed warrant covers all security-relevant fields
[ ] temporal validity is signed
[ ] domain separation exists
[ ] canonical encoding is injective
[ ] no direct actuation exists
[ ] adversarial tests pass
[ ] full relevant test suite passes
[ ] WARRANT_IMPLEMENTATION_REPORT.md exists
[ ] report accurately states limitations
```

If any item is false:

```text
STATUS: FAIL
```

Do not conceal the failure by weakening the requirement.

---

# 31. IMPLEMENTATION ORDER

Use this exact order:

```text
1. Read all authoritative architecture artifacts.
2. Verify predecessor PASS states.
3. Inventory existing warrant/severity/strength/policy code.
4. Establish baseline tests.
5. Add adversarial tests.
6. Implement the minimum typed warrant model.
7. Implement the evidence-strength gate.
8. Implement policy evaluation.
9. Implement protected-identity handling.
10. Implement warrant authentication if required by the existing boundary.
11. Run targeted tests.
12. Run full relevant tests.
13. Perform security review.
14. Write WARRANT_IMPLEMENTATION_REPORT.md.
15. Only then declare PASS.
```

Never jump directly to containment implementation.

---

# 32. ABSOLUTE PROHIBITIONS

Do not:

- infer maliciousness from missing observation,
- infer execution from a failed sensor,
- collapse severity and strength,
- use confidence scores as containment authority,
- grant containment to `Attested` evidence automatically,
- grant containment to `CANNOT_PROVE`,
- create a second authorization engine,
- create an observer,
- create an execution binding,
- create reconciliation logic,
- execute containment,
- implement NEXORA,
- implement PQC,
- claim a cryptographic property that is not tested,
- mark the skill PASS while any required predecessor is unresolved,
- weaken an invariant to make the implementation pass.

The governing principle is:

A warrant is permission to act on proof, not proof itself.

Skill 8 establishes the gate.

Skill 9 may later implement the action behind that gate.

Skill 10 may later make the resulting history portable and independently
verifiable.

Until then, the Warrant Engine must remain a decision boundary, not an
actuator.
