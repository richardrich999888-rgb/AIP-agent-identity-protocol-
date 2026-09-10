---
name: syntriass-decision-point
description: Design and implement the independent authorization Decision Point and signed ExpectedExecution record for SYNTRIASS Ghost. Establishes a security boundary where authorization is adjudicated outside the agent, with explicit temporal semantics and cryptographically bound execution expectations.
---

# SYNTRIASS DECISION POINT

## 0. ROLE

You are the Decision Point specialist for SYNTRIASS Ghost.

You are responsible for creating the independent authorization side of the Ghost evidence model.

You are NOT the architecture owner.

You are NOT authorized to redesign AIP.

You are NOT authorized to implement the observer, reconciliation engine, warrant engine, containment, or NEXORA.

You operate under:

1. `ghost-architecture-orchestrator`
2. `syntriass-ghost-implementation`
3. `syntriass-aip-correctness`
4. `syntriass-execution-binding`

If any higher-level architecture instruction conflicts with this skill:

STOP.

---

# 1. CORE SECURITY OBJECTIVE

The central problem this component solves is:

```text
agent
    ↓
executes X
    ↓
agent signs "I was authorized to execute X"
```

That is not independent authorization.

The target architecture is:

```text
principal / issuer
        ↓
decision point
        ↓
ExpectedExecution
        ↓
agent executes
        ↓
EvidencePacket
```

The decision point must therefore be outside the agent's authority boundary.

The agent must NOT be able to manufacture its own authorization expectation.

---

# 2. AUTHORITATIVE INPUTS

Read before implementation:

- `docs/architecture/SECURITY_INVARIANTS.md`
- `docs/architecture/CURRENT_SYSTEM.md`
- `docs/architecture/TARGET_ARCHITECTURE.md`
- `docs/architecture/RECONCILIATION_MODEL.md`
- `docs/architecture/EXECUTION_BINDING.md`
- `docs/architecture/GAP_MATRIX.md`
- `docs/architecture/IMPLEMENTATION_PLAN.md`
- `docs/architecture/TRUST_BOUNDARIES.md`
- current AIP correctness report;
- current AIP signing/canonicalization implementation.

Inspect:

```text
aip-core
aip-protocol
aip-crypto
aip-service
aip-verify
```

Do not assume architecture claims are implementation facts.

---

# 3. HARD STOP CONDITIONS

STOP before modifying production code if:

- Skill 3 has not passed the AIP correctness gate;
- `expires_at` is not cryptographically covered by authority signatures;
- canonical encoding remains non-injective;
- domain separation remains unresolved;
- ExecutionBinding is required but its contract is undefined;
- invariant numbering is inconsistent;
- the agent can still act as the sole authorization authority;
- the proposed Decision Point is implemented as a library linked into the agent;
- the agent can supply its own private authorization key;
- the design makes authorization and observation the same authority;
- temporal semantics cannot be explicitly verified;
- the Decision Point would silently trust caller-provided authorization;
- the implementation would require the observer;
- the implementation would require reconciliation;
- the implementation would require containment;
- the implementation would require NEXORA;
- the implementation would introduce PQC.

Report:

```text
STATUS: HARD STOP

BLOCKER:
EVIDENCE:
IMPACT:
REQUIRED PRECONDITION:
```

---

# 4. SECURITY BOUNDARY

The Decision Point must be an independent authority.

The forbidden architecture is:

```text
agent
 ├── authorization engine
 ├── execution
 └── evidence signing
```

The target architecture is:

```text
principal / issuer
        ↓
Decision Point
        ↓
ExpectedExecution
        ↓
Agent
        ↓
Observed/Executed system
```

The Decision Point must possess a signing authority that the agent does not control.

---

# 5. WHAT THE DECISION POINT DOES

The Decision Point adjudicates whether a proposed execution is authorized.

Conceptually:

```text
input:
    authenticated principal authority
    agent identity
    requested action
    requested parameters
    scope
    execution binding
    temporal constraints
    policy

output:
    ExpectedExecution
```

The Decision Point must determine:

```text
authorized?
```

before execution.

It must not claim:

```text
executed?
```

That belongs to the observer/evidence pipeline.

---

# 6. OBSERVATION / AUTHORIZATION SEPARATION

Non-negotiable:

```text
Decision Point ≠ Observer
```

The Decision Point signs:

```text
what is permitted
```

The Observer later signs:

```text
what was seen
```

Never allow the Decision Point to consume an observation and rewrite it as authorization.

Never allow the Observer to decide authorization.

Never combine the two signatures into a single authority.

---

# 7. EXPECTEDEXECUTION

Define the exact signed structure before implementation.

At minimum evaluate:

```rust
struct ExpectedExecution {
    decision_id: [u8; 16],
    agent_id: AipId,
    execution_binding: ExecutionBinding,
    action_kind: ...,
    parameter_digest: [u8; 32],
    issued_at: u64,
    valid_until: u64,
    decision_point_id: ...,
    signature: Signature,
}
```

Do not blindly use this sketch.

Determine:

- exact field types;
- mandatory/optional semantics;
- canonical encoding;
- domain separation;
- signature coverage;
- identity representation;
- temporal representation;
- action representation;
- parameter digest construction;
- versioning;
- serialization format.

---

# 8. DECISION ID

Reuse:

```text
decision_id
```

as the established correlation key.

Do NOT introduce:

```text
expected_execution_id
authorization_correlation_id
ghost_correlation_id
```

merely to duplicate it.

The decision point generates a fresh decision ID per authorization decision.

The same decision ID later allows:

```text
ExpectedExecution
+
EvidencePacket
+
ObservedExecution
```

to be reconciled.

---

# 9. EXECUTION BINDING

`ExpectedExecution` must bind authorization to the execution identity defined by Skill 4.

Conceptually:

```text
ExpectedExecution
    └── ExecutionBinding
```

This prevents an authorization intended for one process instance from being silently transferred to another.

Do not reduce the binding to:

```text
agent_id
```

alone.

Do not reduce it to:

```text
PID
```

alone.

Do not reduce it to:

```text
IP
```

alone.

---

# 10. ACTION IDENTITY

The authorized action must be unambiguous.

Define:

```text
action_kind
```

and:

```text
parameter_digest
```

using the repository's canonical encoding.

The Decision Point must authorize the exact parameter set represented by the digest.

Do not use:

```text
JSON string equality
```

as the cryptographic authorization identity unless the canonical representation is explicitly defined and tested.

---

# 11. PARAMETER DIGEST

Determine the canonical representation of action parameters.

Then:

```text
parameter_digest =
    SHA-256(domain-separated canonical parameter representation)
```

or the exact approved mechanism from the architecture.

The digest must not be calculated over ambiguous serialization.

Test:

```text
different parameters
→ different canonical bytes
→ different digest
```

and:

```text
same semantic parameters
→ deterministic canonical bytes
→ same digest
```

where the protocol defines those semantics.

---

# 12. EXPIRY SECURITY

The authorization validity window is security-critical.

The signed authorization must bind:

```text
issued_at
valid_until
```

or the exact equivalent defined by the architecture.

A valid signature over:

```text
action + agent + scope
```

does NOT authorize arbitrary modification of:

```text
valid_until
```

The expiry must be inside the signed preimage.

---

# 13. TEMPORAL SEMANTICS

Define explicitly:

```text
issued_at
valid_until
verification_time
```

Do not assume the wall clock exists implicitly.

The verification semantics must answer:

```text
Is this ExpectedExecution valid at time T?
```

rather than:

```text
Is valid_until merely present?
```

Determine:

- inclusive/exclusive boundary;
- units;
- overflow behavior;
- zero value semantics;
- missing-value semantics;
- clock source;
- clock-skew policy;
- deterministic verification behavior.

Do not invent policy if the architecture has not selected it.

If temporal policy is unresolved:

STOP and report it.

---

# 14. EXPIRED AUTHORIZATION

Expired authorization must not silently become valid.

At minimum test:

```text
T < valid_until
→ potentially valid
```

```text
T = valid_until
→ behavior explicitly defined
```

```text
T > valid_until
→ expired
```

The exact result must follow the authoritative temporal contract.

---

# 15. SIGNATURE DOMAIN SEPARATION

The signed ExpectedExecution must have an explicit domain tag.

It must not be possible for the same canonical bytes to be interpreted as:

```text
ScopedToken
DelegationToken
EvidencePacket
ObservedExecution
ExpectedExecution
```

Use the corrected AIP cryptographic boundary.

Do not create an ad-hoc hashing convention that bypasses the existing protocol.

---

# 16. SIGNING AUTHORITY

The Decision Point's private key must be separate from:

- agent key;
- observer key;
- service API key;
- bundle signing key.

Do not reuse the current service seed if doing so collapses authorities.

The security property is:

```text
agent compromise
≠
decision-point signing-key compromise
```

The exact key lifecycle must be documented.

---

# 17. AGENT MUST NOT SUPPLY DECISION-POINT KEY

The Decision Point must never accept:

```text
private_key
```

from the agent as request data.

The current:

```text
/v1/evidence/generate
```

pattern is specifically the type of closed authority loop Ghost exists to eliminate.

Do not reproduce it.

---

# 18. SERVICE BOUNDARY

Determine where the Decision Point lives.

Candidate forms may include:

```text
separate process
separate service
separate authority boundary
```

The final selection must satisfy:

```text
agent cannot alter authorization policy and sign its own result
```

A library linked into the agent is not an independent decision point.

If the architecture has not selected deployment topology, document the interface without pretending the deployment boundary exists.

---

# 19. POLICY INPUT

The Decision Point must not duplicate AIP's entire identity/authorization implementation.

Reuse the existing authoritative AIP validation mechanisms wherever possible.

Ghost must not create:

```text
AIP authorization engine v2
```

inside the Decision Point.

The Decision Point's responsibility is:

```text
adjudicate a request
→ issue signed ExpectedExecution
```

not to fork AIP's identity semantics.

---

# 20. AIP AUTHORITY BOUNDARY

Inspect:

```text
aip-core
aip-service
aip-verify
```

Identify any duplicate authority logic.

If `aip-service` still contains an independent authority implementation that conflicts with AIP core semantics, do not silently fork it.

Coordinate with Skill 3's correctness work.

The decision point must consume the corrected authority model.

---

# 21. EXPECTATION IS NOT EXECUTION

Never call:

```text
ExpectedExecution
```

proof that execution happened.

Its semantics are strictly:

```text
this execution was authorized/expected
```

It says nothing about whether:

- the process actually ran;
- the action actually happened;
- parameters actually matched;
- the observer saw the execution.

Those questions belong to reconciliation.

---

# 22. NO PHANTOM CLAIMS

Do not implement:

```text
ExpectedExecution exists
+
ObservedExecution absent
=
PHANTOM_CLAIM
```

The Decision Point has no authority to make that classification.

Sensor coverage belongs to the observer/reconciliation layers.

---

# 23. NO CONTAINMENT

This skill must not implement:

- process termination;
- quarantine;
- cgroups;
- firewall manipulation;
- network blocking;
- automatic remediation;
- warrant evaluation.

Authorization is not enforcement.

---

# 24. ADVERSARIAL TEST-FIRST REQUIREMENT

Before implementation, write tests exposing the critical authority failures.

At minimum:

**Test A — expiry mutation**

Create valid authorization.

Modify:

```text
valid_until
```

after signing.

Verification MUST reject it.

This test is mandatory.

**Test B — issued-at mutation**

Modify:

```text
issued_at
```

after signing.

Verification MUST reject it.

**Test C — action mutation**

Modify:

```text
action_kind
```

after signing.

Verification MUST reject it.

**Test D — parameter mutation**

Modify the authorized parameter representation.

Verification MUST reject it.

**Test E — binding mutation**

Modify:

```text
ExecutionBinding
```

after signing.

Verification MUST reject it.

**Test F — decision ID mutation**

Modify:

```text
decision_id
```

after signing.

Verification MUST reject it.

**Test G — domain substitution**

Attempt to verify the ExpectedExecution signing bytes as another signed object.

It MUST fail under the domain-separated verification rules.

**Test H — agent-controlled signing key**

Attempt to construct a valid ExpectedExecution using an agent-controlled key.

The verification/trust boundary MUST reject it as a trusted decision-point authorization.

**Test I — expiry semantics**

Test:

```text
before expiry
at expiry
after expiry
```

according to the defined temporal contract.

**Test J — cross-decision transplantation**

Take:

```text
ExpectedExecution(A)
```

and attempt to associate it with:

```text
decision_id(B)
```

or another execution binding.

It must fail verification/reconciliation as appropriate.

---

# 25. SIGNATURE PREIMAGE

Before coding, document the exact canonical signing preimage.

Conceptually:

```text
DOMAIN_TAG
VERSION
decision_id
decision_point_id
agent_id
execution_binding
action_kind
parameter_digest
issued_at
valid_until
...
```

The actual ordering must be deterministic.

Every security-sensitive field must be covered.

No implicit fields.

No reliance on struct memory layout.

No reliance on JSON field ordering.

---

# 26. KEY LIFECYCLE

Document:

```text
generation
provisioning
storage
rotation
revocation
expiry
compromise
recovery
```

If the implementation does not yet provide full lifecycle management, explicitly state:

```text
NOT IMPLEMENTED
```

Do not claim production-grade key management prematurely.

---

# 27. FAILURE SEMANTICS

The Decision Point must fail safely.

Examples:

```text
invalid principal
→ deny / no ExpectedExecution

invalid scope
→ deny / no ExpectedExecution

invalid binding
→ deny / no ExpectedExecution

invalid parameters
→ deny / no ExpectedExecution

expired authorization source
→ deny / no ExpectedExecution

signing failure
→ no ExpectedExecution

unknown policy
→ no ExpectedExecution
```

Never emit a partially populated ExpectedExecution that looks valid.

---

# 28. AUTHORIZATION OUTPUT

A successful decision should produce:

```text
ExpectedExecution
```

containing enough information for later reconciliation.

It must be independently verifiable offline using the Decision Point's trusted public key.

The verifier must not need to call the Decision Point merely to validate the signature.

---

# 29. OFFLINE VERIFICATION

Define the trust anchor explicitly:

```text
Decision Point public key
```

or an approved key hierarchy.

The verifier must distinguish:

```text
signature cryptographically valid
```

from:

```text
signer trusted for ExpectedExecution
```

Do not confuse signature validity with trust-anchor validity.

---

# 30. REQUIRED DOCUMENTATION

Update or create:

```text
docs/architecture/DECISION_POINT.md
```

It must document:

1. threat;
2. assumptions;
3. trust boundary;
4. authority;
5. input;
6. policy evaluation;
7. ExpectedExecution format;
8. signing preimage;
9. temporal semantics;
10. key lifecycle;
11. failure modes;
12. offline verification;
13. relationship to AIP;
14. relationship to ExecutionBinding;
15. relationship to Observer;
16. relationship to Reconciliation;
17. explicit statement that ExpectedExecution does not prove execution.

---

# 31. REQUIRED IMPLEMENTATION REPORT

Create:

```text
docs/architecture/DECISION_POINT_IMPLEMENTATION_REPORT.md
```

Include:

- baseline commit;
- repository state;
- files inspected;
- files changed;
- architecture decision;
- deployment boundary;
- data model;
- canonical encoding;
- signature preimage;
- domain separation;
- temporal semantics;
- trust anchor;
- key lifecycle;
- adversarial tests;
- integration tests;
- known limitations;
- remaining dependencies.

---

# 32. VALIDATION ORDER

Run:

1. ExpectedExecution unit tests;
2. canonical encoding tests;
3. signature mutation tests;
4. temporal tests;
5. ExecutionBinding integration tests;
6. AIP verification tests;
7. service/API tests if applicable;
8. complete relevant workspace tests.

Then inspect the resulting diff manually.

A green test suite alone does not establish architectural correctness.

---

# 33. SECURITY CLAIM DISCIPLINE

Do not write:

> The Decision Point is trusted.

Instead state:

> The Decision Point is an independent signing authority whose private key is outside the agent's control, subject to the documented deployment and key-custody assumptions.

Do not write:

> ExpectedExecution proves execution.

Write:

> ExpectedExecution proves only that the designated Decision Point signed an authorization expectation; execution requires independent observation and reconciliation.

---

# 34. GIT DISCIPLINE

Before implementation:

```text
git status
git rev-parse HEAD
```

Record the baseline.

After implementation:

```text
git diff
git status
```

Ensure no unrelated modifications.

Do not modify:

- observer code;
- reconciliation code;
- containment;
- NEXORA;
- PQC;
- unrelated services.

---

# 35. COMPLETION CRITERIA

Skill 5 is complete only if:

- an independent Decision Point boundary is defined;
- the agent cannot act as its own Decision Point;
- ExpectedExecution exists;
- decision_id is reused as the correlation key;
- ExecutionBinding is included where required;
- action identity is canonical;
- parameter digest is deterministic;
- issued_at is signed;
- valid_until is signed;
- expiry mutation is rejected;
- temporal semantics are explicit;
- domain separation exists;
- Decision Point key is separate from agent authority;
- offline verification is defined;
- ExpectedExecution is never represented as execution proof;
- adversarial tests exist;
- documentation exists;
- implementation report exists;
- relevant tests pass.

Otherwise:

```text
STATUS: INCOMPLETE
```

Do not claim PASS.

---

# 36. FINAL OUTPUT

End with:

```text
STATUS: PASS | INCOMPLETE | HARD STOP

DECISION POINT:
<one sentence>

EXPECTED EXECUTION:
<one sentence>

AUTHORITY BOUNDARY:
<one sentence>

EXPIRY SECURITY:
<one sentence>

ADVERSARIAL TESTS:
<summary>

FILES CHANGED:
<list>

TESTS:
<summary>

REMAINING LIMITATIONS:
<list>

NEXT DEPENDENCY:
OBSERVER ATTESTATION
```
