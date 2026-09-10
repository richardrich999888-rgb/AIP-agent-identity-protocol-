---
name: syntriass-ghost-containment
description: Implements and verifies the Ghost containment boundary. Containment may only consume an independently produced, valid warrant and must never manufacture, upgrade, infer, or bypass evidence or authorization. Enforces advisory-by-default operation, Proven-evidence gating, explicit operator enablement, protected-identity exemptions, fail-open actuation errors, complete accountability records, and adversarial tests proving suspicion can never reach containment.
---

# SYNTRIASS GHOST — CONTAINMENT ENGINEERING SKILL

## 1. ROLE

You are the containment-stage implementation specialist for SYNTRIASS Ghost.

Your responsibility is to implement and verify the containment boundary only after
the complete upstream evidence chain exists.

Containment is a privileged response surface.

It is NOT:

- a detector;
- an observer;
- a reconciler;
- a warrant generator;
- a severity calculator;
- an authorization authority;
- a replacement for AIP verification.

Containment consumes an already-valid warrant.

It must never manufacture one.

---

## 2. HARD DEPENDENCY GATE

Before inspecting or modifying containment implementation, verify PASS artifacts
for:

1. `syntriass-aip-correctness`
2. `ghost-execution-binding`
3. `ghost-decision-point`
4. `ghost-observer`
5. `ghost-reconciliation`
6. `syntriass-ghost-warrant`

Read their implementation reports and the following architecture artifacts:

- `docs/architecture/SECURITY_INVARIANTS.md`
- `docs/architecture/TARGET_ARCHITECTURE.md`
- `docs/architecture/GAP_MATRIX.md`
- `docs/architecture/CONTAINMENT_MODEL.md`
- `docs/architecture/RECONCILIATION_MODEL.md`
- `docs/architecture/OBSERVER_ATTESTATION.md`
- `docs/architecture/EXECUTION_BINDING.md`

If any required predecessor is:

- missing;
- BLOCKED;
- FAILED;
- incomplete;
- ambiguous;
- or lacks its required implementation report;

STOP.

Do not implement containment.

Return:

```text
STATUS: BLOCKED

BLOCKING PREDECESSOR:
<skill>

REQUIRED ARTIFACT:
<missing or failed artifact>

REASON:
<why containment cannot safely proceed>
```

---

## 3. ABSOLUTE ARCHITECTURAL RULE

Containment must have this shape:

```text
Observation
    ↓
Evidence
    ↓
Reconciliation
    ↓
Evidence Strength
    ↓
Warrant
    ↓
Containment Decision
    ↓
Containment Actuation
```

The implementation MUST NOT permit:

```text
anomaly → containment

severity → containment

confidence → containment

risk_score → containment

trusted=true → containment

observed=true → containment

PHANTOM_CLAIM → containment

CANNOT_PROVE → containment

OBSERVATION_UNAVAILABLE → containment
```

The only permitted path is:

```text
valid Warrant
    +
explicit containment policy
    +
explicit operator enablement where required
    +
target eligibility
    +
validity window
    ↓
ContainmentDecision
    ↓
Actuation
```

---

## 4. CURRENT-STATE VERIFICATION

Before adding any actuation code, establish the actual current state.

Search production code for:

- `kill`
- `SIGKILL`
- `SIGTERM`
- `terminate`
- `cgroup`
- `freeze`
- `iptables`
- `nftables`
- `firewall`
- `XDP`
- `drop`
- `isolate`
- `quarantine`
- `contain`
- process termination APIs
- network blocking APIs

Do not assume absence.

Prove it.

If containment already exists, inspect it before changing anything.

If an implementation exists outside HEAD, treat it as design input only unless
it is part of the current production tree.

---

## 5. THREAT MODEL

Containment must document:

**THREAT**

An attacker may:

- forge or alter observations;
- manipulate severity;
- induce false positives;
- replay evidence;
- manipulate reconciliation inputs;
- attempt to manufacture a warrant;
- present stale warrants;
- present expired warrants;
- modify containment parameters;
- induce containment failures;
- target protected infrastructure;
- compromise an application process;
- attempt to cause denial of service through the response mechanism.

**ASSUMPTIONS**

Explicitly record:

- which component holds the warrant authority;
- which component holds the containment authority;
- which component performs actuation;
- what the containment TCB is;
- what happens if the warrant store is compromised;
- what happens if the control plane is unavailable;
- what happens if the target disappears before actuation.

Do not invent assumptions.

If the repository cannot establish one, record:

`NOT DETERMINABLE FROM CURRENT CODEBASE`.

**MECHANISM**

Containment must validate:

1. warrant authenticity;
2. warrant validity window;
3. warrant evidence reference;
4. reconciliation result;
5. evidence strength;
6. required policy predicate;
7. operator enablement;
8. target eligibility;
9. protected-identity exemption;
10. containment action authorization.

---

## 6. EVIDENCE STRENGTH GATE

Containment MUST require:

```text
EvidenceStrength::Proven
```

or the exact equivalent established by the warrant skill.

The following MUST NOT authorize containment:

```text
Heuristic
Correlated
Attested
```

unless the upstream architecture explicitly changes this rule and the change is
recorded in the authoritative architecture artifacts before implementation.

Do not create a numeric substitute.

Do not implement:

```rust
severity * confidence
```

or any equivalent scalar.

Do not implement:

```rust
if severity >= Critical { contain(); }
```

Do not implement:

```rust
if confidence > 0.99 { contain(); }
```

Do not implement:

```rust
if trusted { contain(); }
```

The warrant is the gate.

---

## 7. WARRANT MUST BE AN INPUT

Containment must accept a validated warrant as an input.

It must not:

- create a warrant;
- upgrade a warrant;
- reinterpret evidence strength;
- recompute severity to bypass policy;
- turn an alert into a warrant;
- convert `CANNOT_PROVE` into a positive claim;
- convert `OBSERVATION_UNAVAILABLE` into a malicious-execution finding.

Conceptually:

```rust
fn contain(
    warrant: &ValidWarrant,
    target: &ContainmentTarget,
    policy: &ContainmentPolicy,
) -> Result<ContainmentResult, ContainmentError>;
```

The exact implementation may differ.

The important property is that a caller cannot reach actuation using a raw
finding or raw severity value.

---

## 8. TYPE-LEVEL GATE

The implementation must structurally prevent bypass.

Prefer types such as:

```text
Finding
    ↓
Warrant
    ↓
ValidatedWarrant
    ↓
ContainmentDecision
    ↓
Actuation
```

rather than:

```text
Finding
    ↓
Containment
```

A raw `Finding` must not be sufficient input to actuation.

A raw `Severity` must not be sufficient input to actuation.

A raw `EvidenceStrength` must not be sufficient input to actuation.

A boolean such as:

```text
trusted
approved
dangerous
high_confidence
authorized
```

must not substitute for a cryptographically/evidentially validated warrant.

---

## 9. WARRANT VALIDATION

Before actuation, validate:

**Authenticity**

The warrant must be authenticated under the designated warrant trust root.

**Integrity**

All security-relevant warrant fields must be covered by the warrant signature.

**Temporal validity**

Validate:

```text
issued_at
valid_until
current verification time
```

according to the warrant contract.

Never rely on an unsigned or caller-supplied expiry.

Add an adversarial test that mutates `valid_until` and proves the modified warrant
cannot authorize containment.

**Evidence reference**

The warrant must reference the evidence/reconciliation result that justified it.

A warrant without an evidence reference must not authorize containment.

**Strength**

The referenced evidence must satisfy the required `Proven` gate.

**Target binding**

The warrant must be bound to the target identity defined by the architecture.

Do not substitute:

- IP address;
- hostname;
- PID alone;
- mutable path;
- process name alone.

---

## 10. OPERATOR ENABLEMENT

Default configuration:

```text
mode = advisory
autonomous_containment = false
```

A deployment must not become autonomously destructive merely because the
containment component is installed.

Explicitly represent:

```text
Advisory
OperatorEnabled
AutonomousEnabled
```

or the equivalent architecture-approved states.

Do not use absence of configuration as permission.

Fail toward:

```text
NO CONTAINMENT
```

when autonomous enablement is absent or invalid.

---

## 11. PROTECTED IDENTITIES

Containment must support protected identities.

At minimum the design must be able to exempt:

- control plane;
- warrant authority;
- observer infrastructure;
- reconciliation infrastructure;
- operator access path;
- explicitly protected workloads.

The exact protected set must come from the architecture/product policy.

Do not invent a universal protected list.

A protected target must not be autonomously contained merely because a valid
finding exists.

---

## 12. FAIL-OPEN ACTUATION

Containment failures must fail open.

Meaning:

```text
actuation failure
    ↓
DO NOT RETRY DESTRUCTIVELY BY DEFAULT
    ↓
record failure
    ↓
emit evidence
```

Do NOT interpret:

```text
containment command failed
```

as:

```text
target is malicious
```

Do not turn response failure into additional evidence strength.

---

## 13. IDEMPOTENCY

Containment commands must be idempotent where technically possible.

A replayed valid containment decision must not accidentally cause:

- repeated destructive actions;
- escalating actions;
- repeated process termination;
- repeated network disruption.

Use a stable containment action identifier derived from the authorized
containment decision.

Do not invent a second identity system if an existing decision/warrant ID can
safely serve the purpose.

---

## 14. REPLAY PROTECTION

Containment must explicitly address replay.

A previously consumed containment warrant/action must not silently become a new
authorization event.

The implementation must define:

- uniqueness key;
- consumed state;
- persistence requirements;
- restart behavior;
- rollback behavior.

If replay protection cannot yet be guaranteed, containment must fail safely to:

```text
NO CONTAINMENT
```

and record the limitation.

---

## 15. CONTAINMENT TARGET

The target must be bound to the execution identity established upstream.

Do not identify a target solely by:

```text
PID
IP
port
hostname
process name
file path
```

Where execution binding exists, use it.

If target identity cannot be established:

```text
CANNOT_PROVE_TARGET
```

and do not contain.

---

## 16. ACTION ENUMERATION

Containment actions must be explicit.

Do not expose arbitrary shell execution such as:

```text
Command::Raw(String)
```

as the containment interface.

Prefer a closed action set such as:

```text
ContainmentAction
    ├── AdvisoryOnly
    ├── QuarantineProcess
    ├── NetworkIsolation
    └── ...
```

Only include actions actually supported and authorized by the product.

Do not add actuation capabilities merely because an enum could contain them.

Every action requires:

- explicit policy;
- explicit authorization;
- target binding;
- audit record;
- test coverage.

---

## 17. NO SHELL ESCAPE HATCH

Do not implement containment through arbitrary:

```text
sh -c
bash -c
system()
exec()
```

or equivalent caller-controlled command strings.

If OS-level actuation is required, use a constrained API with explicit typed
parameters.

Never allow a warrant to carry an arbitrary executable command.

---

## 18. CONTAINMENT DECISION

Create an explicit decision object between warrant validation and actuation.

Conceptually:

```text
ValidatedWarrant
       +
ContainmentPolicy
       +
OperatorState
       +
TargetState
       ↓
ContainmentDecision
       ↓
Actuator
```

The decision must record:

- decision ID;
- warrant ID;
- evidence reference;
- target identity;
- action;
- policy rule;
- operator/autonomous authorization state;
- decision timestamp;
- validity;
- result.

The decision itself becomes evidence.

---

## 19. ACCOUNTABILITY

Every attempted containment must produce an accountable record.

At minimum:

```text
ContainmentAttempt {
    action_id
    warrant_id
    evidence_reference
    target_binding
    action
    policy
    decision_time
    result
}
```

The exact fields must follow the architecture and canonical encoding rules.

Security-relevant fields must be authenticated/sealed according to the existing
evidence protocol.

Do not create a parallel cryptographic model.

Reuse the established AIP signing/canonicalization infrastructure where
appropriate.

---

## 20. CONTAINMENT MUST NOT BECOME A NEW AUTHORITY

Containment cannot decide that something was unauthorized.

Containment cannot decide that an observation was genuine.

Containment cannot decide that evidence is Proven.

Containment cannot issue a warrant.

Containment cannot reinterpret the reconciliation result.

Those decisions belong upstream.

Containment is the final consumer.

---

## 21. AUDITABILITY

A third party must be able to determine:

```text
Why was containment attempted?
Which warrant authorized it?
Which evidence supported the warrant?
Which reconciliation result existed?
What evidence strength existed?
Which policy allowed the action?
Was autonomous mode enabled?
Which target was selected?
What action was attempted?
What happened?
```

If the implementation cannot answer these questions, record the limitation.

---

## 22. ADVERSARIAL TESTS — REQUIRED

The implementation is not complete without tests demonstrating that:

**Test 1 — heuristic cannot contain**

A `Heuristic` finding must not produce containment.

**Test 2 — correlated cannot contain**

A `Correlated` finding must not produce containment.

**Test 3 — attested cannot contain**

An `Attested` finding must not produce autonomous containment.

**Test 4 — CANNOT_PROVE cannot contain**

`CANNOT_PROVE` must never reach actuation.

**Test 5 — observation unavailable cannot contain**

`OBSERVATION_UNAVAILABLE` must never reach actuation.

**Test 6 — severity cannot bypass warrant**

Critical severity without a valid warrant must not contain.

**Test 7 — confidence cannot bypass warrant**

Any confidence value without a valid warrant must not contain.

**Test 8 — stale warrant rejected**

An expired warrant must not authorize containment.

**Test 9 — mutated warrant rejected**

Mutation of a security-relevant warrant field must invalidate authorization.

**Test 10 — wrong evidence reference rejected**

A warrant referring to evidence other than the verified result must fail.

**Test 11 — wrong target rejected**

A warrant for target A must not authorize containment of target B.

**Test 12 — protected target rejected**

A protected identity must not be autonomously contained.

**Test 13 — autonomous mode disabled**

A valid Proven warrant must not autonomously actuate when autonomous mode is
disabled.

**Test 14 — replay rejected**

A consumed containment authorization must not silently authorize another
destructive action.

**Test 15 — actuation failure is non-escalating**

An actuation failure must not increase evidence strength or create a new
malicious-execution verdict.

**Test 16 — arbitrary command rejected**

Caller-controlled shell/command strings must not be accepted as containment
actions.

**Test 17 — missing target identity**

Unbound target identity must not authorize containment.

**Test 18 — warrant manipulation**

Changing action, target, evidence reference, validity, or policy-relevant
fields must invalidate the warrant.

---

## 23. NO DIRECT ACTUATION BEFORE GATES

If the repository does not yet have all prerequisites required to safely
implement real actuation, do NOT add real actuation merely to satisfy the
interface.

It is acceptable to implement:

```text
ContainmentDecision
```

and a non-destructive actuator abstraction while keeping actual actuation
disabled.

It is NOT acceptable to fake a successful containment result.

Never report:

```text
contained = true
```

unless the action actually occurred.

---

## 24. ADVISORY MODE

The default production posture must be:

```text
detect
→ reconcile
→ warrant
→ containment decision
→ advisory result
```

with no autonomous destructive action unless explicitly enabled.

This allows deployment and validation without immediately introducing fleet-wide
denial-of-service risk.

---

## 25. OBSERVATION DEGRADATION

Containment must explicitly reject:

```text
OBSERVATION_UNAVAILABLE
CONTINUITY_FAILURE
SENSOR_INTEGRITY_FAILURE
CANNOT_PROVE
```

unless the upstream architecture explicitly defines a Proven warrant that
independently establishes the required security fact.

Never infer:

```text
sensor disappeared
    =
target malicious
```

Never infer:

```text
observer stopped
    =
execution occurred
```

Never infer:

```text
no observation
    =
no execution
```

---

## 26. PROTECTED CONTROL PLANE

The containment path must not be able to self-disable the system's own
accountability infrastructure.

Prevent autonomous containment of:

- warrant authority;
- observer trust root;
- reconciliation service;
- containment policy authority;
- operator recovery path;

where the architecture defines them as protected.

If a protected identity cannot be reliably established, default to no autonomous
containment.

---

## 27. SECURITY CLAIM DISCIPLINE

Every implemented security property must have:

```text
THREAT
ASSUMPTION
MECHANISM
IMPLEMENTATION
TEST
LIMITATION
```

Do not claim:

- fail-safe containment;
- secure isolation;
- cryptographically authorized containment;
- autonomous safety;
- attack-proof response;

unless the implementation and tests establish the precise property.

---

## 28. OUT-OF-TREE CODE

Do not copy containment code from unmerged branches merely because it appears
complete.

If prior-art implementation exists outside HEAD:

1. inspect it;
2. identify useful design concepts;
3. verify them against current architecture;
4. reimplement only what is justified;
5. never treat the branch as production evidence.

---

## 29. NO SCOPE CREEP

During this skill, do NOT implement:

- NEXORA;
- Merkle commitment protocol;
- PQC;
- new observer mechanisms;
- new authorization systems;
- new reconciliation logic;
- arbitrary policy engines unrelated to containment;
- unrelated AIP refactors.

If a prerequisite defect is discovered, stop at the appropriate boundary and
report it rather than silently expanding scope.

---

## 30. FINAL GATE

Containment implementation may PASS only if all are true:

- Skills 3–8 have explicit PASS artifacts.
- Warrant authenticity is verified.
- Warrant temporal validity is verified.
- Warrant security fields are signature-covered.
- Evidence reference is mandatory.
- `Proven` evidence is required for containment.
- Severity cannot bypass the warrant gate.
- Confidence cannot bypass the warrant gate.
- `CANNOT_PROVE` cannot contain.
- `OBSERVATION_UNAVAILABLE` cannot contain.
- protected identities cannot be autonomously contained.
- autonomous containment defaults OFF.
- operator/advisory semantics are explicit.
- target identity is bound.
- replay is addressed.
- arbitrary command execution is impossible through the containment API.
- containment attempts are accountable.
- actuation failures do not escalate evidence.
- adversarial tests exist and pass.
- no direct actuation path bypasses warrant validation.
- no unrelated production capability was introduced.
- documentation reflects actual implementation.
- limitations are explicitly recorded.

If any item fails:

```text
STATUS: FAIL
```

Do not declare partial success as PASS.

---

## 31. REQUIRED IMPLEMENTATION REPORT

Create:

```text
docs/architecture/CONTAINMENT_IMPLEMENTATION_REPORT.md
```

The report must contain:

```text
# Containment Implementation Report

## Status

PASS / FAIL / BLOCKED

## Preconditions

Skills 3–8 and their report statuses.

## Current State

What existed before implementation.

## Threat Model

THREAT
ASSUMPTION
MECHANISM

## Implementation

Exact components implemented.

## Warrant Gate

How the implementation proves that only valid warrants reach containment.

## Evidence Gate

How Proven evidence is enforced.

## Target Binding

How target identity is established.

## Operator Controls

Advisory/autonomous behavior.

## Protected Identities

How exemptions work.

## Replay

How replay is handled.

## Accountability

How containment actions become evidence.

## Tests

List every adversarial test and its result.

## Security Properties Proven

Only properties actually demonstrated.

## Limitations

Known gaps.

## Deferred

Explicitly deferred work.

## Files Changed

Exact list.

## Final Gate

PASS / FAIL / BLOCKED
```

---

## 32. ABSOLUTE PROHIBITIONS

Never:

1. implement `anomaly → kill`;
2. implement `severity → containment`;
3. implement `confidence → containment`;
4. implement `risk_score → containment`;
5. implement `trusted=true → containment`;
6. allow raw findings to actuate;
7. manufacture a warrant;
8. upgrade evidence strength;
9. infer execution from observation silence;
10. treat sensor failure as malicious execution;
11. bypass target binding;
12. accept unsigned expiry;
13. accept arbitrary shell commands;
14. contain protected infrastructure autonomously;
15. silently fail closed into destructive action;
16. claim containment succeeded when it did not;
17. copy unmerged production capability into HEAD without validation;
18. implement NEXORA during this stage;
19. implement PQC during this stage;
20. weaken adversarial tests to obtain PASS.

---

## 33. EXECUTION INSTRUCTION

Start with inspection.

Do not modify production code until:

1. predecessor PASS artifacts are verified;
2. current containment state is established;
3. the threat model is grounded in the repository;
4. the existing warrant interface is understood.

Then implement the smallest coherent containment boundary.

After every meaningful change:

- format;
- compile;
- run focused tests;
- run adversarial tests;
- inspect diff;
- verify no unrelated files changed.

At completion, produce the required implementation report.

Final response must state:

```text
STATUS:
ACTIVE SKILL:
HEAD:
FILES CHANGED:
TESTS ADDED:
TESTS RUN:
SECURITY PROPERTIES PROVEN:
LIMITATIONS:
NEXT PERMITTED STAGE:
```

If blocked, stop immediately and report the exact blocker.

Do not continue into NEXORA until this skill produces an explicit PASS.
