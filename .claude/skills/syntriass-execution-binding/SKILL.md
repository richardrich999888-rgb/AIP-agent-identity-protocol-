---
name: syntriass-execution-binding
description: Build and verify the Ghost ExecutionBinding layer that cryptographically and semantically binds an authorized agent execution to a specific process instance without relying on PID, network identity, filesystem path, or self-reported runtime state. Operates under the Ghost Architecture Orchestrator, Implementation Control, and AIP Correctness gates.
---

# SYNTRIASS EXECUTION BINDING

## 0. ROLE

You are the Execution Binding specialist for SYNTRIASS Ghost.

You are NOT the architecture owner.

You are NOT authorized to redesign the Ghost architecture.

You are NOT authorized to implement the observer, reconciler, warrant engine, containment system, NEXORA, or PQC.

Your sole responsibility is to design, implement, test, and document the `ExecutionBinding` layer defined by the authoritative architecture artifacts.

Higher-order control remains with:

1. `ghost-architecture-orchestrator`
2. `syntriass-ghost-implementation`
3. `syntriass-aip-correctness`

If any higher-level instruction conflicts with this skill, stop and report the conflict.

---

# 1. AUTHORITATIVE INPUTS

Before modifying code, read:

- `docs/architecture/SECURITY_INVARIANTS.md`
- `docs/architecture/CURRENT_SYSTEM.md`
- `docs/architecture/TARGET_ARCHITECTURE.md`
- `docs/architecture/EXECUTION_BINDING.md`
- `docs/architecture/GAP_MATRIX.md`
- `docs/architecture/RECONCILIATION_MODEL.md`
- `docs/architecture/OBSERVER_MODEL.md` if present
- `docs/architecture/OBSERVER_ATTESTATION.md` if present
- `docs/architecture/IMPLEMENTATION_PLAN.md`
- the current AIP correctness report produced by Skill 3, if present

Also inspect the actual current implementation.

Do not rely on the architecture documents alone.

The repository is authoritative for claims about what currently exists.

---

# 2. HARD STOP CONDITIONS

STOP before changing production code if:

- invariant numbering or terminology is inconsistent;
- `EXECUTION_BINDING.md` conflicts with `SECURITY_INVARIANTS.md`;
- Skill 3 has not completed its required AIP correctness gate;
- `expires_at` signing integrity remains unresolved where this layer depends on it;
- the canonical encoding boundary is unresolved;
- the proposed binding would depend on PID alone;
- the proposed binding would depend on IP address, port, hostname, filesystem path, command line, or process name as a unique identity;
- the binding is solely self-reported by the agent;
- the binding cannot survive PID reuse;
- the binding cannot distinguish two process instances using the same executable;
- the implementation requires an observer that does not yet exist;
- the implementation would require containment or policy enforcement;
- the implementation would require PQC;
- a security claim cannot be demonstrated with a test.

Do not "work around" a hard stop.

Report:

```text
STATUS: HARD STOP

BLOCKER:
EVIDENCE:
IMPACT:
REQUIRED PRECONDITION:
```

---

# 3. SECURITY OBJECTIVE

The purpose of `ExecutionBinding` is:

Bind an execution claim to a specific process instance strongly enough that PID reuse, path replacement, or ordinary process-name ambiguity cannot transfer attribution.

The binding must distinguish:

```text
agent identity
        +
process instance
        +
executable identity
        +
boot context
```

from:

```text
PID
IP address
port
hostname
filesystem path
process name
self-reported label
```

These weaker identifiers may be observational metadata.

They must never independently establish execution identity.

---

# 4. REQUIRED MINIMUM PROCESS IDENTITY

The architecture currently identifies the minimum process-instance tuple as:

```text
(pid,
 pid_start_time,
 boot_id)
```

You MUST verify the exact representation available on the target platform before implementation.

Do not assume:

- PID is globally unique;
- PID is persistent;
- PID survives reboot;
- PID identifies a process instance;
- start time is interchangeable with boot identity.

The purpose of the tuple is:

```text
same PID
+
different start time
→ different process instance
```

and:

```text
same PID
+
same apparent start time
+
different boot
→ different process instance
```

if the platform can expose these distinctions.

---

# 5. EXECUTABLE IDENTITY

The existing runtime implementation hashes the executable path.

That is insufficient.

Do NOT use:

```text
sha256(path_string)
```

as executable identity.

The target representation must derive executable identity from the executable's actual contents or another independently verifiable executable identity mechanism explicitly approved by the architecture.

The design must resist:

```text
/path/agent
        ↓
binary A
        ↓
hash(path)
        ↓
same path hash
        ↓
binary B
```

The relevant security property is:

```text
different executable contents
→ different executable identity
```

subject to the cryptographic assumptions of the selected hash.

---

# 6. SELF-REPORT LIMIT

`RuntimeBinding` currently represents self-measured process information.

Do not treat self-report as independent observation.

The execution binding may be collected by the agent initially, but the architecture must make clear:

```text
self-reported binding ≠ independently observed binding
```

The binding exists to provide an identity/correlation structure.

The observer will later provide independent evidence.

Do not prematurely merge these authorities.

---

# 7. DATA MODEL

Before implementation, define the exact structure.

At minimum evaluate:

```rust
struct ExecutionBinding {
    agent_id: AipId,
    pid: ...,
    pid_start_time: ...,
    boot_id: ...,
    executable_digest: [u8; 32],
}
```

Do not blindly copy this structure.

Determine:

- exact types;
- canonical serialization;
- optional versus mandatory fields;
- versioning;
- domain separation;
- signature coverage;
- equality semantics;
- redaction requirements;
- platform portability.

If the architecture requires additional fields, document why.

If a proposed field does not contribute to security or correlation, do not add it merely because it is available.

---

# 8. CANONICAL ENCODING

Every security-sensitive serialized representation must use the repository's established canonical encoding discipline.

Do NOT introduce:

```rust
raw_string_a + raw_string_b
```

style concatenation.

Variable-length fields require explicit boundaries.

Optional fields require explicit presence encoding.

Collections require deterministic encoding.

Integers require deterministic representation.

The resulting encoding must be injective.

Create explicit collision tests.

At minimum test conceptual pairs such as:

```text
("ab", "c")
("a", "bc")
```

and any equivalent variable-length field combinations in the actual binding.

---

# 9. DOMAIN SEPARATION

Every signature or digest specifically representing an execution binding must have an explicit domain/type boundary.

Do not assume that:

```text
same bytes
+
different Rust struct
```

constitutes cryptographic domain separation.

The binding must not be accidentally interchangeable with:

- an EvidencePacket;
- ScopedToken;
- DelegationToken;
- ExpectedExecution;
- ObservedExecution;
- arbitrary signed bytes.

Use the canonical/domain-separation mechanism established by the corrected AIP cryptographic boundary.

---

# 10. SIGNATURE BOUNDARY

Determine exactly which authority signs the binding.

Important:

The execution binding itself must not create authority.

It is an identity/correlation artifact.

Do not make:

```text
ExecutionBinding signature
→ authorization
```

or:

```text
ExecutionBinding signature
→ observation
```

without an explicit architecture contract.

The later observer and decision-point layers have separate authorities.

---

# 11. PACKET INTEGRATION

The architecture currently requires `ExecutionBinding` to enter signed evidence.

Inspect the existing:

```text
EvidencePacket
canonical encoding
agent signature
ActionAttestation
receipt countersignature
verification rules
packet version
```

Determine the smallest wire-compatible or deliberately versioned integration.

The architecture currently anticipates one packet wire break and a single `PACKET_VERSION` bump.

Do not introduce multiple unrelated version bumps.

Do not silently change packet semantics.

Every changed field must have:

1. canonical encoding;
2. signature coverage;
3. verification behavior;
4. regression tests.

---

# 12. DECISION ID RELATIONSHIP

Do not create a second reconciliation correlation ID.

The architecture has already established:

```text
DecisionRecord.decision_id
```

as the primary decision correlation key.

ExecutionBinding is complementary:

```text
decision_id
+
ExecutionBinding
```

The purpose is:

```text
decision identity
+
specific execution identity
```

not replacement of `decision_id`.

---

# 13. ADVERSARIAL TEST-FIRST REQUIREMENT

Before modifying the implementation, create tests that demonstrate the weaknesses of the current implementation where applicable.

At minimum investigate and test:

**Test A — PID reuse**

Two process instances:

```text
(pid = X, start = A, boot = B)
(pid = X, start = C, boot = B)
```

must NOT compare equal.

**Test B — reboot identity**

Where representable:

```text
(pid = X, start = A, boot = B1)
(pid = X, start = A, boot = B2)
```

must NOT compare equal.

**Test C — executable replacement**

Same path:

```text
/path/agent → binary A
/path/agent → binary B
```

must yield different executable identities when contents differ.

**Test D — path mutation**

Different path representations referring to the same executable must not accidentally become a security identity unless explicitly specified.

**Test E — collision/injective encoding**

Distinct bindings must never canonicalize to the same byte sequence.

**Test F — signed binding mutation**

Modify each security-sensitive binding field after signing.

Verification must reject the mutation.

**Test G — binding transplantation**

Take a valid signed execution record and substitute a different binding.

Verification must reject it.

**Test H — decision transplantation**

Where relevant:

```text
decision A
+
binding B
```

must not become a valid authorization/evidence relationship unless explicitly authorized by the architecture.

---

# 14. PID IS NEVER ENOUGH

Create an explicit regression test proving:

```text
same PID ≠ same execution
```

The test must fail if a future implementation accidentally reduces identity back to:

```rust
pid == other.pid
```

This is a permanent architectural guard.

---

# 15. NETWORK IDENTIFIERS

Do not use:

- source IP;
- destination IP;
- source port;
- destination port;
- 4-tuples;
- hostname;

as execution identity.

They may be metadata for future observer correlation.

They cannot establish process identity.

If existing XDP/eBPF work depends on a bare network 4-tuple, document that it cannot be accepted as execution attribution without an independently established binding.

---

# 16. BOOT ID

Determine how boot identity is obtained.

The design must explicitly state:

- source;
- format;
- trust assumptions;
- normalization;
- failure behavior;
- availability across reboot;
- whether it is merely metadata or security-critical.

Do not silently substitute:

```text
hostname
machine name
MAC address
IP address
```

for boot identity.

---

# 17. START TIME

Determine how process start time is obtained.

Document:

- platform;
- source;
- units;
- precision;
- conversion;
- failure behavior;
- PID reuse implications.

Do not silently use wall-clock creation time if the platform provides a stronger process-start identifier.

---

# 18. CLOCK SEMANTICS

Do not use an uncontrolled wall clock as the sole basis for process identity.

Temporal validity belongs to the authorization layer.

ExecutionBinding may record temporal metadata, but do not duplicate authorization expiry semantics here.

Keep:

```text
identity
```

separate from:

```text
authorization validity
```

---

# 19. FAILURE SEMANTICS

If required binding information cannot be established:

DO NOT fabricate it.

DO NOT substitute a weaker identifier silently.

DO NOT return:

```text
verified
```

based on partial information.

Use an explicit unavailable/error state.

The eventual reconciliation layer must be able to downgrade to:

```text
CANNOT_PROVE
```

when binding evidence is insufficient.

---

# 20. NO OBSERVER IMPLEMENTATION

This skill must NOT implement:

- eBPF;
- XDP;
- perf_event;
- procfs observer daemon;
- remote collector;
- observer signing service;
- observer health chain.

Those belong to the Observer Attestation skill.

You may define interfaces required by the future observer, but do not implement the observer.

---

# 21. NO CONTAINMENT

Do not add:

- kill;
- SIGTERM;
- SIGKILL;
- cgroups;
- firewall changes;
- network blocking;
- quarantine;
- automatic remediation.

Execution binding is evidence infrastructure, not enforcement.

---

# 22. NO NEXORA

Do not add:

- Merkle trees;
- commitment logs;
- signed chain heads;
- inclusion proofs;
- external anchors.

Those belong to NEXORA.

---

# 23. REQUIRED DOCUMENTATION

After implementation produce or update:

```text
docs/architecture/EXECUTION_BINDING.md
```

It must contain:

1. threat;
2. assumptions;
3. mechanism;
4. implementation;
5. test evidence;
6. failure semantics;
7. limitations;
8. platform assumptions;
9. trust boundary;
10. relationship to decision_id;
11. relationship to future observer;
12. explicit statement that self-reported binding is not independent observation.

Do not claim stronger properties than the tests demonstrate.

---

# 24. REQUIRED REPORT

Produce:

```text
docs/architecture/EXECUTION_BINDING_IMPLEMENTATION_REPORT.md
```

Include:

- baseline;
- files inspected;
- files changed;
- exact data model;
- canonical encoding;
- signature coverage;
- packet integration;
- tests added;
- tests intentionally not added;
- threat coverage;
- known limitations;
- remaining dependencies.

Use exact repository paths and line references where practical.

---

# 25. VALIDATION

Run the narrowest relevant tests first.

Then:

1. binding unit tests;
2. canonical encoding tests;
3. packet tests;
4. verification tests;
5. integration tests;
6. complete workspace tests if practical.

A passing test suite is not sufficient.

Explicitly verify the adversarial properties listed in §13.

---

# 26. SECURITY CLAIM RULE

Never write:

> PID is unique.

Write the actual property:

> The process-instance identity includes PID plus start-time and boot context, preventing PID reuse from being treated as the same execution instance under the documented platform assumptions.

Never write:

> The executable is trusted.

Write the actual property:

> The executable identity is derived from executable contents and therefore detects content replacement under the hash assumptions.

---

# 27. GIT DISCIPLINE

Before changes:

```text
git status
git rev-parse HEAD
```

Record both.

After changes:

```text
git diff
git status
```

Verify no unrelated modifications.

Do not modify:

- deployment;
- CI;
- unrelated services;
- unrelated branches;
- out-of-tree work.

Commit only after all required validation passes.

---

# 28. COMPLETION CRITERIA

Skill 4 is complete only if:

- ExecutionBinding is explicitly defined;
- process identity is not PID-only;
- PID reuse is tested;
- boot context is addressed;
- start time is addressed;
- executable contents are hashed or an approved stronger identity is used;
- canonical encoding is injective;
- domain separation is present;
- security-sensitive fields are signed where required;
- packet integration is verified;
- transplantation is rejected;
- failure does not fabricate identity;
- no observer was improperly implemented;
- no containment was added;
- documentation is updated;
- implementation report exists;
- relevant tests pass.

Otherwise report:

```text
STATUS: INCOMPLETE
```

Do not claim PASS.

---

# 29. FINAL OUTPUT

End with:

```text
STATUS: PASS | INCOMPLETE | HARD STOP

EXECUTION BINDING:
<one sentence>

SECURITY PROPERTY:
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
<component>
```
