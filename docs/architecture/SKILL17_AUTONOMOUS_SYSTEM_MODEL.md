# Skill 17 — Autonomous System Model: specification and invariant matrix

**Status** SPECIFICATION. Written before implementation, per the skill's
required workflow step 2.

## 1. What already exists — reuse map

Inspected before designing anything. Existing AIP identifiers remain
authoritative where they already represent the concept.

| Concept | Existing primitive | Where | Reused as |
|---|---|---|---|
| Agent identity | `aip_id: String` (`aip1…`, pubkey+provenance derived) | `aip-crypto::derive_aip_id` | **reused verbatim** |
| Application execution instance | `execution_id: [u8; 16]`, `ExecutionId` | `aip-airi` | **reused verbatim** |
| Application lineage | `parent_execution_id: Option<[u8; 16]>` | `aip-airi` | **reused verbatim** |
| OS execution instance | `ProcessInstance { pid, pid_start_time_ticks, boot_id }` | `aip-types` | **reused verbatim** |
| Agent↔process binding | `ExecutionBinding` | `aip-types` | **reused verbatim** |
| Software identity | `exe_content_sha256: [u8; 32]` | `aip-types` | **reused verbatim** |
| Authority | `ScopedToken` / `DelegationToken` chains | `aip-core` | **referenced, never embedded** |
| Authorization instance | `decision_id: [u8; 16]` | `aip-authorize` | **reused verbatim** |
| Model/env/toolchain provenance | `ProvenanceTriple` | `aip-types` | **reused verbatim** |
| Canonical encoding | `aip_types::canonical::put_*` | `aip-types` | **reused verbatim** |

Genuinely absent, and therefore the only new identifiers introduced:

| Concept | Why nothing existing covers it |
|---|---|
| `SystemId` | No durable identity for the autonomous system as a thing in the world, persisting across agent versions, executions and compute swaps |
| `PlatformId` | No identity for a physical platform (airframe, chassis, hull) that outlives the compute inside it |
| `HardwareId` | `boot_id` identifies a *boot*, not a *machine*. A host rebooted is the same hardware with a different `boot_id` |
| `MissionId` | No task/mission context object |
| `SystemType` | No deployment category |
| `LifecycleState` | No system lifecycle |

Four new identifiers, one enum, one lifecycle. Nothing else.

## 2. The separation, and why each pair must not collapse

```
SystemId        the autonomous system as a durable thing
   │            (a UAS airframe programme, a robot, an enterprise agent product)
   │  is realised, per execution, as
   ▼
AgentId         the autonomous intelligence (AIP-ID) — versioned, replaceable
   │  running as
   ▼
ExecutionId     one execution instance of that intelligence
   │  bound to
   ▼
ExecutionBinding  pid + start ticks + boot id + exe content hash
   │  on
   ▼
HardwareId      the compute/host — survives reboots, replaceable in the field
   │  mounted in
   ▼
PlatformId      the physical platform — survives compute swaps
   │  tasked by
   ▼
MissionId       the mission/task context
```

Every arrow is many-to-many over time, which is precisely why the levels
cannot be merged:

- one platform runs different intelligences at different times (retrofit);
- one intelligence runs on different platforms (fleet);
- one intelligence has many concurrent executions (workers);
- one execution serves one mission, and a mission spans many executions;
- hardware is replaced without the platform changing identity;
- the platform is replaced without the system programme changing identity.

## 3. Design decisions

### D17-1 — `AutonomousSystem` carries no `agent_id`

The user's candidate field list places `agent_id` on the system. It is
deliberately **not** implemented that way: a system that names an agent is a
system fused to one intelligence version, which is the exact collapse the
skill prohibits. `agent_id` lives on `SystemExecution`, where the binding is
actually made and is actually true for a bounded interval.

### D17-2 — Two platform fields, on purpose

`AutonomousSystem.platform` is the platform the system is **registered** as.
`SystemExecution.platform_id` is the platform an execution **ran on**. They
are separate fields and a disagreement between them is *representable* — that
is the point. Detecting one is downstream reconciliation's job, not this
layer's, and this layer must not pre-empt it by making them one field.

### D17-3 — Descriptors, not trust anchors

`AutonomousSystem` and `SystemExecution` are **unsigned descriptors**. They
carry no key, no token, no scope, no signature. Integrity comes from
embedding their canonical bytes in something already signed.

Introducing a new signing key here would be introducing a new trust anchor,
which is a declared STOP condition. It is not needed: everything this model
describes is already anchored by an existing artifact.

### D17-4 — Authority is referenced, never embedded

`AuthorityContext` holds a `decision_id` and an optional root-token JTI. It is
a *citation*, not a grant. It cannot be constructed into a permission, and no
code in the crate reads it to decide anything.

### D17-5 — Profiles are commitments, not content

Skill 17 is the universal abstraction; vertical profiles arrive in Skills
18-27. A profile is therefore a `ProfileRef { kind, id, digest }` — a
domain-separated commitment to a document defined elsewhere. The core commits
to a profile without knowing its content, so adding UAS or industrial
profiles later requires no change here and no schema fork.

### D17-6 — New crate, one direction of dependency

`aip-system` depends on `aip-types` and `aip-crypto` only. Nothing in
`aip-reconcile`, `aip-warrant`, `aip-containment`, `aip-nexora` or `aip-airi`
depends on it, and it depends on none of them. A description layer that the
verdict layers cannot see cannot cause a semantic regression in them.

### D17-7 — Lifecycle is a record, not a gate

`LifecycleState` describes where a system is in its life. It grants nothing,
and no transition confers authority. `Authorized` is a *recorded observation
that an authorization exists elsewhere*, not the authorization.

## 4. Invariant matrix

| ID | Invariant | Enforced by |
|---|---|---|
| S17-1 | Agent identity is never platform identity | distinct types; no conversion |
| S17-2 | Execution identity is never hardware identity | distinct types; no conversion |
| S17-3 | Mission identity is never agent identity | distinct types; no conversion |
| S17-4 | Constructing a system or execution grants no authority | no key/token/scope field exists |
| S17-5 | Parent→child lineage transfers no permission | `parent_execution_id` is data; nothing reads it for a decision |
| S17-6 | One agent may have many executions | `SystemExecution` is per-execution |
| S17-7 | One platform may host different agents over time | `platform_id` is per-execution |
| S17-8 | An execution cannot silently change platform | platform is inside the canonical bytes |
| S17-9 | Identity transplantation is detectable | every id is in the canonical encoding, injectively |
| S17-10 | Round trip preserves relationships | serde + canonical equality test |
| S17-11 | Malformed identifiers fail closed | validated constructors; no public raw field |
| S17-12 | Unknown versions are refused, never guessed | explicit version check |
| S17-13 | Unknown system types are refused | closed enum, no `Other` escape |
| S17-14 | Existing AIP identity semantics unchanged | no edit to `aip-types`/`aip-crypto`/`aip-core` |
| S17-15 | Existing AIRI semantics unchanged | no edit to `aip-airi` |
| S17-16 | Lifecycle state is not a trust anchor | no code branches on it for a decision |
| S17-17 | Canonical encoding is domain-separated and injective | `put_domain` + length-prefixed fields |
| S17-18 | Registered platform ≠ executed platform | separate fields, both encoded |

## 5. Compatibility

- No existing public structure is modified. No wire format changes.
- No existing serialized data is reinterpreted.
- `aip-system` is additive: a workspace member nothing else depends on.
- Versioning follows the repository philosophy — unknown versions are
  **refused**, not guessed. `AUTONOMOUS_SYSTEM_VERSION = 1` is the only
  version this code accepts.

## 6. Out of scope for Skill 17

Vertical profiles (UAS, UGV, robotics, industrial, critical edge, space,
enterprise), the Linux edge reference, hardware attestation, and any change to
reconciliation, warrant, containment, NEXORA or AIRI semantics.
