# Execution identity graph — evidence mapping and remaining implementation

Status: design/mapping v1; a complete P0-057 graph exporter and authenticated
launch-to-logical-agent binding are **not implemented in this checkpoint**.
Existing typed bindings/reconciliation must be extended, not replaced by an AI
inference engine. No diagram or row below constitutes a successful new join.

| Relationship / identifier | Existing evidence source | Verification and limitation |
|---|---|---|
| Agent → key | Administrator-supplied `RunTrustConfig` | Verify configured key and signed records. Operator enrollment is external; display labels are insufficient. |
| Agent → delegation | AIP scoped/delegation tokens; ExpectedExecution `AuthorityRef` root/chain JTIs | Verify chain signatures, attenuation, validity, revocation and trusted issuer at authorization. A JTI reference alone is not the chain. |
| Delegation → tool request | Signed ExpectedExecution and signed gateway receipt | Exact decision ID, action and canonical parameter commitment; keep receipt timestamp/disposition separate. |
| Request → workload launch | Missing independently authenticated launch commitment in the general multi-agent profile | Leave unresolved. A shared UID, interpreter, parent, span ID or close timestamp cannot fill this edge. |
| Workload → process instance | `ExecutionBinding` and `ObservedProcess` | Require boot ID + PID + measured start ticks + executable hash, with available placement. This identifies a process image, not a logical sub-agent. |
| Parent → child | Bound lifecycle event and lineage comparator | Require exact parent/child instances and provenance. Recycled PID/unknown parent remains unresolved. |
| Process → namespace/cgroup | Kernel namespace inode tuple and optional cgroup sampling | Unknown remains unknown. P0-057 double-reads placement but does not establish continuous immobility. |
| Process → kernel event | Bound kernel event, timestamp, source mechanism and collector batch reference | A post-delivery measurement is not automatically historical event-time identity. Unbound events are retained. |
| Collector → evidence chain | Collector ID/key version, original signed batches, health, externally retained checkpoints | Check signatures, continuity, loss, clock and coverage; collector administrative independence requires deployment evidence. |
| Evidence → verdict | Existing native reconciliation and independently recomputed same-run evaluation | Preserve verdict/reason/strength/evidence refs. Request agreement cannot upgrade unsupported kernel action evidence. |
| Tenant/security domain → all nodes | Service tenant anchors and separately provisioned policy | Existing receipt v1 lacks a tenant field; require explicit trusted scoping. Never infer tenant from an agent-supplied label. |

The graph implementation must give each edge a source artifact hash, record
position, verification rule/version, status and limitation. Proposed statuses:
`VERIFIED_FOR_STATED_SCOPE`, `CLAIM_ONLY`, `UNRESOLVED`, `CONFLICTING`,
`INSUFFICIENT_COVERAGE`. Confidence is a deterministic evidence class, not a
model-generated probability. Include observed unattributed processes as nodes.

Next bounded engineering item: add an offline, versioned graph projection over
the existing native verified inputs, with no new positive verdict. Test wrong
tenant/key/decision ID, missing chain/launch commitment, shared interpreter,
PID reuse, duplicate events and conflicting bindings. Only then add an
authority-owned launch/request binding and prove it with fresh observations.
