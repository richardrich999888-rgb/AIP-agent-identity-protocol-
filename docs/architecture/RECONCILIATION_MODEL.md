# RECONCILIATION_MODEL

> **Status (Stage 4 `ad9642a`, corrected `b821a23`; Stage 7 action evidence
> `63c5e0a`; Stage 7b transition evidence; Stage 7c process execution
> `1d52f93`): PARTIALLY_IMPLEMENTED** in `aip-standalone/aip-reconcile`. The
> contract in §3–§5 below is implemented as written, with `CANNOT_PROVE` as
> the `Default`. Reachable results: `CANNOT_PROVE`, `PHANTOM_CLAIM`,
> `IDENTITY_DIVERGENCE`, `SENSOR_INTEGRITY_FAILURE`, `CONTINUITY_FAILURE`, and —
> **for exactly three action classes** — `VERIFIED_EXECUTION` at `Attested`:
> an established TCP connection authorized as `ghost.net.connect.v1`, in two
> distinguishable kinds, `Presence` (a table row: the connection existed at
> the sample) and `Transition` (the kernel reported it being made;
> `ACTION_EVIDENCE.md` §14); a process execution authorized as
> `ghost.process.exec.v1` (the kernel reported the bound instance forking a
> child that executed an image whose content hash is the authorized one;
> `Transition` only; `ACTION_EVIDENCE.md` §15); and, since Gate 3
> (`4e4bd6a`), a socket send authorized as `ghost.net.send.v1` (the kernel
> reported the bound instance handing bytes to a socket whose attested
> transitions name the authorized endpoint; the count, never the bytes;
> `Transition` only; `ACTION_EVIDENCE.md` §16). Unreachable with the current evidence and stated so
> in code: `VERIFIED_EXECUTION` for every other action kind (no action-level
> observation exists), `UNATTRIBUTED_EFFECT` (requires a decision-point-signed
> completeness statement that nothing produces yet). `LINEAGE_VIOLATION` is
> reachable since Phase C2 (`6dcec84`, see below) through `reconcile_lineage`
> only, on complete two-sided evidence. Since Gate 2 (`57849bd`) the record
> is version 5 and carries `wire: WireCorroboration`, the device layer's
> answer to a socket-layer transition verdict ("The wire question" below);
> it never changes the verdict or the strength. See
> `RECONCILIATION_IMPLEMENTATION_REPORT.md` and
> `ACTION_EVIDENCE_IMPLEMENTATION_REPORT.md`. §1 below is preserved as the
> pre-implementation finding for traceability.
>
> The Skill 7 corrective pass hardened the coverage precondition in §4 (see
> the note under it) and added the independence checks the reconciler can
> make when the verifier supplies the agent's public key.

## 1. Current state (at discovery, commit `377d5fc`)

`RECONCILIATION = MISSING`. Zero occurrences of `reconcile` or `Reconciliation`
in production code. No code path anywhere compares an authorized execution
against an independently observed execution — verified claim 16.

This is unsurprising, because **both inputs are absent**: there is no
`ExpectedExecution` producer (`OBSERVATION_MODEL.md` §2) and no observer
(§1). Reconciliation is not the first thing to build; it is the fourth.

## 2. The join key already exists

The one asset AIP contributes here is a stable correlation key.
`DecisionRecord.decision_id: [u8;16]`
(`aip-standalone/aip-protocol/src/evidence_packet.rs:85-98`) is already:

- generated per decision (`aip-service/src/evidence.rs:248`,
  `aip_core::capability::random_jti`),
- **cryptographically bound into every action signature** — it is the first 16
  bytes of `ActionAttestation::canonical_bytes` (`evidence_packet.rs:117-126`),
  and the verifier reconstructs it from the packet's own decision rather than
  from the action (`verification.rs:531`), so an action cannot be transplanted
  to another decision,
- bound into the receipt countersignature (`:182-189`).

`decision_id` is therefore the correct join key for reconciliation. Do not
invent a new correlation id.

## 3. Contract (design only)

```
ExpectedExecution (signed by a decision point the agent does not control)
        +
ObservedExecution (signed by an observer the agent does not control)
        ↓
IDENTITY BINDING     match on ExecutionBinding, not on PID and not on IP (I2)
        ↓
CONTEXT COMPARISON   action_kind, parameter_digest, time window, net_ns
        ↓
EVIDENCE STRENGTH    see §5 — orthogonal to severity (I12)
        ↓
RECONCILIATION RESULT
```

## 4. Result set and the evidence each requires

A classification may only be emitted when its evidence precondition holds.
Emitting one without its precondition is the failure mode this document exists
to prevent.

| Result | Precondition | If precondition is unmet |
|---|---|---|
| `VERIFIED_EXECUTION` | expected ∧ observed ∧ binding match ∧ context match ∧ observer continuity attested over the window | downgrade to `CANNOT_PROVE` |
| `UNATTRIBUTED_EFFECT` | observed ∧ ¬expected ∧ observer continuity attested | `CANNOT_PROVE` |
| `PHANTOM_CLAIM` | expected ∧ ¬observed ∧ **sensor coverage over that exact window is attested** | `CANNOT_PROVE` — never infer non-execution from silence (**I8**) |
| `IDENTITY_DIVERGENCE` | observed binding ≠ expected binding, both attested | `CANNOT_PROVE` |
| `LINEAGE_VIOLATION` | observed process ancestry contradicts the agent's own signed lineage claims — see "The lineage question" below | `CANNOT_PROVE` naming the missing side, or ambiguity; never from one side alone |
| `SENSOR_INTEGRITY_FAILURE` | observer chain/attestation fails arithmetic check | — |
| `CONTINUITY_FAILURE` | observer restart/gap/rollback detected | — |
| `CANNOT_PROVE` | **the default.** Any missing or unattested input | — |

`CANNOT_PROVE` must be the `Default` impl. If the type's default is a verdict
rather than an absence of verdict, silence becomes evidence and **I8** is
violated by construction.

**Terminology (PR3 E-3).** `OBSERVATION_UNAVAILABLE` is an *availability
state* of the observer over a window — an **input** to reconciliation
(`aip_observe::ObservationAvailability::Unavailable { reason }`), not a
reconciliation result. Its reconciliation result is `CANNOT_PROVE`. The
result record must carry the availability state alongside the result so the
warrant layer can refuse both, but the result set above is complete as
written.

**Coverage precondition (PR3 A-3, hardened in the Skill 7 corrective pass).**
"Sensor coverage over that exact window is attested" means, concretely:
`SignedSensorHealth` verifies, its state is `Active`, `probe_policy` is
`RegisteredOnly`, `attested_coverage` contains the window, **and**
`covered_by` contains a kernel-pushed mechanism
(`SourceMechanism::is_kernel_pushed`). Polled coverage can never support
`PHANTOM_CLAIM`.

Those are the collector's *derived* claims, and every input to them
(`claimed_from_ms`, `claimed_to_ms`, `active_mechanisms`, `probe_run_id`) is
authored by the untrusted host-side probe and unvalidated by the collector.
The reconciler therefore **re-derives** coverage from the attested batches it
holds and additionally requires: the claimed intervals to cover the window
without a hole; one `probe_run_id` across them; a kernel-pushed mechanism in
the intersection of their `active_mechanisms`; and the window to end no later
than the moment the collector signed its health record. Without the
recomputation, a probe could manufacture coverage over an interval nothing
sampled — and that interval is exactly what `PHANTOM_CLAIM` speaks about.

**Context match (PR3 item 20, revised by Stage 7).** No observation carries
`action_kind` or `parameter_digest` as fields — the observer never states
meaning (I19). The reconciler instead *interprets* one observation class
deterministically: an ESTABLISHED TCP/TCP6 socket-table row of the anchored
instance is `ghost.net.connect.v1` with parameters `(protocol, remote_addr,
remote_port)`, whose digest is recomputed through the same
`aip_authorize::net_connect_parameters` the decision point's caller used
(`ACTION_EVIDENCE.md`). Since Stage 7c a second mapping exists: a kernel
`sched_process_fork` whose bound parent is the anchored instance, paired with
the `sched_process_exec` of that child (same `child_pid`, exec not earlier
than fork, child start tick inside `[fork − one tick, exec]`), is
`ghost.process.exec.v1` with parameter `exe_sha256` — the SHA-256 of the
child's executed image read under a pidfd anchor, recomputed through
`aip_authorize::process_exec_parameters`; the kernel's `filename` never
enters the digest. Since Gate 3 a third mapping exists: a kernel
`sock_send_length` event whose bound sender is the anchored instance, its
socket's endpoint resolved from the attested `inet_sock_set_state`
transitions of the same `sk` (the latest not later than the send, with no
close of that `sk` in between), is `ghost.net.send.v1` with the endpoint
parameters recomputed through `aip_authorize::net_send_parameters`; the
byte count is signed context and never enters the digest, and no payload
digest exists. For those three classes, and only those, the context-match
precondition can be satisfied. For every other action kind the strongest
positive result remains identity-level corroboration, and identity match
never implies action match.

**Temporal placement of kernel events (Stage 7b, clock corrected in 7c).**
Kernel timestamps (`CLOCK_MONOTONIC`, the perf event clock) and the decision
point's wall clock are different domains. A transition is placed *before* a
decision when the collector signed its batch before the decision was issued
(`attested_at_ms < issued_at`, two off-host clocks) or when the probe's clock
anchor says so; it is placed *inside* only by the anchor, which is the host's
clock and therefore a claim (`Attested` cap); with no anchor it is
`Unanchored` and nothing is inferred. A transition placed before the decision
is `ActionPrecedesAuthorization` and, for a connection, also disqualifies
presence evidence of the same connection. The same rules apply to a process
execution, where the fork is the initiation and the exec the completion; an
execution whose child start tick could not be checked against the anchor is
`KernelTimeUnanchored`, never placed by guess.

**"Continuity attested over the window" — per class.** For `PHANTOM_CLAIM`
(a negative claim) it means whole-window, kernel-pushed, gap-free coverage
re-derived from the batches. For `VERIFIED_EXECUTION` (a positive claim) it
means the batch carrying the matching observation lies wholly inside the
authorized window and inside the collector's signed coverage epoch, on an
`Active` observer; coverage of the *rest* of the window adds nothing to an
observation that was made. The record still reports availability for the
whole window, so a verified result may carry `Unavailable { WindowNotCovered }`
and that is the honest reading.

## 5. Evidence strength — kept separate from severity (I12)

Two independent axes, never collapsed into one score:

| Axis 2 — Evidence strength | Definition | Example |
|---|---|---|
| `Heuristic` | statistical or behavioural inference | rate anomaly |
| `Correlated` | multiple independent unattested sources agree | two logs concur |
| `Attested` | a signed observer with verified continuity | observer-signed exec event |
| `Proven` | arithmetic on held data that any third party can recompute | hash chain break, signature mismatch |

Axis 1 (severity/confidence) answers "how bad if true". Axis 2 answers "how
certain". `HIGH severity + Heuristic` and `HIGH severity + Proven` must remain
distinguishable in the type system, because only the latter may cross the
containment warrant threshold (`CONTAINMENT_MODEL.md`).

Note the repository already contains a correct implementation of exactly this
two-axis idea — on the **unmerged** `import/orbitaltrust-accountability-layer`
branch, `ot-sentinel/src/finding.rs` (`Severity` ⊥ `Strength`) with the warrant
gate at `response.rs:112-129`. Per **I17** it is not production capability, but
it is legitimate design input and should be read before re-deriving the model.

## 6. Why reconciliation cannot be the first implementation target

Building the reconciler first would produce a component whose inputs are both
fabricated by the party under scrutiny — the definition of security theatre.
The dependency order is fixed by evidence, not preference:

1. an authorization decision point that is not the agent → gives `ExpectedExecution`
2. an execution binding that survives PID reuse → gives a join key that means something
3. an observer with a trust root the agent does not hold → gives `ObservedExecution`
4. **then** reconciliation

See `IMPLEMENTATION_PLAN.md`.

## Downstream consumer (Skill 8)

`aip-warrant::evaluate` consumes `Reconciliation` records unchanged: the
typed `result`, `strength`, `availability` and `evidence` are read, never
recomputed; the engine adds an operator-declared severity and returns a
response class gated on `EvidenceStrength::Proven`. Records remain unsigned;
the warrant carries `Reconciliation::digest()` so a later signed-record layer
binds to the same bytes. See `WARRANT_IMPLEMENTATION_REPORT.md`.

## The lineage question (Phase C2)

`reconcile_lineage(ee, observer, ctx, LineageInputs)` asks one question
about one decision: does the kernel-observed ancestry of the authorized
instance contradict the lineage the agent's own signed claims assert?

**Observed side (complete only with all of):** a `LineageEdge` — bound
fork and bound exec, child start tick verified — whose child instance
structurally matches the expectation's binding; the edge's batch inside the
collector's attested coverage under a `RegisteredOnly` probe; the parent
instance attributed to exactly one agent **P** through a
decision-point-signed expectation whose binding matches it structurally.

**Claimed side (complete only with all of):** the decision's authority
chain supplied as tokens whose ids equal the expectation's `AuthorityRef`,
verified by `aip_core` (root signature, every hop, attenuation, expiry),
ending at this agent, in standing at the decision's `issued_at`, with no
revoked id — giving the delegators **D** (root issuer and every hop
issuer); and the agent's identity document whose lineage proof verifies
against the offered parent document — giving the identity parent **A**.

**Decision.** P is the agent itself → `Consistent{SelfSpawn}`; P ∈ D →
`Consistent{Delegator}`; P = A → `Consistent{IdentityParent}`; otherwise
`Contradicted` and the result is `LINEAGE_VIOLATION · Attested` with reason
`LineageContradicted`. Consistency is reported as `CANNOT_PROVE ·
LineageConsistent` with the comparison filled — there is no positive class
for "lineage is fine", and none is invented.

**What it is not.** Not a policy about who should spawn whom: an
orchestrator that spawns a worker whose authority came from the CFO is
consistent (the orchestrator is a delegator or the identity parent, or the
CFO's chain is the one supplied). The violation is a contradiction between
what the kernel showed and what the agent's tokens and identity document
signed — an instance created by an agent that neither authorized it nor
created its identity nor is it.

**Gaps and ambiguity (each `CANNOT_PROVE`, `lineage: Incomplete` or
`Ambiguous`):** no edge for this instance (`LineageEvidenceUnavailable`);
edge outside attested coverage (`LineageEdgeNotCovered`); `Open` probe policy;
parent unattributed (`LineageParentUnattributed`); parent named by two agents,
or two parent instances for one child (`LineageParentAmbiguous`); the child
instance named by another agent's expectation (`LineageChildAmbiguous`);
authority missing, mismatched, invalid, out of standing or revoked
(`LineageAuthorityUnavailable`); identity missing or proof failing
(`LineageIdentityUnavailable`). The observer gates apply exactly as for
actions. The record is version 4: `Reconciliation.lineage` carries the
comparison inside the canonical bytes, and `precondition_holds` admits
`LINEAGE_VIOLATION` only with `lineage == Contradicted` at `Attested`.

Required behaviours from the Gate 1 mandate, each pinned by a test in
`aip-reconcile/tests/lineage_violation.rs`: a child cannot invent a parent
(lv04, lv11); a parent cannot invent a child (lv05, lv13); authority is
cryptographically verified (lv06, lv07, lv12); the graph is built from
verified authority only (Phase D); observed parent must match where the
claim requires it (lv01–lv03); identity lineage needs a valid parent-signed
proof (lv08); authority lineage needs a valid chain (lv09); missing evidence
is `CANNOT_PROVE` (lv04–lv09, lv11, lv12); ambiguity is ambiguity (lv10,
lv13); a positive needs both sides (lv01 vs lv08/lv09).

## The wire question (Gate 2)

When a socket transition carries a `VERIFIED_EXECUTION` for
`ghost.net.connect.v1`, the reconciler asks a second kernel path — the
device layer, through `WireTapAfPacket` segments — whether it saw the
handshake the socket layer reported. The answer is written to
`Reconciliation.wire` (record v5) and cited in `evidence`; it is
**informational**: it raises no strength (both paths sit under the same host
root when the tap runs on the observed host; `Attested` is the ceiling) and
lowers no verdict (a tap may simply not cover the path the packets took).

**Answerable only when** some batch whose claimed window overlaps
`[initiation − 1 s, completion + 1 s]` (kernel monotonic, placed on the wall
clock by the transition batch's anchor) declared `WireTapAfPacket` live,
lies inside the collector's attested coverage, and reports a counted zero
loss. Otherwise `Unavailable` — a tap that dropped frames cannot vouch for
its own silence.

**Placement.** A segment's kernel capture stamp is on the realtime clock
(`SO_TIMESTAMPNS`); it is placed on the monotonic axis through its own
batch's `clock_anchor` (`BootClockAnchor::realtime_ns_to_monotonic`). A
segment in an unanchored batch cannot be placed and is not evidence.

**Decision.** Among placed segments on the transition's protocol and tuple
(local → remote SYN without ACK; remote → local SYN-ACK), take the distinct
SYN sequence numbers inside the window. Two or more →
`Ambiguous{handshakes}`, nothing cited. Exactly one, with a SYN-ACK whose
acknowledgement number is that sequence plus one and that is not earlier
than the SYN → `Corroborated`, both segments cited. Otherwise `NotObserved`.
A retransmitted SYN, or the loopback's two copies of one frame, share a
sequence number and are one handshake.

**What it is not.** Not a third action class, not attribution (a segment
names no process and is never bound), not payload (headers only, I23), not a
statement about hosts or interfaces the tap does not cover, and never a
reason to change `result`, `strength` or `reason`. Verdicts that came from
presence evidence, from process execution, or from no evidence leave
`wire == NotEvaluated`.

Pinned by `aip-reconcile/tests/wire_corroboration.rs`: corroboration and
its citations (wc01, wc03); strength ceiling (wc02); `Unavailable` without a
declared tap (wc04); `NotObserved` for a clean tap with no handshake, a far
handshake, another tuple, a SYN without its SYN-ACK or with a mismatched
acknowledgement, and unplaceable segments (wc05–wc08, wc11); ambiguity
(wc09); loss never corroborates (wc10); wire alone attributes and verifies
nothing (wc12, wc13); record v5 canonical bytes (wc14); a segment altered
after attestation is a `Proven` `SENSOR_INTEGRITY_FAILURE` (wc15). Live:
`ghost-demo/tests/live_wire.rs`.
