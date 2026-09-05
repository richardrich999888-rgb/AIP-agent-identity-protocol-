# RECONCILIATION_MODEL

> **Status (Stage 4 `ad9642a`, corrected `b821a23`; Stage 7 action evidence
> `63c5e0a`; Stage 7b transition evidence): PARTIALLY_IMPLEMENTED** in `aip-standalone/aip-reconcile`. The
> contract in §3–§5 below is implemented as written, with `CANNOT_PROVE` as
> the `Default`. Reachable results: `CANNOT_PROVE`, `PHANTOM_CLAIM`,
> `IDENTITY_DIVERGENCE`, `SENSOR_INTEGRITY_FAILURE`, `CONTINUITY_FAILURE`, and —
> **for exactly one action class**, an established TCP connection authorized
> as `ghost.net.connect.v1` — `VERIFIED_EXECUTION` at `Attested`, in two
> distinguishable kinds: `Presence` (a table row: the connection existed at
> the sample) and `Transition` (the kernel reported it being made;
> `ACTION_EVIDENCE.md` §14). Unreachable with the current evidence and stated so
> in code: `VERIFIED_EXECUTION` for every other action kind (no action-level
> observation exists), `UNATTRIBUTED_EFFECT` (requires a decision-point-signed
> completeness statement that nothing produces yet), `LINEAGE_VIOLATION`
> (requires both fork ends bound). See
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
| `LINEAGE_VIOLATION` | observed process ancestry contradicts the delegation chain | requires process lineage, which does not exist today |
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
(`ACTION_EVIDENCE.md`). For that class, and only that class, the
context-match precondition can be satisfied. For every other action kind the
strongest positive result remains identity-level corroboration, and identity
match never implies action match.

**Temporal placement of kernel events (Stage 7b).** Kernel timestamps and
the decision point's wall clock are different domains. A transition is placed
*before* a decision when the collector signed its batch before the decision
was issued (`attested_at_ms < issued_at`, two off-host clocks) or when the
probe's boot-clock anchor says so; it is placed *inside* only by the anchor,
which is the host's clock and therefore a claim (`Attested` cap); with no
anchor it is `Unanchored` and nothing is inferred. A transition placed before
the decision is `ActionPrecedesAuthorization` and also disqualifies presence
evidence of the same connection.

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
