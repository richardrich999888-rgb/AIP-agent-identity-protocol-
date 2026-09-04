# RECONCILIATION_MODEL

## 1. Current state

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
