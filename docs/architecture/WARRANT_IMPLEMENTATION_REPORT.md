# Warrant Implementation Report

Skill 8 — warrant engine. Crate `aip-standalone/aip-warrant`.

## Status

**PASS** at the Skill 8 boundary (§30 gate below), with the limitations in
"Known Limitations". The engine turns an authenticated-domain reconciliation
record, an operator-declared severity and explicit policy into a typed
response class, signed by a distinct warrant authority. It actuates nothing.

## Preconditions

| Predecessor | Report | State |
|---|---|---|
| Skill 3 AIP correctness | `AIP_CORRECTNESS_REPORT.md` | PASS |
| Skill 4 execution binding | `EXECUTION_BINDING_IMPLEMENTATION_REPORT.md` | PASS |
| Skill 5 decision point | `DECISION_POINT_IMPLEMENTATION_REPORT.md` | PASS (library; process boundary design only) |
| Skill 6 / 6.5 observer | `OBSERVER_IMPLEMENTATION_REPORT.md`, `SNIFFER_DOG_IMPLEMENTATION_REPORT.md` | PASS |
| Skill 7 reconciliation | `RECONCILIATION_IMPLEMENTATION_REPORT.md` | PASS |
| `VERIFIED_EXECUTION` reachable | two action classes (Stages 7/7b/7c) | yes |
| `CANNOT_PROVE` implemented | `ReconciliationResult::default()` | yes |
| `EvidenceStrength` implemented | `aip_reconcile::EvidenceStrength`, four levels | yes |
| `OBSERVATION_UNAVAILABLE` represented | `Reconciliation.availability` on every record | yes |
| Severity represented independently | **no `Severity` type existed anywhere in the repository before this skill** (searched `aip-standalone`, `aip-service`), so nothing collapsed the two axes; Skill 8 introduces `Severity` as its own type, set from policy alone | yes, by construction |

## Existing Implementation

Before Skill 8: no warrant, response, severity or policy type in HEAD.
`CONTAINMENT_MODEL.md` §4–§5 specified the warrant standard and default
posture. The unmerged PR #3 branch (`import/orbitaltrust-accountability-layer`
at `6cc439f`, `rust/ot-sentinel/src/response.rs`) carried a two-axis
`ResponsePolicy::decide` over a three-level `Strength` and JSON findings;
its decision shape (containment requires proof; advisory default; uncited
findings capped; protected subjects exempt) is the design lineage here. It
was not copied: its types (three strengths, string DIDs, JSON, HMAC-era
signatures) are not this repository's, and it has no `Attested` level, which
is HEAD's actual ceiling for content facts.

## Changes

| File | Symbols |
|---|---|
| `aip-warrant/src/policy.rs` (new) | `Severity{Low,Medium,High,Critical}`, `SeverityAssignment::{default_table, with, severity_of}`, `ProtectedIdentitySet::{protect_agent, protect_decision_point, protect_observer, contains_*}`, `WarrantPolicy{version, autonomous_containment, allow_constrain_on_attested, protected, severity, validity_ms}` with advisory `Default`, `with_severity` |
| `aip-warrant/src/warrant.rs` (new) | `WARRANT_DOMAIN`, `WARRANT_VERSION`, `ResponseClass{Observe,Alert,Constrain,Contain}` (ordered), `ResponseTarget{Workload,Observer}`, `Finding`, `Refusal`, `Warrant` (+ `signing_preimage`, `is_valid_at`), `evaluate`, `WarrantAuthority::{new, sign}`, `WarrantTrustAnchors`, `WarrantVerifyError`, `verify_warrant`, `verify_warrant_distinct` |
| `aip-warrant/src/lib.rs`, `Cargo.toml` | crate; workspace member |
| `aip-reconcile/src/result.rs` | `EvidenceRef::canonical_bytes()` made public (wraps the existing private encoder; no encoding change) |
| `aip-test/src/domain_audit.rs`, `Cargo.toml` | nineteenth domain tag in the cross-crate distinctness audit |
| `aip-warrant/tests/warrant.rs` (new) | w01–w19 |

No verification rule, canonical encoder or wire format elsewhere changed.

## Severity Model

`Severity` is declared by the operator per `ReconciliationResult` in
`SeverityAssignment` (shipped table: `VerifiedExecution` Low,
`CannotProve` Low, `ContinuityFailure` Medium, `PhantomClaim` High,
`LineageViolation` High, `UnattributedEffect` Critical,
`IdentityDivergence` Critical, `SensorIntegrityFailure` Critical). A result
absent from the table is `Low`. Severity is never derived from evidence,
counts, timing or any record field.

## Evidence Strength Model

`aip_reconcile::EvidenceStrength` is consumed unchanged from the record. The
engine never constructs, raises or lowers it; the warrant carries it
verbatim.

## Orthogonality Proof

Types: `Severity` (policy crate) and `EvidenceStrength` (reconciler crate)
are distinct enums with no conversion between them and no arithmetic
implemented on either. Sources: severity from `WarrantPolicy`, strength from
`Reconciliation`. Tests: w11 sweeps every (severity, strength) pair and
asserts each warrant field equals its own source; w12 asserts the same in
every cell of the exhaustive sweep. Code: the response is
`min(result_cap, strength_cap, severity_cap)` over an ordered enum — no
product, no threshold on a number.

## Warrant Gate

```rust
let strength_cap = match rec.strength {
    Heuristic | Correlated => Alert,
    Attested => if policy.allow_constrain_on_attested { Constrain } else { Alert },
    Proven => Contain,
};
```

Then `min` with the result cap (`VerifiedExecution` Observe, `CannotProve`
Alert, `ContinuityFailure` Alert/observer, `SensorIntegrityFailure`
Constrain/observer, the four workload violations Contain) and the severity
cap; then capped at Alert if the window was unavailable, the record cites no
evidence, or the subject/decision point/observer is protected; then
`Contain → Alert` unless `autonomous_containment`. `Contain` is therefore
reachable only when strength is `Proven`, the result is a workload violation,
severity is `Critical`, coverage is present, evidence is cited, nothing is
protected and the operator enabled it (w12 proves this over every cell).

## Default Policy

`WarrantPolicy::default()`: version 1, autonomous containment **off**,
constrain-on-attested **off**, no protected identities, shipped severity
table, one-hour validity (w01). Under it no input produces `Contain` (w08).

## Protected Identities

`ProtectedIdentitySet` holds agents, decision points and observers. A
finding is protected if its subject agent is listed, or any evidence
reference names a listed decision point (`Expected`, `CoverageStatement`) or
observer (`Batch`, `Health`). Protected → at most Alert, `warrant.protected =
true` (w07). Represented in policy and in the signed warrant, not in
documentation.

## Evidence References

The warrant carries `reconciliation_digest = Reconciliation::digest()` and
the record's `evidence_refs` verbatim, each encoded with the reconciler's own
canonical encoder inside the signed preimage (w17). An uncited record is
capped at Alert (w09).

## Temporal Integrity

`issued_at = now`, `valid_until = now + policy.validity_ms`; both inside the
preimage (`put_u64`, `put_opt_u64`); `is_valid_at` is inclusive. Mutating
either, or dropping `valid_until`, breaks the signature (w13). A policy with
zero validity is refused rather than issuing an unbounded warrant (w15).

## Domain Separation

`SYNTRIASS/GHOST/WARRANT/v1`, first length-prefixed element of the preimage
via `aip_types::canonical::put_domain` (w19); added to `aip-test`'s
cross-crate audit of all nineteen tags. Signing through
`aip_crypto::sign_ed25519` with the authority's own key; verification
recomputes the preimage hash and the Ed25519 envelope. `verify_warrant_distinct`
refuses an anchor whose key equals a decision-point, observer or agent key
(w14).

## Adversarial Tests

| Required (§23) | Test | Result |
|---|---|---|
| Heuristic + Critical → Alert | w02 | pass |
| Correlated + Critical → Alert | w02 | pass |
| Attested + Critical → no Contain | w02 | pass |
| Proven + Critical + autonomous → Contain eligible | w02, w12 | pass |
| default policy → autonomous disabled | w01 | pass |
| CANNOT_PROVE + Critical → never Contain | w03, w12 | pass |
| OBSERVATION_UNAVAILABLE + Critical → never Contain | w04, w12 | pass |
| DEGRADED (+ Recovering, ContinuityUnverified, Quarantined, WindowNotCovered, HealthStale, NoObserver) → never Contain | w04 | pass |
| CONTINUITY_FAILURE → never Contain | w05, w12 | pass |
| Proven + Critical + protected → never autonomous Contain | w07, w12 | pass |
| Proven + Critical + autonomous disabled → no Contain | w08 | pass |
| containment-capable warrant with no evidence reference → reject (capped) | w09, w12 | pass |
| severity/strength orthogonality | w11, w12 | pass |
| tamper: finding_id, strength, severity, response, policy_version, issued_at, valid_until, evidence_refs (+ warrant_id, result, digest, target, autonomous, protected, subject, unavailable) | w13 | pass |
| §24 properties (∀ severity: strength<Proven ⇒ ≠Contain; ∀ degraded ⇒ ≠Contain; ∀ CANNOT_PROVE ⇒ ≠Contain; ∀ protected ⇒ ≠Contain; changing one axis never changes the other) | w12, exhaustive over 8 results × 4 strengths × 4 severities × 8 availabilities × 2 × 2 × 2 × 2 | pass |
| §12 sensor failure is not workload authority | w06 | pass |
| §20 no actuation | w18 (textual pin over the crate's sources) | pass |
| §26 malformed input refused, never escalated | w16 | pass |
| VERIFIED_EXECUTION warrants nothing | w10 | pass |

## Full Test Results

| Command | Result |
|---|---|
| `cargo test -p aip-warrant` | 19 passed, 0 failed |
| `cargo test --workspace` (aip-standalone) | 613 passed, 0 failed, 3 ignored (before Skill 8: 594) |
| `cargo test` (aip-service) | 39 passed, 0 failed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| `cargo fmt --all --check` | clean |

RED commit `b433f24` (19 tests, 5 compile errors); GREEN commit `9574420`.
Test-file edits since RED: rustfmt and one type alias for a clippy lint.

## Security Review

| THREAT | ASSUMPTION | MECHANISM | IMPLEMENTATION | TEST | LIMITATION |
|---|---|---|---|---|---|
| suspicion escalates to containment | — | strength gate is a `match`; sub-Proven caps at Alert/Constrain | `evaluate` | w02, w12 | none for the gate itself |
| severity substitutes for proof | — | separate types, `min` not product | `policy.rs`, `warrant.rs` | w11, w12 | — |
| sensor outage read as execution | — | `availability` cap; `ContinuityFailure`/`SensorIntegrityFailure` target the observer | `evaluate` | w04–w06 | — |
| operator never opted in yet containment fires | default policy is the deployed one | `autonomous_containment` off by default | `WarrantPolicy::default` | w01, w08 | enablement is a value in a struct; deployment must not set it casually |
| control plane contains itself | operator lists protected identities | `ProtectedIdentitySet` checked against subject and evidence refs | `is_protected` | w07 | a subject the caller does not name (`subject_agent: None`) is checked only through evidence refs |
| forged or altered warrant | warrant key is separate and its anchor is correct | canonical preimage, domain, Ed25519 | `sign`, `verify_warrant` | w13, w19 | keys are software keys; no HSM |
| warrant authority is the agent/DP/observer | caller supplies the other keys | `verify_warrant_distinct` | w14 | only keys the verifier knows |
| unsigned reconciliation record | records come from the builder's own verifier run | none in this crate | — | — | **the record is not authenticated**; a signed reconciliation record is a Phase E precondition and is not built here |
| malformed input | — | closed enums; version checks; refusal | `evaluate` | w16 | — |

## Known Limitations

- Reconciliation records are unsigned; the engine trusts records produced in
  its own trust domain. "Authenticated reconciliation result" in Skill 8 is
  satisfied only by that domain boundary, not by a signature.
- `Contain` is reachable in the engine when a record carries `Proven` on a
  workload violation. Today the reconciler produces `Proven` only for
  `SENSOR_INTEGRITY_FAILURE` (recomputable), which targets the observer. No
  production path currently yields a `Proven` workload violation, so no
  production input reaches `Contain`. That is a property of the evidence
  layer, stated, not a defect of the gate.
- Severity is operator policy; there is no severity *evidence*.
- Warrants are not persisted, transported or revoked here.
- The warrant authority key has no lifecycle (rotation, revocation).

## Deferred Work

Containment (Skill 9): consumes `Warrant`; nothing here signals, freezes,
isolates or filters. NEXORA (Skill 10): warrants are not committed or
anchored. Signed reconciliation records: Sniffer Dog 2.0 Phase E.

## §30 gate

- [x] predecessor Skills 3–7 are PASS
- [x] severity exists independently
- [x] evidence strength exists independently
- [x] CANNOT_PROVE cannot become containment
- [x] OBSERVATION_UNAVAILABLE cannot become containment
- [x] degraded observation cannot become containment
- [x] Heuristic cannot become containment
- [x] Correlated cannot become containment
- [x] Attested cannot become containment without explicit policy (and never Contain)
- [x] containment requires Proven
- [x] autonomous containment defaults OFF
- [x] protected identities cannot be autonomously contained
- [x] warrant requires evidence references (capped at Alert without)
- [x] signed warrant covers all security-relevant fields
- [x] temporal validity is signed
- [x] domain separation exists
- [x] canonical encoding is injective (shared encoder; length-prefixed refs)
- [x] no direct actuation exists
- [x] adversarial tests pass
- [x] full relevant test suite passes
- [x] this report exists
- [x] limitations stated
