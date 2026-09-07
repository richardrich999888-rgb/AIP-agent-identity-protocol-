# Runtime Accountability Trace

Scope: the `prod` branch, which is the only branch carrying the
observation → reconciliation → warrant → containment stack.

## 1. The pipeline as built

```
                observed host                      off-host collector
  ┌──────────────────────────────┐          ┌───────────────────────────┐
  │ aip-observe::probe           │          │ aip-observe::attest       │
  │  · no key field              │  batch   │  · CollectorSigner        │
  │  · no signing method         │ ───────▶ │  · assigns sequence       │
  │  · ObservationBatch has no   │          │  · stamps attested_at_ms  │
  │    signature field           │          │  · signs OBSERVER_HEAD    │
  └──────────────────────────────┘          └─────────────┬─────────────┘
                                                          │ AttestedBatch
   aip-authorize                                          ▼
  ┌──────────────────┐              ┌──────────────────────────────────┐
  │ ExpectedExecution│─────────────▶│ aip-reconcile::reconcile         │
  │  (signed)        │              │  prologue → identity → action →  │
  └──────────────────┘              │  temporal → strength → finish()  │
                                    └─────────────┬────────────────────┘
                                                  │ Reconciliation
                                                  ▼
                                    ┌──────────────────────────────────┐
                                    │ aip-warrant::evaluate            │
                                    │  min3(result, strength, severity)│
                                    └─────────────┬────────────────────┘
                                                  │ Warrant (signed)
                                                  ▼
                                    ┌──────────────────────────────────┐
                                    │ aip-containment::contain         │
                                    │  17 gates, then actuate          │
                                    └──────────────────────────────────┘
```

**The two arrows into `aip-warrant` and `aip-containment` are not exercised
anywhere in the repository.** See §3.4.

## 2. Verdict derivation — the choke point

`aip-reconcile/src/reconcile.rs:89-137`. Every verdict, whichever branch of
the engine proposes it, passes through one function:

```rust
fn finish(self, result, strength, reason) -> Reconciliation {
    let (result, strength, reason) = if self.precondition_holds(result, strength) {
        (result, strength, reason)
    } else {
        (CannotProve, Heuristic, InvariantNotSatisfied)     // fail-closed
    };
    …
}
```

This is the correct shape: per-branch logic decides *which* class to
propose, and a single independent predicate decides whether the evidence in
hand permits it. A proposal that fails is not rejected with an error — it is
silently downgraded to "cannot prove", which is the safe direction.

### 2.1 Preconditions, verbatim in effect

| Verdict | Structural requirement | Strength |
|---|---|---|
| `CannotProve` | none | any |
| `VerifiedExecution` | `ActionComparison::Match` (engine-only constructor) **and** `IdentityComparison::Match` **and** `action_continuity_verified` | `== Attested` |
| `UnattributedEffect` | a `CoverageStatement` in the evidence list | `== Attested` |
| `PhantomClaim` | `coverage_recomputed` **and** `IdentityComparison::NoReference` **and** `availability.is_covered()` | `== Attested` |
| `IdentityDivergence` | `IdentityComparison::Divergent` | `== Attested` |
| `LineageViolation` | `LineageComparison::Contradicted` | `== Attested` |
| `SensorIntegrityFailure` | **none** | `>= Attested` |
| `ContinuityFailure` | **none** | `>= Attested` |

**Finding R-1 (P3, CODE-PROVEN).** The two accusation classes aimed at the
*observer* — `SensorIntegrityFailure` and `ContinuityFailure` — are the only
two with no structural precondition. Their gate is a strength threshold
alone, and the strength is supplied by the calling branch rather than
derived from a witness in the record. Every verdict aimed at the *workload*
must show a structural witness; neither verdict aimed at the sensor must.
The asymmetry runs the wrong way for a system whose threat model includes a
compromised host that would benefit from discrediting its observer.

### 2.2 Verdicts that upgrade uncertainty — none found

The brief asks specifically whether the implementation "accidentally
upgrades uncertainty into VERIFIED". It does not. Three independent
mechanisms prevent it:

1. `ActionComparison::Match` carries an `ActionEvidenceSeal` with a private
   field and `pub(crate)` constructors; no caller can hand the reconciler a
   match (`result.rs:312-322`).
2. `VerifiedExecution` additionally requires `action_continuity_verified`,
   set only by `compare_action` and only when the carrying batch lies wholly
   inside both the authorized window and the collector's attested coverage
   epoch.
3. `strength == Attested` is an equality, not a floor, so a caller passing
   `Proven` for a `VerifiedExecution` is downgraded rather than promoted.

`classify_observer_error` (`reconcile.rs:209-228`) shows the same care in
the opposite direction: a signature that does not cover the bytes is
`Proven` sensor integrity failure, because it is arithmetic anyone can
recompute; an unanchored key or a malformed anchor is *not*, because
accusing the observer of tampering on the strength of the verifier's own bad
configuration would be a false positive at the highest evidence class. The
match is exhaustive so a new variant breaks the build.

This reasoning is correct and is rare in practice.

## 3. Containment reachability — the principal finding

### 3.1 The gate chain

`aip-containment/src/contain.rs`, `fn gates`. Seventeen steps; the three
that matter here:

```
 3. if w.response != ResponseClass::Contain      → Refusal::ResponseNotContain
 5. match w.evidence_strength {
        EvidenceStrength::Proven => {}
        other => return Err(Refusal::StrengthBelowProven(other))
    }
 6. match w.reconciliation_result {
        UnattributedEffect | PhantomClaim
      | IdentityDivergence | LineageViolation => {}
        other => return Err(Refusal::ResultNotWorkloadViolation(other))
    }
```

### 3.2 The contradiction

Gate 6 requires one of exactly four result classes. `precondition_holds`
pins all four at `strength == Attested` **exactly** (§2.1). Gate 5 requires
`Proven`. `Attested != Proven`.

Independently, gate 3 requires `response == Contain`, and
`aip-warrant/src/warrant.rs:213-223` grants `strength_cap = Contain` only
under `EvidenceStrength::Proven`. `response` is `min3(result_cap,
strength_cap, severity_cap)` and is thereafter only lowered.

The two classes that *may* carry `Proven` — `SensorIntegrityFailure`,
`ContinuityFailure` — have `result_cap` of `Constrain` and `Alert`
respectively, and target the `Observer`, so gates 4 and 6 reject them.

### 3.3 Exhaustive verification

**EXECUTION-PROVEN.** A read-only probe crate was built in scratchpad
depending on `prod`'s `aip-reconcile`, `aip-warrant` and `aip-observe` by
path. Nothing was written into the repository. It sweeps all
8 results × 4 strengths under a maximally permissive policy
(`autonomous_containment = true`, `allow_constrain_on_attested = true`,
every result class rated `Critical`, nothing protected, availability
`Covered`, evidence list non-empty), and cross-references each cell against
`precondition_holds`.

```
RESULT                     STRENGTH   RESPONSE   ENGINE-EMITTABLE?
----------------------------------------------------------------
VerifiedExecution          Attested   Observe    yes
UnattributedEffect         Attested   Constrain  yes
UnattributedEffect         Proven     Contain    NO - forged
PhantomClaim               Attested   Constrain  yes
PhantomClaim               Proven     Contain    NO - forged
IdentityDivergence         Attested   Constrain  yes
IdentityDivergence         Proven     Contain    NO - forged
LineageViolation           Attested   Constrain  yes
LineageViolation           Proven     Contain    NO - forged
SensorIntegrityFailure     Proven     Constrain  yes
ContinuityFailure          Proven     Alert      yes
CannotProve                (any)      Alert      yes
                                    … 32 cells swept, 12 shown
================================================================
Contain reachable from an ENGINE-PRODUCED record : 0
Contain reachable only by FORGING a Reconciliation: 4
================================================================
```

**Finding R-2 (P1, EXECUTION-PROVEN).** `aip-containment` cannot actuate on
any reconciliation the engine is capable of producing. 1,537 lines of
containment implementation, including a real cgroup v2 freezer, and 1,436
lines of containment tests, sit behind a gate that engine output cannot
satisfy. The `Contain` response class is dead with respect to the pipeline.

### 3.4 No end-to-end integration exists

**CODE-PROVEN.** `grep -rn 'reconcile_expectation\|reconcile_observation\|
reconcile_lineage' aip-containment/ aip-warrant/` returns **no matches**.
Neither crate has ever called the engine.

`aip-containment/tests/containment.rs:104` defines:

```rust
fn record(result, strength, availability, evidence) -> Reconciliation {
    Reconciliation { version: RECONCILIATION_VERSION, result, strength, … }
}
```

and `:132`:

```rust
fn proven_phantom() -> Reconciliation {
    record(PhantomClaim, EvidenceStrength::Proven, covered(), evidence())
}
```

`proven_phantom` is exactly the combination §3.2 proves the engine cannot
emit. `EvidenceStrength::Proven` appears 29 times across the containment and
warrant crates, always in hand-built records.

The tests are not wrong — they correctly verify that *given* a Proven
workload violation, the seventeen gates behave as specified. They simply do
not, and cannot, establish that such a warrant is obtainable.

### 3.5 Interpretation

Two readings are available and the evidence does not settle between them:

- **Fail-safe by construction.** The system is deliberately incapable of
  autonomous containment, and the gates document an interface reserved for a
  future evidence class that can reach `Proven`. The warrant doc comment
  ("Containment is *permitted* — Skill 9 decides whether to act") is
  consistent with this.
- **An unclosed seam.** The strength ladder was tightened in the reconciler
  after the containment gate was written against an earlier ladder, and the
  two drifted apart without an integration test to catch it.

What is *not* in doubt: the property is currently unverified in either
direction, because no test crosses the boundary. Whichever reading is
correct, the correct remedy is the same — an end-to-end test that drives
`reconcile_*` output into `evaluate` into `contain` and asserts the actual
outcome. Its absence is the finding.

## 4. Domain separation inventory

**CODE-PROVEN.** Fifteen distinct domain tags on `prod`, all
length-prefixed via `put_domain`:

| Family | Tags |
|---|---|
| `AIP/` | `AgentIdentityDocument/v1`, `CapabilityGrant/v1`, `DelegationToken/v1`, `LineageProof/v1`, `ReputationVote/v1`, `ScopedToken/v1`, `Test/v1` |
| `SYNTRIASS/GHOST/` | `CONTAINMENT/v1`, `CONTINUITY_REPORT/v1`, `KERNEL_EVENT/v1`, `OBSERVATION_BATCH/v1`, `OBSERVED_EXECUTION/v1`, `OBSERVED_PROCESS/v1`, `OBSERVER_HEAD/v1`, `OBSERVER_HEALTH/v1`, `RECONCILIATION/v1`, `WARRANT/v1` |
| `SYNTRIASS/NEXORA/` | `HEAD/v1`, `LEAF/v1`, `PROOF/v1` |

A grep will also surface `"AIP/ScopedTokeN/v1"` at
`aip-test/src/domain_audit.rs:66`. **This is not a typo in product code.**
It is a deliberate near-miss fixture: the test builds two equal-length tags
differing in one character and asserts their encodings differ. Reported here
because an automated scan would flag it and a reviewer would be right to
check.

## 5. Merkle construction

**CODE-PROVEN.** `aip-nexora/src/merkle.rs:9-13, 35, 74-75`. Leaves are
`0x00 ‖ …` and internal nodes `0x01 ‖ l ‖ r`, matching RFC 6962, and leaves
are additionally domain-separated under `SYNTRIASS/NEXORA/LEAF/v1` with a
kind code and length-prefixed record bytes. A leaf cannot be mistaken for an
internal node, and a record of one kind cannot be replayed as another.
This is correct.
