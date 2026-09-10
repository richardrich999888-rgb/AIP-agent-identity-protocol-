# Skill 20 — Autonomous Observation Profile: Evidence Report

**Branch** `claude/autonomous-accountability-skills-16-30`
**Specification** `docs/architecture/AUTONOMOUS_OBSERVATION_PROFILE.md`
**ADRs** ADR-001 untouched · **ADR-002 untouched, remains PROPOSED** · ADR-003 new

Epistemic classes used throughout: **CODE-PROVEN** (enforced by the type
system or by a code path), **TEST-PROVEN** (asserted by an executed test),
**DOCUMENTED** (written down, not enforced), **INFERRED**, **UNKNOWN**.

---

## A. What already exists

Recording this precisely mattered more than anything else in this skill,
because the largest risk was duplicating it.

`aip-observe` already carries the independence boundary: `ProcfsProbe` runs on
the observed host and has **no key field and no signing method**;
`CollectorSigner` holds the key off-host, assigns chain position and enforces
the probe registry. Nine `SourceMechanism` variants each document what they
establish and do not. `AttestedBatch` is signed and chained.
`ObserverTrustAnchors` maps `(observer_id, key_version) → key` with rotation
and revocation. `SignedSensorHealth.covered_by` is a **signed** coverage
declaration. `ObserverState` has five states and `UnavailableReason` six.
Continuity, anti-rollback and loss accounting exist. Skill 19 added
`ObservedBoot`. `precondition_holds` caps every content-dependent verdict at
`Attested`.

## B. What Skill 20 adds

1. **`ObservationClass`** — the environment-neutral layer above
   `SourceMechanism`, which is nine *Linux* mechanisms. Without it, every
   future vertical would fork a core-protocol enum.
2. **`EvidenceCeiling`** — each class's declared maximum contribution.
3. **`ObservationProfile`** — what a deployment is *provisioned* to observe.
4. **`ObservationRecord`** — one verified observation, correlated to system,
   execution and host-boot.

## C. What it deliberately does NOT solve

Physical-effect observation (Skill 21) · hardware attestation (ADR-002 stays
PROPOSED) · vertical profiles · any reconciler change · any new trust anchor.

---

## 1-3. Status and baselines

**Status: PASS.**

| | Suites | Passed | Failed | Ignored | Members |
|---|---|---|---|---|---|
| Before | 116 | 1143 | 0 | 6 | 22 |
| After | **122** | **1182** | **0** | 6 | **23** |

Service tier: 79 passed, 0 failed. Net +39 tests.

## 4-6. Commits and files

`b62c317` docs · `37500fc` feat · `df86a39` test · this report.

Added: `aip-standalone/aip-observation/{Cargo.toml, src/×5, tests/×5}`,
`docs/architecture/AUTONOMOUS_OBSERVATION_PROFILE.md`,
`docs/architecture/ADR-003-OBSERVATION-CLASS-BOUNDARY.md`, this report.
Modified: root `Cargo.toml` / `Cargo.lock` (one member).
Deleted: none. **No existing source file was modified.**

## 7-11. The model

**Observation model.** A record answers: who observed (`observer_id`,
`key_version`), what class, when (collector `attested_at_ms`), against which
system/execution/host-boot, by which mechanism, what authority anchors it
(the verifier's `ObserverTrustAnchors`), what it establishes (the class), what
it cannot (`cannot_establish`), and how complete the picture is.

**Trust/provenance.** Five levels, uncollapsed:
`SelfReported` (`aip-airi`) · `Expected` (`aip-authorize`) · `Observed`
(`aip-observe`) · `Attested` (anchors) · `Proven` (**`aip-reconcile` only**).

**Observer boundary.** In-process observer: **PROHIBITED** — the probe has no
key field, so it is unbuildable. Privileged host probe, external collector,
kernel-pushed sources and network TAP: **IMPLEMENTED**. Sidecar:
**REPRESENTABLE**. Hardware-backed and physical-sensor observers:
**DEFERRED**.

**Taxonomy.** Nine classes. Eight capped at `Attested` or below;
`ObserverIntegrity` alone reaches `Proven`; `NetworkWire` is `Corroborative`
because the device layer knows no process; `PhysicalEffect` is declared with
no mechanism.

**Correlation.** System, execution, boot and decision are all inside the
canonical preimage. `describes()` refuses a record for an execution it does
not name, and construction refuses a correlation naming a boot the observer
did not measure.

## 12. Failure and completeness semantics

Three states: `Observed` / `NotObserved` / `NotObservable`. The last two are
distinct for the reason `CANNOT_PROVE` exists. **None asserts
non-occurrence**, and there is no `asserts_absence` method to return one —
CODE-PROVEN by its absence, TEST-PROVEN by `c06`.

An undeclared class defaults to `NotObservable` at the *lowest* ceiling, never
an optimistic default (TEST-PROVEN `f13_f14`, mutation-checked M5).

## 13. NEXORA

**Additive, and no NEXORA code was changed.** An `ObservationRecord::digest()`
is a domain-separated commitment a consumer can embed in an existing leaf. The
verifier authenticates against its **own** anchors, never a package-supplied
one — B-4's rule one layer out. Unknown versions refused.
**DOCUMENTED + CODE-PROVEN** (digest, domain separation, version check);
**not TEST-PROVEN end-to-end through a NEXORA package**, because that would
require changing NEXORA, which the brief forbids without cause.

## 14. Reconciliation

**No change. None was needed.** `precondition_holds` remains the only place
`Proven` is decided. `tests/ceiling.rs` asserts the declared table stays
consistent with it by reading the reconciler's own vocabulary. Verified by
empty diff over `aip-reconcile`, `aip-warrant`, `aip-containment`,
`aip-nexora`, `aip-observe` and `aip-airi`.

## 15. ADRs

**ADR-003 — Observation Class Boundary — ACCEPTED**, scoped to Skill 20's
abstraction. Two decisions: the class layer above `SourceMechanism` (with
rejected alternatives), and that `PhysicalEffect` is representable with ceiling
`Attested` and no mechanism — never `Proven`, for a structural reason rather
than a sensor limitation.

**ADR-002 — untouched, remains PROPOSED / NOT IMPLEMENTED.**

## 16-17. Adversarial and mutation results

25 failure classes covered by 17 tests (several classes are the same property
from different angles and are tested once rather than padded), plus 9
anti-collapse, 9 guards, 4 ceiling.

| Mutation | Fails |
|---|---|
| Record construction skips verification | **4** ✓ |
| Correlation boot id not checked against the measurement | **1** ✓ |
| `PhysicalEffect` declares a `Proven` ceiling | **7** ✓ |
| A profile may raise a ceiling | **2** ✓ |
| Undeclared class defaults to observable | **2** ✓ |
| `NotObservable` collapses into `NotObserved` | **2** ✓ |

## 18. Defects found and fixed

**One correction to my own earlier reporting, not a code defect.** Skills 16-19
each recorded "PostgreSQL store never compiled" as a residual risk. Running
`clippy --workspace --all-targets --all-features` and
`cargo check -p airon-aip --features postgres` shows it **does compile**. The
accurate statement is that it compiles and has never been **exercised against
a live database**. My earlier reports were more pessimistic than the facts;
corrected here.

No implementation defect was found in this crate. That is a weaker statement
than Skills 18 and 19, where auditing my own API turned up real defects — the
guards here were written from those lessons rather than after them.

## 19. Remaining risks and gaps

1. **Nothing consumes `ObservationRecord` yet.** The class layer, ceilings,
   profile and record exist; no producer emits records into a reconciler input
   path or a NEXORA package. **The capability is the abstraction, not its
   use** — this report does not claim otherwise.
2. **`PhysicalEffect` has no mechanism.** The widest gap in the architecture is
   unchanged: a physical action still has no independent evidence path.
3. **Ceiling consistency is asserted, not derived.** `EvidenceCeiling` and
   `EvidenceStrength` are separate types; the test ties them, but a
   sufficiently creative change to `precondition_holds` could diverge without
   failing it. **INFERRED**, not CODE-PROVEN.
4. **Suppression before signing is undetectable** and is recorded as such. A
   host that drops an observation before the collector sees it leaves no trace
   in the chain. **DOCUMENTED, UNKNOWN in practice.**
5. **The postgres store is compiled but never exercised** against a database.
6. Pre-existing load-sensitive flakes unchanged (`fa05_live_*`,
   `live_freeze::f_p_a_*`).

## 20. Explicit confirmations

- **ADR-002 remains PROPOSED** — verified by reading its status line.
- **Observer keys remain in `aip-observe`** — TEST-PROVEN by a source scan
  refusing `SigningKey`, `private_key`, `CollectorSigner` and any signing
  dependency in this crate.
- **No second reconciler exists** — TEST-PROVEN by a scan for verdict
  vocabulary, and by an empty diff over `aip-reconcile`.
- **`EvidenceStrength` was not weakened** — not referenced in this crate;
  `aip-reconcile` untouched.
- **Skills 21-30 were not started** — no vertical-profile type exists.
- **Production readiness is NOT claimed.**

## What the tests prove, and what they do not

**They prove**, at the stated classes:

- An `ObservationRecord` cannot exist without a batch that verified against
  the verifier's own anchors (CODE-PROVEN by construction; TEST-PROVEN by
  `f01`, `c01`; mutation-checked).
- A record cannot claim a host-boot the observer did not measure
  (TEST-PROVEN, mutation-checked).
- No class other than `ObserverIntegrity` can declare a `Proven` ceiling, and
  a profile cannot raise one (TEST-PROVEN, mutation-checked).
- Absence never becomes non-occurrence (CODE-PROVEN by the absent method;
  TEST-PROVEN by `c06`, `f11`).
- Every identity is inside the canonical preimage, so relabelling changes the
  digest (TEST-PROVEN by a collision sweep).

**They do not prove:**

- That any observation is **true**. A verified batch means the observer signed
  those bytes; a root-compromised host can still lie to its own probe. This is
  exactly why content is capped at `Attested`, and no test claims otherwise.
- That an execution **occurred** as described, or that any **external effect**
  happened. No class establishes an effect and `PhysicalEffect` has no
  mechanism.
- That the observer is **honest** about what it watches. That is a verifier
  trust decision, inherited from the anchor model rather than improved on.
- That the system is **secure**, **tamper-proof** or **production-ready**.
  None of those terms is claimed.

## Gate

All 27 acceptance criteria met. Criterion 25 (`clippy --all-features`) passed
with no pre-existing issue to document.

**Skill 21 is permitted** on this evidence, and is the right next step: it owns
the effect boundary, which is where `PhysicalEffect` — declared here, with its
ceiling fixed at `Attested` by ADR-003 — would acquire a mechanism. One
condition carried forward: Skill 21 must not read ADR-003's declaration of the
class as permission to raise its ceiling.

**I have not started Skill 21.**
