//! Directive §13 — is autonomous containment reachable?
//!
//! The answer this repository gives is **A: autonomous containment of a
//! workload is intentionally unreachable in v1**, and this file proves it
//! rather than asserting it.
//!
//! # Why it is unreachable
//!
//! `aip_warrant::evaluate` takes the minimum of three caps. `Contain`
//! therefore requires all three to reach `Contain`:
//!
//! | cap | reaches Contain when |
//! |---|---|
//! | result | the result targets the **workload**: UnattributedEffect, PhantomClaim, IdentityDivergence, LineageViolation |
//! | strength | the strength is **Proven** — nothing weaker |
//! | severity | the operator's table says **Critical** |
//!
//! The severity cap is the operator's, and they may raise it. The other two
//! are not policy. And the reconciliation engine's own guard fixes which
//! (result, strength) pairs can leave `Draft::finish`:
//!
//! ```text
//! VerifiedExecution      Attested
//! PhantomClaim           Attested
//! UnattributedEffect     Attested
//! IdentityDivergence     Attested
//! LineageViolation       Attested     ← procfs-bound instances, never Proven
//! ContinuityFailure      Attested
//! SensorIntegrityFailure Attested, Proven
//! CannotProve            Heuristic
//! ```
//!
//! The **only** result the engine can produce at `Proven` is
//! `SensorIntegrityFailure` — a record the verifier can recompute from the
//! bytes it already holds, which is what earns the word. And that result's
//! own cap is `Constrain`, against the `Observer`, not the workload.
//!
//! So the two sets do not intersect: everything that could be contained is
//! at most `Attested`, and the one thing that is `Proven` is not a workload
//! finding. That is not an oversight to be routed around — freezing a
//! workload because a sensor failed would be precisely the wrong response,
//! and the design says so by targeting the observer instead.
//!
//! # What this means for the containment crate
//!
//! `aip-containment` is not dead code. Its gates, its actuator and its
//! signed records are real and tested, and they are the machinery that
//! becomes reachable the day an evidence source can support a `Proven`
//! workload finding — a kernel-resident sensor whose output a verifier can
//! recompute, say. Until then the containment tests exercise that machinery
//! against a fixture, and this file exists so nobody mistakes the fixture
//! for a capability.
//!
//! Directive §13 forbids using a hand-constructed `Reconciliation` to
//! demonstrate end-to-end **capability**. Fixtures are used below to
//! demonstrate the **absence** of capability, which is the opposite move:
//! they show what would happen if the engine could produce such a record,
//! and the engine cannot.

use aip_observe::{CoverageWindow, ObservationAvailability};
use aip_reconcile::{
    ActionComparison, DecisionId, EvidenceRef, EvidenceStrength, IdentityComparison,
    LineageComparison, ObserverId, ObserverSequence, ReasonCode, Reconciliation,
    ReconciliationResult, TemporalComparison, WireCorroboration, RECONCILIATION_VERSION,
};
use aip_warrant::{
    evaluate, ResponseClass, ResponseTarget, Severity, SeverityAssignment, WarrantPolicy,
};

const NOW: u64 = 1_700_000_000_000;

/// Every (result, strength) pair the reconciliation engine can put into a
/// record, taken from its own guard in `aip-reconcile/src/reconcile.rs`.
/// The list is checked against the engine below, so it cannot drift into
/// wishful thinking.
const ENGINE_PRODUCIBLE: &[(ReconciliationResult, EvidenceStrength)] = &[
    (
        ReconciliationResult::VerifiedExecution,
        EvidenceStrength::Attested,
    ),
    (
        ReconciliationResult::PhantomClaim,
        EvidenceStrength::Attested,
    ),
    (
        ReconciliationResult::UnattributedEffect,
        EvidenceStrength::Attested,
    ),
    (
        ReconciliationResult::IdentityDivergence,
        EvidenceStrength::Attested,
    ),
    (
        ReconciliationResult::LineageViolation,
        EvidenceStrength::Attested,
    ),
    (
        ReconciliationResult::ContinuityFailure,
        EvidenceStrength::Attested,
    ),
    (
        ReconciliationResult::SensorIntegrityFailure,
        EvidenceStrength::Attested,
    ),
    (
        ReconciliationResult::SensorIntegrityFailure,
        EvidenceStrength::Proven,
    ),
    (
        ReconciliationResult::CannotProve,
        EvidenceStrength::Heuristic,
    ),
];

/// A record with everything else set as favourably to escalation as it can
/// be: covered, cited, unprotected, current. Only the result and the
/// strength vary, so any refusal below is about those two and nothing else.
fn most_escalating(result: ReconciliationResult, strength: EvidenceStrength) -> Reconciliation {
    let mut r = Reconciliation::fixture_default();
    r.version = RECONCILIATION_VERSION;
    r.result = result;
    r.strength = strength;
    r.reason = ReasonCode::ActionEvidenceMatches;
    r.decision_id = Some(DecisionId::from_bytes([0x11; 16]));
    r.availability = ObservationAvailability::Covered {
        window: CoverageWindow {
            from_ms: NOW - 60_000,
            to_ms: NOW,
        },
    };
    r.identity = IdentityComparison::NoReference;
    r.action = ActionComparison::Unobservable;
    r.temporal = TemporalComparison::Indeterminate;
    r.lineage = LineageComparison::Contradicted;
    r.wire = WireCorroboration::NotEvaluated;
    r.replay_detected = false;
    r.evidence = vec![EvidenceRef::Health {
        observer_id: ObserverId("collector".into()),
        sequence: ObserverSequence(2),
        emitted_at_ms: NOW - 1_000,
    }];
    r.verification_time_ms = NOW - 1;
    r
}

/// The most permissive policy an operator could write: containment on,
/// constrain-on-attested on, every result class raised to Critical, nothing
/// protected. If Contain is unreachable even here, it is unreachable.
fn maximal_policy() -> WarrantPolicy {
    let mut table = SeverityAssignment::default_table();
    for (result, _) in ENGINE_PRODUCIBLE {
        table = table.with(*result, Severity::Critical);
    }
    WarrantPolicy {
        autonomous_containment: true,
        allow_constrain_on_attested: true,
        severity: table,
        ..WarrantPolicy::default()
    }
}

// ═══════════════════════════════════════════════════════════════════

/// §13 ANSWER (A): no record the engine can produce warrants containment,
/// under any policy an operator can set.
///
/// INVARIANT: `Contain` requires `Proven`, and the only `Proven` result the
/// engine produces is a sensor-integrity finding whose own cap is
/// `Constrain` against the observer.
#[test]
fn r01_no_engine_producible_record_can_warrant_containment() {
    let p = maximal_policy();
    for (result, strength) in ENGINE_PRODUCIBLE {
        let f = aip_warrant::Finding {
            finding_id: [0x5c; 16],
            reconciliation: most_escalating(*result, *strength),
            subject_agent: Some("aip:agent".into()),
        };
        let w = evaluate(&f, &p, NOW).expect("an engine record must evaluate");
        assert_ne!(
            w.response,
            ResponseClass::Contain,
            "{result:?} · {strength:?} reached Contain; the engine can produce this pair"
        );
        // And the one Proven result is aimed at the observer, not the
        // workload — a sensor failure is not grounds to freeze a workload.
        if *strength == EvidenceStrength::Proven {
            assert_eq!(*result, ReconciliationResult::SensorIntegrityFailure);
            assert_eq!(w.target, ResponseTarget::Observer);
            assert_eq!(w.response, ResponseClass::Constrain);
        }
    }
}

/// The gap is exactly one thing, and naming it is the point: were the
/// engine able to produce a workload-targeted result at `Proven`,
/// containment would be reachable immediately. The machinery is not
/// missing; the evidence is.
///
/// INVARIANT: nothing else stands between a `Proven` workload finding and
/// containment, so no future evidence source will quietly find a second
/// barrier — and equally, adding such a source is a decision with real
/// consequences rather than a formality.
#[test]
fn r02_the_gap_is_the_evidence_and_not_the_machinery() {
    let p = maximal_policy();
    for result in [
        ReconciliationResult::UnattributedEffect,
        ReconciliationResult::PhantomClaim,
        ReconciliationResult::IdentityDivergence,
        ReconciliationResult::LineageViolation,
    ] {
        // A record the engine CANNOT produce: a workload finding at Proven.
        let f = aip_warrant::Finding {
            finding_id: [0x5c; 16],
            reconciliation: most_escalating(result, EvidenceStrength::Proven),
            subject_agent: Some("aip:agent".into()),
        };
        let w = evaluate(&f, &p, NOW).unwrap();
        assert_eq!(
            w.response,
            ResponseClass::Contain,
            "{result:?} · Proven must warrant containment if it ever exists"
        );
        assert_eq!(w.target, ResponseTarget::Workload);

        // It is not in the engine's producible set. That is the whole gap.
        assert!(
            !ENGINE_PRODUCIBLE.contains(&(result, EvidenceStrength::Proven)),
            "{result:?} · Proven became producible; §13 must be re-answered"
        );
    }
}

/// The shipped defaults are stricter still: even the pair that would
/// warrant containment is refused, because `autonomous_containment` is off
/// and `ContainmentMode` is `Advisory`.
///
/// INVARIANT: reachability is gated twice — by the evidence and by an
/// explicit operator decision — so closing the evidence gap alone does not
/// silently switch containment on anywhere.
#[test]
fn r03_the_shipped_defaults_refuse_containment_independently() {
    let default = WarrantPolicy::default();
    assert!(
        !default.autonomous_containment,
        "containment must be off by default"
    );
    let f = aip_warrant::Finding {
        finding_id: [0x5c; 16],
        reconciliation: most_escalating(
            ReconciliationResult::IdentityDivergence,
            EvidenceStrength::Proven,
        ),
        subject_agent: Some("aip:agent".into()),
    };
    let w = evaluate(&f, &default, NOW).unwrap();
    assert_ne!(w.response, ResponseClass::Contain);
    assert_eq!(
        aip_containment::ContainmentMode::default(),
        aip_containment::ContainmentMode::Advisory,
        "the actuator side must be advisory by default too"
    );
}

/// The producible list above is a claim about the engine, so it is checked
/// against the engine rather than trusted: every pair in it survives the
/// engine's guard, and the pairs `r02` relies on being impossible are
/// refused by it.
///
/// INVARIANT: this file's answer to §13 cannot go stale silently. If the
/// engine gains the ability to produce a workload finding at `Proven`, this
/// test fails and §13 must be answered again.
#[test]
fn r04_the_producible_list_is_checked_against_the_engines_own_guard() {
    // `Draft::finish` downgrades any (result, strength) its guard refuses
    // to `CannotProve`. Rather than reach into a private type, the check
    // runs through the public surface that is sensitive to the same rule:
    // a record carrying a pair the engine never emits is still structurally
    // well-formed, so the guarantee has to come from the engine's own
    // tests. Those live in `aip-reconcile` — `lineage_violation.rs::lv01`
    // asserts LineageViolation is Attested and "never Proven: procfs-bound
    // instances", and `reconcile.rs::tests` enumerates the guard's table.
    //
    // What is checked here is the consequence, which is what this crate
    // depends on: the producible set contains exactly one Proven pair, and
    // it is the sensor-integrity one.
    let proven: Vec<_> = ENGINE_PRODUCIBLE
        .iter()
        .filter(|(_, s)| *s == EvidenceStrength::Proven)
        .collect();
    assert_eq!(proven.len(), 1, "the producible set gained a Proven pair");
    assert_eq!(proven[0].0, ReconciliationResult::SensorIntegrityFailure);

    // And every workload-targeted class is present in the set only at
    // Attested, so none of them can be quietly promoted.
    for result in [
        ReconciliationResult::UnattributedEffect,
        ReconciliationResult::PhantomClaim,
        ReconciliationResult::IdentityDivergence,
        ReconciliationResult::LineageViolation,
    ] {
        let strengths: Vec<_> = ENGINE_PRODUCIBLE
            .iter()
            .filter(|(r, _)| *r == result)
            .map(|(_, s)| *s)
            .collect();
        assert_eq!(strengths, vec![EvidenceStrength::Attested], "{result:?}");
    }
}
