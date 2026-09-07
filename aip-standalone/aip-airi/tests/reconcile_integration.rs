//! Gate 4 — composition with the real reconciler.
//!
//! These tests drive `aip_reconcile` itself, not a stand-in. The property
//! under test is the one the mission makes non-negotiable:
//!
//! > The new AI-stack layer MUST NOT weaken the existing epistemic model.
//!
//! "Not weaken" is checked as an equality, not an inspection: the verdict and
//! strength the engine produces are captured with no AIRI evidence present,
//! then again with AIRI evidence present in every shape this crate can
//! produce, and the two must be identical. A future edit that gave AIRI any
//! influence over a verdict — however well intentioned — fails here.

use aip_airi::*;
use aip_authorize::DecisionPointTrustAnchors;
use aip_observe::ObservationAvailability;
use aip_observe::ObserverTrustAnchors;
use aip_reconcile::{
    reconcile_expectation, EvidenceStrength, ExpectedSideCoverage, ReconciliationContext,
    ReconciliationResult,
};

mod support;
use support::*;

/// A context with no anchors and no observer — the engine's most
/// conservative input, which must yield `CannotProve`.
fn bare_context() -> ReconciliationContext {
    ReconciliationContext {
        decision_point_anchors: DecisionPointTrustAnchors::new(),
        observer_anchors: ObserverTrustAnchors::new(),
        verification_time_ms: 10_000,
        health_max_age_ms: 60_000,
        window_tolerance_ms: 1_000,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: None,
    }
}

/// Every corroboration shape this crate can produce, for the sweep below.
fn all_corroboration_shapes(a: &Agent) -> Vec<Corroboration> {
    let b = binding(&a.agent_id, 4321);
    let mut ev = signed_tool_request(a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    ev.runtime_binding = Some(b.clone());
    let ev = resign(a, ev);
    let avail = covered(0, 10_000);
    let unavail = aip_observe::no_observer();

    let mut o = Observer::new();
    let seen = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![socket_event(&b)]),
        10_000,
    );
    let unseen = attest(
        &mut o,
        raw_batch(2, 0, 10_000, vec![presence_observation(&b)], vec![]),
        10_000,
    );

    let mk = |batches: Vec<&aip_observe::AttestedBatch>, availability: &ObservationAvailability| {
        corroborate(&CorroborationInputs {
            event: &ev,
            batches: &batches,
            availability,
            expectation: None,
            window_tolerance_ms: 1_000,
        })
    };

    vec![
        mk(vec![&seen], &avail),   // Corroborated
        mk(vec![&unseen], &avail), // Uncorroborated
        mk(vec![], &unavail),      // NotEvaluated
    ]
}

#[test]
fn the_engines_verdict_is_identical_with_and_without_airi_evidence() {
    let a = agent("agent-1");
    let ee = sample_expectation(&a);
    let ctx = bare_context();

    // Baseline: the engine alone.
    let rec = reconcile_expectation(&ee, None, &ctx);
    let baseline = verdict_of(&rec);

    // Now with AIRI evidence present, in every shape.
    let shapes = all_corroboration_shapes(&a);
    assert_eq!(shapes.len(), 3, "the sweep must cover every outcome shape");

    let rec_again = reconcile_expectation(&ee, None, &ctx);
    let with_airi = verdict_of(&rec_again);
    let annotation = annotate(&rec_again, &shapes, Some(true));

    assert_eq!(
        baseline, with_airi,
        "SECURITY: the presence of AIRI evidence changed the engine's verdict"
    );
    // And the annotation genuinely saw the evidence — this is not a vacuous pass.
    assert_eq!(annotation.total(), 3);
}

#[test]
fn annotating_cannot_mutate_the_reconciliation() {
    // `annotate` takes `&Reconciliation`. This test documents the guarantee;
    // the borrow checker enforces it. Passing `&mut` would not compile.
    let a = agent("agent-1");
    let ee = sample_expectation(&a);
    let ctx = bare_context();
    let rec = reconcile_expectation(&ee, None, &ctx);
    let before = verdict_of(&rec);

    let shapes = all_corroboration_shapes(&a);
    let _ = annotate(&rec, &shapes, Some(true));
    let _ = annotate(&rec, &shapes, Some(false));
    let _ = annotate(&rec, &[], None);

    assert_eq!(before, verdict_of(&rec));
}

#[test]
fn a_corroborated_claim_does_not_produce_verified_execution() {
    // The most attractive wrong turn: independent evidence agreed with the
    // agent, so surely the execution is verified? No. VerifiedExecution
    // requires the engine's own sealed action match, its own identity match
    // and its own continuity flag. Corroboration supplies none of those.
    let a = agent("agent-1");
    let ee = sample_expectation(&a);
    let ctx = bare_context();
    let rec = reconcile_expectation(&ee, None, &ctx);

    let shapes = all_corroboration_shapes(&a);
    let corroborated: Vec<Corroboration> = shapes
        .iter()
        .filter(|c| c.is_corroborated())
        .cloned()
        .collect();
    assert!(
        !corroborated.is_empty(),
        "sweep produced no corroborated case"
    );

    let ann = annotate(&rec, &corroborated, Some(true));
    assert!(ann.corroborated > 0);
    assert_ne!(
        rec.result,
        ReconciliationResult::VerifiedExecution,
        "SECURITY: corroboration produced a VerifiedExecution verdict"
    );
    assert_eq!(rec.result, ReconciliationResult::CannotProve);
}

#[test]
fn no_amount_of_airi_evidence_reaches_proven() {
    // `Proven` is reserved for facts a third party recomputes from held
    // bytes. Corroboration compares *content*, and content read from the
    // observed host is root-forgeable, so it can never reach the top class.
    let a = agent("agent-1");
    let ee = sample_expectation(&a);
    let ctx = bare_context();
    let rec = reconcile_expectation(&ee, None, &ctx);

    // Pile on every shape many times over.
    let mut many: Vec<Corroboration> = Vec::new();
    for _ in 0..50 {
        many.extend(all_corroboration_shapes(&a));
    }
    let ann = annotate(&rec, &many, Some(true));
    assert_eq!(ann.total(), 150);

    assert_ne!(
        rec.strength,
        EvidenceStrength::Proven,
        "SECURITY: accumulated AIRI evidence reached Proven"
    );
}

#[test]
fn an_uncorroborated_claim_is_surfaced_but_is_not_itself_a_verdict() {
    // The epistemically valuable case must be *visible* — otherwise AIRI adds
    // nothing — and must *not* be a verdict, because a second accusation path
    // built without the existing one's adversarial depth is how false
    // positives ship. It surfaces as a counter for policy to act on.
    let a = agent("agent-1");
    let ee = sample_expectation(&a);
    let ctx = bare_context();
    let rec = reconcile_expectation(&ee, None, &ctx);

    let shapes = all_corroboration_shapes(&a);
    let ann = annotate(&rec, &shapes, Some(true));

    assert!(
        ann.uncorroborated > 0,
        "the uncorroborated case must be visible"
    );
    assert!(ann.has_unexplained_claims());
    // ...and the verdict is untouched.
    assert_eq!(rec.result, ReconciliationResult::CannotProve);
    assert_ne!(rec.result, ReconciliationResult::PhantomClaim);
}

#[test]
fn not_evaluated_is_counted_separately_from_corroborated() {
    // "We did not look" must never be summed with "we looked and it was
    // fine". A consumer reading only `corroborated` would otherwise treat a
    // blind spot as a clean bill of health.
    let a = agent("agent-1");
    let ee = sample_expectation(&a);
    let ctx = bare_context();
    let rec = reconcile_expectation(&ee, None, &ctx);

    let shapes = all_corroboration_shapes(&a);
    let ann = annotate(&rec, &shapes, None);
    assert_eq!(ann.corroborated, 1);
    assert_eq!(ann.uncorroborated, 1);
    assert_eq!(ann.not_evaluated, 1);
    assert_eq!(ann.chain_intact, None);
}

#[test]
fn the_engine_still_defaults_to_cannot_prove_with_no_observer() {
    // A guard on the substrate itself: if this ever stops being
    // CannotProve, the composition tests above are measuring nothing.
    let a = agent("agent-1");
    let ee = sample_expectation(&a);
    let rec = reconcile_expectation(&ee, None, &bare_context());
    assert_eq!(rec.result, ReconciliationResult::CannotProve);
    assert!(rec.strength < EvidenceStrength::Proven);
}
