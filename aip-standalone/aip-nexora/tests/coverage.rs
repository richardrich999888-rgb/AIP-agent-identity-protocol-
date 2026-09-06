//! Skill 10 Gate 6 — coverage semantics, RED.
//!
//! Coverage is never accepted because a host said so. A package carries no
//! coverage field at all: the verifier derives it from signed observation
//! evidence and the record the reconciler re-drew from that evidence, so
//! there is nothing for an assembler to overstate.
//!
//! The five states the directive distinguishes, and the fixture that
//! produces each — every one measured from the real engine, not asserted
//! into existence:
//!
//! | state              | what it means                                     |
//! |--------------------|---------------------------------------------------|
//! | `Observed`         | the action was seen in attested evidence          |
//! | `AvailableAndEmpty`| the channel was demonstrably watching and carried nothing — the only state that licenses a statement about something *not* happening |
//! | `Ambiguous`        | evidence exists and does not resolve to one answer |
//! | `Loss`             | the channel reported dropped events over the window |
//! | `CannotEstablish`  | no attested coverage: no observer, a gap, a restart, staleness, quarantine |
//!
//! The distinction that carries the whole gate is between the second and
//! the last. "The observer was watching and saw nothing" is evidence.
//! "The observer saw nothing" is not — it is compatible with the observer
//! not having been watching at all. A proof that blurs them turns absence
//! of evidence into evidence of absence.

mod common;

use aip_nexora::proof::*;
use aip_nexora::verify::*;

fn package(s: &common::Scenario) -> NexoraProof {
    let mut b = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        });
    if !s.evidence.batches.is_empty() {
        b = b.observer(s.evidence.batches.clone(), s.evidence.health.clone());
    }
    b.build()
}

fn anchors(s: &common::Scenario) -> VerifierAnchors {
    VerifierAnchors {
        decision_point: s.a.dp_anchors.clone(),
        observer: s.o.anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: s.a.issuer_keys.clone(),
        agent_public_key: Some(s.a.agent_kp.public_key.clone()),
    }
}

fn coverage_of(s: &common::Scenario) -> Coverage {
    let v = verify_nexora_proof(&package(s), &anchors(s));
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    v.coverage
}

// ═══ The five states, each from a real engine record ═══

#[test]
fn g6_01_an_observed_action_reports_observed_and_complete() {
    let c = coverage_of(&common::verified_execution());
    assert_eq!(c.observation, ObservationCoverage::Observed);
    assert_eq!(c.completeness, Completeness::Complete);
}

#[test]
fn g6_02_a_watched_and_empty_channel_is_the_only_state_that_speaks_of_absence() {
    let s = common::phantom_claim();
    assert_eq!(
        s.reconciliation.result,
        aip_reconcile::ReconciliationResult::PhantomClaim,
        "the fixture must reach PHANTOM_CLAIM through the engine"
    );
    let c = coverage_of(&s);
    assert_eq!(c.observation, ObservationCoverage::AvailableAndEmpty);
    assert_eq!(c.completeness, Completeness::Complete);
}

#[test]
fn g6_03_seeing_nothing_without_attested_coverage_is_not_the_same_thing() {
    // Same absence of events, but the window was never covered. The engine
    // says CANNOT_PROVE and the coverage must say so too: this is the state
    // that must never be mistaken for the one above.
    let s = common::covered_but_empty();
    assert_eq!(
        s.reconciliation.result,
        aip_reconcile::ReconciliationResult::CannotProve
    );
    let c = coverage_of(&s);
    assert_eq!(
        c.observation,
        ObservationCoverage::CannotEstablish,
        "an uncovered window with no events must not read as 'watched and empty'"
    );
    assert_eq!(c.completeness, Completeness::Partial);
    assert_ne!(c.observation, ObservationCoverage::AvailableAndEmpty);
}

#[test]
fn g6_04_a_channel_that_reported_loss_says_so() {
    let s = common::with_loss();
    let c = coverage_of(&s);
    assert_eq!(c.observation, ObservationCoverage::Loss);
    assert_eq!(c.completeness, Completeness::Partial);
}

#[test]
fn g6_05_no_observer_at_all_establishes_nothing() {
    let s = common::cannot_prove();
    let c = coverage_of(&s);
    assert_eq!(c.observation, ObservationCoverage::CannotEstablish);
    assert_eq!(c.completeness, Completeness::Partial);
}

// ═══ Coverage is derived, never claimed ═══

#[test]
fn g6_06_a_package_carries_no_coverage_for_an_assembler_to_overstate() {
    let s = common::verified_execution();
    let json = serde_json::to_string(&package(&s)).unwrap().to_lowercase();
    for word in ["coverage", "complete", "observed", "continuous"] {
        assert!(
            !json.contains(word),
            "a package must not state {word}: coverage is the verifier's to derive, {json}"
        );
    }
}

#[test]
fn g6_07_editing_what_the_host_authored_cannot_manufacture_coverage() {
    // The claimed window and the declared mechanisms are written by the
    // untrusted probe. Changing either must break the package rather than
    // improve the coverage it appears to have.
    let s = common::phantom_claim();
    assert_eq!(
        coverage_of(&s).observation,
        ObservationCoverage::AvailableAndEmpty
    );

    let mut p = package(&s);
    p.observer.as_mut().unwrap().batches[1]
        .batch
        .claimed_to_ms += 60_000;
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(
        matches!(v.verdict, ProofVerdict::Invalid(_)),
        "a widened claimed window must not verify: {v:#?}"
    );

    let mut p = package(&s);
    p.observer.as_mut().unwrap().batches[1]
        .batch
        .active_mechanisms
        .clear();
    assert!(matches!(
        verify_nexora_proof(&p, &anchors(&s)).verdict,
        ProofVerdict::Invalid(_)
    ));
}

#[test]
fn g6_08_the_vocabulary_is_closed_and_its_codes_are_distinct() {
    let all = ObservationCoverage::ALL;
    assert_eq!(all.len(), 5);
    let mut codes: Vec<u8> = all.iter().map(|c| c.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), all.len());
    // The one state that licenses a claim about absence says so itself.
    assert!(ObservationCoverage::AvailableAndEmpty.licenses_absence_claim());
    for c in all {
        if c != ObservationCoverage::AvailableAndEmpty {
            assert!(
                !c.licenses_absence_claim(),
                "{c:?} must not license a statement about what did not happen"
            );
        }
    }
}
