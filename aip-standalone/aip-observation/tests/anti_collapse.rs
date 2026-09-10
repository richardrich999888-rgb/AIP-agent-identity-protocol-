//! Skill 20 — one test per prohibited false equivalence.
//!
//! Each of these is a collapse that a well-meaning change could introduce, and
//! each would be invisible until an incident. They are listed as equalities so
//! a reader can check the list against the brief's.

use aip_observation::*;
use aip_observe::{ObserverTrustAnchors, SourceMechanism};

mod support;
use support::*;

#[test]
fn c01_self_report_is_not_observation() {
    // The subject being judged must not control the evidence used to judge it.
    // An observation exists only after a batch verifies against the verifier's
    // anchors; a self-report has no such batch and no such anchors.
    let mut o = observer();
    let batch = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 1);
    assert!(
        ObservationRecord::from_attested(
            &batch,
            &ObserverTrustAnchors::new(),
            0,
            correlation(BOOT_P, EXEC_A, "sys:fleet-1")
        )
        .is_err(),
        "SECURITY: material became an observation without verifier trust"
    );
}

#[test]
fn c02_observation_is_not_attestation_of_content() {
    // A verified batch means the observer signed exactly these bytes. It does
    // not mean the bytes are true: a root-compromised host can lie to its own
    // probe about procfs content. Every content-bearing class is therefore
    // capped at Attested and none is Proven.
    for class in ObservationClass::ALL {
        if class == ObservationClass::ObserverIntegrity {
            continue;
        }
        assert!(
            class.ceiling() < EvidenceCeiling::Proven,
            "SECURITY: {class:?} claims a Proven ceiling. Only chain arithmetic \
             over held bytes may, because only it survives host root."
        );
    }
}

#[test]
fn c03_attestation_is_not_hardware_identity() {
    // An observer's attestation authenticates the observer, not the machine.
    // Nothing here carries a hardware identity, and no class accepts one.
    let r = record_on(BOOT_P, SourceMechanism::PidFdAnchored);
    let json = serde_json::to_string(&r).unwrap();
    for banned in ["tpm", "quote", "hardware_id", "ek_", "attestation"] {
        assert!(
            !json.to_lowercase().contains(banned),
            "SECURITY: an observation record carries {banned:?}: {json}"
        );
    }
}

#[test]
fn c04_c05_execution_is_not_effect_and_request_is_not_execution() {
    // Skill 18's ladder, preserved from the observation side. Observing that a
    // process ran says nothing about what it achieved, and no class claims
    // otherwise.
    assert!(ObservationClass::ProcessLifecycle
        .cannot_establish()
        .contains("effect"));
    assert!(ObservationClass::ProcessIdentity
        .cannot_establish()
        .contains("behaved"));
    // The class that would carry an effect has no mechanism at all.
    assert!(!ObservationClass::PhysicalEffect.is_implemented());
}

#[test]
fn c06_absence_of_observation_is_not_absence_of_execution() {
    // The single most important collapse to prevent. Three states, none of
    // which asserts non-occurrence, and no API that returns such an assertion.
    for c in [
        Completeness::Observed,
        Completeness::NotObserved,
        Completeness::NotObservable,
    ] {
        // The only predicate is positive. There is deliberately no
        // `asserts_absence`, so a caller cannot read one out.
        let _ = c.asserts_observation();
    }
    assert!(!Completeness::NotObserved.asserts_observation());
    assert!(!Completeness::NotObservable.asserts_observation());
    assert!(Completeness::Observed.asserts_observation());
}

#[test]
fn c07_observer_availability_is_not_event_occurrence() {
    // A healthy observer that recorded nothing has not established that
    // nothing happened. A profile declaring a class observable yields
    // NotObserved — an absence of evidence, not evidence of absence.
    let profile = ObservationProfile::new("collector-o")
        .unwrap()
        .with_mechanism(SourceMechanism::SchedTracepoint);
    assert!(profile
        .capability(ObservationClass::ProcessLifecycle)
        .is_observable());
    assert_eq!(
        profile.completeness_without_evidence(ObservationClass::ProcessLifecycle),
        Completeness::NotObserved,
        "SECURITY: an available observer with no evidence produced anything \
         other than 'not observed'"
    );
}

#[test]
fn c08_signed_is_not_truthful() {
    // A batch that verifies proves authorship and integrity. The record
    // carries the observer id and chain position so a reader knows *who*
    // signed — and nothing in the type claims the content is correct. The
    // ceiling is where that is enforced: content stays at Attested.
    let r = record_on(BOOT_P, SourceMechanism::PidFdAnchored);
    assert_eq!(r.completeness(), Completeness::Observed);
    assert_eq!(
        r.class().ceiling(),
        EvidenceCeiling::Attested,
        "SECURITY: a signed observation of procfs content was allowed above \
         Attested"
    );
}

#[test]
fn c09_authenticated_is_not_correct() {
    // Same distinction from the observer's side: a correctly anchored observer
    // using a weak mechanism is still bounded by the mechanism.
    let wire = record_on(BOOT_P, SourceMechanism::WireTapAfPacket);
    assert_eq!(wire.observer_id(), OBSERVER_ID, "the observer is anchored");
    assert_eq!(
        wire.class().ceiling(),
        EvidenceCeiling::Corroborative,
        "SECURITY: authentication raised what the mechanism could establish"
    );
}

#[test]
fn c10_tpm_attested_is_not_a_completed_physical_action() {
    // ADR-002 remains PROPOSED and ADR-003 §2 forbids mapping any mechanism to
    // PhysicalEffect. Even if hardware attestation existed, it would attest a
    // key — not that an actuator moved.
    assert!(!ObservationClass::PhysicalEffect.is_implemented());
    assert_eq!(
        ObservationClass::PhysicalEffect.ceiling(),
        EvidenceCeiling::Attested,
        "SECURITY: PhysicalEffect was given a Proven ceiling. A sensor reading \
         is content read from a device, root-forgeable on the observed host."
    );
    assert!(ObservationClass::PhysicalEffect
        .cannot_establish()
        .contains("no mechanism"));
}
