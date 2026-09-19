//! ROBOTICS-PHYSICAL-OBSERVATION-001, as an executable specification.
//!
//! The scenario the brief defines:
//!
//! ```text
//!   1. a UGV moves from A to B
//!   2. its onboard telemetry reports movement
//!   3. its controller reports success
//!   4. an external camera observes displacement
//!   5. an external collector timestamps and records the observation
//!   6. Vanian receives the external evidence
//!   7. an accountability decision is evaluated
//! ```
//!
//! Seven cases, A–G. **No robot and no camera were involved**: these tests
//! drive the adapter over constructed observations, so they establish what the
//! *decision procedure* does, not what any robot did. That is the honest limit
//! of what is runnable in this environment, and the scenario manifest in
//! `../../scenarios/` records the same thing.
//!
//! The one result that matters across all seven: **no case promotes a
//! controller success into a proven physical effect.**

use vanian_external_adapter::{
    admit, Admission, AdmissionLedger, AdmissionPolicy, EventType, ExternalObservation,
    ObservationNonce, ObserverPosture, ProvenanceClass, RawCapture, RefusalReason, SourceAgreement,
    SubjectIdentity,
};

const NOW: u64 = 100_000;

fn observation(
    source: &str,
    class: ProvenanceClass,
    event: EventType,
    at_ms: u64,
    seq: u64,
    payload: serde_json::Value,
) -> ExternalObservation {
    let bytes = serde_json::to_vec(&payload).expect("payload");
    ExternalObservation {
        source: source.to_owned(),
        mechanism: "scenario-fixture".to_owned(),
        timestamp_ms: at_ms,
        subject_identity: SubjectIdentity::FiducialMarker { marker_id: 7 },
        event_type: event,
        payload,
        provenance_class: class,
        nonce: ObservationNonce {
            observer_id: source.to_owned(),
            sequence: seq,
        },
        raw: RawCapture::new(source, None, at_ms, bytes).expect("capture"),
    }
}

/// The robot's own account of having moved.
fn onboard_telemetry(at_ms: u64, seq: u64, moved_mm: i64) -> ExternalObservation {
    observation(
        "ugv-odom",
        ProvenanceClass::SubjectSelfReport,
        EventType::Displacement,
        at_ms,
        seq,
        serde_json::json!({ "displacement_mm": moved_mm }),
    )
}

/// The controller's account of having executed the command.
fn controller_ack(at_ms: u64, seq: u64, success: bool) -> ExternalObservation {
    observation(
        "ros2-control",
        ProvenanceClass::ControllerAcknowledgement,
        EventType::AcknowledgementObserved,
        at_ms,
        seq,
        serde_json::json!({ "result": if success { "SUCCEEDED" } else { "REJECTED" } }),
    )
}

/// The external camera's account, through an anchored collector.
fn external_camera(at_ms: u64, seq: u64, moved_mm: i64) -> ExternalObservation {
    observation(
        "external-camera",
        ProvenanceClass::ExternalSensorAnchored,
        EventType::Displacement,
        at_ms,
        seq,
        serde_json::json!({ "displacement_mm": moved_mm }),
    )
}

fn admit_at(o: &ExternalObservation, p: ObserverPosture, now: u64) -> Admission {
    admit(
        o,
        p,
        now,
        AdmissionPolicy {
            freshness_bound_ms: 5_000,
        },
        &mut AdmissionLedger::new(),
    )
}

// ─── A. normal movement ───

#[test]
fn case_a_normal_movement_admits_three_things_and_proves_no_physical_effect() {
    let telem = admit_at(
        &onboard_telemetry(99_000, 1, 2_000),
        ObserverPosture::Present,
        NOW,
    );
    let ack = admit_at(
        &controller_ack(99_100, 1, true),
        ObserverPosture::Present,
        NOW,
    );
    let cam = admit_at(
        &external_camera(99_200, 1, 1_980),
        ObserverPosture::Present,
        NOW,
    );

    // All three are admitted — and at three different standings.
    assert!(matches!(telem, Admission::AdmittedAsClaim { .. }));
    assert!(matches!(ack, Admission::AdmittedAsClaim { .. }));
    assert!(matches!(cam, Admission::AdmittedAsCorroboration { .. }));

    // And none of them supports a physical-effect claim, including the camera.
    for a in [&telem, &ack, &cam] {
        assert!(
            !a.supports_physical_effect(),
            "the happy path must not manufacture physical proof: {a:?}"
        );
    }
}

// ─── B. command rejected ───

#[test]
fn case_b_a_rejected_command_is_a_claim_like_any_other() {
    let ack = admit_at(
        &controller_ack(99_100, 1, false),
        ObserverPosture::Present,
        NOW,
    );
    assert!(matches!(ack, Admission::AdmittedAsClaim { .. }));
    assert!(!ack.supports_physical_effect());
    // A rejection is the controller's account of itself, exactly as an
    // acceptance is. Neither is worth more than the other.
    let accepted = admit_at(
        &controller_ack(99_100, 2, true),
        ObserverPosture::Present,
        NOW,
    );
    assert_eq!(ack.ceiling(), accepted.ceiling());
}

// ─── C. command accepted, nothing moved ───

#[test]
fn case_c_controller_success_with_no_external_displacement_is_a_conflict_not_a_success() {
    // The case the whole exercise exists for. The controller says SUCCEEDED and
    // the odometry says 2 m; the camera saw nothing move.
    let ack = admit_at(
        &controller_ack(99_100, 1, true),
        ObserverPosture::Present,
        NOW,
    );
    let telem = admit_at(
        &onboard_telemetry(99_000, 1, 2_000),
        ObserverPosture::Present,
        NOW,
    );
    let cam = admit_at(
        &external_camera(99_200, 1, 0),
        ObserverPosture::Present,
        NOW,
    );
    assert!(ack.is_admitted() && telem.is_admitted() && cam.is_admitted());

    let agreement = SourceAgreement {
        agreeing: vec![
            ProvenanceClass::SubjectSelfReport,
            ProvenanceClass::ControllerAcknowledgement,
        ],
        disagreeing: vec![ProvenanceClass::ExternalSensorAnchored],
    };
    assert!(
        !agreement.is_resolvable(),
        "two subject-side sources must not outvote one external observation"
    );
    assert!(!agreement.classify().establishes());
    // And the crucial negative: nothing here promotes controller_success into
    // physical_effect_proven.
    assert!(!ack.supports_physical_effect());
}

// ─── D. movement without an expected command ───

#[test]
fn case_d_displacement_with_no_command_is_admitted_and_explains_nothing() {
    // The camera saw the robot move and no command was issued. The observation
    // is admissible as corroboration; what it corroborates is a question for
    // the reconciler, not for this adapter, and the adapter must not invent an
    // explanation.
    let cam = admit_at(
        &external_camera(99_200, 1, 1_500),
        ObserverPosture::Present,
        NOW,
    );
    assert!(matches!(cam, Admission::AdmittedAsCorroboration { .. }));
    assert!(!cam.supports_physical_effect());
}

// ─── E. stale telemetry ───

#[test]
fn case_e_stale_telemetry_is_refused_rather_than_weakened() {
    let stale = onboard_telemetry(90_000, 1, 2_000); // 10 s old, bound is 5 s
    match admit_at(&stale, ObserverPosture::Present, NOW) {
        Admission::Refused {
            reason: RefusalReason::Stale { age_ms, bound_ms },
        } => {
            assert_eq!(age_ms, 10_000);
            assert_eq!(bound_ms, 5_000);
        }
        other => panic!("stale telemetry must be refused, got {other:?}"),
    }
    // And a fresh one from the same source is admitted, so the test is
    // sensitive to staleness rather than to the source.
    assert!(admit_at(
        &onboard_telemetry(99_000, 2, 2_000),
        ObserverPosture::Present,
        NOW
    )
    .is_admitted());
}

// ─── F. observer unavailable ───

#[test]
fn case_f_observer_unavailable_refuses_and_concludes_nothing() {
    let cam = external_camera(99_200, 1, 1_980);
    let refused = admit_at(&cam, ObserverPosture::Unavailable, NOW);
    assert_eq!(
        refused,
        Admission::Refused {
            reason: RefusalReason::ObserverUnavailable
        }
    );
    // "Nobody looked" must not become "nothing happened".
    assert!(!ObserverPosture::Unavailable.silence_establishes_non_occurrence());
    // And the subject's own claims are unaffected by the observer being down:
    // they remain claims, neither strengthened nor refuted.
    assert!(matches!(
        admit_at(
            &onboard_telemetry(99_000, 1, 2_000),
            ObserverPosture::Present,
            NOW
        ),
        Admission::AdmittedAsClaim { .. }
    ));
}

#[test]
fn case_f2_observer_integrity_unknown_is_distinct_from_unavailable() {
    // The 12767ea finding, in the physical layer: a live observer that may have
    // been blind is not the same as no observer, and neither is the same as an
    // observer that looked and saw nothing.
    let cam = external_camera(99_200, 1, 1_980);
    let outcomes: Vec<Admission> = [
        ObserverPosture::Unavailable,
        ObserverPosture::IntegrityUnknown,
        ObserverPosture::PresentAndSilent,
    ]
    .iter()
    .map(|p| admit_at(&cam, *p, NOW))
    .collect();
    assert_ne!(outcomes[0], outcomes[1]);
    assert_ne!(outcomes[1], outcomes[2]);
    assert_ne!(outcomes[0], outcomes[2]);
    for o in &outcomes {
        assert!(!o.is_admitted());
        assert!(!o.supports_physical_effect());
    }
}

// ─── G. external observer disagreement ───

#[test]
fn case_g_a_disagreeing_external_observer_is_never_outvoted() {
    for onboard_count in 1..=8usize {
        let agreement = SourceAgreement {
            agreeing: vec![ProvenanceClass::SubjectSelfReport; onboard_count],
            disagreeing: vec![ProvenanceClass::ExternalSensorAnchored],
        };
        assert!(
            !agreement.is_resolvable(),
            "{onboard_count} subject-side sources must not resolve a conflict"
        );
        assert!(!agreement.classify().establishes());
        // And no count raises the ceiling.
        assert_eq!(
            agreement.ceiling_after_agreement(aip_observation::EvidenceCeiling::Corroborative),
            aip_observation::EvidenceCeiling::Corroborative
        );
    }
}

// ─── the standing negative, over the whole scenario ───

#[test]
fn no_case_in_the_scenario_promotes_controller_success_to_physical_effect() {
    let mut ledger = AdmissionLedger::new();
    let mut seq = 0u64;
    let mut next = || {
        seq += 1;
        seq
    };
    let stream = [
        onboard_telemetry(99_000, next(), 2_000),
        controller_ack(99_100, next(), true),
        external_camera(99_200, next(), 1_980),
        external_camera(99_300, next(), 0),
    ];
    for o in &stream {
        let a = admit(
            o,
            ObserverPosture::Present,
            NOW,
            AdmissionPolicy {
                freshness_bound_ms: 5_000,
            },
            &mut ledger,
        );
        assert!(
            !a.supports_physical_effect(),
            "{}: physical effect became provable",
            o.source
        );
    }
    assert_eq!(ledger.len(), 4);
}
