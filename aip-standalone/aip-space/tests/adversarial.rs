//! The twelve adversarial cases Skill 26 names, plus the standing negatives.
//!
//! Required property, asserted case by case: **no test turns uncertainty into
//! success.** Every refusal here is a statement about the evidence, and none is
//! a statement that anything did or did not happen aboard the vehicle.

use aip_observe::{ContinuityFault, ContinuityStatus};
use aip_space::{
    AutonomyMode, AutonomyModeTransition, BundleLedger, BundleSegment, CommandTiming,
    DelayedEvidence, GroundConclusion, GroundVerificationContext, LinkState, MissionState,
    SegmentLedger, SegmentOutcome, SourceAgreement, SpaceError, SpaceEvidence, SpaceSensingSource,
    StoreAndForwardBundle,
};
use aip_system::{MissionId, SystemId};

fn head_for(n: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_le_bytes());
    h
}

fn seg(sequence: u64) -> BundleSegment {
    BundleSegment {
        sequence,
        prev_head: head_for(sequence - 1),
        head: head_for(sequence),
        attested_at_ms: 1_000 + sequence,
        payload_digest: [0xAB; 32],
    }
}

fn sys() -> SystemId {
    SystemId::parse("space:sat-7").expect("system id")
}
fn mission() -> MissionId {
    MissionId::parse("mission:pass-114").expect("mission id")
}

fn bundle(range: std::ops::RangeInclusive<u64>) -> StoreAndForwardBundle {
    StoreAndForwardBundle::new(
        sys(),
        mission(),
        "onboard-collector",
        range.map(seg).collect(),
        1_000,
        9_000,
        LinkState::Reconnected,
    )
    .expect("bundle")
}

fn station() -> GroundVerificationContext {
    GroundVerificationContext::new("gs-svalbard", 1_000_000, true).expect("station")
}

// ─── 1. missing middle segment ───

#[test]
fn s1_a_missing_middle_segment_is_recorded_and_never_becomes_non_occurrence() {
    let mut l = SegmentLedger::new();
    l.stage(bundle(1..=3)).unwrap();
    l.stage(bundle(7..=9)).unwrap();
    let outcomes = l.drain().unwrap();
    match &outcomes[1] {
        SegmentOutcome::AdmittedWithGap { missing, .. } => assert_eq!(missing, &vec![4, 5, 6]),
        other => panic!("expected a gap, got {other:?}"),
    }
    assert_eq!(l.unfilled_gaps(), vec![4, 5, 6]);
    assert_eq!(l.continuity_status(), ContinuityStatus::GapObserved);
    assert!(!l.non_occurrence_admissible());
    let c = station().conclude(&l);
    assert_eq!(
        c,
        GroundConclusion::EvidenceIncomplete {
            missing: vec![4, 5, 6]
        }
    );
    assert!(!c.asserts_non_occurrence());
    assert!(!c.asserts_completeness());
}

// ─── 2. delayed middle segment arriving after later evidence ───

#[test]
fn s2_a_delayed_middle_segment_does_not_close_the_gap_it_would_have_filled() {
    let mut l = SegmentLedger::new();
    l.stage(bundle(1..=3)).unwrap();
    l.stage(bundle(7..=9)).unwrap();
    l.drain().unwrap();
    assert_eq!(l.unfilled_gaps(), vec![4, 5, 6]);

    l.stage(bundle(4..=6)).unwrap();
    let outcomes = l.drain().unwrap();
    assert!(matches!(outcomes[0], SegmentOutcome::LateArrival { .. }));
    assert!(!outcomes[0].advanced_chain());
    assert_eq!(
        l.unfilled_gaps(),
        vec![4, 5, 6],
        "a gap is closed by evidence arriving in order and by nothing else"
    );
    assert_eq!(l.continuity_status(), ContinuityStatus::GapObserved);
    assert!(!l.completeness_claimable());
    assert!(l.require_filled(&[4, 5, 6]).is_err());
}

// ─── 3. replayed old segment after reconnection ───

#[test]
fn s3_a_replayed_segment_after_reconnection_is_refused_by_the_ledger() {
    let mut l = SegmentLedger::new();
    l.stage(bundle(1..=3)).unwrap();
    l.drain().unwrap();
    // A different bundle, re-offering the segment already at the chain head.
    let replay = StoreAndForwardBundle::new(
        sys(),
        MissionId::parse("mission:pass-115").unwrap(),
        "onboard-collector",
        (3..=5).map(seg).collect(),
        1_000,
        9_000,
        LinkState::Reconnected,
    )
    .unwrap();
    l.stage(replay).unwrap();
    assert!(matches!(
        l.drain(),
        Err(SpaceError::ContinuityRefused {
            fault: ContinuityFault::Replay { sequence: 3 }
        })
    ));
}

// ─── 4. duplicated store-and-forward bundle ───

#[test]
fn s4_a_duplicated_bundle_is_refused_at_the_second_contact() {
    let mut ledger = BundleLedger::new();
    let b = bundle(1..=3);
    assert!(ledger.admit(&b).is_ok());
    assert!(matches!(
        ledger.admit(&b),
        Err(SpaceError::BundleAlreadySeen { .. })
    ));
    assert_eq!(ledger.len(), 1);

    // And through the segment layer, where staging is the entry point.
    let mut l = SegmentLedger::new();
    l.stage(bundle(1..=3)).unwrap();
    assert!(matches!(
        l.stage(bundle(1..=3)),
        Err(SpaceError::BundleAlreadySeen { .. })
    ));
}

// ─── 5. reordered evidence ───

#[test]
fn s5_reordered_bundles_are_reassembled_and_never_silently_accepted_out_of_order() {
    let mut l = SegmentLedger::new();
    l.stage(bundle(7..=9)).unwrap();
    l.stage(bundle(4..=6)).unwrap();
    l.stage(bundle(1..=3)).unwrap();
    let outcomes = l.drain().unwrap();
    assert_eq!(outcomes.len(), 3);
    assert!(
        l.unfilled_gaps().is_empty(),
        "three contacts in the wrong order is not a gap"
    );
    assert!(l.completeness_claimable());
    assert_eq!(l.continuity_status(), ContinuityStatus::Verified);
    assert_eq!(
        station().conclude(&l),
        GroundConclusion::EvidenceComplete { segments: 9 }
    );
}

// ─── 6. forked history A/B ───

#[test]
fn s6_a_forked_history_is_never_silently_collapsed() {
    // Two distinct bundles claiming the same starting sequence.
    let mut l = SegmentLedger::new();
    l.stage(bundle(1..=3)).unwrap();
    let forked = StoreAndForwardBundle::new(
        sys(),
        mission(),
        "onboard-collector",
        (1..=4).map(seg).collect(),
        1_000,
        9_000,
        LinkState::Reconnected,
    )
    .unwrap();
    assert!(matches!(
        l.stage(forked),
        Err(SpaceError::ContinuityRefused {
            fault: ContinuityFault::Fork { .. }
        })
    ));

    // And a fork inside one run: the same sequence with a different head.
    let mut l2 = SegmentLedger::new();
    l2.stage(bundle(1..=3)).unwrap();
    l2.drain().unwrap();
    let mut divergent = seg(3);
    divergent.head = [0xEE; 32];
    let branch = StoreAndForwardBundle::new(
        sys(),
        MissionId::parse("mission:pass-116").unwrap(),
        "onboard-collector",
        vec![divergent, {
            let mut s4 = seg(4);
            s4.prev_head = [0xEE; 32];
            s4
        }],
        1_000,
        9_000,
        LinkState::Reconnected,
    )
    .unwrap();
    l2.stage(branch).unwrap();
    assert!(matches!(
        l2.drain(),
        Err(SpaceError::ContinuityRefused {
            fault: ContinuityFault::Fork { .. }
        })
    ));
    assert!(l2.is_quarantined());
    assert_eq!(l2.continuity_status(), ContinuityStatus::Broken);
    assert_eq!(station().conclude(&l2), GroundConclusion::ContinuityBroken);
}

// ─── 7. delayed ground command ───

#[test]
fn s7_a_delayed_ground_command_keeps_its_six_moments_distinct() {
    let t = CommandTiming {
        authorized_at_ms: 1_000,
        transmitted_at_ms: Some(2_000),
        received_onboard_at_ms: Some(3_000),
        executed_at_ms: Some(4_000),
        observed_at_ms: Some(4_100),
        ground_verified_at_ms: Some(900_000),
    };
    assert_eq!(t.recorded_moments(), 6);
    assert!(!t.cross_clock_order_established());
    assert!(!t.execution_follows_authorization());
}

// ─── 8. observation arrives after command ───

#[test]
fn s8_an_observation_arriving_after_a_command_says_nothing_about_when_it_happened() {
    let e = DelayedEvidence::new("attested batch", 4_100, 900_000).unwrap();
    assert_eq!(e.latency_ms(), 895_900);
    assert!(!e.event_time_established());
    assert!(!e.receipt_time_is_event_time());
    assert!(!e.describes_event_at(900_000));
    let (bound, basis) = e.event_time_upper_bound();
    assert_eq!(bound, 4_100);
    assert!(basis.bounds_event_time());
    // The mission state cannot be upgraded by the arrival either.
    assert_eq!(
        MissionState::assertable(MissionState::Completed, SpaceEvidence::ExecutionObserved),
        MissionState::Unknown
    );
}

// ─── 9. forged continuity restoration ───

#[test]
fn s9_reconnection_restores_no_continuity_and_grants_nothing() {
    let mut l = SegmentLedger::new();
    l.stage(bundle(1..=3)).unwrap();
    l.stage(bundle(7..=9)).unwrap();
    l.drain().unwrap();
    let before = l.continuity_status();

    // A bundle explicitly labelled as arriving on a restored link.
    let restored = StoreAndForwardBundle::new(
        sys(),
        mission(),
        "onboard-collector",
        (10..=12).map(seg).collect(),
        1_000,
        9_000,
        LinkState::Connected,
    )
    .unwrap();
    l.stage(restored).unwrap();
    l.drain().unwrap();

    assert_eq!(before, ContinuityStatus::GapObserved);
    assert_eq!(
        l.continuity_status(),
        ContinuityStatus::GapObserved,
        "a healthy link does not restore continuity"
    );
    assert_eq!(l.unfilled_gaps(), vec![4, 5, 6]);
    for s in LinkState::ALL {
        assert!(!s.changes_evidential_standing(), "{s:?}");
    }
}

// ─── 10. forged bundle metadata ───

#[test]
fn s10_forged_bundle_metadata_changes_the_digest_and_is_not_the_same_bundle() {
    let real = bundle(1..=3);
    let relabelled = StoreAndForwardBundle::new(
        sys(),
        MissionId::parse("mission:pass-999").unwrap(),
        "onboard-collector",
        (1..=3).map(seg).collect(),
        1_000,
        9_000,
        LinkState::Reconnected,
    )
    .unwrap();
    assert_ne!(real.digest(), relabelled.digest());
    // A ledger that admitted the real one does not treat the forgery as seen,
    // and vice versa: they are two different bundles, which is the point.
    let mut ledger = BundleLedger::new();
    ledger.admit(&real).unwrap();
    assert!(!ledger.has_seen(&relabelled));
}

// ─── 11. malformed bundle ───

#[test]
fn s11_a_malformed_bundle_is_refused_rather_than_partially_accepted() {
    // A hole inside the run.
    assert!(matches!(
        StoreAndForwardBundle::new(
            sys(),
            mission(),
            "obs",
            vec![seg(1), seg(2), seg(9)],
            1_000,
            9_000,
            LinkState::Connected,
        ),
        Err(SpaceError::BundleNotContiguous { .. })
    ));
    // An internal chain that does not link.
    let mut broken = vec![seg(1), seg(2)];
    broken[1].prev_head = [0xFF; 32];
    assert!(StoreAndForwardBundle::new(
        sys(),
        mission(),
        "obs",
        broken,
        1_000,
        9_000,
        LinkState::Connected
    )
    .is_err());
    // No observer, no segments, backwards interval.
    assert!(StoreAndForwardBundle::new(
        sys(),
        mission(),
        "",
        vec![seg(1)],
        1,
        2,
        LinkState::Connected
    )
    .is_err());
    assert!(
        StoreAndForwardBundle::new(sys(), mission(), "o", vec![], 1, 2, LinkState::Connected)
            .is_err()
    );
    assert!(StoreAndForwardBundle::new(
        sys(),
        mission(),
        "o",
        vec![seg(1)],
        2,
        1,
        LinkState::Connected
    )
    .is_err());
}

// ─── 12. truncated bundle / missing tail ───

#[test]
fn s12_a_truncated_bundle_fails_its_own_range_check_at_the_receiver() {
    let good = bundle(1..=5);
    let mut json = serde_json::to_value(&good).unwrap();
    let kept = json["segments"].as_array().unwrap()[..2].to_vec();
    json["segments"] = serde_json::Value::Array(kept);
    let truncated: StoreAndForwardBundle = serde_json::from_value(json).unwrap();
    assert!(matches!(
        truncated.check(),
        Err(SpaceError::BundleRangeMismatch { .. })
    ));
    // And the ledger refuses it at the door, before anything is admitted.
    let mut l = SegmentLedger::new();
    assert!(l.stage(truncated).is_err());
    assert_eq!(l.admitted_count(), 0);
}

// ─── the standing negatives ───

#[test]
fn s13_no_number_of_onboard_sources_resolves_a_disagreement_with_ground_tracking() {
    for n in 1..=8usize {
        let a = SourceAgreement {
            agreeing: vec![SpaceSensingSource::HousekeepingTelemetry; n],
            disagreeing: vec![SpaceSensingSource::GroundRadiometricTracking],
        };
        assert!(!a.is_resolvable(), "{n}");
        assert!(!a.classify().establishes(), "{n}");
        assert_eq!(
            a.ceiling_after_agreement(aip_observation::EvidenceCeiling::Corroborative),
            aip_observation::EvidenceCeiling::Corroborative
        );
    }
}

#[test]
fn s14_a_mode_transition_establishes_neither_its_cause_nor_its_occurrence() {
    for to in [
        AutonomyMode::SafeMode,
        AutonomyMode::LinkLossContingency,
        AutonomyMode::OnboardAutonomous,
    ] {
        let t = AutonomyModeTransition::new(
            sys(),
            mission(),
            1,
            AutonomyMode::SupervisedSequence,
            to,
            LinkState::Disconnected,
            10_000,
            "loss of signal",
        )
        .unwrap();
        assert!(!t.cause_established(), "{to:?}");
        assert!(!t.independently_observed(), "{to:?}");
    }
}

#[test]
fn s15_nothing_arriving_at_all_concludes_cannot_prove() {
    let l = SegmentLedger::new();
    let c = station().conclude(&l);
    assert!(matches!(c, GroundConclusion::CannotProve { .. }));
    assert!(!c.asserts_non_occurrence());
    assert!(!c.asserts_completeness());
}
