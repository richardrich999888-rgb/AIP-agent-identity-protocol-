//! Skills 23 and 24 must not drift apart.
//!
//! # Why this file exists instead of a shared crate
//!
//! `aip-uas` and `aip-robotics` implement three generic rules independently:
//!
//! 1. agreement never raises a ceiling;
//! 2. a state claim never outruns its evidence tier, and may only echo or
//!    weaken;
//! 3. a source that is positionally independent but has no implemented
//!    mechanism establishes nothing.
//!
//! Extracting them into a shared profile kit is the right long-term answer and
//! is deliberately not done here: it would mean editing Skill 23, which this
//! skill's brief forbids, and two instances is too few to know what is
//! genuinely common — the third vertical is where the shape becomes visible.
//! See ADR-006.
//!
//! Until then, duplication without a guard is duplication that diverges. This
//! file is the guard: it drives both profiles through the same questions and
//! asserts they answer identically. A future extraction should delete it and
//! keep the properties.

use aip_observation::EvidenceCeiling;

#[test]
fn both_verticals_refuse_to_raise_a_ceiling_on_agreement() {
    for n in 1..=8usize {
        let uas = aip_uas::SensorAgreement {
            quantity: aip_uas::NavigationQuantity::Position,
            agreeing: vec![aip_uas::TelemetrySource::GnssReceiverOnboard; n],
            disagreeing: vec![],
        };
        let robot = aip_robotics::SensorAgreement {
            agreeing: vec![aip_robotics::SensingSource::EncoderOnboard; n],
            disagreeing: vec![],
        };
        for base in [
            EvidenceCeiling::Corroborative,
            EvidenceCeiling::Attested,
            EvidenceCeiling::Proven,
        ] {
            assert_eq!(
                uas.ceiling_after_agreement(base),
                base,
                "uas, {n}, {base:?}"
            );
            assert_eq!(
                robot.ceiling_after_agreement(base),
                base,
                "robotics, {n}, {base:?}"
            );
        }
    }
}

#[test]
fn both_verticals_report_a_conflict_rather_than_resolving_it() {
    let uas = aip_uas::SensorAgreement {
        quantity: aip_uas::NavigationQuantity::Altitude,
        agreeing: vec![
            aip_uas::TelemetrySource::GnssReceiverOnboard,
            aip_uas::TelemetrySource::ImuOnboard,
            aip_uas::TelemetrySource::FlightControllerTelemetry,
        ],
        disagreeing: vec![aip_uas::TelemetrySource::BarometerOnboard],
    };
    let robot = aip_robotics::SensorAgreement {
        agreeing: vec![
            aip_robotics::SensingSource::EncoderOnboard,
            aip_robotics::SensingSource::OdometryOnboard,
            aip_robotics::SensingSource::ImuOnboard,
        ],
        disagreeing: vec![aip_robotics::SensingSource::LidarOnboard],
    };
    assert!(matches!(
        uas.classify(),
        aip_uas::Agreement::Conflicting { .. }
    ));
    assert!(matches!(
        robot.classify(),
        aip_robotics::Agreement::Conflicting { .. }
    ));
    assert!(!uas.is_resolvable());
    assert!(!robot.is_resolvable());
    assert!(!uas.classify().establishes());
    assert!(!robot.classify().establishes());
}

#[test]
fn both_verticals_agree_that_corroboration_establishes_nothing() {
    let uas = aip_uas::Agreement::Corroborated {
        agreeing: 9,
        independent: 9,
    };
    let robot = aip_robotics::Agreement::Corroborated {
        agreeing: 9,
        independent: 9,
    };
    assert_eq!(uas.establishes(), robot.establishes());
    assert!(!uas.establishes());
}

#[test]
fn both_state_models_may_only_echo_or_weaken() {
    // The rule stated over the full product of states and tiers, in both
    // profiles. A divergence here would mean one vertical had learned to
    // strengthen a claim.
    for claimed in aip_uas::MissionState::ALL {
        for tier in [
            aip_uas::StateEvidence::Declared,
            aip_uas::StateEvidence::DecisionSigned,
            aip_uas::StateEvidence::ExecutionObserved,
            aip_uas::StateEvidence::PhysicallyObserved,
        ] {
            let out = aip_uas::MissionState::assertable(claimed, tier);
            assert!(
                out == claimed || out == aip_uas::MissionState::Unknown,
                "uas: {claimed:?}/{tier:?} → {out:?}"
            );
        }
    }
    for claimed in aip_robotics::TaskState::ALL {
        for tier in [
            aip_robotics::TaskEvidence::Declared,
            aip_robotics::TaskEvidence::DecisionSigned,
            aip_robotics::TaskEvidence::ExecutionObserved,
            aip_robotics::TaskEvidence::PhysicallyObserved,
        ] {
            let out = aip_robotics::TaskState::assertable(claimed, tier);
            assert!(
                out == claimed || out == aip_robotics::TaskState::Unknown,
                "robotics: {claimed:?}/{tier:?} → {out:?}"
            );
        }
    }
}

#[test]
fn both_verticals_agree_the_physical_tier_is_unreachable() {
    assert!(!aip_uas::StateEvidence::PhysicallyObserved.is_reachable());
    assert!(!aip_robotics::TaskEvidence::PhysicallyObserved.is_reachable());
    // And therefore that a completion claim is unreachable in both.
    assert_eq!(
        aip_uas::MissionState::assertable(
            aip_uas::MissionState::Completed,
            aip_uas::StateEvidence::PhysicallyObserved
        ),
        aip_uas::MissionState::Unknown
    );
    assert_eq!(
        aip_robotics::TaskState::assertable(
            aip_robotics::TaskState::Completed,
            aip_robotics::TaskEvidence::PhysicallyObserved
        ),
        aip_robotics::TaskState::Unknown
    );
}

#[test]
fn both_verticals_agree_that_independence_without_a_mechanism_establishes_nothing() {
    // UAS: a ground-station track. Robotics: an external camera. Both outside
    // the subject, neither implemented.
    let uas = aip_uas::NavigationEvidence::from_sources(
        aip_uas::NavigationQuantity::Position,
        &[aip_uas::TelemetrySource::GroundStationTrack],
        false,
    );
    let robot = aip_robotics::NavigationEvidence::from_sources(
        aip_robotics::PoseQuantity::Position,
        &[aip_robotics::SensingSource::ExternalTracking],
        false,
    );
    assert!(!uas.establishes());
    assert!(!robot.establishes());
    assert_eq!(uas.ceiling(), robot.ceiling());
    assert_eq!(uas.ceiling(), EvidenceCeiling::Corroborative);
}

#[test]
fn both_verticals_agree_a_signature_moves_no_occurrence_answer() {
    for authenticated in [true, false] {
        let uas = aip_uas::NavigationEvidence::from_sources(
            aip_uas::NavigationQuantity::Altitude,
            &[aip_uas::TelemetrySource::BarometerOnboard],
            authenticated,
        );
        let robot = aip_robotics::NavigationEvidence::from_sources(
            aip_robotics::PoseQuantity::Odometry,
            &[aip_robotics::SensingSource::OdometryOnboard],
            authenticated,
        );
        assert!(!uas.establishes());
        assert!(!robot.establishes());
    }
}

#[test]
fn the_two_verticals_occupy_the_same_slot_under_different_ids() {
    let uas = aip_uas::UasProfile::new("o", &[aip_uas::TelemetrySource::ImuOnboard])
        .unwrap()
        .profile_ref()
        .unwrap();
    let robot = aip_robotics::RoboticsProfile::new("o", &[aip_robotics::SensingSource::ImuOnboard])
        .unwrap()
        .profile_ref()
        .unwrap();
    assert_eq!(uas.kind, aip_system::ProfileKind::Environment);
    assert_eq!(robot.kind, aip_system::ProfileKind::Environment);
    assert_ne!(
        uas.id(),
        robot.id(),
        "the id is what tells a verifier which vertical a commitment is about"
    );
    assert_ne!(
        uas.digest, robot.digest,
        "two verticals declaring one sensor must not collide"
    );
}

#[test]
fn the_two_action_namespaces_are_disjoint() {
    let uas: Vec<&str> = aip_uas::UasAction::ALL.iter().map(|a| a.kind()).collect();
    let robot: Vec<&str> = aip_robotics::RobotAction::ALL
        .iter()
        .map(|a| a.kind())
        .collect();
    for u in &uas {
        assert!(!robot.contains(u), "{u} appears in both vocabularies");
    }
    for r in &robot {
        assert!(r.starts_with("robot."), "{r}");
    }
    for u in &uas {
        assert!(u.starts_with("uas."), "{u}");
    }
}
