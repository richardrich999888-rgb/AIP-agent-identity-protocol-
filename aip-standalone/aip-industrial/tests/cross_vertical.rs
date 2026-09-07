//! Skills 23, 24 and 25 must not drift apart.
//!
//! # Why this file replaces the two-vertical one
//!
//! ADR-007 installed a two-way consistency guard in `aip-robotics` and deferred
//! extracting the shared rules until a third vertical existed. This is that
//! third vertical, and ADR-008 records what it showed: industrial is a third
//! *embodied* vertical, so the common shape it reveals is still an
//! embodiment-shaped one, and extracting now would produce the abstraction
//! ADR-007 warned an enterprise profile would have to work around. The guard is
//! therefore widened rather than retired.
//!
//! `aip-robotics/tests/cross_vertical.rs` remains as Skill 24 shipped it — a
//! completed skill is not reopened to serve the next one's tidiness. This file
//! is the superset: every property it checks, checked across all three.
//!
//! The three rules under guard:
//!
//! 1. agreement never raises a ceiling;
//! 2. a state claim never outruns its evidence tier, and may only echo or
//!    weaken;
//! 3. a source that is positionally independent but has no implemented
//!    mechanism establishes nothing.
//!
//! Plus three structural properties: the three verticals occupy one profile
//! slot under three ids, their action namespaces are disjoint, and all three
//! agree the physical tier is unreachable.

use aip_industrial::ProtocolAdapter;
use aip_observation::EvidenceCeiling;

// ─── rule 1: agreement never raises a ceiling ───

#[test]
fn all_three_verticals_refuse_to_raise_a_ceiling_on_agreement() {
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
        let ics = aip_industrial::InstrumentAgreement {
            agreeing: vec![aip_industrial::ProcessSensingSource::ProcessTransmitter; n],
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
            assert_eq!(
                ics.ceiling_after_agreement(base),
                base,
                "industrial, {n}, {base:?}"
            );
        }
    }
}

#[test]
fn all_three_verticals_report_a_conflict_rather_than_resolving_it() {
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
    let ics = aip_industrial::InstrumentAgreement {
        agreeing: vec![
            aip_industrial::ProcessSensingSource::ProcessTransmitter,
            aip_industrial::ProcessSensingSource::HistorianArchive,
            aip_industrial::ProcessSensingSource::HmiOperatorLog,
        ],
        disagreeing: vec![aip_industrial::ProcessSensingSource::IndependentPlantSensor],
    };
    assert!(matches!(
        uas.classify(),
        aip_uas::Agreement::Conflicting { .. }
    ));
    assert!(matches!(
        robot.classify(),
        aip_robotics::Agreement::Conflicting { .. }
    ));
    assert!(matches!(
        ics.classify(),
        aip_industrial::Agreement::Conflicting { .. }
    ));
    assert!(!uas.is_resolvable());
    assert!(!robot.is_resolvable());
    assert!(!ics.is_resolvable());
    assert!(!uas.classify().establishes());
    assert!(!robot.classify().establishes());
    assert!(!ics.classify().establishes());
}

#[test]
fn all_three_verticals_agree_that_corroboration_establishes_nothing() {
    let uas = aip_uas::Agreement::Corroborated {
        agreeing: 9,
        independent: 9,
    };
    let robot = aip_robotics::Agreement::Corroborated {
        agreeing: 9,
        independent: 9,
    };
    let ics = aip_industrial::Agreement::Corroborated {
        agreeing: 9,
        independent: 9,
    };
    assert_eq!(uas.establishes(), robot.establishes());
    assert_eq!(robot.establishes(), ics.establishes());
    assert!(!uas.establishes());
}

// ─── rule 2: echo or weaken, never strengthen ───

#[test]
fn all_three_state_models_may_only_echo_or_weaken() {
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
    for claimed in aip_industrial::LoopState::ALL {
        for tier in [
            aip_industrial::ProcessEvidence::Declared,
            aip_industrial::ProcessEvidence::DecisionSigned,
            aip_industrial::ProcessEvidence::ExecutionObserved,
            aip_industrial::ProcessEvidence::PhysicallyObserved,
        ] {
            let out = aip_industrial::LoopState::assertable(claimed, tier);
            assert!(
                out == claimed || out == aip_industrial::LoopState::Unknown,
                "industrial: {claimed:?}/{tier:?} → {out:?}"
            );
        }
    }
}

#[test]
fn all_three_verticals_agree_the_physical_tier_is_unreachable() {
    assert!(!aip_uas::StateEvidence::PhysicallyObserved.is_reachable());
    assert!(!aip_robotics::TaskEvidence::PhysicallyObserved.is_reachable());
    assert!(!aip_industrial::ProcessEvidence::PhysicallyObserved.is_reachable());
    // And therefore that a completion claim is unreachable in all three.
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
    assert_eq!(
        aip_industrial::LoopState::assertable(
            aip_industrial::LoopState::ShutdownComplete,
            aip_industrial::ProcessEvidence::PhysicallyObserved
        ),
        aip_industrial::LoopState::Unknown
    );
}

#[test]
fn the_three_evidence_ladders_have_the_same_shape_rung_for_rung() {
    // Not just "each is conservative" but "each is conservative in the same
    // places". A vertical that reordered its tiers would still pass the
    // echo-or-weaken test and would be a different accountability model.
    assert!(aip_uas::StateEvidence::Declared < aip_uas::StateEvidence::DecisionSigned);
    assert!(aip_uas::StateEvidence::DecisionSigned < aip_uas::StateEvidence::ExecutionObserved);
    assert!(aip_uas::StateEvidence::ExecutionObserved < aip_uas::StateEvidence::PhysicallyObserved);

    assert!(aip_robotics::TaskEvidence::Declared < aip_robotics::TaskEvidence::DecisionSigned);
    assert!(
        aip_robotics::TaskEvidence::DecisionSigned < aip_robotics::TaskEvidence::ExecutionObserved
    );
    assert!(
        aip_robotics::TaskEvidence::ExecutionObserved
            < aip_robotics::TaskEvidence::PhysicallyObserved
    );

    assert!(
        aip_industrial::ProcessEvidence::Declared < aip_industrial::ProcessEvidence::DecisionSigned
    );
    assert!(
        aip_industrial::ProcessEvidence::DecisionSigned
            < aip_industrial::ProcessEvidence::ExecutionObserved
    );
    assert!(
        aip_industrial::ProcessEvidence::ExecutionObserved
            < aip_industrial::ProcessEvidence::PhysicallyObserved
    );

    // The three lowest tiers are reachable in all three, and only the top is
    // not.
    assert!(aip_uas::StateEvidence::ExecutionObserved.is_reachable());
    assert!(aip_robotics::TaskEvidence::ExecutionObserved.is_reachable());
    assert!(aip_industrial::ProcessEvidence::ExecutionObserved.is_reachable());
}

// ─── rule 3: independence without a mechanism establishes nothing ───

#[test]
fn all_three_verticals_agree_that_independence_without_a_mechanism_establishes_nothing() {
    // UAS: a ground-station track. Robotics: an external camera. Industrial: an
    // instrument on a separate loop. All three outside the subject, none
    // implemented.
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
    let ics = aip_industrial::PhysicalProcessEffect::from_sources(
        aip_industrial::ProcessVariable::Pressure,
        aip_industrial::ProcessClaim::ProcessVariableIsValue,
        &[aip_industrial::ProcessSensingSource::IndependentPlantSensor],
    );
    assert!(!uas.establishes());
    assert!(!robot.establishes());
    assert!(!ics.establishes());
    assert_eq!(uas.ceiling(), robot.ceiling());
    assert_eq!(robot.ceiling(), ics.ceiling());
    assert_eq!(uas.ceiling(), EvidenceCeiling::Corroborative);
}

#[test]
fn all_three_verticals_agree_a_signature_moves_no_occurrence_answer() {
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

        // The industrial form of the same question: authentication is a
        // property of a protocol exchange, and moves neither the ceiling nor
        // the occurrence answer.
        let ics = aip_industrial::OpcUaAdapter.interaction(
            true,
            authenticated,
            &[aip_industrial::ProcessSensingSource::EdgeNetworkObservation],
        );
        assert!(!ics.establishes_process_change());
        assert_eq!(ics.evidence_ceiling(), EvidenceCeiling::Attested);
    }
}

// ─── structural: one slot, three ids, three namespaces ───

#[test]
fn the_three_verticals_occupy_the_same_slot_under_different_ids() {
    let uas = aip_uas::UasProfile::new("o", &[aip_uas::TelemetrySource::ImuOnboard])
        .unwrap()
        .profile_ref()
        .unwrap();
    let robot = aip_robotics::RoboticsProfile::new("o", &[aip_robotics::SensingSource::ImuOnboard])
        .unwrap()
        .profile_ref()
        .unwrap();
    let ics = aip_industrial::IndustrialProfile::new(
        "o",
        &[aip_industrial::ProcessSensingSource::ProcessTransmitter],
        &[aip_industrial::IndustrialProtocol::ModbusTcp],
    )
    .unwrap()
    .profile_ref()
    .unwrap();

    for r in [&uas, &robot, &ics] {
        assert_eq!(r.kind, aip_system::ProfileKind::Environment);
    }
    let ids = [uas.id(), robot.id(), ics.id()];
    for (i, a) in ids.iter().enumerate() {
        for (j, b) in ids.iter().enumerate() {
            if i != j {
                assert_ne!(
                    a, b,
                    "the id is what tells a verifier which vertical applied"
                );
            }
        }
    }
    let digests = [uas.digest, robot.digest, ics.digest];
    for (i, a) in digests.iter().enumerate() {
        for (j, b) in digests.iter().enumerate() {
            if i != j {
                assert_ne!(
                    a, b,
                    "three verticals declaring one sensor must not collide"
                );
            }
        }
    }
}

#[test]
fn the_three_action_namespaces_are_disjoint() {
    let uas: Vec<&str> = aip_uas::UasAction::ALL.iter().map(|a| a.kind()).collect();
    let robot: Vec<&str> = aip_robotics::RobotAction::ALL
        .iter()
        .map(|a| a.kind())
        .collect();
    let ics: Vec<&str> = aip_industrial::IndustrialCommand::ALL
        .iter()
        .map(|c| c.kind())
        .collect();

    for u in &uas {
        assert!(u.starts_with("uas."), "{u}");
        assert!(!robot.contains(u) && !ics.contains(u), "{u} appears twice");
    }
    for r in &robot {
        assert!(r.starts_with("robot."), "{r}");
        assert!(!uas.contains(r) && !ics.contains(r), "{r} appears twice");
    }
    for c in &ics {
        assert!(c.starts_with("ics."), "{c}");
        assert!(!uas.contains(c) && !robot.contains(c), "{c} appears twice");
    }
}

#[test]
fn the_three_domain_tags_and_parameter_keys_are_distinct() {
    // Domain separation across verticals: a preimage from one profile must
    // never be a valid preimage in another.
    let domains = [
        "SYNTRIASS/AUTONOMY/UAS_PROFILE/v1",
        aip_robotics::ROBOTICS_PROFILE_DOMAIN,
        aip_industrial::INDUSTRIAL_PROFILE_DOMAIN,
    ];
    assert_ne!(domains[1], domains[2]);
    assert_ne!(domains[0], domains[2]);

    let keys = [
        aip_uas::MISSION_PARAMETER_KEY,
        aip_robotics::TASK_PARAMETER_KEY,
        aip_industrial::CONTROL_LOOP_PARAMETER_KEY,
        aip_industrial::SAFETY_BOUNDARY_PARAMETER_KEY,
    ];
    for (i, a) in keys.iter().enumerate() {
        for (j, b) in keys.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "two commitments must not share a parameter key");
            }
        }
    }
}

#[test]
fn no_vertical_reaches_further_along_its_own_chain_than_the_others_do() {
    // Each vertical stops at the last rung a Linux mechanism covers, and each
    // reports the remaining distance rather than rounding it away.
    assert_eq!(
        aip_robotics::EmbodiedChain::current().highest_observable(),
        Some(aip_robotics::EmbodiedRung::TaskCommand)
    );
    assert_eq!(
        aip_industrial::ControlLoopChain::current().highest_observable(),
        Some(aip_industrial::ControlRung::CommandIssued)
    );
    assert_eq!(
        aip_robotics::EmbodiedChain::current().unobserved_boundaries_to_outcome(),
        5
    );
    assert_eq!(
        aip_industrial::ControlLoopChain::current().unobserved_boundaries_to_effect(),
        6
    );
}
