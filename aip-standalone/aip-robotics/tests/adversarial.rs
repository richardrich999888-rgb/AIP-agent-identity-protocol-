//! The Skill 24 adversarial matrix, numbered to the brief.
//!
//! Each test names the case or cases it discharges. Where numbered items are
//! the same assertion under different words they share a test and say so;
//! splitting them would produce tests that fail together and prove one thing.
//!
//! Cases needing live kernel evidence — observer loss, collector loss, replay
//! against real batches, cross-execution injection — are in `integration.rs`,
//! which drives the Skill 22 reference rather than reimplementing it.

use aip_observation::{Completeness, EvidenceCeiling, ObservationClass};
use aip_robotics::{
    Agreement, ClaimSupport, EmbodiedChain, EmbodiedRung, ManipulationEvidence, Measurement,
    NavigationEvidence, ObjectStateClaim, PoseQuantity, RobotAction, RobotIdentityKind,
    RobotIdentityStability, RoboticsProfile, SafetyAction, SafetyEvidence, SemanticClaim,
    SensingSource, SensorAgreement, TaskEvidence, TaskPlan, TaskState, TaskWindow,
};

/// A well-equipped robot: every onboard sensor, signed telemetry, no
/// independent observer of anything.
const ROBOT: [SensingSource; 10] = [
    SensingSource::AutonomyRuntimeReport,
    SensingSource::ControllerTelemetry,
    SensingSource::EncoderOnboard,
    SensingSource::OdometryOnboard,
    SensingSource::ImuOnboard,
    SensingSource::ForceTorqueOnboard,
    SensingSource::TactileOnboard,
    SensingSource::CameraOnboard,
    SensingSource::LidarOnboard,
    SensingSource::LocalizationEstimateOnboard,
];

fn robot_profile() -> RoboticsProfile {
    RoboticsProfile::new("cell-collector", &ROBOT)
        .unwrap()
        .with_authenticated_telemetry()
}

fn plan(revision: u32, workspace: &str, actions: &[RobotAction]) -> TaskPlan {
    TaskPlan::new(
        aip_system::MissionId::parse("task:palletise-4").unwrap(),
        revision,
        aip_system::SystemId::parse("robot:cell-3-arm-1").unwrap(),
        TaskWindow {
            from_ms: 1_000,
            until_ms: 100_000,
        },
        workspace,
        actions,
    )
    .unwrap()
}

// ─── 1, 22. Self-reported task completion ───

#[test]
fn c01_c22_self_reported_task_completion_is_never_asserted() {
    for tier in [
        TaskEvidence::Declared,
        TaskEvidence::DecisionSigned,
        TaskEvidence::ExecutionObserved,
        TaskEvidence::PhysicallyObserved,
    ] {
        assert_eq!(
            TaskState::assertable(TaskState::Completed, tier),
            TaskState::Unknown,
            "COMPLETED became assertable at {tier:?}"
        );
    }
    // And a task *command* observed leaving the autonomy stack is not the task
    // being done (22).
    for a in RobotAction::ALL {
        assert_eq!(
            a.highest_established_rung(),
            EmbodiedRung::TaskCommand,
            "{a:?}"
        );
        assert!(!a.effect_observable(), "{a:?}");
    }
}

// ─── 2, 23, 24, 25. Self-reported robot state ───

#[test]
fn c02_c23_c24_c25_no_onboard_navigation_source_is_ground_truth() {
    // Odometry (23), SLAM (24) and an onboard camera (25) are three names for
    // the same fact: the robot reporting on itself.
    let p = robot_profile();
    for q in PoseQuantity::ALL {
        let e = p.navigation_evidence(q);
        assert!(!e.establishes(), "{q:?} was treated as truth");
        assert_eq!(e.ceiling(), EvidenceCeiling::Corroborative, "{q:?}");
    }
    for (source, quantity) in [
        (SensingSource::OdometryOnboard, PoseQuantity::Odometry),
        (
            SensingSource::LocalizationEstimateOnboard,
            PoseQuantity::Position,
        ),
        (
            SensingSource::CameraOnboard,
            PoseQuantity::ObstacleInteraction,
        ),
    ] {
        let e = NavigationEvidence::from_sources(quantity, &[source], true);
        assert!(!e.establishes(), "{source:?} was read as ground truth");
    }
}

// ─── 3, 4, 5, 21, 26. Self-reported object state ───

#[test]
fn c03_c04_c05_c21_c26_no_object_state_claim_survives_onboard_sensing() {
    // Grasp success (4), placement success (5), a gripper command read as grasp
    // proof (21) and a force reading read as task success (26) are one error
    // with four names: the object is a third party none of the robot's sensors
    // measures.
    let p = robot_profile();
    for c in ObjectStateClaim::ALL {
        let e = p.manipulation_evidence(c);
        assert!(!e.establishes(), "{c:?} was established by onboard sensing");
    }
    assert_eq!(
        aip_robotics::semantics::support_for(
            Measurement::GripperAperture,
            SemanticClaim::ObjectGrasped
        ),
        ClaimSupport::Bears
    );
    assert_eq!(
        aip_robotics::semantics::support_for(
            Measurement::ForceMagnitude,
            SemanticClaim::CollisionOccurred
        ),
        ClaimSupport::Bears
    );
}

// ─── 6. Forged telemetry ───

#[test]
fn c06_forging_telemetry_changes_nothing_because_authenticity_was_never_the_question() {
    let signed = RoboticsProfile::new("o", &ROBOT)
        .unwrap()
        .with_authenticated_telemetry();
    let unsigned = RoboticsProfile::new("o", &ROBOT).unwrap();
    for q in PoseQuantity::ALL {
        assert_eq!(
            signed.navigation_evidence(q).establishes(),
            unsigned.navigation_evidence(q).establishes(),
            "{q:?}"
        );
        assert_eq!(
            signed.navigation_evidence(q).ceiling(),
            unsigned.navigation_evidence(q).ceiling(),
            "{q:?}"
        );
    }
}

// ─── 7, 8, 31, 32, 33, 34, 35, 36. Wrong-subject and cross-injection ───

#[test]
fn c07_c08_c31_c32_c33_c34_c35_c36_a_task_document_binds_to_one_robot_task_and_workspace() {
    let a = plan(1, "cell-3", &[RobotAction::Pick]);
    // Wrong task revision (8, 35, 36): a different document, a different digest.
    assert!(!a.is_committed_by(Some(&plan(2, "cell-3", &[RobotAction::Pick]).digest())));
    // Wrong workspace (32): part of the preimage.
    assert!(!a.is_committed_by(Some(&plan(1, "cell-4", &[RobotAction::Pick]).digest())));
    // Wrong robot (7, 33): the system id is inside the preimage.
    let other_robot = TaskPlan::new(
        aip_system::MissionId::parse("task:palletise-4").unwrap(),
        1,
        aip_system::SystemId::parse("robot:cell-9-arm-2").unwrap(),
        TaskWindow {
            from_ms: 1_000,
            until_ms: 100_000,
        },
        "cell-3",
        &[RobotAction::Pick],
    )
    .unwrap();
    assert_ne!(a.digest(), other_robot.digest());
    assert!(!other_robot.is_committed_by(Some(&a.digest())));
    // Wrong object (31): the object id is inside the DP-signed parameter set.
    assert_ne!(
        aip_robotics::action::object_parameters("widget-7")
            .unwrap()
            .digest(),
        aip_robotics::action::object_parameters("widget-8")
            .unwrap()
            .digest(),
    );
}

#[test]
fn c09_c10_c11_wrong_execution_platform_and_boot_are_the_cores_job_and_not_routed_around() {
    // The profile adds no path to an observation record except the core's own
    // constructor: every source that claims to produce one has a mechanism.
    for s in SensingSource::ALL {
        if s.can_produce_observation_record() {
            assert!(s.mechanism().is_some(), "{s:?}");
        }
    }
    let p = RoboticsProfile::new("o", &SensingSource::ALL).unwrap();
    let op = p.observation_profile().unwrap();
    assert_eq!(
        op.capability(ObservationClass::ProcessIdentity).ceiling(),
        EvidenceCeiling::Attested,
        "the profile may not raise what the core caps"
    );
}

// ─── 12, 13, 14, 15, 16, 39. Timing and absence ───

#[test]
fn c12_c13_c14_c15_c16_c39_absent_or_disordered_observation_asserts_nothing() {
    // Replay (12), duplication (13), reordering (14) and staleness (15) are
    // handled by the collector's chain and the reconciler's replay detection
    // over real batches, in Skill 22's suite and this crate's integration
    // tests. What the profile must not do is turn any of them — or plain
    // absence (16, 39) — into a statement about the robot.
    let empty = RoboticsProfile::new("o", &[]).unwrap();
    for q in PoseQuantity::ALL {
        let e = empty.navigation_evidence(q);
        assert!(!e.self_reported);
        assert!(!e.establishes());
        assert_eq!(
            e.statement(),
            "no source bears on this quantity in this deployment"
        );
    }
    for c in ObjectStateClaim::ALL {
        assert!(!empty.manipulation_evidence(c).establishes(), "{c:?}");
    }
    // Absence of observation is never non-occurrence: there is no method
    // anywhere in the profile that returns such a claim.
    assert_eq!(
        TaskState::assertable(TaskState::Aborted, TaskEvidence::ExecutionObserved),
        TaskState::Unknown
    );
}

// ─── 17, 18, 41. Observer, collector and suppression ───

#[test]
fn c17_c18_c41_losing_or_suppressing_the_observer_yields_unknown() {
    // Suppression is indistinguishable from absence, and must reach the same
    // conservative answer.
    let no_observer = RoboticsProfile::new("o", &ROBOT).unwrap();
    assert!(no_observer.mechanised_sources().is_empty());
    assert_eq!(no_observer.highest_established_rung(), None);
    let op = no_observer.observation_profile().unwrap();
    assert_eq!(
        op.completeness_without_evidence(ObservationClass::ProcessIdentity),
        Completeness::NotObservable,
        "a deployment with no observer records that it cannot look"
    );
    for a in SafetyAction::ALL {
        assert!(!SafetyEvidence::derive(a, false).request_observed, "{a:?}");
    }
}

// ─── 19, 20, 45. Acknowledgement is not effect ───

#[test]
fn c19_c20_c45_no_acknowledgement_or_command_becomes_a_physical_outcome() {
    // A controller acknowledgement (19), a motor command (20) and a software
    // success (45) are three labels for one claim: a message about a device is
    // not the device acting.
    for r in [
        EmbodiedRung::ControllerCommand,
        EmbodiedRung::ActuatorExecution,
        EmbodiedRung::ObservedActuatorState,
    ] {
        assert_eq!(
            r.origin(),
            aip_execution::EvidenceOrigin::SelfReported,
            "{r:?}"
        );
        assert!(!r.origin().can_establish_occurrence(), "{r:?}");
        assert!(!r.independently_observable(), "{r:?}");
    }
    let chain = EmbodiedChain::current();
    assert_eq!(chain.highest_observable(), Some(EmbodiedRung::TaskCommand));
    assert_eq!(
        chain.unobserved_boundaries_to_outcome(),
        5,
        "five boundaries lie between a sent command and a changed world"
    );
    assert!(!robot_profile().establishes_physical_effect());
}

// ─── 27, 28. Sensor agreement ───

#[test]
fn c27_c28_agreement_is_not_proof_and_conflict_is_not_resolved() {
    let agree = SensorAgreement {
        agreeing: vec![
            SensingSource::EncoderOnboard,
            SensingSource::OdometryOnboard,
            SensingSource::LocalizationEstimateOnboard,
        ],
        disagreeing: vec![],
    };
    assert!(!agree.classify().establishes());
    for base in [
        EvidenceCeiling::Corroborative,
        EvidenceCeiling::Attested,
        EvidenceCeiling::Proven,
    ] {
        assert_eq!(agree.ceiling_after_agreement(base), base);
    }
    let conflict = SensorAgreement {
        agreeing: vec![
            SensingSource::EncoderOnboard,
            SensingSource::OdometryOnboard,
            SensingSource::ImuOnboard,
        ],
        disagreeing: vec![SensingSource::LidarOnboard],
    };
    assert!(matches!(conflict.classify(), Agreement::Conflicting { .. }));
    assert!(
        !conflict.is_resolvable(),
        "three-to-one is not a resolution"
    );
}

// ─── 29, 30. Safety actions ───

#[test]
fn c29_c30_a_stop_command_is_not_a_stop() {
    for a in SafetyAction::ALL {
        assert!(!a.effect_establishable(), "{a:?}");
        assert!(
            !SafetyEvidence::derive(a, true).establishes_effect(),
            "{a:?}"
        );
        assert_eq!(
            a.effect_evidence_required(),
            TaskEvidence::PhysicallyObserved
        );
    }
    let e = SafetyEvidence::derive(SafetyAction::EmergencyStop, true);
    assert!(e.request_observed, "the command leaving is observable");
    assert!(!e.establishes_effect(), "the machine stopping is not");
    assert!(RobotAction::EmergencyStop.effect_gap().contains("brake"));
}

// ─── 37, 38. Ceiling integrity ───

#[test]
fn c37_the_profile_cannot_raise_its_own_ceiling() {
    // (a) declare everything: the projection still takes the class's ceiling.
    let p = RoboticsProfile::new("o", &SensingSource::ALL).unwrap();
    let op = p.observation_profile().unwrap();
    for class in ObservationClass::ALL {
        assert!(
            op.capability(class).ceiling() <= class.ceiling(),
            "{class:?}"
        );
    }
    // (b) agree with itself many times: agreement is not a ceiling operator.
    let many = SensorAgreement {
        agreeing: vec![SensingSource::EncoderOnboard; 16],
        disagreeing: vec![],
    };
    assert_eq!(
        many.ceiling_after_agreement(EvidenceCeiling::Corroborative),
        EvidenceCeiling::Corroborative
    );
    // (c) no source declares more than its class allows, and none reaches
    // Proven.
    for s in SensingSource::ALL {
        if let Some(class) = s.observation_class() {
            assert!(s.ceiling() <= class.ceiling(), "{s:?}");
        } else {
            assert_eq!(s.ceiling(), EvidenceCeiling::Corroborative, "{s:?}");
        }
        assert_ne!(s.ceiling(), EvidenceCeiling::Proven, "{s:?}");
    }
}

#[test]
fn c38_physical_effect_is_not_promoted_by_any_route() {
    for sources in [&ROBOT[..], &SensingSource::ALL[..]] {
        let p = RoboticsProfile::new("o", sources).unwrap();
        assert!(!p.establishes_physical_effect());
    }
    for c in SemanticClaim::ALL {
        assert!(!c.establishable_from_measurement(), "{c:?}");
    }
    for s in TaskState::ALL.iter().filter(|s| s.is_physical_claim()) {
        assert!(!s.reachable_in_this_build(), "{s:?}");
    }
}

// ─── 40. Unauthorized action ───

#[test]
fn c40_an_action_the_task_does_not_authorize_is_not_authorized() {
    let p = plan(1, "cell-3", &[RobotAction::NavigateTo, RobotAction::Pick]);
    assert!(p.authorizes(RobotAction::Pick));
    assert!(!p.authorizes(RobotAction::Place));
    assert!(!p.authorizes(RobotAction::ActivateTool));
    assert!(!p.authorizes(RobotAction::EmergencyStop));
    assert!(!p.applies_at(999));
    assert!(!p.applies_at(100_000));
}

// ─── 42, 43. Identity substitution ───

#[test]
fn c42_c43_controller_and_hardware_identity_are_never_established() {
    // Substituting a controller or a chassis is undetectable here, and the
    // profile says so rather than reporting continuity.
    for k in [RobotIdentityKind::Controller, RobotIdentityKind::Container] {
        assert!(!k.independently_established(), "{k:?}");
        for s in [
            k.across_process_restart(),
            k.across_controller_restart(),
            k.across_companion_reboot(),
            k.across_component_replacement(),
        ] {
            assert_eq!(s, RobotIdentityStability::NotEstablished, "{k:?}");
        }
    }
    // And a component replacement leaves the software untouched, which must
    // not be reported as continuity of the machine.
    for k in [
        RobotIdentityKind::Process,
        RobotIdentityKind::CompanionBoot,
        RobotIdentityKind::Platform,
    ] {
        assert_eq!(
            k.across_component_replacement(),
            RobotIdentityStability::NotEstablished,
            "{k:?}: software continuity is not physical continuity"
        );
    }
}

// ─── 44. Environment inferred without measurement ───

#[test]
fn c44_no_environment_state_is_inferred_from_a_transducer() {
    // The heart of the semantic boundary. Each pairing below is one people
    // make; each must come back `Bears`, never `Establishes`.
    for (m, c) in [
        (
            Measurement::RangeReading,
            SemanticClaim::SafeSeparationAchieved,
        ),
        (
            Measurement::ProximityFieldChange,
            SemanticClaim::HumanPresent,
        ),
        (
            Measurement::ForceMagnitude,
            SemanticClaim::CollisionOccurred,
        ),
        (Measurement::ImageFrame, SemanticClaim::ObjectIdentified),
        (Measurement::ShaftAngle, SemanticClaim::RobotMoved),
        (Measurement::PoseEstimate, SemanticClaim::GoalReached),
    ] {
        let support = aip_robotics::semantics::support_for(m, c);
        assert_eq!(support, ClaimSupport::Bears, "{m:?} → {c:?}");
        assert!(!support.permits_assertion(), "{m:?} → {c:?}");
    }
    // A collision is not damage, and nothing bears on damage at all.
    assert!(SemanticClaim::DamageOccurred
        .commonly_argued_from()
        .is_empty());
    assert!(!SemanticClaim::DamageOccurred.establishable_from_measurement());
}

// ─── Sweep ───

#[test]
fn nothing_in_this_profile_asserts_that_something_did_not_happen() {
    for a in [
        Agreement::Corroborated {
            agreeing: 9,
            independent: 9,
        },
        Agreement::Conflicting {
            agreeing: 1,
            disagreeing: 1,
        },
        Agreement::Insufficient { reporting: 0 },
    ] {
        assert!(!a.establishes(), "{a:?}");
    }
    for c in SemanticClaim::ALL {
        assert!(!c.establishable_from_measurement(), "{c:?}");
    }
    assert!(!RobotIdentityStability::NotEstablished.asserts_continuity());
}

#[test]
fn every_manipulation_claim_needs_something_no_onboard_sensor_provides() {
    for c in ObjectStateClaim::ALL {
        let e = ManipulationEvidence::from_sources(c, &SensingSource::ALL);
        assert!(!e.establishes(), "{c:?}");
        assert!(!c.requires().is_empty(), "{c:?}");
    }
}
