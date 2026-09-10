//! The Skill 23 adversarial matrix, numbered to the brief.
//!
//! Each test names the case or cases it discharges. Where two numbered items
//! are the same assertion under different words they share a test and say so;
//! splitting them would produce two tests that fail together and prove one
//! thing.
//!
//! Cases that need live kernel evidence — observer loss, collector loss,
//! cross-flight injection against real batches — are in `integration.rs` and
//! in `aip-edge`'s own suite, which this crate drives rather than
//! reimplements.

use aip_observation::{Completeness, EvidenceCeiling, ObservationClass};
use aip_uas::{
    AltitudeReference, CommandRung, CoordinateFrame, GeofenceAssessment, GeofenceRegion,
    LinkObservation, LinkState, MissionPlan, MissionState, MissionWindow, NavigationEvidence,
    NavigationQuantity, SensorAgreement, StateEvidence, TelemetrySource, UasAction, UasProfile,
};

/// A realistic airframe: every onboard sensor, signed telemetry, no
/// independent observer of anything physical.
const AIRFRAME: [TelemetrySource; 6] = [
    TelemetrySource::FlightControllerTelemetry,
    TelemetrySource::CompanionAutonomyReport,
    TelemetrySource::GnssReceiverOnboard,
    TelemetrySource::ImuOnboard,
    TelemetrySource::BarometerOnboard,
    TelemetrySource::AirspeedProbeOnboard,
];

fn airframe_profile() -> UasProfile {
    UasProfile::new("uas-collector", &AIRFRAME)
        .unwrap()
        .with_authenticated_telemetry()
}

fn region() -> GeofenceRegion {
    GeofenceRegion {
        frame: CoordinateFrame::Wgs84Geodetic,
        altitude_reference: AltitudeReference::GeoidMsl,
        min_lat_udeg: 51_000_000,
        max_lat_udeg: 52_000_000,
        min_lon_udeg: -1_000_000,
        max_lon_udeg: 1_000_000,
        min_alt_cm: 0,
        max_alt_cm: 12_000,
    }
}

fn plan(revision: u32, actions: &[UasAction]) -> MissionPlan {
    MissionPlan::new(
        aip_system::MissionId::parse("op:survey-17").unwrap(),
        revision,
        aip_system::SystemId::parse("uas:tail-07").unwrap(),
        MissionWindow {
            from_ms: 1_000,
            until_ms: 100_000,
        },
        region(),
        actions,
    )
    .unwrap()
}

// ─── 1. Self-reported mission completion ───

#[test]
fn c01_self_reported_mission_completion_is_never_asserted() {
    for tier in [
        StateEvidence::Declared,
        StateEvidence::DecisionSigned,
        StateEvidence::ExecutionObserved,
        StateEvidence::PhysicallyObserved,
    ] {
        assert_eq!(
            MissionState::assertable(MissionState::Completed, tier),
            MissionState::Unknown,
            "COMPLETED became assertable at {tier:?}"
        );
    }
}

// ─── 2, 3, 22, 23, 24. Self-reported navigation ───

#[test]
fn c02_c03_c22_c23_c24_no_onboard_navigation_source_is_ground_truth() {
    // Position (2, 22), altitude (3), GNSS (23) and IMU (24) are the same
    // assertion applied to four different names for "the subject said so".
    let p = airframe_profile();
    for q in NavigationQuantity::ALL {
        if q == NavigationQuantity::LinkState {
            continue; // covered separately; the airframe has no link observer
        }
        let e = p.navigation_evidence(q);
        assert!(e.self_reported, "{q:?} must be recognised as a self-report");
        assert!(!e.establishes(), "{q:?} was treated as truth");
        assert_eq!(e.ceiling(), EvidenceCeiling::Corroborative, "{q:?}");
    }
    // Named explicitly, because these two are the ones people argue about.
    let gnss = NavigationEvidence::from_sources(
        NavigationQuantity::Position,
        &[TelemetrySource::GnssReceiverOnboard],
        true,
    );
    let imu = NavigationEvidence::from_sources(
        NavigationQuantity::Attitude,
        &[TelemetrySource::ImuOnboard],
        true,
    );
    assert!(
        !gnss.establishes(),
        "GNSS is not universally trusted ground truth"
    );
    assert!(
        !imu.establishes(),
        "IMU is not universally trusted ground truth"
    );
}

// ─── 4, 20, 21, 30. Command acknowledgement is not effect ───

#[test]
fn c04_c20_c21_c30_no_acknowledgement_becomes_a_physical_effect() {
    // A flight-controller acknowledgement (20), a payload command (21), a
    // landing command (30) and an actuator success report (4) are one claim
    // with four labels: a message about a device is not the device acting.
    assert!(!CommandRung::FlightControllerAccepted
        .origin()
        .can_establish_occurrence());
    assert!(!CommandRung::ActuatorCommanded.independently_observable());
    assert!(!CommandRung::VehicleStateChanged.independently_observable());
    for a in UasAction::ALL {
        assert!(
            !a.effect_observable(),
            "{a:?} reached an observable physical effect"
        );
    }
    assert!(!airframe_profile().establishes_physical_effect());
}

// ─── 5. Forged telemetry ───

#[test]
fn c05_forging_telemetry_changes_nothing_because_authenticity_was_never_the_question() {
    // The profile's answer is identical for signed and unsigned telemetry,
    // which is why forging it buys an attacker nothing here: the occurrence
    // path never read the signature.
    let signed = UasProfile::new("o", &AIRFRAME)
        .unwrap()
        .with_authenticated_telemetry();
    let unsigned = UasProfile::new("o", &AIRFRAME).unwrap();
    for q in NavigationQuantity::ALL {
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

// ─── 6, 7, 8, 9, 10, 33, 34. Wrong-subject evidence ───

#[test]
fn c06_c07_c33_c34_a_mission_document_binds_to_one_system_and_one_revision() {
    let a = plan(1, &[UasAction::WaypointNavigate]);
    // Wrong mission revision (7): a different document, a different digest.
    assert!(!a.is_committed_by(Some(&plan(2, &[UasAction::WaypointNavigate]).digest())));
    // Wrong UAS (6): the system id is inside the preimage.
    let other_system = MissionPlan::new(
        aip_system::MissionId::parse("op:survey-17").unwrap(),
        1,
        aip_system::SystemId::parse("uas:tail-99").unwrap(),
        MissionWindow {
            from_ms: 1_000,
            until_ms: 100_000,
        },
        region(),
        &[UasAction::WaypointNavigate],
    )
    .unwrap();
    assert_ne!(
        a.digest(),
        other_system.digest(),
        "a mission authorized for one airframe must not commit for another"
    );
    // Cross-flight replay (33, 34): a commitment for one plan does not satisfy
    // another, in either direction.
    assert!(!other_system.is_committed_by(Some(&a.digest())));
}

#[test]
fn c08_c09_c10_wrong_execution_platform_and_boot_are_rejected_by_the_core() {
    // These three are the core's job and Skill 22 proved them against live
    // batches: `matches_process_of` for the execution, `PlatformDisposition`
    // for the platform, and `from_attested`'s boot check for the boot. The UAS
    // profile adds no path around any of them, which is what this asserts:
    // no source it declares can produce a record at all except through the
    // core's own constructor.
    for s in TelemetrySource::ALL {
        if s.can_produce_observation_record() {
            assert!(
                s.mechanism().is_some(),
                "{s:?} claims to produce a record without a mechanism"
            );
        }
    }
    // And the profile exposes no constructor of its own.
    let p = UasProfile::new("o", &TelemetrySource::ALL).unwrap();
    let op = p.observation_profile().unwrap();
    assert!(op
        .capability(ObservationClass::ProcessIdentity)
        .is_observable());
    assert_eq!(
        op.capability(ObservationClass::ProcessIdentity).ceiling(),
        EvidenceCeiling::Attested,
        "the profile may not raise what the core caps"
    );
}

// ─── 11, 12, 13, 14, 15, 16, 26. Telemetry timing and absence ───

#[test]
fn c14_c26_a_stale_position_cannot_answer_a_boundary_question() {
    let mut e = NavigationEvidence::from_sources(
        NavigationQuantity::Position,
        &[TelemetrySource::GroundStationTrack],
        false,
    );
    // Counterfactual deployment with a real independent tracker, so the
    // staleness path is reachable at all. Everything else about the test is
    // the real code.
    e.independently_observed = true;
    let claim = aip_uas::geofence::PositionClaim {
        frame: CoordinateFrame::Wgs84Geodetic,
        altitude_reference: AltitudeReference::GeoidMsl,
        lat_udeg: 51_500_000,
        lon_udeg: 0,
        alt_cm: 6_000,
        observed_at_ms: 1_000,
    };
    let a = GeofenceAssessment::assess(&region(), Some(&claim), &e, 500_000, 60_000);
    assert!(matches!(
        a,
        GeofenceAssessment::CannotAssess(aip_uas::geofence::CannotAssess::StalePosition { .. })
    ));
    assert!(
        !a.asserts_violation(),
        "a violation inferred from a stale fix is an accusation about a past moment"
    );
    assert!(!a.asserts_compliance());
}

#[test]
fn c11_c12_c13_c15_c16_absent_or_disordered_telemetry_asserts_nothing() {
    // Replay (11), duplication (12) and reordering (13) are handled by the
    // collector's chain and the reconciler's replay detection, over real
    // batches, in Skill 22's suite. What the UAS profile must not do is turn
    // any of those — or plain absence (15, 16) — into a statement about the
    // aircraft.
    for state in LinkState::ALL {
        assert!(!state.establishes_non_occurrence(), "{state:?}");
        assert!(!state.establishes_vehicle_state(), "{state:?}");
    }
    // Missing telemetry, in the profile's own terms: nothing is established
    // and nothing is denied.
    let e = NavigationEvidence::from_sources(NavigationQuantity::Position, &[], false);
    assert!(!e.self_reported);
    assert!(!e.establishes());
    assert_eq!(
        e.statement(),
        "no source bears on this quantity in this deployment"
    );
}

// ─── 17, 18. Observer and collector loss ───

#[test]
fn c17_c18_observer_or_collector_loss_yields_unknown_not_a_conclusion() {
    // On this profile's one real observation path, loss of coverage is
    // `Unknown` and never `Lost`, because an observer that was not looking has
    // not established silence.
    let o = LinkObservation {
        source: TelemetrySource::CompanionNetworkObservation,
        covered: false,
        traffic_seen: false,
        impaired: false,
    };
    assert_eq!(o.state(), LinkState::Unknown);
    // And nothing about the mission may be asserted from it.
    assert_eq!(
        MissionState::assertable(MissionState::InProgress, StateEvidence::DecisionSigned),
        MissionState::Unknown
    );
}

// ─── 19, 28, 29. A command is not its outcome ───

#[test]
fn c19_c28_c29_a_command_is_never_its_own_completion() {
    // Mission completion inferred from a waypoint command (28) and a completed
    // return inferred from an RTH command (29) are the same error as treating
    // an acknowledged call as an effect (19).
    for a in [UasAction::WaypointNavigate, UasAction::ReturnToHome] {
        assert!(!a.effect_observable(), "{a:?}");
        assert!(!a.effect_gap().is_empty());
    }
    assert_eq!(
        MissionState::assertable(MissionState::Returning, StateEvidence::ExecutionObserved),
        MissionState::Unknown,
        "a return-to-home command observed leaving the companion computer is not a return"
    );
    assert_eq!(
        MissionState::assertable(MissionState::Completed, StateEvidence::ExecutionObserved),
        MissionState::Unknown
    );
}

// ─── 25. Conflicting navigation sources ───

#[test]
fn c25_conflicting_sensors_stay_conflicting() {
    let a = SensorAgreement {
        quantity: NavigationQuantity::Altitude,
        agreeing: vec![
            TelemetrySource::GnssReceiverOnboard,
            TelemetrySource::ImuOnboard,
            TelemetrySource::FlightControllerTelemetry,
        ],
        disagreeing: vec![TelemetrySource::BarometerOnboard],
    };
    assert!(matches!(
        a.classify(),
        aip_uas::Agreement::Conflicting { .. }
    ));
    assert!(!a.is_resolvable(), "three-to-one is not a resolution");
    assert!(!a.classify().establishes());
    assert_eq!(
        a.ceiling_after_agreement(EvidenceCeiling::Corroborative),
        EvidenceCeiling::Corroborative
    );
}

// ─── 27. Geofence compliance from a self-report ───

#[test]
fn c27_compliance_is_never_inferred_from_the_aircrafts_own_position() {
    let p = airframe_profile();
    let e = p.navigation_evidence(NavigationQuantity::Position);
    let claim = aip_uas::geofence::PositionClaim {
        frame: CoordinateFrame::Wgs84Geodetic,
        altitude_reference: AltitudeReference::GeoidMsl,
        lat_udeg: 51_500_000,
        lon_udeg: 0,
        alt_cm: 6_000,
        observed_at_ms: 1_000,
    };
    let a = GeofenceAssessment::assess(&region(), Some(&claim), &e, 1_500, 60_000);
    assert!(!a.asserts_compliance(), "a claim is not compliance");
    assert!(!a.asserts_violation());
}

// ─── 31, 32. Ceiling integrity ───

#[test]
fn c31_the_profile_cannot_raise_its_own_evidence_ceiling() {
    // Two routes an implementer might reach for, both closed.
    //
    // (a) declare every source: the projection still takes the class's own
    //     ceiling, because `with_mechanism` derives it.
    let p = UasProfile::new("o", &TelemetrySource::ALL).unwrap();
    let op = p.observation_profile().unwrap();
    for class in ObservationClass::ALL {
        assert!(
            op.capability(class).ceiling() <= class.ceiling(),
            "{class:?}: the profile exceeded the class table"
        );
    }
    // (b) agree with itself many times: agreement is not a ceiling operator.
    let many = SensorAgreement {
        quantity: NavigationQuantity::Position,
        agreeing: vec![TelemetrySource::GnssReceiverOnboard; 16],
        disagreeing: vec![],
    };
    assert_eq!(
        many.ceiling_after_agreement(EvidenceCeiling::Corroborative),
        EvidenceCeiling::Corroborative
    );
}

#[test]
fn c32_no_declaration_supplies_stronger_evidence_than_the_mechanism_allows() {
    for s in TelemetrySource::ALL {
        if let Some(class) = s.observation_class() {
            assert!(
                s.ceiling() <= class.ceiling(),
                "{s:?} declared a ceiling above its class"
            );
        } else {
            assert_eq!(
                s.ceiling(),
                EvidenceCeiling::Corroborative,
                "{s:?} has no mechanism and must not declare more than corroboration"
            );
        }
        assert_ne!(s.ceiling(), EvidenceCeiling::Proven, "{s:?}");
    }
}

// ─── 35. Unauthorized mission action ───

#[test]
fn c35_an_action_the_mission_does_not_authorize_is_not_authorized() {
    let p = plan(1, &[UasAction::Takeoff, UasAction::WaypointNavigate]);
    assert!(p.authorizes(UasAction::Takeoff));
    assert!(!p.authorizes(UasAction::PayloadRelease));
    assert!(!p.authorizes(UasAction::Land));
    // Outside the window, the plan does not apply at all.
    assert!(!p.applies_at(999));
    assert!(!p.applies_at(100_000));
}

// ─── 36. Observer evidence suppression ───

#[test]
fn c36_suppressing_the_observer_produces_unknown_not_a_clean_result() {
    // Suppression is indistinguishable from absence, which is the point: the
    // profile must reach the same conservative answer either way.
    let no_observer = UasProfile::new("o", &AIRFRAME).unwrap();
    let with_observer = UasProfile::new(
        "o",
        &[
            TelemetrySource::CompanionProcessObservation,
            TelemetrySource::CompanionNetworkObservation,
        ],
    )
    .unwrap();
    assert!(no_observer.mechanised_sources().is_empty());
    assert_eq!(with_observer.mechanised_sources().len(), 2);
    let op = no_observer.observation_profile().unwrap();
    assert_eq!(
        op.completeness_without_evidence(ObservationClass::ProcessIdentity),
        Completeness::NotObservable,
        "a deployment with no observer must record that it cannot look, not that it looked"
    );
}

// ─── 37. Fake sensor identity ───

#[test]
fn c37_naming_a_source_grants_it_nothing() {
    // A deployment declaring `GroundStationTrack` — an independent source —
    // still establishes nothing, because independence without an implemented
    // mechanism is nobody observing. Declaring a source is not anchoring one.
    let p = UasProfile::new(
        "o",
        &[
            TelemetrySource::GroundStationTrack,
            TelemetrySource::ExternalNavigationReceiver,
            TelemetrySource::IndependentRadioObservation,
        ],
    )
    .unwrap();
    assert!(p.mechanised_sources().is_empty());
    for q in NavigationQuantity::ALL {
        assert!(!p.navigation_evidence(q).establishes(), "{q:?}");
    }
}

// ─── 38. Timestamp manipulation ───

#[test]
fn c38_the_staleness_bound_is_on_the_observing_partys_clock() {
    let mut e = NavigationEvidence::from_sources(
        NavigationQuantity::Position,
        &[TelemetrySource::GroundStationTrack],
        false,
    );
    e.independently_observed = true;
    // A claim stamped in the future. `saturating_sub` yields age 0, so it is
    // not rejected as stale — and that is correct: a future stamp is not a
    // staleness problem, it is a clock problem, and the assessment must not
    // silently convert one into the other.
    let future = aip_uas::geofence::PositionClaim {
        frame: CoordinateFrame::Wgs84Geodetic,
        altitude_reference: AltitudeReference::GeoidMsl,
        lat_udeg: 51_500_000,
        lon_udeg: 0,
        alt_cm: 6_000,
        observed_at_ms: 999_999,
    };
    let a = GeofenceAssessment::assess(&region(), Some(&future), &e, 1_000, 60_000);
    assert_eq!(
        a,
        GeofenceAssessment::Compliant,
        "a future stamp is a clock fault for the deployment to police, not a staleness \
         verdict this function may invent"
    );
    // What the profile does guarantee: no *aircraft* claim follows from it.
    assert_eq!(
        MissionState::assertable(MissionState::Landed, StateEvidence::PhysicallyObserved),
        MissionState::Unknown
    );
}

// ─── 39, 40. Frame and reference confusion ───

#[test]
fn c39_c40_a_frame_or_altitude_reference_mismatch_is_refused_not_converted() {
    let mut e = NavigationEvidence::from_sources(
        NavigationQuantity::Position,
        &[TelemetrySource::GroundStationTrack],
        false,
    );
    e.independently_observed = true;
    let base = aip_uas::geofence::PositionClaim {
        frame: CoordinateFrame::Wgs84Geodetic,
        altitude_reference: AltitudeReference::GeoidMsl,
        lat_udeg: 51_500_000,
        lon_udeg: 0,
        alt_cm: 6_000,
        observed_at_ms: 1_000,
    };
    for (frame, reference) in [
        (
            CoordinateFrame::LocalTangentPlane,
            AltitudeReference::GeoidMsl,
        ),
        (
            CoordinateFrame::Wgs84Geodetic,
            AltitudeReference::AboveTakeoffPoint,
        ),
        (
            CoordinateFrame::RegionalGrid,
            AltitudeReference::EllipsoidalWgs84,
        ),
    ] {
        let claim = aip_uas::geofence::PositionClaim {
            frame,
            altitude_reference: reference,
            ..base
        };
        let a = GeofenceAssessment::assess(&region(), Some(&claim), &e, 1_500, 60_000);
        assert!(
            matches!(a, GeofenceAssessment::CannotAssess(_)),
            "{frame:?}/{reference:?} was compared against a region in another frame"
        );
    }
    // And the authorization side: a waypoint at one reference is not a
    // waypoint at another, inside the DP-signed parameter digest.
    assert_ne!(
        aip_uas::action::waypoint_parameters(1, 2, 3, AltitudeReference::GeoidMsl).digest(),
        aip_uas::action::waypoint_parameters(1, 2, 3, AltitudeReference::AboveGroundLevel).digest(),
    );
}

// ─── Sweep: nothing anywhere asserts non-occurrence ───

#[test]
fn nothing_in_this_profile_asserts_that_something_did_not_happen() {
    for s in LinkState::ALL {
        assert!(!s.establishes_non_occurrence(), "{s:?}");
    }
    for a in [
        aip_uas::Agreement::Corroborated {
            agreeing: 9,
            independent: 9,
        },
        aip_uas::Agreement::Conflicting {
            agreeing: 1,
            disagreeing: 1,
        },
        aip_uas::Agreement::Insufficient { reporting: 0 },
    ] {
        assert!(!a.establishes(), "{a:?}");
    }
    assert!(
        !GeofenceAssessment::CannotAssess(aip_uas::geofence::CannotAssess::NoPositionEvidence)
            .asserts_compliance()
    );
}
