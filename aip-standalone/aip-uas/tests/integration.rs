//! The UAS profile driven against real kernel evidence.
//!
//! # What is real here and what is not
//!
//! There is no aircraft. There is a **companion computer**, and on a real UAS
//! that is a Linux host running the autonomy stack — which is exactly what the
//! Skill 22 reference already exercises with three real processes, real procfs
//! and socket-table measurement, a real off-process collector, and the real
//! reconciliation engine.
//!
//! So this file runs that reference and reads it as a UAS deployment:
//!
//! ```text
//!   aip-edge-workload   ←→   the autonomy stack on the companion computer
//!   its TCP connection  ←→   the link it uses to reach a flight controller
//!   aip-edge-observer   ←→   an anchored observer on the companion computer
//! ```
//!
//! The mapping is honest in both directions. Everything the reference
//! establishes about a Linux process is genuinely established about the
//! autonomy stack. Everything it cannot establish about an aircraft — which is
//! everything about an aircraft — the profile reports as unestablished.
//!
//! The point of the exercise is not that a UAS flight was verified. It is that
//! the profile's claims and the evidence's limits are checked against each
//! other on live output rather than agreeing on paper.

use aip_edge::orchestrate::{run, RunConfig, Scenario};
use aip_system::{PlatformId, SystemId};
use aip_uas::{
    CommandRung, FlightControlLadder, GeofenceAssessment, LinkObservation, LinkState, MissionState,
    NavigationQuantity, StateEvidence, TelemetrySource, UasProfile,
};

/// The airframe's own avionics, plus an anchored observer on the companion
/// computer. This is the strongest realistic UAS deployment today.
const DEPLOYMENT: [TelemetrySource; 8] = [
    TelemetrySource::FlightControllerTelemetry,
    TelemetrySource::CompanionAutonomyReport,
    TelemetrySource::GnssReceiverOnboard,
    TelemetrySource::ImuOnboard,
    TelemetrySource::BarometerOnboard,
    TelemetrySource::AirspeedProbeOnboard,
    TelemetrySource::CompanionProcessObservation,
    TelemetrySource::CompanionNetworkObservation,
];

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("aip-uas-{}-{tag}", std::process::id()))
}

/// Run the Skill 22 reference as a UAS companion computer.
fn companion_run(tag: &str, scenario: Scenario) -> aip_edge::orchestrate::RunOutcome {
    let dir = scratch(tag);
    let cfg = RunConfig {
        dir: dir.clone(),
        // A UAS system id and an airframe platform id, in their own
        // namespaces. Reused types; no new identity.
        system_id: SystemId::parse("uas:tail-07").expect("system id"),
        authorized_platform: PlatformId::parse("airframe:tail-07").expect("platform"),
        registered_platform: PlatformId::parse("airframe:tail-07").expect("platform"),
        scenario,
    };
    let out = run(&cfg).unwrap_or_else(|e| panic!("{tag}: {e}"));
    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[test]
fn a_live_companion_computer_establishes_its_own_execution_and_nothing_about_an_aircraft() {
    let out = companion_run("live", Scenario::Honest);
    let profile = UasProfile::new("uas-collector", &DEPLOYMENT)
        .unwrap()
        .with_authenticated_telemetry();

    // ── What the live run really established ─────────────────────────────
    assert!(
        !out.reference.records.is_empty(),
        "the reference must have produced correlated records from real kernel evidence"
    );
    assert_eq!(
        out.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION",
        "the autonomy stack's execution is verifiable"
    );
    assert!(
        out.reference.establishes_named_effect,
        "and so is the link it opened"
    );

    // ── What the UAS profile says about the aircraft ─────────────────────
    for q in [
        NavigationQuantity::Position,
        NavigationQuantity::Altitude,
        NavigationQuantity::Velocity,
        NavigationQuantity::Attitude,
        NavigationQuantity::Heading,
    ] {
        let e = profile.navigation_evidence(q);
        assert!(
            !e.establishes(),
            "{q:?} was established by a run that only watched a Linux process"
        );
        assert!(
            e.self_reported && e.cryptographically_authenticated,
            "{q:?} is reported and signed, which is precisely why it is worth saying it \
             establishes nothing"
        );
    }

    // ── And the one quantity a companion observer really does establish ──
    let link = profile.navigation_evidence(NavigationQuantity::LinkState);
    assert!(
        link.establishes(),
        "the socket observation is real evidence about the link"
    );
    assert_eq!(link.ceiling(), aip_observation::EvidenceCeiling::Attested);

    // ── Physical effect, on live output ──────────────────────────────────
    assert!(!profile.establishes_physical_effect());
    assert!(!out.reference.physical_effect.establishes_physical_effect());
}

#[test]
fn a_verified_autonomy_execution_does_not_make_a_mission_complete() {
    let out = companion_run("mission", Scenario::Honest);
    assert_eq!(
        out.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION"
    );

    // The strongest evidence tier this live run can support.
    let available = StateEvidence::ExecutionObserved;

    // States about software: assertable.
    for claimed in [MissionState::Started, MissionState::InProgress] {
        assert_eq!(
            MissionState::assertable(claimed, available),
            claimed,
            "{claimed:?} is a statement about the autonomy stack"
        );
    }
    // States about the aircraft: not, however green the reconciliation is.
    for claimed in [
        MissionState::Completed,
        MissionState::Landed,
        MissionState::Returning,
        MissionState::Aborted,
    ] {
        assert_eq!(
            MissionState::assertable(claimed, available),
            MissionState::Unknown,
            "{claimed:?} became assertable from a verified Linux execution"
        );
    }
}

#[test]
fn the_flight_control_ladder_stops_where_the_live_evidence_stops() {
    let out = companion_run("ladder", Scenario::Honest);
    let ladder = FlightControlLadder::current();

    // The reference established that the autonomy process ran and that bytes
    // left it. That is exactly the ladder's reach.
    assert!(out
        .reference
        .ladder
        .contiguous_to("INDEPENDENT OBSERVATION"));
    assert_eq!(
        ladder.highest_observable(),
        Some(CommandRung::CommandTransmitted)
    );
    for r in [
        CommandRung::FlightControllerAccepted,
        CommandRung::ActuatorCommanded,
        CommandRung::VehicleStateChanged,
    ] {
        assert!(!r.independently_observable(), "{r:?}");
    }
}

#[test]
fn observer_loss_on_the_companion_computer_degrades_and_never_accuses() {
    let out = companion_run("loss", Scenario::ObserverLost);
    assert_eq!(out.reference.reconciliation.result.as_str(), "CANNOT_PROVE");
    assert!(!out.reference.finding.asserts_non_occurrence());

    // With no observer, even `Started` is not assertable — and nothing about
    // the aircraft is asserted either way.
    assert_eq!(
        MissionState::assertable(MissionState::Started, StateEvidence::DecisionSigned),
        MissionState::Unknown
    );
    // Link state from an observer that was not there.
    let o = LinkObservation {
        source: TelemetrySource::CompanionNetworkObservation,
        covered: false,
        traffic_seen: false,
        impaired: false,
    };
    assert_eq!(o.state(), LinkState::Unknown);
    assert!(!o.state().establishes_non_occurrence());
}

#[test]
fn evidence_from_another_process_does_not_become_evidence_about_this_flight() {
    // Found by mutation testing. Bypassing the core's process-instance
    // correlation (`ObservedProcess::matches_process_of` against the DP-signed
    // binding) was killed by `aip-edge`'s own suite and *survived* this
    // crate's, because every UAS test drove the honest scenario. A profile
    // whose tests are insensitive to the guard it rests on is a profile that
    // will not notice when the guard goes.
    //
    // So the profile now drives the injection case itself: a real observation,
    // really signed, really about a different process on this host.
    let out = companion_run("cross", Scenario::CrossExecutionInjection);
    assert!(
        out.reference.observations_offered > 0,
        "the injected observation must exist, or nothing was excluded"
    );
    assert_eq!(
        out.reference.records.len(),
        0,
        "an observation of another process instance became evidence about this flight"
    );
    assert!(!out.reference.establishes_named_effect);

    // And the profile's own answers degrade with it: with no correlated
    // record, the one navigation quantity a companion observer can establish
    // is established about nothing.
    assert!(
        !out.reference
            .ladder
            .contiguous_to("INDEPENDENT OBSERVATION"),
        "the ladder must not reach independent observation on an uncorrelated run"
    );
    for claimed in [MissionState::Started, MissionState::InProgress] {
        assert_eq!(
            MissionState::assertable(claimed, StateEvidence::DecisionSigned),
            MissionState::Unknown,
            "{claimed:?} must not be assertable when nothing correlated"
        );
    }
}

#[test]
fn a_geofence_question_cannot_be_answered_by_a_live_companion_run() {
    use aip_uas::{AltitudeReference, CoordinateFrame, GeofenceRegion};

    let _out = companion_run("fence", Scenario::Honest);
    let profile = UasProfile::new("uas-collector", &DEPLOYMENT)
        .unwrap()
        .with_authenticated_telemetry();
    let region = GeofenceRegion {
        frame: CoordinateFrame::Wgs84Geodetic,
        altitude_reference: AltitudeReference::GeoidMsl,
        min_lat_udeg: 51_000_000,
        max_lat_udeg: 52_000_000,
        min_lon_udeg: -1_000_000,
        max_lon_udeg: 1_000_000,
        min_alt_cm: 0,
        max_alt_cm: 12_000,
    };
    let evidence = profile.navigation_evidence(NavigationQuantity::Position);
    let assessment = GeofenceAssessment::assess(&region, None, &evidence, 0, 60_000);
    assert!(
        matches!(assessment, GeofenceAssessment::CannotAssess(_)),
        "a verified companion-computer execution answers no boundary question"
    );
    assert!(!assessment.asserts_compliance());
    assert!(!assessment.asserts_violation());
}

#[test]
fn the_profile_needs_no_change_to_nexora_or_to_the_reconciler() {
    use aip_nexora::{verify_proof, CommitmentLog, LeafKind, NexoraSigner, NexoraTrustAnchors};

    let out = companion_run("nexora", Scenario::Honest);
    let profile = UasProfile::new("uas-collector", &DEPLOYMENT).unwrap();

    // The profile's own document commits under an existing profile slot, and
    // the run's artifacts commit under existing leaf kinds. Nothing new.
    let profile_ref = profile.profile_ref().unwrap();
    assert_eq!(profile_ref.kind, aip_system::ProfileKind::Environment);

    let kp = aip_crypto::generate_ed25519_keypair();
    let signer = NexoraSigner::new("uas-log", 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = NexoraTrustAnchors::new().trust("uas-log", 1, &kp.public_key);
    let mut log = CommitmentLog::new([0x23; 16]);
    let idx = log.append(
        LeafKind::Reconciliation,
        &out.reference.reconciliation.canonical_bytes(),
    );
    log.append(LeafKind::Expectation, &out.expectation.signing_preimage());
    for b in &out.batches {
        log.append(LeafKind::AttestedBatch, &b.batch.canonical_bytes());
    }
    let head = log.head(&signer, 1_000).unwrap();
    let proof = log.proof_for(idx, &head).unwrap();
    verify_proof(&proof, &anchors).expect("the existing proof path verifies a UAS run unchanged");

    assert_eq!(
        LeafKind::ALL.len(),
        11,
        "Skill 23 must add no leaf kind: a UAS proof tree would be a second proof tree \
         (the list stands at eleven: `SignedReconciliation` is SD-10's signed verdict leaf and \
         `AccessLedger` is R3's per-agent ledger; neither is a profile's)"
    );
}
