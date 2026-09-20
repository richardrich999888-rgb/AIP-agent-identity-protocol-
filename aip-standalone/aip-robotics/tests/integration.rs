//! The robotics profile driven against real kernel evidence.
//!
//! # What is real here and what is not
//!
//! There is no robot. There is a **companion computer**, and on a real
//! autonomous robot that is a Linux host running the autonomy stack — which is
//! exactly what the Skill 22 reference exercises with three real processes,
//! real procfs and socket-table measurement, a real off-process collector and
//! the real reconciliation engine.
//!
//! ```text
//!   aip-edge-workload   ←→   the autonomy stack on the companion computer
//!   its TCP connection  ←→   the link it uses to reach a motion controller
//!   aip-edge-observer   ←→   an anchored observer on the companion computer
//! ```
//!
//! Everything the reference establishes about a Linux process is genuinely
//! established about the autonomy stack. Everything it cannot establish about a
//! machine that moves — which is everything about a machine that moves — the
//! profile reports as unestablished.

use aip_edge::orchestrate::{run, RunConfig, Scenario};
use aip_robotics::{
    EmbodiedRung, ObjectStateClaim, PoseQuantity, RoboticsProfile, SafetyAction, SafetyEvidence,
    SensingSource, TaskEvidence, TaskState,
};
use aip_system::{PlatformId, SystemId};

/// The strongest realistic robotics deployment today: full onboard sensing
/// plus an anchored observer on the companion computer.
const DEPLOYMENT: [SensingSource; 12] = [
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
    SensingSource::CompanionProcessObservation,
    SensingSource::CompanionNetworkObservation,
];

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("aip-robotics-{}-{tag}", std::process::id()))
}

fn companion_run(tag: &str, scenario: Scenario) -> aip_edge::orchestrate::RunOutcome {
    let dir = scratch(tag);
    let cfg = RunConfig {
        dir: dir.clone(),
        // A robot system id and a chassis platform id, in their own namespaces.
        // Reused types; no new identity.
        system_id: SystemId::parse("robot:cell-3-arm-1").expect("system id"),
        authorized_platform: PlatformId::parse("chassis:UGV-7").expect("platform"),
        registered_platform: PlatformId::parse("chassis:UGV-7").expect("platform"),
        scenario,
    };
    // The reference spawns `aip-edge-observer` and `aip-edge-workload`, which
    // `cargo test --workspace` does not build: a package's binaries are
    // compiled for tests only when that package has integration tests of its
    // own, and those two have none. Without this, these tests pass only when
    // something else in the same invocation happened to build them first --
    // and worse, a binary left over from before a protocol change is found,
    // spawned, and produces records the current engine refuses.
    aip_edge::transport::ensure_sibling_binaries().unwrap_or_else(|e| panic!("{tag}: {e}"));
    let out = run(&cfg).unwrap_or_else(|e| panic!("{tag}: {e}"));
    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[test]
fn a_live_companion_computer_establishes_its_execution_and_nothing_about_a_machine() {
    let out = companion_run("live", Scenario::Honest);
    let profile = RoboticsProfile::new("cell-collector", &DEPLOYMENT)
        .unwrap()
        .with_authenticated_telemetry();

    // What the live run really established.
    assert!(!out.reference.records.is_empty());
    assert_eq!(
        out.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION"
    );
    assert!(out.reference.establishes_named_effect);
    assert_eq!(
        profile.highest_established_rung(),
        Some(EmbodiedRung::TaskCommand)
    );

    // What it did not. Every pose quantity, on a run that reached
    // VERIFIED_EXECUTION.
    for q in PoseQuantity::ALL {
        let e = profile.navigation_evidence(q);
        assert!(
            !e.establishes(),
            "{q:?} was established by watching a process"
        );
        assert!(
            e.self_reported && e.cryptographically_authenticated,
            "{q:?} is reported and signed, which is why it is worth saying it establishes nothing"
        );
    }
    // And every object-state claim.
    for c in ObjectStateClaim::ALL {
        assert!(!profile.manipulation_evidence(c).establishes(), "{c:?}");
    }
    assert!(!profile.establishes_physical_effect());
    assert!(!out.reference.physical_effect.establishes_physical_effect());
}

#[test]
fn a_verified_autonomy_execution_does_not_complete_a_task() {
    let out = companion_run("task", Scenario::Honest);
    assert_eq!(
        out.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION"
    );
    let available = TaskEvidence::ExecutionObserved;
    for claimed in [TaskState::Started, TaskState::Executing, TaskState::Paused] {
        assert_eq!(
            TaskState::assertable(claimed, available),
            claimed,
            "{claimed:?}"
        );
    }
    for claimed in [
        TaskState::Completed,
        TaskState::Aborted,
        TaskState::Recovering,
    ] {
        assert_eq!(
            TaskState::assertable(claimed, available),
            TaskState::Unknown,
            "{claimed:?} became assertable from a verified Linux execution"
        );
    }
}

#[test]
fn a_safety_stop_command_leaving_the_autonomy_stack_is_not_a_machine_stopping() {
    let out = companion_run("safety", Scenario::Honest);
    assert!(out.reference.establishes_named_effect, "the command left");
    let e = SafetyEvidence::derive(SafetyAction::EmergencyStop, true);
    assert!(e.request_observed);
    assert!(
        !e.establishes_effect(),
        "a verified command is not a verified stop"
    );
}

#[test]
fn evidence_from_another_process_does_not_become_evidence_about_this_robot() {
    // Built in from the start, having learned it in Skill 23: a profile whose
    // tests only drive the honest scenario is insensitive to the core guard it
    // rests on, and will not notice when that guard goes.
    let out = companion_run("cross", Scenario::CrossExecutionInjection);
    assert!(
        out.reference.observations_offered > 0,
        "the injected observation must exist, or nothing was excluded"
    );
    assert_eq!(
        out.reference.records.len(),
        0,
        "an observation of another process instance became evidence about this robot"
    );
    assert!(!out.reference.establishes_named_effect);
    assert!(!out
        .reference
        .ladder
        .contiguous_to("INDEPENDENT OBSERVATION"));
    for claimed in [TaskState::Started, TaskState::Executing] {
        assert_eq!(
            TaskState::assertable(claimed, TaskEvidence::DecisionSigned),
            TaskState::Unknown,
            "{claimed:?} must not be assertable when nothing correlated"
        );
    }
}

#[test]
fn observer_loss_degrades_and_never_accuses() {
    let out = companion_run("loss", Scenario::ObserverLost);
    assert_eq!(out.reference.reconciliation.result.as_str(), "CANNOT_PROVE");
    assert!(!out.reference.finding.asserts_non_occurrence());
    assert_eq!(
        TaskState::assertable(TaskState::Executing, TaskEvidence::DecisionSigned),
        TaskState::Unknown
    );
    for a in SafetyAction::ALL {
        assert!(!SafetyEvidence::derive(a, false).request_observed, "{a:?}");
    }
}

#[test]
fn the_profile_needs_no_change_to_nexora_or_to_the_reconciler() {
    use aip_nexora::{verify_proof, CommitmentLog, LeafKind, NexoraSigner, NexoraTrustAnchors};

    let out = companion_run("nexora", Scenario::Honest);
    let profile = RoboticsProfile::new("cell-collector", &DEPLOYMENT).unwrap();
    let profile_ref = profile.profile_ref().unwrap();
    assert_eq!(profile_ref.kind, aip_system::ProfileKind::Environment);

    let kp = aip_crypto::generate_ed25519_keypair();
    let signer = NexoraSigner::new("robot-log", 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = NexoraTrustAnchors::new().trust("robot-log", 1, &kp.public_key);
    let mut log = CommitmentLog::new([0x24; 16]);
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
    verify_proof(&proof, &anchors).expect("the existing proof path verifies a robotics run");

    assert_eq!(
        LeafKind::ALL.len(),
        11,
        "Skill 24 must add no leaf kind: a robotics proof tree would be a second proof tree \
         (the list stands at eleven: `SignedReconciliation` is SD-10's signed verdict leaf and \
         `AccessLedger` is R3's per-agent ledger; neither is a profile's)"
    );
}
