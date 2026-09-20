//! The Skill 26 acceptance gate: a **simulated** disconnected mission.
//!
//! ```text
//!   execute locally  →  collect locally  →  lose the link  →  keep going
//!        →  regain the link  →  bundle  →  transfer  →  reconstruct on the
//!        ground  →  verify offline  →  gaps preserved
//! ```
//!
//! # What is real here and what is not
//!
//! **There is no spacecraft.** There is an onboard computer, and on a real
//! vehicle that is a Linux host running flight software — which is exactly what
//! the Skill 22 reference exercises with three real processes, real procfs and
//! socket-table measurement, a real off-process collector and the real verdict
//! engine.
//!
//! ```text
//!   aip-edge-workload   ←→   flight software on the onboard computer
//!   its TCP connection  ←→   the bus or radio link it uses
//!   aip-edge-observer   ←→   an anchored observer on the onboard computer
//! ```
//!
//! The **link outage is simulated**: contacts are modelled by which bundles the
//! ground station is handed and when. Nothing here is validated against
//! spacecraft hardware, orbital timing or a real radio, and no claim in this
//! file may be read as such.
//!
//! Everything the reference establishes about a Linux process is genuinely
//! established about the flight software. Everything it cannot establish about
//! a vehicle in orbit — which is everything about a vehicle in orbit — the
//! profile reports as unestablished.

use aip_edge::orchestrate::{run, RunConfig, Scenario};
use aip_observe::ContinuityStatus;
use aip_space::{
    AutonomyMode, AutonomyModeTransition, BundleSegment, DelayedEvidence, GroundConclusion,
    GroundVerificationContext, LinkState, MissionState, SegmentLedger, SpaceEvidence,
    SpaceExecutionProfile, SpaceSensingSource, StoreAndForwardBundle,
};
use aip_system::{MissionId, PlatformId, SystemId};

const DEPLOYMENT: [SpaceSensingSource; 9] = [
    SpaceSensingSource::OnboardAutonomyReport,
    SpaceSensingSource::HousekeepingTelemetry,
    SpaceSensingSource::AttitudeSolutionOnboard,
    SpaceSensingSource::NavigationSolutionOnboard,
    SpaceSensingSource::PayloadInstrument,
    SpaceSensingSource::OnboardEventLog,
    SpaceSensingSource::OnboardProcessObservation,
    SpaceSensingSource::OnboardLifecycleObservation,
    SpaceSensingSource::OnboardLinkObservation,
];

const MODES: [AutonomyMode; 4] = [
    AutonomyMode::SupervisedSequence,
    AutonomyMode::UnsupervisedSequence,
    AutonomyMode::OnboardAutonomous,
    AutonomyMode::SafeMode,
];

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("aip-space-{}-{tag}", std::process::id()))
}

/// One real execution on the onboard computer.
fn onboard_run(tag: &str, scenario: Scenario) -> aip_edge::orchestrate::RunOutcome {
    let dir = scratch(tag);
    let cfg = RunConfig {
        dir: dir.clone(),
        system_id: SystemId::parse("space:sat-7").expect("system id"),
        authorized_platform: PlatformId::parse("bus:OBC-2").expect("platform"),
        registered_platform: PlatformId::parse("bus:OBC-2").expect("platform"),
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

fn profile() -> SpaceExecutionProfile {
    SpaceExecutionProfile::new("onboard-collector", &DEPLOYMENT, &MODES, 7 * 86_400_000)
        .expect("profile")
        .with_authenticated_telemetry()
}

fn head_for(n: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_le_bytes());
    h
}

/// A segment standing for evidence the onboard collector really produced.
///
/// The `payload_digest` is the digest of a real attested batch from the live
/// run, so the bundle commits to bytes that exist rather than to a fixture.
fn seg_for(sequence: u64, payload_digest: [u8; 32], attested_at_ms: u64) -> BundleSegment {
    BundleSegment {
        sequence,
        prev_head: head_for(sequence - 1),
        head: head_for(sequence),
        attested_at_ms,
        payload_digest,
    }
}

fn bundle(
    range: std::ops::RangeInclusive<u64>,
    payload_digest: [u8; 32],
    link_at_close: LinkState,
) -> StoreAndForwardBundle {
    let segs: Vec<BundleSegment> = range
        .clone()
        .map(|s| seg_for(s, payload_digest, 10_000 + s))
        .collect();
    StoreAndForwardBundle::new(
        SystemId::parse("space:sat-7").unwrap(),
        MissionId::parse("mission:pass-114").unwrap(),
        "onboard-collector",
        segs,
        10_000 + range.start(),
        10_000 + range.end(),
        link_at_close,
    )
    .expect("bundle")
}

// ─── the gate ───

#[test]
fn a_disconnected_mission_executes_collects_bundles_transfers_and_verifies_offline() {
    // 1. EXECUTE LOCALLY — a real process, really measured, on the onboard
    //    computer. This part is not simulated.
    let out = onboard_run("mission", Scenario::Honest);
    assert_eq!(
        out.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION",
        "the onboard execution must genuinely verify"
    );
    assert!(!out.reference.records.is_empty());

    // 2. COLLECT LOCALLY — the collector signed real batches with no ground in
    //    the loop. Their digests are what the bundles commit to.
    let batch_digest = out
        .batches
        .first()
        .expect("the run produced an attested batch")
        .batch
        .digest();
    let p = profile();
    assert!(
        p.collects_while_disconnected(),
        "an anchored onboard observer works whether or not ground can hear it"
    );

    // 3. LOSE THE LINK, and 4. KEEP GOING. The vehicle declares the mode change
    //    and the declaration is committed; nothing outside the vehicle saw it.
    let transition = AutonomyModeTransition::new(
        SystemId::parse("space:sat-7").unwrap(),
        MissionId::parse("mission:pass-114").unwrap(),
        1,
        AutonomyMode::SupervisedSequence,
        AutonomyMode::UnsupervisedSequence,
        LinkState::Disconnected,
        10_500,
        "loss of signal at horizon",
    )
    .unwrap();
    assert!(!transition.cause_established());
    assert!(!transition.independently_observed());

    // 5. REGAIN THE LINK and 6. BUNDLE. Three contiguous runs, collected across
    //    the outage and closed at three different link states.
    let mut ledger = SegmentLedger::new();
    ledger
        .stage(bundle(1..=3, batch_digest, LinkState::Connected))
        .unwrap();
    ledger
        .stage(bundle(4..=6, batch_digest, LinkState::Disconnected))
        .unwrap();
    ledger
        .stage(bundle(7..=9, batch_digest, LinkState::Reconnected))
        .unwrap();

    // 7. TRANSFER, and 8. RECONSTRUCT ON THE GROUND. Draining orders the
    //    bundles by sequence, which is what lets contacts happen in any order.
    let outcomes = ledger.drain().expect("a complete run reassembles");
    assert_eq!(outcomes.len(), 3);
    assert!(ledger.unfilled_gaps().is_empty());
    assert_eq!(ledger.continuity_status(), ContinuityStatus::Verified);
    assert_eq!(ledger.admitted_count(), 9);

    // 9. VERIFY OFFLINE. The station reaches its conclusion with no network.
    let station = GroundVerificationContext::new("gs-svalbard", 900_000, true).unwrap();
    assert!(!station.requires_network());
    assert_eq!(
        station.conclude(&ledger),
        GroundConclusion::EvidenceComplete { segments: 9 }
    );

    // And the delayed-arrival rule holds over the real batch: it arrived long
    // after it was attested, and that says nothing about when anything
    // happened.
    let delayed = DelayedEvidence::new(batch_digest, 10_001, 900_000)
        .unwrap()
        .verified_at(900_500)
        .unwrap();
    assert!(delayed.latency_ms() > 800_000);
    assert!(!delayed.event_time_established());
    assert!(!delayed.receipt_time_is_event_time());

    // 10. And what the mission still cannot claim, on a run that reached
    //     VERIFIED_EXECUTION.
    assert!(!p.establishes_physical_effect());
    assert!(!out.reference.physical_effect.establishes_physical_effect());
    assert_eq!(
        MissionState::assertable(MissionState::Completed, SpaceEvidence::ExecutionObserved),
        MissionState::Unknown,
        "a verified Linux execution does not complete a mission"
    );
}

#[test]
fn the_same_mission_with_a_lost_contact_preserves_the_gap_and_never_succeeds() {
    // The other half of the gate: continuity failure must be explicit and must
    // not silently downgrade into success.
    let out = onboard_run("gap", Scenario::Honest);
    let batch_digest = out.batches.first().unwrap().batch.digest();

    let mut ledger = SegmentLedger::new();
    ledger
        .stage(bundle(1..=3, batch_digest, LinkState::Connected))
        .unwrap();
    // The middle contact never happened.
    ledger
        .stage(bundle(7..=9, batch_digest, LinkState::Reconnected))
        .unwrap();
    ledger.drain().unwrap();

    assert_eq!(ledger.unfilled_gaps(), vec![4, 5, 6]);
    assert_eq!(ledger.continuity_status(), ContinuityStatus::GapObserved);
    assert!(!ledger.completeness_claimable());
    assert!(!ledger.non_occurrence_admissible());

    let station = GroundVerificationContext::new("gs-svalbard", 900_000, true).unwrap();
    let conclusion = station.conclude(&ledger);
    assert_eq!(
        conclusion,
        GroundConclusion::EvidenceIncomplete {
            missing: vec![4, 5, 6]
        }
    );
    assert!(!conclusion.asserts_completeness());
    assert!(!conclusion.asserts_non_occurrence());

    // And the missing bundle arriving at a later contact does not repair it.
    ledger
        .stage(bundle(4..=6, batch_digest, LinkState::Reconnected))
        .unwrap();
    ledger.drain().unwrap();
    assert_eq!(ledger.unfilled_gaps(), vec![4, 5, 6]);
    assert!(!ledger.completeness_claimable());
    assert_eq!(
        station.conclude(&ledger),
        GroundConclusion::EvidenceIncomplete {
            missing: vec![4, 5, 6]
        }
    );
}

#[test]
fn offline_reconstruction_flows_through_the_existing_verifier() {
    // NEXORA is reused, not replaced: the mission's evidence goes into the
    // existing commitment log, is exported, imported on a second machine and
    // verified by the existing verifier against anchors provisioned separately.
    use aip_nexora::{verify_proof, CommitmentLog, LeafKind, NexoraSigner, NexoraTrustAnchors};

    let out = onboard_run("nexora", Scenario::Honest);

    let kp = aip_crypto::generate_ed25519_keypair();
    let signer = NexoraSigner::new("mission-log", 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = NexoraTrustAnchors::new().trust("mission-log", 1, &kp.public_key);
    let mut log = CommitmentLog::new([0x26; 16]);
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

    // Serialise, move, parse — the store-and-forward path for the proof
    // itself. The container is not security-relevant: every hash and signature
    // is recomputed from the parsed structure, so a round trip through JSON
    // cannot change a verdict.
    let bytes = serde_json::to_vec(&proof).expect("serialise");
    let reimported: aip_nexora::ProofObject =
        serde_json::from_slice(&bytes).expect("parse on the ground");
    verify_proof(&reimported, &anchors)
        .expect("the existing verifier verifies a mission proof after transport");

    // And the anchors travelled separately: a package that carried the keys
    // that check it would prove nothing.
    let wrong = NexoraTrustAnchors::new().trust(
        "mission-log",
        1,
        &aip_crypto::generate_ed25519_keypair().public_key,
    );
    assert!(
        verify_proof(&reimported, &wrong).is_err(),
        "a proof must not verify against anchors that did not sign it"
    );

    assert_eq!(
        LeafKind::ALL.len(),
        11,
        "Skill 26 must add no leaf kind: a mission proof tree would be a second proof tree"
    );
}

#[test]
fn an_observer_lost_during_the_outage_degrades_and_never_accuses() {
    let out = onboard_run("loss", Scenario::ObserverLost);
    assert_eq!(out.reference.reconciliation.result.as_str(), "CANNOT_PROVE");
    assert!(!out.reference.finding.asserts_non_occurrence());

    // Nothing arrived, so the station concludes nothing — about the link, not
    // about the vehicle.
    let ledger = SegmentLedger::new();
    let station = GroundVerificationContext::new("gs", 900_000, true).unwrap();
    match station.conclude(&ledger) {
        GroundConclusion::CannotProve { reason } => {
            assert!(reason.contains("not about the vehicle"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        MissionState::assertable(MissionState::Executing, SpaceEvidence::DecisionSigned),
        MissionState::Unknown
    );
}
