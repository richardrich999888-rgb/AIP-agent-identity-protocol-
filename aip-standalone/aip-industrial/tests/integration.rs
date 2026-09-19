//! The industrial profile driven against real kernel evidence.
//!
//! # What is real here and what is not
//!
//! There is no plant. There is a **critical-edge node**, and on a real
//! industrial deployment that is a Linux host running the supervisory software
//! — which is exactly what the Skill 22 reference exercises with three real
//! processes, real procfs and socket-table measurement, a real off-process
//! collector and the real verdict engine.
//!
//! ```text
//!   aip-edge-workload   ←→   the supervisory software on the edge node
//!   its TCP connection  ←→   the protocol session it uses to reach a PLC
//!   aip-edge-observer   ←→   an anchored observer on the edge node
//! ```
//!
//! Everything the reference establishes about a Linux process is genuinely
//! established about the supervisory software. Everything it cannot establish
//! about a plant — which is everything about a plant — the profile reports as
//! unestablished.
//!
//! These runs are the crate's EXECUTION-PROVEN evidence. Every other test in
//! this crate is TEST-PROVEN over constructed values.

use aip_edge::orchestrate::{run, RunConfig, Scenario};
use aip_industrial::{
    ContainmentScope, ControlRung, CoverageDomain, IndustrialCommand, IndustrialProfile,
    IndustrialProtocol, LoopState, OverrideClaim, OverrideKind, ProcessClaim, ProcessEvidence,
    ProcessSensingSource, ProcessVariable, SafetyFunction,
};
use aip_system::{AuthorityContext, PlatformId, SystemId};

/// The strongest realistic critical-edge deployment today: full plant
/// instrumentation plus an anchored observer on the edge node.
const DEPLOYMENT: [ProcessSensingSource; 13] = [
    ProcessSensingSource::SupervisoryRuntimeReport,
    ProcessSensingSource::ControllerStatusReport,
    ProcessSensingSource::ProcessTransmitter,
    ProcessSensingSource::ActuatorPositionFeedback,
    ProcessSensingSource::HistorianArchive,
    ProcessSensingSource::HmiOperatorLog,
    ProcessSensingSource::SafetySystemStatus,
    ProcessSensingSource::MeteringDevice,
    ProcessSensingSource::EdgeProcessObservation,
    ProcessSensingSource::EdgeLifecycleObservation,
    ProcessSensingSource::EdgeNetworkObservation,
    ProcessSensingSource::EdgeDataTransferObservation,
    ProcessSensingSource::ProtocolWireObservation,
];

const PROTOCOLS: [IndustrialProtocol; 2] =
    [IndustrialProtocol::ModbusTcp, IndustrialProtocol::OpcUa];

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("aip-industrial-{}-{tag}", std::process::id()))
}

fn edge_run(tag: &str, scenario: Scenario) -> aip_edge::orchestrate::RunOutcome {
    let dir = scratch(tag);
    let cfg = RunConfig {
        dir: dir.clone(),
        // An industrial system id and an edge-node platform id, in their own
        // namespaces. Reused types; no new identity.
        system_id: SystemId::parse("ics:unit-4-supervisor").expect("system id"),
        authorized_platform: PlatformId::parse("edge:RTU-12").expect("platform"),
        registered_platform: PlatformId::parse("edge:RTU-12").expect("platform"),
        scenario,
    };
    let out = run(&cfg).unwrap_or_else(|e| panic!("{tag}: {e}"));
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn profile() -> IndustrialProfile {
    IndustrialProfile::new("edge-collector", &DEPLOYMENT, &PROTOCOLS)
        .expect("profile")
        .with_authenticated_telemetry()
}

#[test]
fn a_live_edge_node_establishes_its_execution_and_nothing_about_a_plant() {
    let out = edge_run("live", Scenario::Honest);
    let p = profile();

    // What the live run really established.
    assert!(!out.reference.records.is_empty());
    assert_eq!(
        out.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION"
    );
    assert!(out.reference.establishes_named_effect);
    assert_eq!(
        p.highest_established_rung(),
        Some(ControlRung::CommandIssued)
    );

    // What it did not. Every process claim, on a run that reached
    // VERIFIED_EXECUTION.
    for variable in ProcessVariable::ALL {
        for claim in ProcessClaim::ALL {
            let e = p.process_effect(variable, claim);
            assert!(
                !e.establishes(),
                "{variable:?}/{claim:?} was established by watching a process"
            );
        }
    }
    assert!(!p.establishes_process_effect());
    assert!(!out.reference.physical_effect.establishes_physical_effect());

    // And the acceptance gate, on real evidence: command execution is
    // establishable, physical process confirmation is not.
    let (execution, confirmation) = p.execution_versus_confirmation();
    assert!(
        execution,
        "a live, observed edge node establishes its command"
    );
    assert!(!confirmation, "and establishes nothing about the plant");
}

#[test]
fn a_verified_edge_execution_does_not_shut_a_process_down() {
    let out = edge_run("state", Scenario::Honest);
    assert_eq!(
        out.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION"
    );
    let available = ProcessEvidence::ExecutionObserved;
    for claimed in [
        LoopState::CommandIssued,
        LoopState::Executing,
        LoopState::Suspended,
        LoopState::Degraded,
    ] {
        assert_eq!(
            LoopState::assertable(claimed, available),
            claimed,
            "{claimed:?}"
        );
    }
    for claimed in [
        LoopState::OutputEnergised,
        LoopState::ActuatorMoved,
        LoopState::ProcessChanged,
        LoopState::ShutdownComplete,
    ] {
        assert_eq!(
            LoopState::assertable(claimed, available),
            LoopState::Unknown,
            "{claimed:?} became assertable from a verified Linux execution"
        );
    }
}

#[test]
fn an_emergency_shutdown_command_leaving_the_edge_node_is_not_a_plant_in_a_safe_state() {
    let out = edge_run("esd", Scenario::Honest);
    assert!(out.reference.establishes_named_effect, "the command left");
    let p = profile();
    for f in [
        SafetyFunction::EmergencyShutdownSystem,
        SafetyFunction::SafetyInstrumentedFunction,
    ] {
        let e = p.safety_evidence(f);
        assert!(
            e.command_observed,
            "{f:?}: the command leaving is observable"
        );
        assert!(
            !e.establishes_action(),
            "{f:?}: a verified command is not a verified trip"
        );
    }
    assert!(IndustrialCommand::EmergencyShutdown
        .effect_gap()
        .contains("safe state"));
    // And containing the edge node would not fix it either.
    assert!(!ContainmentScope::EdgeCompute.restores_process_safe_state());
}

#[test]
fn evidence_from_another_process_does_not_become_evidence_about_this_edge_node() {
    // Built in from the start, having learned it in Skills 23 and 24: a profile
    // whose tests only drive the honest scenario is insensitive to the core
    // guard it rests on, and will not notice when that guard goes.
    let out = edge_run("cross", Scenario::CrossExecutionInjection);
    assert!(
        out.reference.observations_offered > 0,
        "the injected observation must exist, or nothing was excluded"
    );
    assert_eq!(
        out.reference.records.len(),
        0,
        "an observation of another process instance became evidence about this edge node"
    );
    assert!(!out.reference.establishes_named_effect);
    assert!(!out
        .reference
        .ladder
        .contiguous_to("INDEPENDENT OBSERVATION"));
    for claimed in [LoopState::CommandIssued, LoopState::Executing] {
        assert_eq!(
            LoopState::assertable(claimed, ProcessEvidence::DecisionSigned),
            LoopState::Unknown,
            "{claimed:?} must not be assertable when nothing correlated"
        );
    }
}

#[test]
fn a_replayed_observation_is_detected_and_does_not_inflate_the_evidence() {
    // The specification names replay explicitly. This is the version that runs:
    // the same attested batch offered twice, through the real engine.
    let replayed = edge_run("replay", Scenario::ReplayedObservation);
    assert!(
        replayed.reference.reconciliation.replay_detected,
        "the existing engine must detect the duplicate"
    );
    let honest = edge_run("replay-honest", Scenario::Honest);
    assert_eq!(
        replayed.reference.records.len(),
        honest.reference.records.len(),
        "one observation offered twice must not read as two"
    );
    // And the profile's answer about the plant is identical either way, which
    // is the point: replay changes the evidence count and changes nothing
    // about what may be said.
    let p = profile();
    assert!(!p.establishes_process_effect());
    assert_eq!(
        p.highest_established_rung(),
        Some(ControlRung::CommandIssued)
    );
}

#[test]
fn observer_loss_degrades_and_never_accuses() {
    let out = edge_run("loss", Scenario::ObserverLost);
    assert_eq!(out.reference.reconciliation.result.as_str(), "CANNOT_PROVE");
    assert!(!out.reference.finding.asserts_non_occurrence());
    assert_eq!(
        LoopState::assertable(LoopState::Executing, ProcessEvidence::DecisionSigned),
        LoopState::Unknown
    );
    // And an override claim does not close the gap the outage opened.
    let claim = OverrideClaim::new(
        OverrideKind::HmiWriteOnObservedHost,
        "op-7",
        AuthorityContext::none(),
    )
    .expect("claim");
    assert!(!claim.excuses_divergence());
    assert!(!claim.accepted_as_authority(ProcessEvidence::ExecutionObserved));
}

#[test]
fn a_boot_or_platform_mismatch_never_becomes_a_plant_claim() {
    for (tag, scenario) in [
        ("wrongboot", Scenario::WrongBoot),
        ("wrongplatform", Scenario::WrongPlatform),
    ] {
        let out = edge_run(tag, scenario);
        assert!(
            !out.reference.finding.asserts_non_occurrence(),
            "{tag}: a binding mismatch must not become an accusation"
        );
        let p = profile();
        assert!(!p.establishes_process_effect(), "{tag}");
        for claim in ProcessClaim::ALL {
            assert!(
                !p.process_effect(ProcessVariable::Flow, claim).establishes(),
                "{tag}/{claim:?}"
            );
        }
    }
}

#[test]
fn the_live_run_projects_the_three_coverage_domains_honestly() {
    let out = edge_run("coverage", Scenario::Honest);
    assert_eq!(
        out.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION"
    );
    let coverage = profile().coverage();
    assert!(coverage.domain(CoverageDomain::Compute).observable);
    assert!(coverage.domain(CoverageDomain::Network).observable);
    assert!(
        !coverage.domain(CoverageDomain::ProcessState).observable,
        "a verified Linux execution must not make the plant observable"
    );
    // The observer the run actually produced: its signed health decides
    // whether absence may be claimed, and the profile defers to it rather than
    // re-deriving the rule.
    let health = out.health.last().expect("the run signed a health");
    for domain in CoverageDomain::ALL {
        let admissible = coverage.non_occurrence_admissible(domain, health);
        assert_eq!(
            admissible,
            domain.can_support_non_occurrence()
                && coverage.domain(domain).gate_independent
                && health.covered_by_kernel_pushed_source(),
            "{domain:?}"
        );
        assert!(
            !admissible || domain != CoverageDomain::ProcessState,
            "absence in the plant is never admissible"
        );
    }
}

#[test]
fn the_profile_needs_no_change_to_nexora_or_to_the_verdict_engine() {
    use aip_nexora::{verify_proof, CommitmentLog, LeafKind, NexoraSigner, NexoraTrustAnchors};

    let out = edge_run("nexora", Scenario::Honest);
    let p = profile();
    let profile_ref = p.profile_ref().expect("profile ref");
    assert_eq!(profile_ref.kind, aip_system::ProfileKind::Environment);

    let kp = aip_crypto::generate_ed25519_keypair();
    let signer = NexoraSigner::new("ics-log", 1, &kp.private_key, &kp.public_key).expect("signer");
    let anchors = NexoraTrustAnchors::new().trust("ics-log", 1, &kp.public_key);
    let mut log = CommitmentLog::new([0x25; 16]);
    let idx = log.append(
        LeafKind::Reconciliation,
        &out.reference.reconciliation.canonical_bytes(),
    );
    log.append(LeafKind::Expectation, &out.expectation.signing_preimage());
    for b in &out.batches {
        log.append(LeafKind::AttestedBatch, &b.batch.canonical_bytes());
    }
    let head = log.head(&signer, 1_000).expect("head");
    let proof = log.proof_for(idx, &head).expect("proof");
    verify_proof(&proof, &anchors).expect("the existing proof path verifies an industrial run");

    assert_eq!(
        LeafKind::ALL.len(),
        11,
        "Skill 25 must add no leaf kind: an industrial proof tree would be a second proof tree"
    );
}

#[test]
fn containment_of_an_industrial_execution_stays_on_the_existing_warrant_path() {
    // The specification's third non-negotiable rule, driven end to end: the
    // only route to a containment action is the existing warrant engine, over
    // a verdict the existing reconciler produced. This profile contributes no
    // input to it and cannot: `evaluate` takes a record the engine drew, and
    // `aip-industrial` has no way to draw one.
    use aip_warrant::{evaluate, Finding, WarrantPolicy};

    let out = edge_run("warrant", Scenario::Honest);
    let finding = Finding {
        finding_id: [0x25; 16],
        reconciliation: out.reference.reconciliation.clone(),
        subject_agent: Some(out.reference.system_execution.agent_id().to_owned()),
    };
    let warrant = evaluate(&finding, &WarrantPolicy::default(), 1_000)
        .expect("the existing engine evaluates an industrial run unchanged");

    // The warrant rests on the engine's record, byte for byte.
    assert_eq!(
        warrant.reconciliation_digest,
        out.reference.reconciliation.digest()
    );
    assert_eq!(warrant.finding_id, finding.finding_id);

    // And the profile's own position is unchanged by any of it: both scopes
    // require a warrant, and neither leaves the plant safe.
    for scope in ContainmentScope::ALL {
        assert!(scope.requires_warrant(), "{scope:?}");
        assert!(!scope.restores_process_safe_state(), "{scope:?}");
    }
}
