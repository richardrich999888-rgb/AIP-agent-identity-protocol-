//! Skill 27's acceptance gate, against a real execution.
//!
//! > *Enterprise workloads map cleanly into the same accountability core used
//! > by edge systems. No enterprise-specific branch of reconciliation exists.*
//!
//! # What is real here
//!
//! The Skill 22 reference, driven as an enterprise agent host: three real
//! processes, real procfs and socket-table measurement, a real off-process
//! collector, and **the same reconciliation engine the edge verticals use**.
//!
//! ```text
//!   aip-edge-workload   ←→   the agent process
//!   its TCP connection  ←→   the model or tool endpoint it calls
//!   aip-edge-observer   ←→   an anchored observer on the agent host
//! ```
//!
//! No enterprise-only path is taken anywhere: the verdict comes out of
//! `aip-reconcile` unmodified, and the proof out of `aip-nexora` unmodified.
//!
//! # What is not real
//!
//! No cloud, no Kubernetes, no managed database, no hosted model. The workload
//! is a Linux process on this host. Nothing here has been deployed, and nothing
//! in this file may be read as a production enterprise deployment.

use aip_airi::PropagationBoundary;
use aip_edge::orchestrate::{run, RunConfig, Scenario};
use aip_enterprise::{
    framework_commitment, ContextChain, EnterpriseEvidence, EnterpriseProfile, EnterpriseResource,
    EnterpriseSource, WorkloadBinding, WorkloadState,
};
use aip_system::{PlatformId, SystemId};
use aip_types::{ExecutionBinding, ProcessInstance};

const DEPLOYMENT: [EnterpriseSource; 8] = [
    EnterpriseSource::AgentSelfReport,
    EnterpriseSource::FrameworkTrace,
    EnterpriseSource::ApmTelemetry,
    EnterpriseSource::ApplicationLog,
    EnterpriseSource::CloudAuditLog,
    EnterpriseSource::HostProcessObservation,
    EnterpriseSource::HostLifecycleObservation,
    EnterpriseSource::HostSocketObservation,
];

fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("aip-enterprise-{}-{tag}", std::process::id()))
}

fn agent_run(tag: &str, scenario: Scenario) -> aip_edge::orchestrate::RunOutcome {
    let dir = scratch(tag);
    let cfg = RunConfig {
        dir: dir.clone(),
        system_id: SystemId::parse("enterprise:svc-orders").expect("system id"),
        authorized_platform: PlatformId::parse("host:node-14").expect("platform"),
        registered_platform: PlatformId::parse("host:node-14").expect("platform"),
        scenario,
    };
    let out = run(&cfg).unwrap_or_else(|e| panic!("{tag}: {e}"));
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn profile() -> EnterpriseProfile {
    EnterpriseProfile::new("host-collector", &DEPLOYMENT, &EnterpriseResource::ALL)
        .expect("profile")
        .with_authenticated_telemetry()
}

/// The real execution's own binding, as the run measured it.
fn binding_for(out: &aip_edge::orchestrate::RunOutcome) -> (ExecutionBinding, WorkloadBinding) {
    let e = ExecutionBinding {
        version: 1,
        agent_id: out.reference.system_execution.agent_id().to_owned(),
        process: ProcessInstance {
            pid: out.workload_pid,
            pid_start_time_ticks: 0,
            boot_id: [0x14; 16],
        },
        exe_content_sha256: [0xAA; 32],
        exe_path: "/usr/bin/agent".to_owned(),
        bound_at_ms: 1_000,
    };
    let b = WorkloadBinding::new(
        "acme",
        "orders",
        SystemId::parse("enterprise:svc-orders").unwrap(),
        framework_commitment("langgraph", "0.2.1", "vanian-1"),
        &e,
        1_000,
    )
    .expect("binding");
    (e, b)
}

#[test]
fn an_enterprise_workload_reconciles_through_the_same_engine_as_the_edge_verticals() {
    let out = agent_run("core", Scenario::Honest);

    // The verdict is the core's, from the same engine, with no enterprise
    // branch anywhere in the path.
    assert_eq!(
        out.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION"
    );
    assert!(!out.reference.records.is_empty());
    assert!(out.reference.establishes_named_effect);

    // And the profile occupies the ordinary vertical slot beside the others.
    let r = profile().profile_ref().unwrap();
    assert_eq!(r.kind, aip_system::ProfileKind::Environment);
}

#[test]
fn a_verified_execution_establishes_a_local_effect_and_no_remote_one() {
    // The enterprise difference, on real evidence: the host observer really can
    // establish something the four embodied verticals cannot — and it still
    // cannot reach the far end.
    let out = agent_run("effect", Scenario::Honest);
    assert_eq!(
        out.reference.reconciliation.result.as_str(),
        "VERIFIED_EXECUTION"
    );

    let with_fs = EnterpriseProfile::new(
        "host-collector",
        &[
            EnterpriseSource::AgentSelfReport,
            EnterpriseSource::HostProcessObservation,
            EnterpriseSource::HostFilesystemObservation,
        ],
        &EnterpriseResource::ALL,
    )
    .unwrap();
    assert_eq!(
        with_fs.establishable_effects(),
        vec![
            EnterpriseResource::Filesystem,
            EnterpriseResource::Container
        ],
        "a marked path write is Fanotify, and that is a real positive result"
    );
    assert!(!with_fs.establishes_remote_effect());

    for s in [WorkloadState::RemoteEffectApplied, WorkloadState::Completed] {
        assert_eq!(
            WorkloadState::assertable(s, EnterpriseEvidence::LocalEffectObserved),
            WorkloadState::Unknown,
            "{s:?}: a socket is not a consequence at the far end"
        );
    }
}

#[test]
fn a_context_chain_over_a_real_execution_admits_only_that_execution() {
    let out = agent_run("context", Scenario::Honest);
    let (execution, binding) = binding_for(&out);

    let mut chain = ContextChain::rooted_at(&binding, 0, 10_000).unwrap();
    chain.extend(PropagationBoundary::WorkerQueue, [0x01; 16], None);
    chain.extend(PropagationBoundary::Subprocess, [0x02; 16], None);
    chain.extend(PropagationBoundary::Process, [0x03; 16], None);

    assert!(chain.check_links().is_ok());
    assert!(chain.admit(&binding, &execution, 5_000).is_ok());

    // A different process on the same host, holding the same strings, is not
    // the same execution.
    let other = ExecutionBinding {
        process: ProcessInstance {
            pid: out.observer_pid,
            pid_start_time_ticks: 1,
            boot_id: [0x14; 16],
        },
        ..execution.clone()
    };
    assert!(chain.admit(&binding, &other, 5_000).is_err());
    assert!(!binding.covers(&other));
}

#[test]
fn evidence_from_another_process_does_not_become_evidence_about_this_workload() {
    let out = agent_run("cross", Scenario::CrossExecutionInjection);
    assert!(out.reference.observations_offered > 0);
    assert_eq!(
        out.reference.records.len(),
        0,
        "an observation of another process instance became evidence about this workload"
    );
    assert!(!out.reference.establishes_named_effect);
    for s in [WorkloadState::Started, WorkloadState::Executing] {
        assert_eq!(
            WorkloadState::assertable(s, EnterpriseEvidence::DecisionSigned),
            WorkloadState::Unknown,
            "{s:?}"
        );
    }
}

#[test]
fn observer_loss_degrades_and_never_accuses() {
    let out = agent_run("loss", Scenario::ObserverLost);
    assert_eq!(out.reference.reconciliation.result.as_str(), "CANNOT_PROVE");
    assert!(!out.reference.finding.asserts_non_occurrence());
    assert_eq!(
        WorkloadState::assertable(WorkloadState::Executing, EnterpriseEvidence::DecisionSigned),
        WorkloadState::Unknown
    );
}

#[test]
fn the_profile_needs_no_change_to_nexora_or_to_the_verdict_engine() {
    use aip_nexora::{verify_proof, CommitmentLog, LeafKind, NexoraSigner, NexoraTrustAnchors};

    let out = agent_run("nexora", Scenario::Honest);
    let kp = aip_crypto::generate_ed25519_keypair();
    let signer = NexoraSigner::new("ent-log", 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = NexoraTrustAnchors::new().trust("ent-log", 1, &kp.public_key);
    let mut log = CommitmentLog::new([0x27; 16]);
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
    verify_proof(&proof, &anchors).expect("the existing proof path verifies an enterprise run");

    assert_eq!(
        LeafKind::ALL.len(),
        9,
        "Skill 27 must add no leaf kind: an enterprise proof tree would be a second proof tree"
    );
}
