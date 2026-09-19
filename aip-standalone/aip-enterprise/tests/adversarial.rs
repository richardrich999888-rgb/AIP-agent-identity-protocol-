//! The ten transplantation attacks Skill 27 names.
//!
//! Required property: every attack must **fail verification, fail binding, or
//! remain UNKNOWN/CANNOT_PROVE**. None may silently create a valid
//! authorization or execution identity.
//!
//! The shape of every one of them is the same: an attacker holds strings — a
//! tenant, a workload, a framework label, a context token — and does not hold
//! the victim's process instance or executable content. The binding commits to
//! all of it together, so the strings alone never add up.

use aip_airi::PropagationBoundary;
use aip_enterprise::{
    framework_commitment, ContainerAttribution, ContextChain, EnterpriseAdapter, EnterpriseEffect,
    EnterpriseError, EnterpriseEvidence, EnterpriseProfile, EnterpriseResource, EnterpriseSource,
    GraphFrameworkAdapter, IdentityKind, SourceAgreement, WorkloadBinding, WorkloadState,
};
use aip_types::{ExecutionBinding, ProcessInstance, EXECUTION_BINDING_VERSION};

fn execution(agent: &str, pid: u32, ticks: u64, exe: u8, boot: u8) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent.to_owned(),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: ticks,
            boot_id: [boot; 16],
        },
        exe_content_sha256: [exe; 32],
        exe_path: "/usr/bin/agent".to_owned(),
        bound_at_ms: 1_000,
        container: None,
    }
}

fn sys(name: &str) -> aip_system::SystemId {
    aip_system::SystemId::parse(name).expect("system id")
}

fn langgraph() -> [u8; 32] {
    framework_commitment("langgraph", "0.2.1", "vanian-1")
}

fn binding(
    tenant: &str,
    workload: &str,
    system: &str,
    fw: [u8; 32],
    e: &ExecutionBinding,
) -> WorkloadBinding {
    WorkloadBinding::new(tenant, workload, sys(system), fw, e, 1_000).expect("binding")
}

/// The victim: tenant `acme`, workload `orders`, one real process.
fn victim() -> (ExecutionBinding, WorkloadBinding) {
    let e = execution("aip:agent-1", 42, 900, 0xAA, 0x11);
    let b = binding("acme", "orders", "enterprise:svc-orders", langgraph(), &e);
    (e, b)
}

/// The attacker: a different process, on the same host.
fn attacker() -> ExecutionBinding {
    execution("aip:agent-1", 77, 950, 0xAA, 0x11)
}

// ─── 1. cross-tenant transplantation ───

#[test]
fn e1_a_binding_does_not_transplant_across_tenants() {
    let (e, acme) = victim();
    let globex = binding("globex", "orders", "enterprise:svc-orders", langgraph(), &e);
    assert_ne!(acme.digest(), globex.digest());
    assert!(!acme.same_tenant(&globex));
    // Both cover the same execution — the execution is not the thing that
    // separates tenants — and the commitments are different, so a decision
    // point that signed one has not signed the other.
    assert!(acme.covers(&e) && globex.covers(&e));
    assert!(!acme.is_committed_by(Some(&globex.digest())));
}

// ─── 2. cross-agent transplantation ───

#[test]
fn e2_a_binding_does_not_transplant_across_agents() {
    let (_e, b) = victim();
    let other_agent = execution("aip:agent-2", 42, 900, 0xAA, 0x11);
    assert!(!b.covers(&other_agent));
    assert!(matches!(
        b.admit(&other_agent),
        Err(EnterpriseError::BindingDoesNotCoverExecution { .. })
    ));
}

// ─── 3. cross-framework transplantation ───

#[test]
fn e3_a_binding_does_not_transplant_across_frameworks() {
    let (e, b) = victim();
    let autogen = binding(
        "acme",
        "orders",
        "enterprise:svc-orders",
        framework_commitment("autogen", "0.4.0", "vanian-1"),
        &e,
    );
    assert_ne!(b.digest(), autogen.digest());
    // And a changed adapter version is a changed claim from the same framework.
    let relabelled_adapter = binding(
        "acme",
        "orders",
        "enterprise:svc-orders",
        framework_commitment("langgraph", "0.2.1", "vanian-2"),
        &e,
    );
    assert_ne!(b.digest(), relabelled_adapter.digest());
    // Nothing branches on the name: two adapters get the same ceiling.
    let g = GraphFrameworkAdapter {
        framework_version: "0.2.1".into(),
        adapter_version: "vanian-1".into(),
    };
    assert!(!g.framework_grants_authority());
}

// ─── 4. copied workload identity ───

#[test]
fn e4_a_copied_workload_identity_without_the_execution_is_refused() {
    let (_e, b) = victim();
    let thief = attacker();
    // The attacker knows the tenant and the workload — they are strings in a
    // config map — and builds a binding that names them.
    let forged = binding(
        "acme",
        "orders",
        "enterprise:svc-orders",
        langgraph(),
        &thief,
    );
    assert_eq!(b.tenant(), forged.tenant());
    assert_eq!(b.workload(), forged.workload());
    // And it is a different commitment, and the real one refuses the thief.
    assert_ne!(b.digest(), forged.digest());
    assert!(matches!(
        b.admit(&thief),
        Err(EnterpriseError::BindingDoesNotCoverExecution { .. })
    ));
}

// ─── 5. copied execution context ───

#[test]
fn e5_a_copied_context_cannot_be_presented_by_another_execution() {
    let (e, b) = victim();
    let mut chain = ContextChain::rooted_at(&b, 1_000, 2_000).unwrap();
    chain.extend(PropagationBoundary::WorkerQueue, [0x01; 16], None);
    chain.extend(PropagationBoundary::Subprocess, [0x02; 16], None);

    // The rightful holder is admitted.
    assert!(chain.admit(&b, &e, 1_500).is_ok());
    // A copy of the whole chain, presented by another process, is not.
    let thief = attacker();
    assert!(matches!(
        chain.admit(&b, &thief, 1_500),
        Err(EnterpriseError::BindingDoesNotCoverExecution { .. })
    ));
}

// ─── 6. subprocess boundary substitution ───

#[test]
fn e6_a_substituted_subprocess_hop_breaks_the_chain() {
    let (e, b) = victim();
    let mut mine = ContextChain::rooted_at(&b, 1_000, 2_000).unwrap();
    mine.extend(PropagationBoundary::WorkerQueue, [0x01; 16], None);
    mine.extend(PropagationBoundary::Subprocess, [0x02; 16], None);
    assert!(mine.check_links().is_ok());

    // Another workload's chain, and its second hop pasted into mine.
    let thief = attacker();
    let other_b = binding(
        "globex",
        "billing",
        "enterprise:svc-billing",
        langgraph(),
        &thief,
    );
    let mut theirs = ContextChain::rooted_at(&other_b, 1_000, 2_000).unwrap();
    theirs.extend(PropagationBoundary::WorkerQueue, [0x01; 16], None);
    theirs.extend(PropagationBoundary::Subprocess, [0x09; 16], None);

    // The splice happens on the wire, which is where it would happen: the
    // attacker edits the serialised chain rather than calling an API, because
    // there is no API that lets a hop be replaced.
    let mut json = serde_json::to_value(&mine).unwrap();
    let theirs_json = serde_json::to_value(&theirs).unwrap();
    json["hops"].as_array_mut().unwrap()[1] = theirs_json["hops"].as_array().unwrap()[1].clone();
    let spliced: ContextChain = serde_json::from_value(json).unwrap();
    assert!(matches!(
        spliced.check_links(),
        Err(EnterpriseError::ContextChainBroken { at_hop: 1 })
    ));
    assert!(spliced.admit(&b, &e, 1_500).is_err());
}

// ─── 7. container boundary substitution ───

#[test]
fn e7_a_substituted_container_changes_the_chain_and_was_never_measured() {
    let (e, b) = victim();
    let mut a = ContextChain::rooted_at(&b, 1_000, 2_000).unwrap();
    a.extend(
        PropagationBoundary::Process,
        [0x01; 16],
        Some(ContainerAttribution::new("cid-real", "reg/app:1.2").unwrap()),
    );
    let mut c = ContextChain::rooted_at(&b, 1_000, 2_000).unwrap();
    c.extend(
        PropagationBoundary::Process,
        [0x01; 16],
        Some(ContainerAttribution::new("cid-forged", "reg/app:1.2").unwrap()),
    );
    assert_ne!(a.digest(), c.digest());

    // And the honest limit: neither attribution was measured, so substituting
    // one establishes nothing either way. The process behind it is what is
    // measured, and the binding covers that.
    assert!(!a.container_identity_measured());
    assert!(!c.container_identity_measured());
    assert!(
        c.admit(&b, &e, 1_500).is_ok(),
        "the process is still the right one"
    );
    assert!(
        c.admit(&b, &attacker(), 1_500).is_err(),
        "and a different one is not"
    );
}

// ─── 8. API / tool identity substitution ───

#[test]
fn e8_substituting_a_tool_or_api_changes_what_was_authorized() {
    // The resources are distinct in the vocabulary and in their standing.
    assert_ne!(
        EnterpriseResource::Tool.code(),
        EnterpriseResource::Api.code()
    );
    let adapter = GraphFrameworkAdapter {
        framework_version: "0.2.1".into(),
        adapter_version: "vanian-1".into(),
    };
    assert_eq!(
        adapter.resource_of("tool_call"),
        Some(EnterpriseResource::Tool)
    );
    // An event the adapter does not know maps to nothing, never to a guess.
    assert_eq!(adapter.resource_of("unknown_event"), None);
    // And neither a tool nor an API has an establishable outcome, so
    // substituting one for the other cannot manufacture one.
    for r in [EnterpriseResource::Tool, EnterpriseResource::Api] {
        assert!(!r.outcome_establishable(), "{r:?}");
    }
}

// ─── 9. database / filesystem operation transplanted between workloads ───

#[test]
fn e9_an_operation_does_not_transplant_between_workloads() {
    let (e, orders) = victim();
    let thief = attacker();
    let billing = binding(
        "acme",
        "billing",
        "enterprise:svc-billing",
        langgraph(),
        &thief,
    );

    // Two workloads under one tenant, two bindings, two executions.
    assert!(orders.same_tenant(&billing));
    assert_ne!(orders.digest(), billing.digest());
    assert!(!orders.covers(&thief));
    assert!(!billing.covers(&e));

    // A filesystem effect is establishable — and only for the execution the
    // binding covers. The effect itself carries no workload, so the binding is
    // what attributes it, and the binding does not transplant.
    let sources = [
        EnterpriseSource::AgentSelfReport,
        EnterpriseSource::HostFilesystemObservation,
    ];
    let fs = EnterpriseEffect::from_sources(EnterpriseResource::Filesystem, &sources);
    assert!(fs.establishes_occurrence(), "a local write is observable");
    let db = EnterpriseEffect::from_sources(EnterpriseResource::Database, &sources);
    assert!(
        !db.establishes_occurrence(),
        "a socket to a database is not a row"
    );
    assert!(!db.establishes_remote_outcome());
}

// ─── 10. stale context replay ───

#[test]
fn e10_a_stale_context_is_refused_at_both_ends_of_its_window() {
    let (e, b) = victim();
    let mut chain = ContextChain::rooted_at(&b, 1_000, 2_000).unwrap();
    chain.extend(PropagationBoundary::WorkerQueue, [0x01; 16], None);

    assert!(chain.admit(&b, &e, 1_000).is_ok());
    assert!(chain.admit(&b, &e, 1_999).is_ok());
    assert!(matches!(
        chain.admit(&b, &e, 2_000),
        Err(EnterpriseError::ContextStale { .. })
    ));
    assert!(matches!(
        chain.admit(&b, &e, 999),
        Err(EnterpriseError::ContextStale { .. })
    ));
    // Staleness is not repaired by holding a valid binding: a replayed context
    // is not a live one.
    assert!(b.covers(&e));
    assert!(chain.admit(&b, &e, 10_000).is_err());
}

// ─── the standing negatives ───

#[test]
fn e11_the_four_identities_never_substitute_for_one_another() {
    for a in IdentityKind::ALL {
        for b in IdentityKind::ALL {
            assert!(!a.may_substitute_for(b), "{a:?} -> {b:?}");
        }
    }
}

#[test]
fn e12_no_number_of_in_process_sources_outvotes_one_host_observation() {
    for n in 1..=8usize {
        let a = SourceAgreement {
            agreeing: vec![EnterpriseSource::AgentSelfReport; n],
            disagreeing: vec![EnterpriseSource::HostSocketObservation],
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
fn e13_no_remote_state_is_assertable_at_any_tier() {
    for tier in [
        EnterpriseEvidence::Declared,
        EnterpriseEvidence::DecisionSigned,
        EnterpriseEvidence::ExecutionObserved,
        EnterpriseEvidence::LocalEffectObserved,
    ] {
        for s in [WorkloadState::RemoteEffectApplied, WorkloadState::Completed] {
            assert_eq!(
                WorkloadState::assertable(s, tier),
                WorkloadState::Unknown,
                "{s:?}/{tier:?}"
            );
        }
    }
}

#[test]
fn e14_a_cloud_audit_log_never_anchors_an_effect() {
    let p = EnterpriseProfile::new(
        "collector",
        &[
            EnterpriseSource::AgentSelfReport,
            EnterpriseSource::CloudAuditLog,
            EnterpriseSource::ServiceMeshRecord,
        ],
        &EnterpriseResource::ALL,
    )
    .unwrap();
    assert!(!p.has_host_observer());
    assert!(p.establishable_effects().is_empty());
    assert!(!p.establishes_remote_effect());
}
