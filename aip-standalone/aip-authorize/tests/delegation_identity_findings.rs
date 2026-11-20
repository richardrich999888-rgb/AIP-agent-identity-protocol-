//! Adversarial #5 (unauthorized child delegation) and #6 (forged identity)
//! at the protocol layer (enterprise WOW loop, item 2.5a).
//!
//! `finding_*` tests pin **current** behaviour that the plan expects to be
//! refused. They are recorded findings, not acceptance. When the behaviour
//! is fixed, flip each one to expect refusal; never delete it.
//! `control_*` tests show the mechanisms that do work, so the findings are
//! not misread as "nothing is checked".

use aip_authorize::*;
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::{create_delegation, create_sub_delegation, verify_delegation_chain};
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_types::{
    Action, AipError, CapabilityScope, ExecutionBinding, KeyPair, ProcessInstance,
    ProvenanceTriple, ScopeAction, EXECUTION_BINDING_VERSION,
};
use std::collections::HashMap;

const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const ROOT_LIFETIME_MS: u64 = 3_600_000;

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn write_only() -> CapabilityScope {
    CapabilityScope {
        allowed: vec![ScopeAction::Standard(Action::Write)],
        denied: vec![],
    }
}

fn binding(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: 4243,
            pid_start_time_ticks: 433_900,
            boot_id: [0x0c; 16],
        },
        exe_content_sha256: sha256(b"agent binary v1"),
        exe_path: "/opt/agent/bin/agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

struct Fx {
    dp: DecisionPoint,
    root: aip_types::ScopedToken,
    hop1: aip_types::DelegationToken,
    recon_id: String,
    recon_kp: KeyPair,
    keys: HashMap<String, Vec<u8>>,
}

/// CFO → orchestrator (root, orchestrator scope incl. Delegate) →
/// recon-reporter (hop 1, submitter scope: Write only, **no Delegate**).
fn fixture() -> Fx {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (recon, recon_kp) = create_identity(provenance("recon-reporter"), None).unwrap();
    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch.id,
        scope_orchestrator(),
        Some(ROOT_LIFETIME_MS),
    )
    .unwrap();
    let hop1 =
        create_delegation(&root, &orch_kp.private_key, &recon.id, scope_submitter()).unwrap();
    assert!(
        !hop1
            .scope
            .allowed
            .contains(&ScopeAction::Standard(Action::Delegate)),
        "fixture: recon-reporter must not hold Delegate"
    );
    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch.id, &orch_kp.public_key)
        .trust_issuer(&recon.id, &recon_kp.public_key);
    let mut keys = HashMap::new();
    keys.insert(cfo_id, cfo_kp.public_key.clone());
    keys.insert(orch.id.clone(), orch_kp.public_key.clone());
    keys.insert(recon.id.clone(), recon_kp.public_key.clone());
    Fx {
        dp,
        root,
        hop1,
        recon_id: recon.id,
        recon_kp,
        keys,
    }
}

fn request(f: &Fx, agent_id: &str, chain: Vec<aip_types::DelegationToken>) -> AuthorizationRequest {
    AuthorizationRequest {
        agent_id: agent_id.to_string(),
        root_token: f.root.clone(),
        delegation_chain: chain,
        action_kind: ScopeAction::Standard(Action::Write),
        parameters: ActionParameters::from_pairs([("report", b"r-1".to_vec())]).unwrap(),
        execution_binding: binding(agent_id),
        requested_ttl_ms: TTL,
    }
}

fn now(f: &Fx, chain: &[aip_types::DelegationToken]) -> u64 {
    chain
        .iter()
        .map(|t| t.issued_at)
        .chain([f.root.issued_at])
        .max()
        .unwrap()
        + 1
}

// ─── #5 unauthorized child delegation ───

#[test]
fn finding_holder_without_delegate_scope_can_sub_delegate_and_grandchild_is_authorized() {
    let f = fixture();
    let (grandchild, _) = create_identity(provenance("grandchild"), None).unwrap();
    // recon-reporter holds Write only, no Delegate, yet sub-delegation succeeds.
    let hop2 = create_sub_delegation(
        &f.hop1,
        &f.recon_kp.private_key,
        &grandchild.id,
        write_only(),
    )
    .expect("finding: sub-delegation without Delegate is currently accepted");
    let chain = vec![f.hop1.clone(), hop2];
    assert!(verify_delegation_chain(&f.root, &chain, &f.keys).is_ok());
    let at = now(&f, &chain);
    match f.dp.authorize_at(&request(&f, &grandchild.id, chain), at) {
        Decision::Authorized(ee) => assert_eq!(ee.agent_id, grandchild.id),
        Decision::Denied(d) => {
            panic!("finding fixed? flip this test and update ADVERSARIAL_RESULTS #5: {d:?}")
        }
    }
}

#[test]
fn control_sub_delegation_cannot_exceed_the_parent_scope() {
    let f = fixture();
    let (grandchild, _) = create_identity(provenance("grandchild"), None).unwrap();
    let wider = CapabilityScope {
        allowed: vec![
            ScopeAction::Standard(Action::Write),
            ScopeAction::Standard(Action::Delete),
        ],
        denied: vec![],
    };
    assert_eq!(
        create_sub_delegation(&f.hop1, &f.recon_kp.private_key, &grandchild.id, wider).unwrap_err(),
        AipError::AttenuationViolation
    );
}

// ─── #6 forged identity ───

#[test]
fn finding_decision_point_takes_no_proof_of_possession_for_the_agent_id() {
    // The request names recon-reporter, and is built with none of its key
    // material: AuthorizationRequest has no requester signature to check.
    let f = fixture();
    let chain = vec![f.hop1.clone()];
    let at = now(&f, &chain);
    match f.dp.authorize_at(&request(&f, &f.recon_id, chain), at) {
        Decision::Authorized(ee) => assert_eq!(ee.agent_id, f.recon_id),
        Decision::Denied(d) => {
            panic!("finding fixed? flip this test and update ADVERSARIAL_RESULTS #6: {d:?}")
        }
    }
}

#[test]
fn control_a_forged_key_does_not_derive_the_claimed_id() {
    let f = fixture();
    let attacker = generate_ed25519_keypair();
    assert_ne!(
        derive_aip_id(&attacker.public_key, &provenance("recon-reporter")),
        f.recon_id
    );
    assert_eq!(
        derive_aip_id(&f.recon_kp.public_key, &provenance("recon-reporter")),
        f.recon_id
    );
}

#[test]
fn control_chain_leaf_must_be_the_requesting_agent() {
    let f = fixture();
    let (other, _) = create_identity(provenance("other"), None).unwrap();
    let chain = vec![f.hop1.clone()];
    let at = now(&f, &chain);
    match f.dp.authorize_at(&request(&f, &other.id, chain), at) {
        Decision::Denied(d) => assert_eq!(d.reason, DenialReason::ChainLeafNotAgent),
        Decision::Authorized(_) => panic!("a chain for recon-reporter authorized another agent"),
    }
}
