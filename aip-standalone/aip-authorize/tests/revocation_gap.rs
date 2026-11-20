//! Characterises a known gap, recorded in
//! `docs/enterprise-wow/ADR-001-decisionpoint-revocation.md`: the decision
//! point does not consult revocation.
//!
//! These tests pin **current** behaviour so the gap cannot be described in
//! documents more weakly, or more strongly, than the code shows. They are
//! not a statement that the behaviour is acceptable. When ADR-001 is
//! implemented, `gap_*` must flip to expecting `DenialReason::AuthorityRevoked`.
//! It must not be deleted.

use aip_authorize::*;
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_core::revocation::{check_delegation_valid, check_token_valid, RevocationLog};
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_types::{
    Action, AipError, ExecutionBinding, ProcessInstance, ProvenanceTriple, RevocationReason,
    ScopeAction, EXECUTION_BINDING_VERSION,
};

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

struct Fx {
    dp: DecisionPoint,
    req: AuthorizationRequest,
    now: u64,
}

/// CFO → orchestrator (root token) → payments agent (one delegation hop).
fn fixture() -> Fx {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent, _agent_kp) = create_identity(provenance("payments-agent"), None).unwrap();
    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch.id,
        scope_orchestrator(),
        Some(ROOT_LIFETIME_MS),
    )
    .unwrap();
    let hop = create_delegation(&root, &orch_kp.private_key, &agent.id, scope_submitter()).unwrap();
    let now = root.issued_at.max(hop.issued_at) + 1;
    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch.id, &orch_kp.public_key);
    let req = AuthorizationRequest {
        agent_id: agent.id.clone(),
        root_token: root,
        delegation_chain: vec![hop],
        action_kind: ScopeAction::Standard(Action::Write),
        parameters: ActionParameters::from_pairs([("invoice", b"INV-1".to_vec())]).unwrap(),
        execution_binding: ExecutionBinding {
            version: EXECUTION_BINDING_VERSION,
            agent_id: agent.id,
            process: ProcessInstance {
                pid: 4242,
                pid_start_time_ticks: 433_843,
                boot_id: [0x0c; 16],
            },
            exe_content_sha256: sha256(b"payments-agent binary v1"),
            exe_path: "/opt/agent/bin/payments-agent".into(),
            bound_at_ms: 1_700_000_000_000,
            container: None,
        },
        requested_ttl_ms: TTL,
    };
    Fx { dp, req, now }
}

fn revoked(jti: [u8; 16]) -> RevocationLog {
    let mut log = RevocationLog::new();
    log.revoke(
        jti,
        RevocationReason::AgentCompromised,
        "security-officer",
        false,
        None,
    );
    log
}

#[test]
fn revocation_store_does_report_the_revoked_root() {
    // The information exists: aip_core's own check rejects both tokens.
    let f = fixture();
    let log = revoked(f.req.root_token.jti);
    assert!(log.is_revoked(&f.req.root_token.jti));
    assert_eq!(
        check_token_valid(&f.req.root_token, &log),
        Err(AipError::IdentityRevoked)
    );
    // The hop's parent is the root, so the hop is rejected too.
    assert_eq!(
        check_delegation_valid(&f.req.delegation_chain[0], &log),
        Err(AipError::IdentityRevoked)
    );
}

#[test]
fn gap_decision_point_authorizes_under_a_revoked_root() {
    let f = fixture();
    let _log = revoked(f.req.root_token.jti);
    // DecisionPoint has no revocation input: nothing can pass `_log` to it.
    match f.dp.authorize_at(&f.req, f.now) {
        Decision::Authorized(ee) => assert_eq!(ee.authority.root_jti, f.req.root_token.jti),
        Decision::Denied(d) => panic!("gap closed? update ADR-001 and flip this test: {d:?}"),
    }
}

#[test]
fn gap_decision_point_authorizes_under_a_revoked_delegation_hop() {
    let f = fixture();
    let _log = revoked(f.req.delegation_chain[0].jti);
    match f.dp.authorize_at(&f.req, f.now) {
        Decision::Authorized(ee) => {
            assert_eq!(ee.authority.chain_jtis, vec![f.req.delegation_chain[0].jti])
        }
        Decision::Denied(d) => panic!("gap closed? update ADR-001 and flip this test: {d:?}"),
    }
}
