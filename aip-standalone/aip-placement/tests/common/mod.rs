//! A real decision point signing a real expectation, for placement tests.

#![allow(dead_code)]

use aip_authorize::{
    ActionParameters, AuthorizationRequest, Decision, DecisionPoint, DecisionPointTrustAnchors,
    ExpectedExecution,
};
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_placement::PlacementAuthority;
use aip_types::{
    Action, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple, ScopeAction,
    EXECUTION_BINDING_VERSION,
};

const MAX_TTL: u64 = 3_600_000;
pub const TTL: u64 = 60_000;

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

/// A decision point, the request it authorised, and the agent's key.
pub struct Authorised {
    pub dp: DecisionPoint,
    pub dp_kp: KeyPair,
    pub agent_kp: KeyPair,
    pub req: AuthorizationRequest,
    pub now: u64,
}

impl Authorised {
    /// A freshly signed expectation — each call is a new decision.
    pub fn expectation(&self) -> ExpectedExecution {
        match self.dp.authorize_at(&self.req, self.now) {
            Decision::Authorized(ee) => *ee,
            Decision::Denied(d) => panic!("fixture must authorise: {d:?}"),
        }
    }

    /// The supervisor's trust: this decision point, and the agent's key so
    /// an anchor under it is refused.
    pub fn authority(&self) -> PlacementAuthority {
        PlacementAuthority::new(
            DecisionPointTrustAnchors::new().trust(self.dp.id(), &self.dp_kp.public_key),
            Some(self.agent_kp.public_key.clone()),
        )
    }
}

pub fn authorised() -> Authorised {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent, agent_kp) = create_identity(provenance("agent"), None).unwrap();
    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch.id,
        scope_orchestrator(),
        Some(MAX_TTL),
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
        parameters: ActionParameters::empty(),
        execution_binding: ExecutionBinding {
            version: EXECUTION_BINDING_VERSION,
            agent_id: agent.id,
            process: ProcessInstance {
                pid: 4242,
                pid_start_time_ticks: 433_843,
                boot_id: [0x0c; 16],
            },
            exe_content_sha256: sha256(b"agent binary v1"),
            exe_path: "/opt/agent/bin/agent".into(),
            bound_at_ms: 1_700_000_000_000,
            container: None,
        },
        requested_ttl_ms: TTL,
    };
    Authorised {
        dp,
        dp_kp,
        agent_kp,
        req,
        now,
    }
}
