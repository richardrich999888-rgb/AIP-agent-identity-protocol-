//! A treasury agent under a real decision point enforcing a real signed spend
//! policy: $1,000 per payment, human approval above $500 (ADR-018).

#![allow(dead_code)]

use aip_aibom::evidence::AssessorContext;
use aip_authorize::{
    ActionParameters, AuthorizationRequest, DecisionPoint, DecisionPointTrustAnchors,
    SpendDecision, SpendRecord,
};
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_spend::{
    SignedSpendAttestation, SignedSpendPolicy, SignedSpendRefusal, SpendPolicy, SpendPolicyAnchors,
    SpendRule, SPEND_POLICY_VERSION,
};
use aip_types::{
    Action, ExecutionBinding, KeyPair, ProcessInstance, ScopeAction, EXECUTION_BINDING_VERSION,
};

pub const POLICY_ISSUER: &str = "bank.example/treasury-policy";
pub const LIMIT_CENTS: u64 = 100_000;
pub const APPROVAL_ABOVE_CENTS: u64 = 50_000;
pub const REVISION: u64 = 3;
const MAX_TTL: u64 = 3_600_000;
const TTL: u64 = 60_000;

pub fn pay() -> ScopeAction {
    ScopeAction::Standard(Action::Write)
}

pub struct Treasury {
    pub dp: DecisionPoint,
    pub dp_id: String,
    pub dp_anchors: DecisionPointTrustAnchors,
    pub agent_id: String,
    pub agent_kp: KeyPair,
    pub issuer_kp: KeyPair,
    pub base: AuthorizationRequest,
    pub now: u64,
}

pub fn treasury() -> Treasury {
    let p = super::provenance;
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &p("cfo"));
    let (orch, orch_kp) = create_identity(p("orchestrator"), None).unwrap();
    let (agent, agent_kp) = create_identity(p("treasury-agent"), None).unwrap();
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
    let dp_id = derive_aip_id(&dp_kp.public_key, &p("decision-point"));
    let issuer_kp = generate_ed25519_keypair();

    let mut t = Treasury {
        dp: DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
            .unwrap()
            .trust_issuer(&cfo_id, &cfo_kp.public_key)
            .trust_issuer(&orch.id, &orch_kp.public_key),
        dp_anchors: DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key),
        dp_id,
        agent_id: agent.id.clone(),
        agent_kp,
        issuer_kp,
        base: AuthorizationRequest {
            agent_id: agent.id.clone(),
            root_token: root,
            delegation_chain: vec![hop],
            action_kind: pay(),
            parameters: ActionParameters::empty(),
            execution_binding: ExecutionBinding {
                version: EXECUTION_BINDING_VERSION,
                agent_id: agent.id,
                process: ProcessInstance {
                    pid: 3_920_002,
                    pid_start_time_ticks: 700_002,
                    boot_id: [0x3e; 16],
                },
                exe_content_sha256: sha256(b"treasury-agent binary v1.2.0"),
                exe_path: "/opt/treasury/bin/agent".into(),
                bound_at_ms: 1_700_000_000_000,
                container: None,
            },
            requested_ttl_ms: TTL,
        },
        now,
    };
    let held = t
        .signed(t.policy(REVISION, LIMIT_CENTS, Some(APPROVAL_ABOVE_CENTS)))
        .verify(&t.anchors())
        .unwrap();
    t.dp = t.dp.with_spend_policy(held).unwrap();
    t
}

impl Treasury {
    pub fn policy(&self, revision: u64, max: u64, above: Option<u64>) -> SpendPolicy {
        SpendPolicy {
            version: SPEND_POLICY_VERSION,
            policy_id: "treasury-payments".into(),
            issuer_id: POLICY_ISSUER.into(),
            revision,
            issued_at_ms: 1_700_000_000_000,
            agent_id: self.agent_id.clone(),
            rules: vec![SpendRule {
                action: pay(),
                amount_parameter: "amount_cents".into(),
                currency: "USD".into(),
                exponent: 2,
                max_per_action: max,
                approval_above: above,
            }],
        }
    }

    pub fn signed(&self, p: SpendPolicy) -> SignedSpendPolicy {
        SignedSpendPolicy::sign(p, &self.issuer_kp.private_key).unwrap()
    }

    /// The policy the decision point holds, as the institution signed it.
    pub fn current(&self) -> SignedSpendPolicy {
        self.signed(self.policy(REVISION, LIMIT_CENTS, Some(APPROVAL_ABOVE_CENTS)))
    }

    pub fn anchors(&self) -> SpendPolicyAnchors {
        SpendPolicyAnchors::new().trust(POLICY_ISSUER, &self.issuer_kp.public_key)
    }

    pub fn ask(&self, cents: &str) -> SpendDecision {
        let mut req = self.base.clone();
        req.parameters = ActionParameters::from_pairs([
            ("payee", b"ACME-SUPPLIES-LTD".to_vec()),
            ("amount_cents", cents.as_bytes().to_vec()),
        ])
        .unwrap();
        self.dp.authorize_spend_at(&req, self.now)
    }

    /// An authorised payment's expectation and attestation.
    pub fn paid(&self, cents: &str) -> (aip_authorize::ExpectedExecution, SignedSpendAttestation) {
        let d = self.ask(cents);
        match (d.decision.expected().cloned(), d.record) {
            (Some(ee), Some(SpendRecord::Attested(a))) => (ee, a),
            other => panic!("expected an attested authorisation, got {other:?}"),
        }
    }

    pub fn refused(&self, cents: &str) -> SignedSpendRefusal {
        match self.ask(cents).record {
            Some(SpendRecord::Refused(r)) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The assessor trusts this decision point and this policy issuer.
    pub fn ctx(&self) -> AssessorContext {
        let mut c = AssessorContext::trusting_nothing(self.now + 1);
        c.decision_points = self.dp_anchors.clone();
        c.spend_policy_anchors = self.anchors();
        c
    }
}
