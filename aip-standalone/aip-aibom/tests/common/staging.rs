//! An authorised execution and an independent observer of it, for the
//! execution-environment tests. Adapted from `aip-conformance/tests/staging`.

#![allow(dead_code)]

use aip_authorize::{
    ActionParameters, AuthorizationRequest, Decision, DecisionPoint, DecisionPointTrustAnchors,
    ExpectedExecution,
};
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_nexora::{DeclaredParameters, NexoraProof, VerifierAnchors, VerifierCapability};
use aip_observe::{
    AgentClaim, AttestedBatch, CollectorSigner, ObservedEffect, ObservedExecution, ObservedProcess,
    ObserverAttestor, ObserverTrustAnchors, ProcfsProbe, SourceMechanism,
};
use aip_reconcile::{
    reconcile_expectation, ExpectedSideCoverage, ObserverEvidence, ReconciliationContext,
};
use aip_types::{
    Action, DelegationToken, ExecutionBinding, KeyPair, ProcessInstance, ScopeAction, ScopedToken,
    EXECUTION_BINDING_VERSION,
};
use std::collections::HashMap;

pub const PID: u32 = 3_920_001;
pub const TTL: u64 = 60_000;
pub const MAX_TTL: u64 = 3_600_000;
pub const HEALTH_MAX_AGE: u64 = 3_600_000;
pub const OBSERVER_ID: &str = "aibom-collector";
pub const PROBE_ID: &str = "aibom-probe";

pub fn exe_bytes() -> &'static [u8] {
    b"treasury-agent binary v1.2.0"
}

pub struct Authorised {
    pub ee: ExpectedExecution,
    pub dp_anchors: DecisionPointTrustAnchors,
    pub agent_id: String,
    pub agent_kp: KeyPair,
    pub root: ScopedToken,
    pub chain: Vec<DelegationToken>,
    pub issuers: HashMap<String, Vec<u8>>,
    pub now: u64,
}

pub fn authorised() -> Authorised {
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
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch.id, &orch_kp.public_key);
    let binding = ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent.id.clone(),
        process: ProcessInstance {
            pid: PID,
            pid_start_time_ticks: 700_001,
            boot_id: [0x3f; 16],
        },
        exe_content_sha256: sha256(exe_bytes()),
        exe_path: "/opt/treasury/bin/agent".into(),
        bound_at_ms: 1_700_000_000_000,
        // Unknown placement: the fixture does not run in a container the
        // collector can read, and `None` is the honest value for that.
        container: None,
    };
    let req = AuthorizationRequest {
        agent_id: agent.id.clone(),
        root_token: root.clone(),
        delegation_chain: vec![hop.clone()],
        action_kind: ScopeAction::Standard(Action::Write),
        parameters: ActionParameters::from_pairs([("amount_cents", b"50000".to_vec())]).unwrap(),
        execution_binding: binding,
        requested_ttl_ms: TTL,
    };
    let ee = match dp.authorize_at(&req, now) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("fixture must authorise: {d:?}"),
    };
    let mut issuers = HashMap::new();
    issuers.insert(cfo_id, cfo_kp.public_key.clone());
    issuers.insert(orch.id.clone(), orch_kp.public_key.clone());
    Authorised {
        ee,
        dp_anchors: DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key),
        agent_id: agent.id,
        agent_kp,
        root,
        chain: vec![hop],
        issuers,
        now,
    }
}

pub struct Observer {
    pub signer: CollectorSigner,
    pub probe: ProcfsProbe,
    pub anchors: ObserverTrustAnchors,
}

pub fn observer() -> Observer {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
    let mut probe = ProcfsProbe::new(PROBE_ID);
    probe.declare_source(SourceMechanism::ProcConnector);
    Observer {
        signer,
        probe,
        anchors: ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key),
    }
}

impl Observer {
    fn present(&mut self, p: ObservedProcess, claim: &AgentClaim, at: u64) -> ObservedExecution {
        self.probe
            .observation(p, ObservedEffect::ProcessPresent, Some(claim), at)
    }
    fn batch(&mut self, id: u8, from: u64, to: u64, obs: Vec<ObservedExecution>) -> AttestedBatch {
        self.signer
            .attest(self.probe.batch([id; 16], from, to, obs))
            .unwrap()
    }
}

pub fn at_of(a: &Authorised) -> u64 {
    a.now + TTL + 1_000
}

/// Evidence in which the collector measured the authorised process running
/// `exe` — the authorised content, or something else.
pub fn evidence(a: &Authorised, o: &mut Observer, exe: &[u8]) -> ObserverEvidence {
    let claim = AgentClaim {
        agent_id: a.agent_id.clone(),
        claim_source: "orchestrator".into(),
        decision_id: Some(a.ee.decision_id),
    };
    let measured = ObservedProcess {
        process: a.ee.execution_binding.process,
        exe_content_sha256: sha256(exe),
        exe_path: a.ee.execution_binding.exe_path.clone(),
        container: None,
    };
    let obs = o.present(measured, &claim, a.now + 10);
    let b1 = o.batch(1, a.now - 2_000, a.now - 1_000, vec![]);
    let b2 = o.batch(2, a.now - 1_000, at_of(a), vec![obs]);
    ObserverEvidence {
        batches: vec![b1, b2],
        health: o.signer.health(at_of(a)).unwrap(),
    }
}

pub fn ctx(a: &Authorised, o: &Observer) -> ReconciliationContext {
    ReconciliationContext {
        decision_point_anchors: a.dp_anchors.clone(),
        observer_anchors: o.anchors.clone(),
        verification_time_ms: at_of(a),
        health_max_age_ms: HEALTH_MAX_AGE,
        window_tolerance_ms: 0,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: Some(a.agent_kp.public_key.clone()),
    }
}

/// A NEXORA proof whose claim is the engine's own reconciliation of `ev`.
pub fn proof(a: &Authorised, o: &Observer, ev: &ObserverEvidence) -> NexoraProof {
    let at = at_of(a);
    let rec = reconcile_expectation(&a.ee, Some(ev), &ctx(a, o));
    NexoraProof::builder(a.agent_id.clone(), rec)
        .issued_at(at + 1)
        .authority(a.root.clone(), a.chain.clone())
        .expectation(a.ee.clone())
        .observer(ev.batches.clone(), ev.health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: at,
            health_max_age_ms: HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build()
}

pub fn verifier_anchors(a: &Authorised, o: &Observer) -> VerifierAnchors {
    VerifierAnchors {
        decision_point: a.dp_anchors.clone(),
        observer: o.anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: a.issuers.clone(),
        agent_public_key: Some(a.agent_kp.public_key.clone()),
        capability: VerifierCapability::strict(),
        present_time_ms: None,
    }
}
