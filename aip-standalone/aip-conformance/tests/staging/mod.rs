//! Fixtures for the executed threat model: real signed artifacts, built
//! through the production constructors.
//!
//! Nothing here fakes a signature or hand-assembles a verdict. An expectation
//! comes out of a real `DecisionPoint`; a batch comes out of a real
//! `CollectorSigner`; a forgery is made by editing signed bytes, or — where a
//! real attacker would hold the key — by re-signing with it. An attack staged
//! against a mock would measure the mock.
//!
//! This lives in `tests/` because
//! `no_second_architecture::the_program_holds_no_key_and_signs_nothing`
//! forbids the library from touching a key. That guard is the reason the
//! staging is here and not in `src/`.

#![allow(dead_code)]

use aip_authorize::{
    ActionParameters, AuthorizationRequest, Decision, DecisionPoint, DecisionPointTrustAnchors,
    ExpectedExecution,
};
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256, sign_ed25519};
use aip_observe::{
    AgentClaim, AttestedBatch, CollectorSigner, KernelLifecycleKind, ObservedEffect,
    ObservedExecution, ObservedProcess, ObserverAttestor, ObserverTrustAnchors, ProcEvent,
    ProcfsProbe, SignedSensorHealth, SourceMechanism,
};
use aip_reconcile::{ExpectedSideCoverage, ObserverEvidence, ReconciliationContext};
use aip_types::{
    Action, DelegationToken, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple,
    ScopeAction, ScopedToken, EXECUTION_BINDING_VERSION,
};

/// A pid that will not exist on the test host, so `ProcfsProbe` cannot
/// accidentally anchor a kernel event to a real process.
pub const PID: u32 = 3_910_001;
pub const OTHER_PID: u32 = 3_910_777;
pub const TTL: u64 = 60_000;
pub const MAX_TTL: u64 = 3_600_000;
pub const HEALTH_MAX_AGE: u64 = 3_600_000;
pub const OBSERVER_ID: &str = "empirical-collector";
pub const PROBE_ID: &str = "empirical-probe";

pub fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

pub fn binding_for(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: PID,
            pid_start_time_ticks: 512_101,
            boot_id: [0x2e; 16],
        },
        exe_content_sha256: sha256(b"empirical-agent binary v1"),
        exe_path: "/opt/agent/bin/empirical-agent".into(),
        bound_at_ms: 1_700_000_000_000,
    }
}

/// One authorised execution, plus everything a verifier would need to
/// evaluate it.
pub struct Expected {
    pub ee: ExpectedExecution,
    pub anchors: DecisionPointTrustAnchors,
    pub dp_id: String,
    pub dp_kp: KeyPair,
    pub agent_id: String,
    pub agent_kp: KeyPair,
    pub root: ScopedToken,
    pub chain: Vec<DelegationToken>,
    /// Issuer public keys by AIP-ID, so a verifier can walk the chain.
    pub issuer_keys: std::collections::HashMap<String, Vec<u8>>,
    /// `ee.issued_at`; the window is `[now, now + TTL]`.
    pub now: u64,
}

/// A real authorisation: CFO issues to an orchestrator, the orchestrator
/// delegates to the agent, a decision point authorises one action.
pub fn expected() -> Expected {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(provenance("empirical-agent"), None).unwrap();

    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(MAX_TTL),
    )
    .unwrap();
    let hop = create_delegation(
        &root,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .unwrap();
    let now = root.issued_at.max(hop.issued_at) + 1;

    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);
    let anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);

    let req = AuthorizationRequest {
        agent_id: agent_aid.id.clone(),
        root_token: root.clone(),
        delegation_chain: vec![hop.clone()],
        action_kind: ScopeAction::Standard(Action::Write),
        parameters: ActionParameters::from_pairs([
            ("invoice", b"INV-2026-0900".to_vec()),
            ("amount_cents", b"1250000".to_vec()),
        ])
        .unwrap(),
        execution_binding: binding_for(&agent_aid.id),
        requested_ttl_ms: TTL,
    };
    let ee = match dp.authorize_at(&req, now) {
        Decision::Authorized(ee) => *ee,
        Decision::Denied(d) => panic!("fixture must authorize, got {d:?}"),
    };
    let mut issuer_keys = std::collections::HashMap::new();
    issuer_keys.insert(cfo_id.clone(), cfo_kp.public_key.clone());
    issuer_keys.insert(orch_aid.id.clone(), orch_kp.public_key.clone());
    Expected {
        ee,
        anchors,
        issuer_keys,
        dp_id,
        dp_kp,
        agent_id: agent_aid.id,
        agent_kp,
        root,
        chain: vec![hop],
        now,
    }
}

/// A collector under its own key, off the observed host.
pub struct Observer {
    pub signer: CollectorSigner,
    pub probe: ProcfsProbe,
    pub kp: KeyPair,
    pub anchors: ObserverTrustAnchors,
    pub id: String,
}

impl Observer {
    /// `kernel`: the probe declares a live proc connector (kernel-pushed).
    /// `registered`: the collector runs `RegisteredOnly`.
    pub fn new(kernel: bool, registered: bool) -> Self {
        Self::with_id(OBSERVER_ID, kernel, registered)
    }

    pub fn with_id(observer_id: &str, kernel: bool, registered: bool) -> Self {
        let kp = generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new(observer_id, 1, &kp.private_key, &kp.public_key).unwrap();
        if registered {
            signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
        }
        let mut probe = ProcfsProbe::new(PROBE_ID);
        probe.declare_source(if kernel {
            SourceMechanism::ProcConnector
        } else {
            SourceMechanism::ProcfsPoll
        });
        let anchors = ObserverTrustAnchors::new().trust(observer_id, 1, &kp.public_key);
        Self {
            signer,
            probe,
            kp,
            anchors,
            id: observer_id.to_string(),
        }
    }

    pub fn present(
        &mut self,
        p: ObservedProcess,
        claim: Option<&AgentClaim>,
        wall_ms: u64,
    ) -> ObservedExecution {
        self.probe
            .observation(p, ObservedEffect::ProcessPresent, claim, wall_ms)
    }

    pub fn batch(
        &mut self,
        id: u8,
        from: u64,
        to: u64,
        obs: Vec<ObservedExecution>,
    ) -> AttestedBatch {
        self.signer
            .attest(self.probe.batch([id; 16], from, to, obs))
            .unwrap()
    }

    pub fn health(&self, at: u64) -> SignedSensorHealth {
        self.signer.health(at).unwrap()
    }

    pub fn evidence(&self, batches: Vec<AttestedBatch>, at: u64) -> ObserverEvidence {
        ObserverEvidence {
            batches,
            health: self.health(at),
        }
    }

    /// What an attacker holding the collector key could do: edit and re-sign.
    pub fn resign_batch(&self, mut b: AttestedBatch) -> AttestedBatch {
        b.attestation =
            sign_ed25519(&self.kp.private_key, &self.id, &b.signing_preimage()).unwrap();
        b
    }
}

pub fn process_of(ee: &ExpectedExecution) -> ObservedProcess {
    ObservedProcess {
        process: ee.execution_binding.process,
        exe_content_sha256: ee.execution_binding.exe_content_sha256,
        exe_path: ee.execution_binding.exe_path.clone(),
    }
}

/// A process that is not the authorised one — the decoy an unrelated
/// observation is about.
pub fn other_process() -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: OTHER_PID,
            pid_start_time_ticks: 91,
            boot_id: [0x2e; 16],
        },
        exe_content_sha256: sha256(b"an unrelated binary"),
        exe_path: "/usr/bin/unrelated".into(),
    }
}

/// The authorised process, but running a different executable: what a
/// compromised process looks like from the collector's side.
pub fn swapped_binary(ee: &ExpectedExecution) -> ObservedProcess {
    let mut p = process_of(ee);
    p.exe_content_sha256 = sha256(b"empirical-agent binary v1 (attacker patched)");
    p
}

pub fn claim_for(x: &Expected) -> AgentClaim {
    AgentClaim {
        agent_id: x.agent_id.clone(),
        claim_source: "orchestrator".into(),
        decision_id: Some(x.ee.decision_id),
    }
}

pub fn exec_event(pid: u32, ts_ns: u64) -> ProcEvent {
    ProcEvent {
        kind: KernelLifecycleKind::Exec { pid, tgid: pid },
        cpu: 0,
        timestamp_ns: ts_ns,
    }
}

pub fn ctx(x: &Expected, o: &Observer, verification_time_ms: u64) -> ReconciliationContext {
    ReconciliationContext {
        decision_point_anchors: x.anchors.clone(),
        observer_anchors: o.anchors.clone(),
        verification_time_ms,
        health_max_age_ms: HEALTH_MAX_AGE,
        window_tolerance_ms: 0,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key: Some(x.agent_kp.public_key.clone()),
    }
}

/// Reconciliation time in the standard scenario: 1 s after the window closes.
pub fn at_of(x: &Expected) -> u64 {
    x.now + TTL + 1_000
}

/// An epoch-start batch and one contiguous batch spanning the expectation's
/// window with 1 s slack on each side, carrying `obs`.
pub fn covered_chain(
    x: &Expected,
    o: &mut Observer,
    obs: Vec<ObservedExecution>,
) -> Vec<AttestedBatch> {
    let now = x.now;
    let b1 = o.batch(1, now - 2_000, now - 1_000, vec![]);
    let b2 = o.batch(2, now - 1_000, at_of(x), obs);
    vec![b1, b2]
}
