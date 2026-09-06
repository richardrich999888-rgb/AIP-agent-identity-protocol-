//! Shared fixtures for the AIRI test suites.
//!
//! Everything here builds *genuine* events with *genuine* signatures. The
//! attacks in the suites are substitutions and replays of real material,
//! not malformed bytes — a verifier that only rejects garbage is not a
//! verifier.

#![allow(dead_code)]

use aip_airi::*;
use aip_crypto::generate_ed25519_keypair;
use aip_types::{ExecutionBinding, ProcessInstance, Signature};

pub const EXEC_A: [u8; 16] = [0xA1; 16];
pub const EXEC_B: [u8; 16] = [0xB2; 16];
pub const DECISION_A: [u8; 16] = [0xD1; 16];
pub const DECISION_B: [u8; 16] = [0xD2; 16];

/// A keypair plus the AIP-ID the tests use as `agent_id`.
///
/// The id is the caller-supplied label rather than a derived AIP-ID: these
/// tests are about binding and substitution, and a readable id makes a
/// failure message legible. Derivation is `aip-crypto`'s to test.
pub struct Agent {
    pub agent_id: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub fn agent(id: &str) -> Agent {
    let kp = generate_ed25519_keypair();
    Agent {
        agent_id: id.to_string(),
        private_key: kp.private_key,
        public_key: kp.public_key,
    }
}

pub fn commit(params: &[u8]) -> [u8; 32] {
    parameter_commitment(params)
}

pub fn framework() -> FrameworkIdentity {
    FrameworkIdentity {
        name: "langgraph".into(),
        version: "0.2.0".into(),
        adapter_version: "vanian-airi-adapter/1".into(),
    }
}

pub fn binding(agent_id: &str, pid: u32) -> ExecutionBinding {
    ExecutionBinding {
        version: aip_types::EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: 4242,
            boot_id: [0x7; 16],
        },
        exe_content_sha256: [0x33; 32],
        exe_path: "/usr/bin/python3".into(),
        bound_at_ms: 1_000,
    }
}

/// An unsigned skeleton every builder starts from.
fn skeleton(exec: [u8; 16], decision: Option<[u8; 16]>, payload: AiriPayload) -> AiriEvent {
    AiriEvent {
        version: AIRI_EVENT_VERSION,
        agent_id: String::new(),
        execution_id: exec,
        parent_execution_id: None,
        decision_id: decision,
        sequence: 0,
        prev_event_hash: [0u8; 32],
        emitted_at_ms: 1_000,
        framework: framework(),
        runtime_binding: None,
        payload,
        signature: empty_signature(),
    }
}

pub fn empty_signature() -> Signature {
    Signature {
        algorithm: aip_types::AlgorithmId::Ed25519,
        signer_id: String::new(),
        timestamp: 0,
        nonce: [0u8; 16],
        payload_hash: [0u8; 32],
        signature_bytes: vec![],
    }
}

pub fn tool_payload(tool_id: &str, params: &[u8]) -> AiriPayload {
    AiriPayload::ToolInvocationRequested(ToolInvocation {
        tool_id: tool_id.to_string(),
        action_kind: "http.post".into(),
        parameter_commitment: commit(params),
        tool_call_id: Some(ToolCallId("call_1".into())),
        target: Some("payments.internal".into()),
    })
}

pub fn signed_tool_request(
    a: &Agent,
    exec: [u8; 16],
    decision: Option<[u8; 16]>,
    tool_id: &str,
    params: &[u8],
) -> AiriEvent {
    let ev = skeleton(exec, decision, tool_payload(tool_id, params));
    sign_airi_event(&a.private_key, &a.agent_id, ev).expect("sign")
}

pub fn model_payload(model_id: &str, digest: [u8; 32]) -> AiriPayload {
    AiriPayload::ModelInvocationRequested(ModelProvenance {
        model_id: model_id.to_string(),
        model_digest: Some(digest),
        runtime: "hosted-api".into(),
        runtime_version: Some("2026-09".into()),
        inference_request_id: Some(InferenceRequestId("req_1".into())),
        prompt_commitment: Some(commit(b"prompt")),
        output_commitment: Some(commit(b"output")),
        accelerator: None,
    })
}

pub fn signed_model_request(
    a: &Agent,
    exec: [u8; 16],
    decision: Option<[u8; 16]>,
    model_id: &str,
    digest: [u8; 32],
) -> AiriEvent {
    let ev = skeleton(exec, decision, model_payload(model_id, digest));
    sign_airi_event(&a.private_key, &a.agent_id, ev).expect("sign")
}

/// Re-sign an event after a field was changed, so a test can isolate a rule
/// from the signature check.
pub fn resign(a: &Agent, ev: AiriEvent) -> AiriEvent {
    let mut ev = ev;
    let preimage = ev.signing_preimage();
    ev.signature =
        aip_crypto::sign_ed25519(&a.private_key, &a.agent_id, &preimage).expect("resign");
    ev
}

/// Two events differing only in how one string is split across two adjacent
/// fields, for the injectivity test.
pub fn preimage_with_ids(a: &Agent, tool: &str, target: &str) -> Vec<u8> {
    let payload = AiriPayload::ToolInvocationRequested(ToolInvocation {
        tool_id: tool.to_string(),
        action_kind: target.to_string(),
        parameter_commitment: commit(b"{}"),
        tool_call_id: None,
        target: None,
    });
    let mut ev = skeleton(EXEC_A, Some(DECISION_A), payload);
    ev.agent_id = a.agent_id.clone();
    ev.signing_preimage()
}

/// Build a chain of `n` signed tool-request events for one execution.
pub fn signed_chain(a: &Agent, exec: [u8; 16], n: u64) -> Vec<AiriEvent> {
    let mut out: Vec<AiriEvent> = Vec::new();
    let mut prev = [0u8; 32];
    for i in 0..n {
        let mut ev = skeleton(exec, Some(DECISION_A), tool_payload("tool.http.post", b"{}"));
        ev.sequence = i;
        ev.prev_event_hash = prev;
        ev.emitted_at_ms = 1_000 + i;
        let ev = sign_airi_event(&a.private_key, &a.agent_id, ev).expect("sign");
        prev = ev.event_hash();
        out.push(ev);
    }
    out
}

// ─── Observer fixtures ───
//
// Genuine collector-signed batches, so the corroboration suite attacks real
// evidence rather than stubs. The collector key is generated per fixture and
// is never the agent's — that separation is the property under test.

use aip_observe::{
    AgentAttribution, AttestedBatch, CollectorSigner, CoverageWindow, KernelLifecycleEvent,
    KernelLifecycleKind, ObservationAvailability, ObservationBatch, ObservedExecution,
    ObservedEffect, ObservedProcess, ObserverAttestor, SocketEndpoint, SocketProtocol,
    SourceMechanism, OBSERVE_PROTOCOL_VERSION,
};

pub const PROBE_ID: &str = "probe-1";
pub const OBSERVER_ID: &str = "collector-1";
pub const RUN: [u8; 16] = [0x5A; 16];

/// The observer's view of a process instance. `exe_content_sha256` is the
/// measurement the observer took, which is what distinguishes it from the
/// agent's self-reported `exe_path`.
fn observed_process(b: &ExecutionBinding) -> ObservedProcess {
    ObservedProcess {
        process: b.process,
        exe_path: b.exe_path.clone(),
        exe_content_sha256: b.exe_content_sha256,
    }
}

pub struct Observer {
    pub signer: CollectorSigner,
}

impl Observer {
    pub fn new() -> Self {
        let kp = aip_crypto::generate_ed25519_keypair();
        Self {
            signer: CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap(),
        }
    }
}

pub fn covered(from: u64, to: u64) -> ObservationAvailability {
    ObservationAvailability::Covered {
        window: CoverageWindow {
            from_ms: from,
            to_ms: to,
        },
    }
}

fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketEndpoint {
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&[a, b, c, d]);
    SocketEndpoint { addr, is_v6: false, port }
}

pub fn raw_batch(
    id: u8,
    from: u64,
    to: u64,
    observations: Vec<ObservedExecution>,
    events: Vec<KernelLifecycleEvent>,
) -> ObservationBatch {
    ObservationBatch {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        batch_id: [id; 16],
        probe_run_id: RUN,
        probe_seq_first: 1,
        probe_seq_last: 1,
        dropped_events: Some(0),
        active_mechanisms: SourceMechanism::canonical_set(vec![
            SourceMechanism::PidFdAnchored,
            SourceMechanism::ProcNetTable,
            SourceMechanism::SockStateTracepoint,
        ]),
        claimed_from_ms: from,
        claimed_to_ms: to,
        observations,
        kernel_events: events,
        clock_anchor: None,
    }
}

/// A kernel-pushed socket transition bound to `binding`'s exact instance —
/// the strong corroboration path.
pub fn socket_event(b: &ExecutionBinding) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SockStateTracepoint,
        kind: KernelLifecycleKind::SocketState {
            protocol: SocketProtocol::Tcp,
            local: ep(127, 0, 0, 1, 0),
            remote: ep(10, 0, 0, 9, 443),
            old_state: 7,
            new_state: 2,
            sk: 0xDEAD,
            current_pid: b.process.pid,
        },
        cpu: 1,
        kernel_timestamp_ns: 1_000_000,
        probe_seq: 1,
        bound: Some(observed_process(b)),
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

/// A process-exec event for the same instance — used to show that an
/// observation of the *wrong class* does not corroborate a network claim.
pub fn exec_event(b: &ExecutionBinding) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessExec {
            pid: b.process.pid,
            old_pid: b.process.pid,
            filename: "/bin/sh".into(),
        },
        cpu: 1,
        kernel_timestamp_ns: 1_000_000,
        probe_seq: 1,
        bound: Some(observed_process(b)),
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

/// A bare "the process was alive" observation. Presence is a fact about the
/// observer's sampling, never about an act.
pub fn presence_observation(b: &ExecutionBinding) -> ObservedExecution {
    ObservedExecution {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        observed: observed_process(b),
        attribution: AgentAttribution::NotEstablished,
        effect: ObservedEffect::ProcessPresent,
        mechanism: SourceMechanism::PidFdAnchored,
        claimed_decision_id: None,
        host_wall_clock_ms: 1_000,
        probe_monotonic_ns: 1_000_000,
    }
}

/// Attest a batch under a fresh collector key.
pub fn attest(o: &mut Observer, batch: ObservationBatch, at_ms: u64) -> AttestedBatch {
    o.signer.attest_at(batch, at_ms).expect("attest")
}

// ─── Expectation fixture (for the composition tests) ───

use aip_authorize::{AuthorityRef, ExpectedExecution, EXPECTED_EXECUTION_VERSION};

/// A structurally valid, decision-point-signed expectation.
///
/// The composition tests do not anchor the decision point, so the reconciler
/// refuses the expectation and returns `CannotProve` — which is exactly the
/// baseline those tests need. What matters is that the value is well formed,
/// not that it is trusted.
pub fn sample_expectation(a: &Agent) -> ExpectedExecution {
    let dp = aip_crypto::generate_ed25519_keypair();
    let mut ee = ExpectedExecution {
        version: EXPECTED_EXECUTION_VERSION,
        decision_id: DECISION_A,
        decision_point_id: "dp-1".into(),
        agent_id: a.agent_id.clone(),
        authority: AuthorityRef {
            root_jti: [0x01; 16],
            chain_jtis: vec![],
        },
        action_kind: aip_types::ScopeAction::Custom("http.post".into()),
        parameter_digest: [0x44; 32],
        execution_binding: binding(&a.agent_id, 4321),
        issued_at: 0,
        valid_until: 10_000,
        decision_sig: empty_signature(),
    };
    let preimage = ee.signing_preimage();
    ee.decision_sig = aip_crypto::sign_ed25519(&dp.private_key, "dp-1", &preimage).expect("sign");
    ee
}
