//! Phase 2 exit gate: a mis-parameterised tool call is caught against the
//! gateway's receipt, and the finding does not rest on the agent's account.
//!
//! Every document here is genuinely signed. The decision point seals an
//! `ExpectedExecution` over the commitment of the *authorised* arguments; the
//! gateway issues a `ToolReceipt` over the commitment of the arguments it
//! *received*; `compare_tool_boundary` recomputes and compares. Nothing is
//! hand-mocked — the crate under test computes the same commitment the
//! decision point does, which is the whole point.

use aip_airi::{
    compare_tool_boundary, verify_tool_receipt, GatewayDisposition, GatewaySigner,
    GatewayTrustAnchors, ToolBoundary, ToolBoundaryDivergence,
};
use aip_authorize::{
    tool_invoke_action, tool_invoke_parameters, AuthorityRef, DecisionPointTrustAnchors,
    ExpectedExecution, EXPECTED_EXECUTION_VERSION,
};
use aip_crypto::generate_ed25519_keypair;
use aip_mcp_gateway::{parameter_commitment, ToolCall, MCP_TOOLS_CALL};
use serde_json::{json, Value};

const DECISION: [u8; 16] = [7u8; 16];
const AGENT: &str = "agent.langgraph.1";
const TOOL: &str = "banking.transfer";
const GATEWAY: &str = "gateway.pilot";

struct Keys {
    dp: aip_types::KeyPair,
    gw: aip_types::KeyPair,
    agent: aip_types::KeyPair,
}

fn keys() -> Keys {
    Keys {
        dp: generate_ed25519_keypair(),
        gw: generate_ed25519_keypair(),
        agent: generate_ed25519_keypair(),
    }
}

/// A decision-point-signed expectation authorising `authorised_args` for the
/// tool. `parameter_digest` is sealed exactly as the gateway computes it, via
/// the shared `tool_invoke_parameters` over the gateway's argument commitment.
fn expectation(
    k: &Keys,
    authorised_args: &Value,
) -> (ExpectedExecution, DecisionPointTrustAnchors) {
    let commitment = parameter_commitment(authorised_args);
    let params = tool_invoke_parameters(TOOL, commitment).expect("tool params");
    let mut ee = ExpectedExecution {
        version: EXPECTED_EXECUTION_VERSION,
        decision_id: DECISION,
        decision_point_id: "dp.pilot".into(),
        agent_id: AGENT.into(),
        authority: AuthorityRef {
            root_jti: [1u8; 16],
            chain_jtis: vec![],
        },
        action_kind: tool_invoke_action(),
        parameter_digest: params.digest(),
        execution_binding: binding(),
        issued_at: 0,
        valid_until: u64::MAX,
        decision_sig: empty_sig(),
    };
    ee.decision_sig =
        aip_crypto::sign_ed25519(&k.dp.private_key, "dp.pilot", &ee.signing_preimage())
            .expect("sign expectation");
    let anchors = DecisionPointTrustAnchors::new().trust("dp.pilot", &k.dp.public_key);
    (ee, anchors)
}

fn call(args: &Value) -> ToolCall {
    ToolCall {
        method: MCP_TOOLS_CALL.into(),
        tool_name: TOOL.into(),
        decision_id: DECISION,
        agent_id: AGENT.into(),
        tool_call_id: Some("call-1".into()),
        arguments: args.clone(),
    }
}

// ── The honest path ──────────────────────────────────────────────────────

#[test]
fn the_authorised_call_agrees() {
    let k = keys();
    let args = json!({"amount": 500, "beneficiary": "acct-9", "currency": "INR"});
    let (ee, dp_anchors) = expectation(&k, &args);

    let signer = GatewaySigner::new(GATEWAY, 1, &k.gw.private_key).unwrap();
    let signed = aip_mcp_gateway::issue_receipt(
        &signer,
        &call(&args),
        GatewayDisposition::Forwarded,
        None,
        1_000,
    )
    .unwrap();

    let gw_anchors = GatewayTrustAnchors::new().trust(GATEWAY, 1, &k.gw.public_key);
    let verified = verify_tool_receipt(&signed, &gw_anchors, Some(&k.agent.public_key)).unwrap();

    let boundary = compare_tool_boundary(&ee, &dp_anchors, Some(&verified), None);
    assert!(
        matches!(boundary, ToolBoundary::Agrees { .. }),
        "an honest call must agree: {boundary:?}"
    );
}

// ── The decisive case: mis-parameterised, caught without the agent ────────

#[test]
fn a_misparameterised_call_diverges_and_does_not_rest_on_the_agents_account() {
    let k = keys();
    let authorised = json!({"amount": 500, "beneficiary": "acct-9", "currency": "INR"});
    let (ee, dp_anchors) = expectation(&k, &authorised);

    // What actually reached the gateway: a different amount and beneficiary.
    let received = json!({"amount": 5_000_000, "beneficiary": "acct-mule", "currency": "INR"});
    let signer = GatewaySigner::new(GATEWAY, 1, &k.gw.private_key).unwrap();
    let signed = aip_mcp_gateway::issue_receipt(
        &signer,
        &call(&received),
        GatewayDisposition::Forwarded,
        None,
        1_000,
    )
    .unwrap();
    let gw_anchors = GatewayTrustAnchors::new().trust(GATEWAY, 1, &k.gw.public_key);
    let verified = verify_tool_receipt(&signed, &gw_anchors, Some(&k.agent.public_key)).unwrap();

    // claim = None: the agent's own account is not supplied, so the finding
    // rests only on the gateway receipt versus the decision.
    let boundary = compare_tool_boundary(&ee, &dp_anchors, Some(&verified), None);
    assert!(
        matches!(
            boundary,
            ToolBoundary::Diverges {
                divergence: ToolBoundaryDivergence::ReceiptDoesNotMatchAuthorization { .. }
            }
        ),
        "a mis-parameterised call must diverge with no agent claim in evidence: {boundary:?}"
    );
}

// ── The gateway key must not be the agent's ──────────────────────────────

#[test]
fn a_receipt_signed_under_the_agents_key_is_refused() {
    let k = keys();
    let args = json!({"amount": 500});
    // Sign the receipt with the AGENT's key, and anchor that key as the
    // gateway — the impostor case.
    let impostor = GatewaySigner::new(GATEWAY, 1, &k.agent.private_key).unwrap();
    let signed = aip_mcp_gateway::issue_receipt(
        &impostor,
        &call(&args),
        GatewayDisposition::Forwarded,
        None,
        1_000,
    )
    .unwrap();
    let anchors = GatewayTrustAnchors::new().trust(GATEWAY, 1, &k.agent.public_key);
    let err = verify_tool_receipt(&signed, &anchors, Some(&k.agent.public_key)).unwrap_err();
    assert!(
        format!("{err:?}").contains("GatewayKeyIsAgentKey"),
        "a gateway anchored under the agent key must be refused: {err:?}"
    );
}

// ── The header/body agreement (2026-07-28 spec) ──────────────────────────

#[test]
fn a_header_that_disagrees_with_the_body_is_rejected_before_signing() {
    let c = call(&json!({"amount": 500}));
    // Header claims a different tool than the body.
    let err =
        aip_mcp_gateway::check_header_body(MCP_TOOLS_CALL, "some.other.tool", &c).unwrap_err();
    assert!(
        matches!(
            err,
            aip_mcp_gateway::GatewayError::HeaderBodyMismatch { .. }
        ),
        "header/body disagreement must be rejected: {err:?}"
    );
    // And the honest header passes.
    assert!(aip_mcp_gateway::check_header_body(MCP_TOOLS_CALL, TOOL, &c).is_ok());
}

// ── Commitment stability across argument key order ───────────────────────

#[test]
fn key_order_does_not_turn_an_honest_call_into_a_divergence() {
    let k = keys();
    let authorised = json!({"amount": 500, "beneficiary": "acct-9"});
    let (ee, dp_anchors) = expectation(&k, &authorised);

    // Same arguments, different key order — a real client/SDK/gateway will not
    // agree on order, and this must not manufacture a divergence.
    let received = json!({"beneficiary": "acct-9", "amount": 500});
    let signer = GatewaySigner::new(GATEWAY, 1, &k.gw.private_key).unwrap();
    let signed = aip_mcp_gateway::issue_receipt(
        &signer,
        &call(&received),
        GatewayDisposition::Forwarded,
        None,
        1_000,
    )
    .unwrap();
    let gw_anchors = GatewayTrustAnchors::new().trust(GATEWAY, 1, &k.gw.public_key);
    let verified = verify_tool_receipt(&signed, &gw_anchors, Some(&k.agent.public_key)).unwrap();
    let boundary = compare_tool_boundary(&ee, &dp_anchors, Some(&verified), None);
    assert!(
        matches!(boundary, ToolBoundary::Agrees { .. }),
        "argument key order must not change the outcome: {boundary:?}"
    );
}

// ── helpers ──────────────────────────────────────────────────────────────

fn empty_sig() -> aip_types::Signature {
    aip_types::Signature {
        algorithm: aip_types::AlgorithmId::Ed25519,
        signer_id: String::new(),
        timestamp: 0,
        nonce: [0u8; 16],
        payload_hash: [0u8; 32],
        signature_bytes: vec![],
    }
}

fn binding() -> aip_types::ExecutionBinding {
    // A minimal, structurally valid binding. The tool-boundary comparison does
    // not read it; it exists because ExpectedExecution requires one.
    aip_types::ExecutionBinding {
        version: aip_types::EXECUTION_BINDING_VERSION,
        agent_id: AGENT.to_string(),
        process: aip_types::ProcessInstance {
            pid: 4321,
            pid_start_time_ticks: 4242,
            boot_id: [0x7; 16],
        },
        exe_content_sha256: [0x33; 32],
        exe_path: "/usr/bin/python3".into(),
        bound_at_ms: 1_000,
        container: None,
    }
}
