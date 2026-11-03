//! Real-signature fixtures exercise the public-key-only CLI and native encoder.
use std::io::Write;
use std::process::{Command, Stdio};

use aip_airi::{GatewayDisposition, GatewaySigner, SignedToolReceipt};
use aip_crypto::generate_ed25519_keypair;
use aip_mcp_gateway::{issue_receipt, ToolCall};
use serde_json::{json, Value};

fn fixture(disposition: GatewayDisposition) -> (SignedToolReceipt, Value, Vec<u8>) {
    let key = generate_ed25519_keypair();
    let signer = GatewaySigner::new("gateway", 1, &key.private_key).unwrap();
    let call = ToolCall {
        method: "tools/call".into(),
        tool_name: "read".into(),
        agent_id: "agent".into(),
        decision_id: [7; 16],
        tool_call_id: Some("request-one".into()),
        arguments: json!({"loan_id": 17, "amount": 0}),
    };
    let receipt = issue_receipt(&signer, &call, disposition, None, 100).unwrap();
    let request = json!({"method": call.method, "tool_name": call.tool_name,
        "agent_id": call.agent_id, "decision_id": "07".repeat(16),
        "tool_call_id": call.tool_call_id, "arguments": call.arguments});
    (receipt, request, key.public_key)
}

fn run(signed: &SignedToolReceipt, request: Value, public_key: &[u8]) -> Result<Value, ()> {
    let public_key: String = public_key.iter().map(|b| format!("{b:02x}")).collect();
    let mut child = Command::new(env!("CARGO_BIN_EXE_aip-tool-receipt"))
        .arg("compare-request")
        .env_clear()
        .env("AIP_GATEWAY_ID", "gateway")
        .env("AIP_GATEWAY_KEY_VERSION", "1")
        .env("AIP_GATEWAY_PUBLIC_KEY", public_key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            &serde_json::to_vec(&json!({"signed_receipt": signed, "request": request})).unwrap(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    if output.status.success() {
        Ok(serde_json::from_slice(&output.stdout).unwrap())
    } else {
        assert!(output.stdout.is_empty());
        Err(())
    }
}

#[test]
fn public_key_only_comparison_preserves_uncertainty() {
    let (signed, request, key) = fixture(GatewayDisposition::Forwarded);
    let result = run(&signed, request, &key).unwrap();
    assert_eq!(result["request_comparison"]["agreement"], "Matches");
    assert_eq!(result["receipt_signature"], "VERIFIED");
    assert_eq!(result["authorization"], "NOT_ASSESSED");
    assert_eq!(result["kernel_execution"], "CANNOT_PROVE");
}

#[test]
fn changed_arguments_are_not_a_match() {
    let (signed, mut request, key) = fixture(GatewayDisposition::Forwarded);
    request["arguments"]["amount"] = json!(1);
    let result = run(&signed, request, &key).unwrap();
    assert_eq!(result["request_comparison"]["agreement"], "Differs");
    assert_eq!(
        result["request_comparison"]["differences"],
        json!(["Arguments"])
    );
}

#[test]
fn each_context_identifier_is_bound() {
    let (signed, request, key) = fixture(GatewayDisposition::Forwarded);
    for (field, value, difference) in [
        ("agent_id", "other", "AgentId"),
        ("tool_name", "other", "ToolId"),
        ("tool_call_id", "replayed-for-another-request", "ToolCallId"),
        (
            "decision_id",
            "08080808080808080808080808080808",
            "DecisionId",
        ),
    ] {
        let mut altered = request.clone();
        altered[field] = json!(value);
        let result = run(&signed, altered, &key).unwrap();
        assert_eq!(
            result["request_comparison"]["differences"],
            json!([difference])
        );
    }
}

#[test]
fn missing_identifiers_and_wrong_method_are_refused() {
    let (signed, request, key) = fixture(GatewayDisposition::Forwarded);
    for (field, value) in [
        ("tool_call_id", ""),
        ("agent_id", ""),
        ("tool_name", ""),
        ("method", "tools/list"),
    ] {
        let mut altered = request.clone();
        altered[field] = json!(value);
        assert!(run(&signed, altered, &key).is_err());
    }
    let mut altered = request;
    altered.as_object_mut().unwrap().remove("tool_call_id");
    assert!(run(&signed, altered, &key).is_err());
}

#[test]
fn forged_receipt_and_wrong_anchor_are_refused() {
    let (mut signed, request, key) = fixture(GatewayDisposition::Forwarded);
    assert!(run(
        &signed,
        request.clone(),
        &generate_ed25519_keypair().public_key
    )
    .is_err());
    signed.receipt.parameter_commitment[0] ^= 1;
    assert!(run(&signed, request, &key).is_err());
}

#[test]
fn refused_and_failed_dispositions_are_never_upgraded() {
    for disposition in [GatewayDisposition::Refused, GatewayDisposition::Failed] {
        let (signed, request, key) = fixture(disposition);
        let result = run(&signed, request, &key).unwrap();
        assert_eq!(result["request_comparison"]["agreement"], "Matches");
        assert_eq!(
            result["request_comparison"]["gateway_disposition"],
            json!(disposition)
        );
        assert_eq!(result["kernel_execution"], "CANNOT_PROVE");
    }
}

#[test]
fn scalar_arguments_and_unexpected_authority_fields_are_refused() {
    let (signed, request, key) = fixture(GatewayDisposition::Forwarded);
    let mut altered = request.clone();
    altered["arguments"] = json!(true);
    assert!(run(&signed, altered, &key).is_err());
    let mut altered = request;
    altered["allow"] = json!(true);
    assert!(run(&signed, altered, &key).is_err());
}

#[test]
fn native_json_semantics_preserve_number_type() {
    let (signed, mut request, key) = fixture(GatewayDisposition::Forwarded);
    request["arguments"]["amount"] = json!(0.0);
    let result = run(&signed, request, &key).unwrap();
    assert_eq!(
        result["request_comparison"]["differences"],
        json!(["Arguments"])
    );
}
