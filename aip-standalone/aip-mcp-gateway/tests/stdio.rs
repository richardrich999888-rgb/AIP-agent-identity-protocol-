//! Exercise the real stdio executable and independently verify its receipts.
//! The upstream is the reference echo stub, not a live MCP tool server.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use aip_airi::{verify_tool_receipt, GatewayDisposition, GatewayTrustAnchors, SignedToolReceipt};
use aip_crypto::generate_ed25519_keypair;
use aip_mcp_gateway::{parameter_commitment, response_commitment};
use serde_json::{json, Value};

const GATEWAY: &str = "gateway.stdio.test";
const DECISION: [u8; 16] = [0xab; 16];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Gateway {
    directory: PathBuf,
    key: aip_types::KeyPair,
}

impl Gateway {
    fn new() -> Self {
        let key = generate_ed25519_keypair();
        // A fresh public key supplies a unique name; create_dir refuses reuse.
        let directory = std::env::temp_dir().join(format!("aip-stdio-{}", hex(&key.public_key)));
        std::fs::create_dir(&directory).unwrap();
        Self { directory, key }
    }

    fn receipts_path(&self) -> PathBuf {
        self.directory.join("receipts.jsonl")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aip-mcp-gateway"));
        command
            .env_clear()
            .env("AIP_GATEWAY_KEY", hex(&self.key.private_key))
            .env("AIP_GATEWAY_ID", GATEWAY)
            .env("AIP_GATEWAY_KEY_VERSION", "3")
            .env("AIP_GATEWAY_RECEIPTS", self.receipts_path());
        command
    }

    fn receipts(&self) -> Vec<SignedToolReceipt> {
        let anchors = GatewayTrustAnchors::new().trust(GATEWAY, 3, &self.key.public_key);
        std::fs::read_to_string(self.receipts_path())
            .unwrap()
            .lines()
            .map(|line| {
                let receipt = serde_json::from_str(line).unwrap();
                verify_tool_receipt(&receipt, &anchors, None).expect("verify gateway signature");
                receipt
            })
            .collect()
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn run(mut command: Command, input: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn responses(output: &Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "gateway exited: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn request(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "authorization": {"agent_id": "agent.test", "decision_id": hex(&DECISION)},
        "params": {
            "name": "banking.transfer", "tool_call_id": "call-1",
            "arguments": {"transfers": [{"amount": 5, "currency": "INR"}]}
        }
    })
}

fn lines(requests: &[Value]) -> String {
    requests
        .iter()
        .map(|request| format!("{request}\n"))
        .collect()
}

#[test]
fn a_successful_call_persists_a_verifiable_receipt_over_the_body() {
    let gateway = Gateway::new();
    let mut req = request(17);
    // Mixed-case hex is a valid decision id. A client-supplied digest must
    // never replace the gateway's own computation over the body.
    req["authorization"]["decision_id"] = hex(&DECISION).to_uppercase().into();
    req["authorization"]["parameter_commitment"] = "forged-client-digest".into();
    let output = run(gateway.command(), &format!("\n{}\n\n", req));
    let replies = responses(&output);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0]["jsonrpc"], "2.0");
    assert_eq!(replies[0]["id"], 17);
    assert!(replies[0].get("error").is_none());
    let receipts = gateway.receipts();
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0].receipt;
    assert_eq!(receipt.decision_id, DECISION);
    assert_eq!(receipt.agent_id, "agent.test");
    assert_eq!(receipt.tool_id, "banking.transfer");
    assert_eq!(receipt.tool_call_id.as_ref().unwrap().0, "call-1");
    assert_eq!(receipt.disposition, GatewayDisposition::Forwarded);
    assert_eq!(
        receipt.parameter_commitment,
        parameter_commitment(&req["params"]["arguments"])
    );
    assert_eq!(
        receipt.response_commitment,
        Some(response_commitment(
            &json!({"echo": req["params"]["arguments"]})
        ))
    );
    assert_eq!(
        replies[0]["result"]["aip_receipt"]["parameter_commitment"],
        hex(&receipt.parameter_commitment)
    );
}

#[test]
fn malformed_json_does_not_terminate_the_stream_or_create_a_receipt() {
    let gateway = Gateway::new();
    let output = run(gateway.command(), &format!("{{broken\n{}\n", request(2)));
    let replies = responses(&output);
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0]["error"]["code"], -32700);
    assert_eq!(replies[0]["id"], Value::Null);
    assert_eq!(replies[1]["id"], 2);
    assert!(replies[1].get("result").is_some());
    assert_eq!(gateway.receipts().len(), 1);
}

#[test]
fn both_header_mismatches_produce_signed_refusals_and_the_stream_recovers() {
    let gateway = Gateway::new();
    let mut method = request(1);
    method["headers"] = json!({"Mcp-Method": "tools/list"});
    let mut name = request(2);
    name["headers"] = json!({"Mcp-Name": "another.tool"});
    let output = run(gateway.command(), &lines(&[method, name, request(3)]));
    let replies = responses(&output);
    assert_eq!(replies.len(), 3);
    let receipts = gateway.receipts();
    assert_eq!(receipts.len(), 3);
    for index in 0..2 {
        assert_eq!(replies[index]["error"]["code"], -32600);
        assert!(replies[index].get("result").is_none());
        assert_eq!(
            receipts[index].receipt.disposition,
            GatewayDisposition::Refused
        );
        assert_eq!(receipts[index].receipt.response_commitment, None);
        assert_eq!(receipts[index].receipt.tool_id, "banking.transfer");
    }
    assert!(replies[2].get("result").is_some());
    assert_eq!(
        receipts[2].receipt.disposition,
        GatewayDisposition::Forwarded
    );
}

#[test]
fn malformed_decision_ids_are_errors_not_zero_id_receipts_or_panics() {
    let gateway = Gateway::new();
    // "aéx" has an even UTF-8 byte length but slicing at byte 2 panics.
    let invalid = [
        json!("aéx"),
        json!("0"),
        json!("gg".repeat(16)),
        json!("ab".repeat(15)),
        Value::Null,
        json!(42),
    ];
    let mut requests = Vec::new();
    for value in invalid {
        let mut req = request(1);
        req["authorization"]["decision_id"] = value;
        requests.push(req);
    }
    let mut missing = request(1);
    missing.as_object_mut().unwrap().remove("authorization");
    requests.push(missing);
    requests.push(request(99));
    let replies = responses(&run(gateway.command(), &lines(&requests)));
    assert_eq!(replies.len(), requests.len());
    for reply in &replies[..replies.len() - 1] {
        assert_eq!(reply["error"]["code"], -32602);
        assert!(reply.get("result").is_none());
    }
    assert_eq!(replies.last().unwrap()["id"], 99);
    assert!(replies.last().unwrap().get("result").is_some());
    assert_eq!(gateway.receipts().len(), 1);
}

#[test]
fn absent_or_invalid_agent_attribution_is_rejected() {
    let gateway = Gateway::new();
    let mut requests = Vec::new();
    for value in [Value::Null, json!(""), json!(42)] {
        let mut req = request(1);
        req["authorization"]["agent_id"] = value;
        requests.push(req);
    }
    let mut missing = request(1);
    missing["authorization"]
        .as_object_mut()
        .unwrap()
        .remove("agent_id");
    requests.push(missing);
    let replies = responses(&run(gateway.command(), &lines(&requests)));
    assert_eq!(replies.len(), requests.len());
    for reply in replies {
        assert_eq!(reply["error"]["code"], -32602);
        assert!(reply.get("result").is_none());
    }
    assert!(gateway.receipts().is_empty());
}

#[test]
fn missing_tool_name_is_rejected_without_a_receipt() {
    let gateway = Gateway::new();
    let mut req = request(1);
    req["params"].as_object_mut().unwrap().remove("name");
    let replies = responses(&run(gateway.command(), &lines(&[req])));
    assert_eq!(replies[0]["error"]["code"], -32602);
    assert!(gateway.receipts().is_empty());
}

#[test]
fn invalid_startup_keys_fail_without_creating_a_receipt_sink() {
    for key in ["01", "gg", "aéx"] {
        let gateway = Gateway::new();
        let mut command = gateway.command();
        command.env("AIP_GATEWAY_KEY", key);
        let output = run(command, "");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
        assert!(!gateway.receipts_path().exists());
    }
    let gateway = Gateway::new();
    let mut command = gateway.command();
    command.env_remove("AIP_GATEWAY_KEY");
    assert!(!run(command, "").status.success());
    assert!(!gateway.receipts_path().exists());
}

#[test]
fn an_unopenable_receipt_sink_fails_before_processing_requests() {
    let gateway = Gateway::new();
    let mut command = gateway.command();
    command.env("AIP_GATEWAY_RECEIPTS", &gateway.directory);
    let output = run(command, &lines(&[request(1)]));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn receipt_write_failure_returns_an_error_instead_of_success() {
    let gateway = Gateway::new();
    let mut command = gateway.command();
    command.env("AIP_GATEWAY_RECEIPTS", "/dev/full");
    let replies = responses(&run(command, &lines(&[request(1)])));
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0]["error"]["code"], -32603);
    assert!(replies[0].get("result").is_none());
}
