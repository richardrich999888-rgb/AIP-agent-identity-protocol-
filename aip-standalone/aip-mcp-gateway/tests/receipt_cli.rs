//! The real gateway signer has no upstream and never invents forwarding.
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use aip_airi::{verify_tool_receipt, GatewayDisposition, GatewayTrustAnchors, SignedToolReceipt};
use aip_crypto::generate_ed25519_keypair;
use serde_json::{json, Value};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Harness {
    directory: PathBuf,
    key: aip_types::KeyPair,
}

impl Harness {
    fn new() -> Self {
        let key = generate_ed25519_keypair();
        let directory = std::env::temp_dir().join(format!("aip-receipt-{}", hex(&key.public_key)));
        std::fs::create_dir(&directory).unwrap();
        let key_path = directory.join("gateway.key");
        std::fs::write(&key_path, hex(&key.private_key)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self { directory, key }
    }
    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aip-tool-receipt"));
        command
            .env_clear()
            .arg(mode)
            .env("AIP_GATEWAY_ID", "gateway.real")
            .env("AIP_GATEWAY_KEY_VERSION", "1")
            .env("AIP_GATEWAY_KEY_FILE", self.directory.join("gateway.key"))
            .env("AIP_GATEWAY_PUBLIC_KEY", hex(&self.key.public_key))
            .env(
                "AIP_GATEWAY_RECEIPTS",
                self.directory.join("receipts.jsonl"),
            );
        command
    }
    fn receipts(&self) -> Vec<SignedToolReceipt> {
        std::fs::read_to_string(self.directory.join("receipts.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn request() -> Value {
    json!({"method":"tools/call", "tool_name":"loan_read", "arguments":{"id":17},
        "agent_id":"agent.bank", "decision_id":"01".repeat(16),
        "tool_call_id":"request-1", "received_at_ms": 1200})
}
fn run(mut command: Command, input: &Value) -> Output {
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
        .write_all(input.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn check_does_not_emit_a_receipt_and_issue_requires_an_explicit_outcome() {
    let h = Harness::new();
    assert!(run(h.command("check"), &request()).status.success());
    assert!(h.receipts().is_empty());
    assert!(!run(h.command("issue"), &request()).status.success());
    assert!(h.receipts().is_empty());
}

#[test]
fn actual_dispositions_are_signed_and_verified_offline_without_the_private_key() {
    let h = Harness::new();
    for disposition in ["Forwarded", "Failed", "Refused"] {
        let mut req = request();
        req["disposition"] = disposition.into();
        req["response"] = json!({"isError": disposition == "Failed"});
        let output = run(h.command("issue"), &req);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let receipts = h.receipts();
    assert_eq!(receipts.len(), 3);
    assert_eq!(
        receipts[0].receipt.disposition,
        GatewayDisposition::Forwarded
    );
    assert_eq!(receipts[1].receipt.disposition, GatewayDisposition::Failed);
    assert_eq!(receipts[2].receipt.disposition, GatewayDisposition::Refused);
    let mut verify = h.command("verify");
    verify
        .env_remove("AIP_GATEWAY_KEY_FILE")
        .env_remove("AIP_GATEWAY_RECEIPTS");
    assert!(run(verify, &serde_json::to_value(&receipts[0]).unwrap())
        .status
        .success());
    let mut tampered = serde_json::to_value(&receipts[0]).unwrap();
    tampered["receipt"]["tool_id"] = "other-tool".into();
    assert!(!run(h.command("verify"), &tampered).status.success());
}

#[test]
fn incorrect_anchor_and_invalid_identity_fail_before_receipt_creation() {
    let h = Harness::new();
    let mut command = h.command("check");
    command.env("AIP_GATEWAY_PUBLIC_KEY", "00".repeat(32));
    assert!(!run(command, &request()).status.success());
    assert!(h.receipts().is_empty());
    for (field, value) in [
        ("decision_id", json!("aéx")),
        ("agent_id", json!("")),
        ("arguments", json!([])),
    ] {
        let mut req = request();
        req[field] = value;
        assert!(!run(h.command("check"), &req).status.success());
    }
    assert!(h.receipts().is_empty());
}

#[test]
fn header_disagreement_only_allows_a_refusal() {
    let h = Harness::new();
    let mut req = request();
    req["headers"] = json!({"mCp-NaMe":"wrong"});
    assert!(!run(h.command("check"), &req).status.success());
    req["disposition"] = "Forwarded".into();
    assert!(!run(h.command("issue"), &req).status.success());
    req["disposition"] = "Refused".into();
    assert!(run(h.command("issue"), &req).status.success());
    assert_eq!(
        h.receipts()[0].receipt.disposition,
        GatewayDisposition::Refused
    );
}

#[test]
fn concurrent_signers_append_complete_verifiable_records_and_restart_preserves_them() {
    let h = Harness::new();
    let commands: Vec<_> = (0..16).map(|_| h.command("issue")).collect();
    let handles: Vec<_> = commands
        .into_iter()
        .enumerate()
        .map(|(index, command)| {
            std::thread::spawn(move || {
                let mut req = request();
                req["disposition"] = "Forwarded".into();
                req["tool_call_id"] = format!("call-{index}").into();
                run(command, &req).status.success()
            })
        })
        .collect();
    assert!(handles.into_iter().all(|handle| handle.join().unwrap()));
    assert_eq!(h.receipts().len(), 16);
    let anchors = GatewayTrustAnchors::new().trust("gateway.real", 1, &h.key.public_key);
    for receipt in h.receipts() {
        verify_tool_receipt(&receipt, &anchors, None).unwrap();
    }
    assert!(run(h.command("check"), &request()).status.success());
    assert_eq!(h.receipts().len(), 16);
}

#[test]
fn a_directory_cannot_be_used_as_a_receipt_sink() {
    let h = Harness::new();
    let mut command = h.command("check");
    command.env("AIP_GATEWAY_RECEIPTS", &h.directory);
    assert!(!run(command, &request()).status.success());
}
