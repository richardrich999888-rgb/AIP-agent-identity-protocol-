//! Integration tests for the offline verifier, run against fixtures the
//! REAL TypeScript console generated — so a pass here is cross-language
//! proof that the Rust verifier recomputes the browser's exact bytes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ot-verifier"))
        .args(args)
        .output()
        .expect("verifier binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn write_temp(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ot-verifier-test-{}-{name}", std::process::id()));
    std::fs::write(&path, contents).expect("temp fixture writes");
    path
}

#[test]
fn valid_dossier_passes_with_exit_0() {
    let output = run(&[
        "--dossier",
        fixture("valid-mission-dossier.json").to_str().unwrap(),
    ]);
    let text = stdout(&output);
    assert!(output.status.success(), "expected exit 0, got: {text}");
    assert!(text.contains("[PASS]"), "expected [PASS]: {text}");
}

#[test]
fn valid_dossier_verbose_traces_every_anchor_and_packet() {
    let output = run(&[
        "--dossier",
        fixture("valid-mission-dossier.json").to_str().unwrap(),
        "--verbose",
    ]);
    let text = stdout(&output);
    assert!(output.status.success());
    assert!(
        text.contains("[TRACE] anchor-chain #001 AGENT_GENESIS hash ok"),
        "{text}"
    );
    assert!(text.contains("[TRACE] packet-chain #001"), "{text}");
    assert!(text.contains("[TRACE] root-digest"), "{text}");
}

#[test]
fn strict_mode_fails_placeholder_model_digests() {
    // The fixture's modelDigest is the all-zero placeholder: honest about
    // attesting configuration rather than weights — and exactly what
    // --strict exists to refuse.
    let output = run(&[
        "--dossier",
        fixture("valid-mission-dossier.json").to_str().unwrap(),
        "--strict",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("placeholder"));
}

#[test]
fn json_output_is_machine_readable() {
    let output = run(&[
        "--dossier",
        fixture("valid-mission-dossier.json").to_str().unwrap(),
        "--json",
    ]);
    assert!(output.status.success());
    let doc: Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(doc["pass"], Value::Bool(true));
    assert!(doc["stats"]["anchors"].as_u64().unwrap() >= 3);
    assert!(doc["stats"]["packets"].as_u64().unwrap() >= 3);
}

#[test]
fn multisig_gated_tool_with_co_signature_passes() {
    let output = run(&[
        "--dossier",
        fixture("multisig-mission-dossier.json").to_str().unwrap(),
    ]);
    let text = stdout(&output);
    assert!(output.status.success(), "expected exit 0: {text}");
}

#[test]
fn stripping_the_co_signature_from_a_gated_tool_fails() {
    let text = std::fs::read_to_string(fixture("multisig-mission-dossier.json")).unwrap();
    let mut dossier: Value = serde_json::from_str(&text).unwrap();
    dossier["evidencePackets"][0]["toolExecuted"]
        .as_object_mut()
        .unwrap()
        .remove("supervisorCoSignature");
    let path = write_temp("no-cosig.json", &serde_json::to_string(&dossier).unwrap());
    let output = run(&["--dossier", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let out = stdout(&output);
    // The edit breaks both the packet hash and the multisig requirement.
    assert!(
        out.contains("multisig") || out.contains("packet-chain"),
        "{out}"
    );
}

#[test]
fn mutated_anchor_payload_at_sequence_2_fails_naming_the_sequence() {
    let text = std::fs::read_to_string(fixture("valid-mission-dossier.json")).unwrap();
    let mut dossier: Value = serde_json::from_str(&text).unwrap();
    dossier["lifecycleAnchors"][1]["payload"]["scope"] =
        serde_json::json!(["fly_to_location", "execute_maneuver"]);
    let path = write_temp(
        "tampered-anchor.json",
        &serde_json::to_string(&dossier).unwrap(),
    );
    let output = run(&["--dossier", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let out = stdout(&output);
    assert!(
        out.contains("anchorHash mismatch at sequence 2"),
        "expected the exact broken sequence named: {out}",
    );
    assert!(out.contains("root digest mismatch"), "{out}");
    assert!(out.contains("[FAIL]"), "{out}");
}

#[test]
fn post_revocation_execution_fails() {
    let output = run(&[
        "--dossier",
        fixture("post-revocation-execution.json").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let out = stdout(&output);
    assert!(
        out.contains("UNAUTHORIZED_POST_REVOCATION_EXECUTION"),
        "{out}"
    );
    assert!(out.contains("no ACTION_EXECUTION_SEAL"), "{out}");
}

#[test]
fn jsonl_forensic_stream_verifies_the_packet_chain() {
    let text = std::fs::read_to_string(fixture("valid-mission-dossier.json")).unwrap();
    let dossier: Value = serde_json::from_str(&text).unwrap();
    let stream: String = dossier["evidencePackets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| serde_json::to_string(p).unwrap() + "\n")
        .collect();
    let path = write_temp("stream.jsonl", &stream);
    let output = run(&["--dossier", path.to_str().unwrap()]);
    assert!(output.status.success(), "{}", stdout(&output));

    // Now corrupt the stream's second packet.
    let mut lines: Vec<Value> = stream
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    lines[1]["rawPrompt"] = Value::String("forged".into());
    let forged: String = lines
        .iter()
        .map(|p| serde_json::to_string(p).unwrap() + "\n")
        .collect();
    let path = write_temp("forged-stream.jsonl", &forged);
    let output = run(&["--dossier", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout(&output).contains("sequence 2"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn signed_attestations_verify_offline_and_reject_tampering() {
    use ot_pqc::{attest_json, CryptoSuite, SignatureKeyPair};

    let signer = SignatureKeyPair::generate(CryptoSuite::X25519MlKem1024MlDsa87).unwrap();
    let identity = signer.verifying_key().identity_hex();
    let envelope = attest_json(
        serde_json::json!({
            "agentDid": "did:syntriass:agent:AGT-1",
            "sequenceNumber": 4,
            "tailHash": "ab".repeat(32),
        }),
        &signer,
        b"ot-governance/ingest-receipt/v1",
    )
    .unwrap();
    let path = write_temp(
        "attestation.json",
        &serde_json::to_string(&envelope).unwrap(),
    );

    // Verifies, and pins to the right signer.
    let output = run(&[
        "--attestation",
        path.to_str().unwrap(),
        "--signer",
        &identity,
    ]);
    assert!(output.status.success(), "{}", stdout(&output));
    assert!(stdout(&output).contains("(pinned)"), "{}", stdout(&output));

    // The wrong pinned signer is refused.
    let output = run(&[
        "--attestation",
        path.to_str().unwrap(),
        "--signer",
        &"0".repeat(64),
    ]);
    assert_eq!(output.status.code(), Some(1));

    // A tampered payload no longer verifies.
    let mut forged = envelope.clone();
    forged["payload"]["sequenceNumber"] = serde_json::json!(5);
    let path = write_temp(
        "forged-attestation.json",
        &serde_json::to_string(&forged).unwrap(),
    );
    let output = run(&["--attestation", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("[FAIL]"), "{}", stdout(&output));

    // Machine-readable output parses.
    let path = write_temp(
        "attestation2.json",
        &serde_json::to_string(&envelope).unwrap(),
    );
    let output = run(&["--attestation", path.to_str().unwrap(), "--json"]);
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["pass"], Value::Bool(true));
    assert_eq!(doc["signerIdentity"].as_str().unwrap(), identity);
}
