//! Signed authorization TEST FIXTURE for the live gateway harness.
//! This is not a runtime observer, institutional authority, or banking outcome.
//! The binding is structurally valid fixture data, never kernel evidence.

use std::io::Read;

use aip_authorize::{
    tool_invoke_action, tool_invoke_parameters, AuthorityRef, ExpectedExecution,
    EXPECTED_EXECUTION_VERSION,
};
use aip_crypto::{generate_ed25519_keypair, sign_ed25519};
use aip_mcp_gateway::parameter_commitment;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    agent_id: String,
    decision_id: String,
    tool_id: String,
    arguments: Value,
}

fn main() {
    let mut input = String::new();
    std::io::stdin()
        .take(524_289)
        .read_to_string(&mut input)
        .unwrap();
    assert!(input.len() <= 524_288, "fixture input too large");
    let request: Input = serde_json::from_str(&input).unwrap();
    assert!(request.decision_id.is_ascii() && request.decision_id.len() == 32);
    let mut decision_id = [0; 16];
    for (index, byte) in decision_id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&request.decision_id[index * 2..index * 2 + 2], 16).unwrap();
    }
    let key = generate_ed25519_keypair();
    let parameters =
        tool_invoke_parameters(&request.tool_id, parameter_commitment(&request.arguments)).unwrap();
    let mut expectation = ExpectedExecution {
        version: EXPECTED_EXECUTION_VERSION,
        decision_id,
        decision_point_id: "dp.contextforge.test-fixture".into(),
        agent_id: request.agent_id.clone(),
        authority: AuthorityRef {
            root_jti: [1; 16],
            chain_jtis: vec![],
        },
        action_kind: tool_invoke_action(),
        parameter_digest: parameters.digest(),
        execution_binding: aip_types::ExecutionBinding {
            version: aip_types::EXECUTION_BINDING_VERSION,
            agent_id: request.agent_id,
            process: aip_types::ProcessInstance {
                pid: std::process::id(),
                pid_start_time_ticks: 1,
                boot_id: [0x7; 16],
            },
            exe_content_sha256: aip_crypto::sha256(b"fixture-only-not-observed"),
            exe_path: "fixture-only-not-observed".into(),
            bound_at_ms: 0,
            container: None,
        },
        issued_at: 0,
        valid_until: u64::MAX,
        decision_sig: aip_types::Signature {
            algorithm: aip_types::AlgorithmId::Ed25519,
            signer_id: String::new(),
            timestamp: 0,
            nonce: [0; 16],
            payload_hash: [0; 32],
            signature_bytes: vec![],
        },
    };
    expectation.decision_sig = sign_ed25519(
        &key.private_key,
        &expectation.decision_point_id,
        &expectation.signing_preimage(),
    )
    .unwrap();
    println!(
        "{}",
        json!({"expectation":expectation, "decision_point_id":"dp.contextforge.test-fixture",
        "public_key": key.public_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "scope":"signed test authorization; fixture binding is not runtime evidence"})
    );
}
