use aip_airi::{verify_airi_event, AiriEvent, AiriPayload};
use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdk/python/tests/python_events.json")
}

#[test]
fn rust_production_verifier_accepts_complete_python_events() {
    let raw = std::fs::read_to_string(fixture_path()).expect("run Python fixture test first");
    let root: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let agent_id = root["agent_id"].as_str().unwrap();
    let public_key = hex::decode(root["public_key"].as_str().unwrap()).unwrap();
    assert_eq!(public_key.len(), 32);
    let values = root["events"].as_array().unwrap();
    assert!(!values.is_empty());
    let mut events = Vec::new();
    for (i, value) in values.iter().enumerate() {
        let event: AiriEvent = serde_json::from_value(value.clone())
            .unwrap_or_else(|e| panic!("event {i} deserialization: {e}"));
        assert_eq!(event.agent_id, agent_id);
        assert_eq!(event.sequence, i as u64);
        assert_eq!(event.signature.signer_id, agent_id);
        assert_eq!(
            event.signature.payload_hash,
            aip_crypto::sha256(&event.signing_preimage())
        );
        verify_airi_event(&event, &public_key)
            .unwrap_or_else(|e| panic!("event {i} production verification: {e}"));
        events.push(event);
    }
    for pair in events.windows(2) {
        assert_eq!(pair[1].sequence, pair[0].sequence + 1);
        assert_eq!(pair[1].prev_event_hash, pair[0].event_hash());
    }

    let mut altered = events[0].clone();
    if let AiriPayload::AgentExecutionStarted(ref mut body) = altered.payload {
        body.agent_role = Some("tampered".into());
    } else {
        panic!("fixture event zero should be AgentExecutionStarted");
    }
    assert!(
        verify_airi_event(&altered, &public_key).is_err(),
        "tampered payload must fail"
    );
    let mut altered_signature = events[0].clone();
    altered_signature.signature.nonce[0] ^= 1;
    assert!(
        verify_airi_event(&altered_signature, &public_key).is_err(),
        "tampered envelope must fail"
    );
    assert!(
        events
            .windows(2)
            .all(|p| p[1].prev_event_hash == p[0].event_hash()),
        "original chain remains valid"
    );
}
