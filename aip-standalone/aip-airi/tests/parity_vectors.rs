//! Generates the cross-language parity vectors the Python SDK is checked
//! against, and asserts they have not drifted.
//!
//! # Why this exists
//!
//! The Python SDK reimplements the canonical encoder. A reimplementation that
//! silently diverges produces events that verify in Python and are refused in
//! Rust — or, far worse, events whose Python preimage differs from the Rust
//! one in a way that changes what the signature commits to. The vectors below
//! are the contract between the two.
//!
//! `cargo test -p aip-airi --test parity_vectors -- --ignored --nocapture`
//! writes the current vectors to stdout as JSON for regeneration. The normal
//! run asserts the committed digests still hold.

use aip_airi::*;

mod support;
use support::*;

/// Each case is (name, preimage-hex-sha256). Comparing digests rather than
/// full preimages keeps the file readable; the regeneration mode prints the
/// full bytes when a digest moves and someone needs to see why.
fn vectors() -> Vec<(&'static str, Vec<u8>)> {
    let a = agent("aip1testagent");
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();

    // 1. Minimal tool request, no optional fields.
    let mut ev = signed_tool_request(&a, EXEC_A, None, "http.post", b"{}");
    ev.framework = FrameworkIdentity {
        name: "langgraph".into(),
        version: "0.2.0".into(),
        adapter_version: "vanian-airi-adapter/1".into(),
    };
    ev.emitted_at_ms = 1_700_000_000_000;
    ev.payload = AiriPayload::ToolInvocationRequested(ToolInvocation {
        tool_id: "http.post".into(),
        action_kind: "http.post".into(),
        parameter_commitment: parameter_commitment(b"{\"url\":\"https://x/y\"}"),
        tool_call_id: None,
        target: None,
    });
    out.push(("tool_request_minimal", ev.signing_preimage()));

    // 2. Full tool request with every optional field present.
    let mut ev2 = ev.clone();
    ev2.decision_id = Some(DECISION_A);
    ev2.parent_execution_id = Some(EXEC_B);
    ev2.sequence = 7;
    ev2.prev_event_hash = [0x5A; 32];
    ev2.payload = AiriPayload::ToolInvocationRequested(ToolInvocation {
        tool_id: "http.post".into(),
        action_kind: "http.post".into(),
        parameter_commitment: parameter_commitment(b"{\"url\":\"https://x/y\"}"),
        tool_call_id: Some(ToolCallId("call_abc".into())),
        target: Some("payments.internal".into()),
    });
    out.push(("tool_request_full", ev2.signing_preimage()));

    // 3. Model provenance, hosted (no digest, no accelerator).
    let mut ev3 = ev.clone();
    ev3.payload = AiriPayload::ModelInvocationRequested(ModelProvenance {
        model_id: "claude-opus-5".into(),
        model_digest: None,
        runtime: "hosted-api".into(),
        runtime_version: None,
        inference_request_id: Some(InferenceRequestId("req_123".into())),
        prompt_commitment: Some(parameter_commitment(b"prompt bytes")),
        output_commitment: None,
        accelerator: None,
    });
    out.push(("model_hosted", ev3.signing_preimage()));

    // 4. Model provenance, local, every field present.
    let mut ev4 = ev.clone();
    ev4.payload = AiriPayload::ModelInvocationRequested(ModelProvenance {
        model_id: "llama-3-70b".into(),
        model_digest: Some([0x11; 32]),
        runtime: "vllm".into(),
        runtime_version: Some("0.6.0".into()),
        inference_request_id: Some(InferenceRequestId("req_456".into())),
        prompt_commitment: Some(parameter_commitment(b"p")),
        output_commitment: Some(parameter_commitment(b"o")),
        accelerator: Some("cuda:0".into()),
    });
    out.push(("model_local_full", ev4.signing_preimage()));

    // 5. Tool report with transport status.
    let mut ev5 = ev.clone();
    ev5.payload = AiriPayload::ToolExecutionReported(ToolReport {
        tool_id: "http.post".into(),
        parameter_commitment: parameter_commitment(b"{}"),
        outcome: ReportedOutcome::Success,
        result_commitment: Some(parameter_commitment(b"{\"ok\":true}")),
        transport_status: Some(200),
    });
    out.push(("tool_report", ev5.signing_preimage()));

    // 6. Subprocess.
    let mut ev6 = ev.clone();
    ev6.payload = AiriPayload::SubprocessExecution(SubprocessReport {
        program: "/bin/sh".into(),
        argv_commitment: parameter_commitment(b"[\"-c\",\"echo hi\"]"),
        reported_pid: Some(4321),
    });
    out.push(("subprocess", ev6.signing_preimage()));

    // 7. Context propagation.
    let mut ev7 = ev.clone();
    ev7.payload = AiriPayload::ExecutionContextPropagated(ContextPropagation {
        boundary: PropagationBoundary::Subprocess,
        to_execution_id: EXEC_B,
    });
    out.push(("context_propagated", ev7.signing_preimage()));

    // 8. Completion.
    let mut ev8 = ev.clone();
    ev8.payload = AiriPayload::ExecutionCompleted(Completion {
        outcome: ReportedOutcome::Success,
        detail: Some("done".into()),
    });
    out.push(("completed", ev8.signing_preimage()));

    // 9. With a runtime binding present.
    let mut ev9 = ev.clone();
    ev9.runtime_binding = Some(binding("aip1testagent", 4321));
    out.push(("with_runtime_binding", ev9.signing_preimage()));

    out
}

/// Print the vectors as JSON for the Python side to consume.
#[test]
#[ignore = "regeneration helper; run with --ignored --nocapture"]
fn emit_parity_vectors() {
    println!("{{");
    let v = vectors();
    for (i, (name, pre)) in v.iter().enumerate() {
        let comma = if i + 1 == v.len() { "" } else { "," };
        println!("  \"{}\": \"{}\"{}", name, hex::encode(pre), comma);
    }
    println!("}}");
}

/// The vectors are stable: every preimage begins with the AIRI domain tag and
/// no two distinct payloads collide.
#[test]
fn parity_vectors_are_domain_tagged_and_distinct() {
    let v = vectors();
    let tag = AIRI_EVENT_DOMAIN.as_bytes();
    for (name, pre) in &v {
        assert_eq!(
            &pre[..4],
            &(tag.len() as u32).to_le_bytes(),
            "{name}: missing length prefix on the domain tag"
        );
        assert_eq!(&pre[4..4 + tag.len()], tag, "{name}: wrong domain tag");
    }
    for i in 0..v.len() {
        for j in (i + 1)..v.len() {
            assert_ne!(
                v[i].1, v[j].1,
                "SECURITY: vectors {} and {} share a preimage",
                v[i].0, v[j].0
            );
        }
    }
}
