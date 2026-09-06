//! Gate 1 — cryptographic binding.
//!
//! The question this file answers: can a statement the agent's runtime made
//! about one execution be made to verify as a statement about a different
//! agent, a different execution, a different model, a different tool, or a
//! different parameter set?
//!
//! Every test here is a substitution. The event is genuine and its signature
//! is genuine; only the binding is wrong. A verifier that accepts any of
//! these lets an attacker relabel true statements, which is cheaper and
//! quieter than forging false ones.

use aip_airi::*;

mod support;
use support::*;

// ─── The event verifies at all ───

#[test]
fn a_well_formed_event_verifies_against_the_signing_agent() {
    let a = agent("agent-1");
    let ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{\"url\":\"x\"}");
    assert!(verify_airi_event(&ev, &a.public_key).is_ok());
}

#[test]
fn the_signature_covers_every_field_the_verifier_later_reads() {
    let a = agent("agent-1");
    let base = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");

    // Each mutation touches exactly one field and leaves the signature alone.
    /// One named single-field mutation of an otherwise valid event.
    type Mutation = (&'static str, Box<dyn Fn(&mut AiriEvent)>);

    let mutations: Vec<Mutation> = vec![
        ("agent_id", Box::new(|e: &mut AiriEvent| e.agent_id = "agent-2".into())),
        ("execution_id", Box::new(|e: &mut AiriEvent| e.execution_id = EXEC_B)),
        ("parent_execution_id", Box::new(|e: &mut AiriEvent| e.parent_execution_id = Some(EXEC_B))),
        ("decision_id", Box::new(|e: &mut AiriEvent| e.decision_id = Some(DECISION_B))),
        ("sequence", Box::new(|e: &mut AiriEvent| e.sequence = 99)),
        ("emitted_at_ms", Box::new(|e: &mut AiriEvent| e.emitted_at_ms += 1)),
        ("prev_event_hash", Box::new(|e: &mut AiriEvent| e.prev_event_hash = [9u8; 32])),
        ("version", Box::new(|e: &mut AiriEvent| e.version = 7)),
    ];

    for (field, mutate) in mutations {
        let mut ev = base.clone();
        mutate(&mut ev);
        assert!(
            verify_airi_event(&ev, &a.public_key).is_err(),
            "SECURITY: `{field}` was changed without re-signing and the event still verified"
        );
    }
}

// ─── Cross-agent transplantation ───

#[test]
fn an_event_does_not_verify_under_another_agents_key() {
    let a = agent("agent-1");
    let b = agent("agent-2");
    let ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    assert!(
        verify_airi_event(&ev, &b.public_key).is_err(),
        "SECURITY: agent-1's event verified under agent-2's key"
    );
}

#[test]
fn relabelling_an_event_to_another_agent_fails_even_with_that_agents_key() {
    // The attacker holds agent-2's key and wants agent-1's genuine event to
    // count as agent-2's work. Rewriting agent_id breaks the signature;
    // re-signing under agent-2 produces a *different* event, which is the
    // point — it can no longer claim agent-1 did anything.
    let a = agent("agent-1");
    let b = agent("agent-2");
    let mut ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    ev.agent_id = "agent-2".into();
    assert!(verify_airi_event(&ev, &b.public_key).is_err());
    assert!(verify_airi_event(&ev, &a.public_key).is_err());
}

// ─── Cross-execution transplantation ───

#[test]
fn an_event_cannot_be_moved_to_another_execution() {
    let a = agent("agent-1");
    let mut ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    ev.execution_id = EXEC_B;
    assert!(
        verify_airi_event(&ev, &a.public_key).is_err(),
        "SECURITY: an event was transplanted onto another execution"
    );
}

#[test]
fn an_event_cannot_be_moved_to_another_expected_execution() {
    let a = agent("agent-1");
    let mut ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    ev.decision_id = Some(DECISION_B);
    assert!(
        verify_airi_event(&ev, &a.public_key).is_err(),
        "SECURITY: an event was reattached to another ExpectedExecution"
    );
}

// ─── Parameter substitution ───

#[test]
fn parameter_substitution_is_detected() {
    let a = agent("agent-1");
    let authorized = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post",
        br#"{"url":"https://payments.internal/refund","amount":5}"#);
    let mut swapped = authorized.clone();
    // Same tool, same execution, same agent — different money.
    swapped.payload = AiriPayload::ToolInvocationRequested(ToolInvocation {
        parameter_commitment: commit(br#"{"url":"https://payments.internal/refund","amount":500000}"#),
        ..match &authorized.payload {
            AiriPayload::ToolInvocationRequested(t) => t.clone(),
            _ => unreachable!(),
        }
    });
    assert!(
        verify_airi_event(&swapped, &a.public_key).is_err(),
        "SECURITY: the parameter commitment was swapped and the event still verified"
    );
}

#[test]
fn the_parameter_commitment_is_domain_separated_from_a_bare_hash() {
    // A commitment must not equal SHA-256 of the parameters, or a hash taken
    // anywhere else in the system could be replayed as a parameter commitment.
    let params = br#"{"amount":5}"#;
    assert_ne!(
        commit(params).to_vec(),
        aip_crypto::sha256(params).to_vec(),
        "SECURITY: parameter commitment is a bare SHA-256 and is replayable across domains"
    );
}

// ─── Model substitution ───

#[test]
fn model_substitution_is_detected() {
    let a = agent("agent-1");
    let ev = signed_model_request(&a, EXEC_A, Some(DECISION_A), "claude-opus-5", [0x11; 32]);
    let mut swapped = ev.clone();
    swapped.payload = match &ev.payload {
        AiriPayload::ModelInvocationRequested(m) => {
            AiriPayload::ModelInvocationRequested(ModelProvenance {
                model_id: "some-cheaper-model".into(),
                ..m.clone()
            })
        }
        _ => unreachable!(),
    };
    assert!(
        verify_airi_event(&swapped, &a.public_key).is_err(),
        "SECURITY: the model identifier was swapped and the event still verified"
    );
}

#[test]
fn model_digest_substitution_is_detected() {
    let a = agent("agent-1");
    let ev = signed_model_request(&a, EXEC_A, Some(DECISION_A), "claude-opus-5", [0x11; 32]);
    let mut swapped = ev.clone();
    swapped.payload = match &ev.payload {
        AiriPayload::ModelInvocationRequested(m) => {
            AiriPayload::ModelInvocationRequested(ModelProvenance {
                model_digest: Some([0x22; 32]),
                ..m.clone()
            })
        }
        _ => unreachable!(),
    };
    assert!(verify_airi_event(&swapped, &a.public_key).is_err());
}

// ─── Cross-kind / cross-framework transplantation ───

#[test]
fn an_event_of_one_kind_cannot_be_presented_as_another() {
    let a = agent("agent-1");
    let ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    let mut swapped = ev.clone();
    swapped.payload = AiriPayload::ExecutionCompleted(Completion {
        outcome: ReportedOutcome::Success,
        detail: None,
    });
    assert!(
        verify_airi_event(&swapped, &a.public_key).is_err(),
        "SECURITY: a tool request was re-presented as a completion"
    );
}

#[test]
fn framework_identity_substitution_is_detected() {
    let a = agent("agent-1");
    let ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    let mut swapped = ev.clone();
    let adapter_version = swapped.framework.adapter_version.clone();
    swapped.framework = FrameworkIdentity {
        name: "some-other-framework".into(),
        version: "9.9.9".into(),
        adapter_version,
    };
    assert!(
        verify_airi_event(&swapped, &a.public_key).is_err(),
        "SECURITY: framework identity was rewritten and the event still verified"
    );
}

// ─── Domain separation against the rest of the system ───

#[test]
fn an_airi_preimage_is_not_a_valid_preimage_in_any_other_aip_domain() {
    let a = agent("agent-1");
    let ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    let pre = ev.signing_preimage();

    // The preimage must lead with AIRI's own length-prefixed domain tag.
    let tag = AIRI_EVENT_DOMAIN.as_bytes();
    assert_eq!(&pre[..4], &(tag.len() as u32).to_le_bytes());
    assert_eq!(&pre[4..4 + tag.len()], tag);

    // And that tag must not collide with any domain already in the system.
    for other in [
        "AIP/ScopedToken/v1",
        "AIP/DelegationToken/v1",
        "AIP/AgentIdentityDocument/v1",
        "SYNTRIASS/GHOST/OBSERVER_HEAD/v1",
        "SYNTRIASS/GHOST/OBSERVATION_BATCH/v1",
        "SYNTRIASS/GHOST/RECONCILIATION/v1",
        "SYNTRIASS/GHOST/WARRANT/v1",
        "SYNTRIASS/NEXORA/LEAF/v1",
    ] {
        assert_ne!(AIRI_EVENT_DOMAIN, other, "AIRI reuses an existing signing domain");
    }
}

#[test]
fn the_preimage_is_injective_across_adjacent_string_fields() {
    // Classic concatenation collision: ("ab","c") vs ("a","bc"). If the
    // encoder is not prefix-free these produce identical bytes and one
    // signature covers both.
    let a = agent("x");
    let p1 = preimage_with_ids(&a, "ab", "c");
    let p2 = preimage_with_ids(&a, "a", "bc");
    assert_ne!(p1, p2, "SECURITY: AIRI preimage is not injective across adjacent strings");
}

#[test]
fn optional_fields_distinguish_absent_from_present() {
    let a = agent("agent-1");
    let none = signed_tool_request(&a, EXEC_A, None, "t", b"{}");
    let some = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "t", b"{}");
    assert_ne!(
        none.signing_preimage(),
        some.signing_preimage(),
        "SECURITY: a missing decision_id and a present one share a preimage"
    );
}

// ─── Malformed input fails closed ───

#[test]
fn a_malformed_public_key_is_an_error_not_a_pass() {
    let a = agent("agent-1");
    let ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "t", b"{}");
    for bad in [vec![], vec![0u8; 31], vec![0u8; 33], vec![0u8; 32]] {
        assert!(
            verify_airi_event(&ev, &bad).is_err(),
            "SECURITY: verification passed against a malformed key"
        );
    }
}

#[test]
fn an_unsupported_version_is_refused() {
    let a = agent("agent-1");
    let mut ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "t", b"{}");
    ev.version = AIRI_EVENT_VERSION + 1;
    // Re-sign so the failure is about the version rule, not the signature.
    let ev = resign(&a, ev);
    assert!(
        matches!(verify_airi_event(&ev, &a.public_key), Err(AiriError::UnsupportedVersion(_))),
        "an event of an unknown version must be refused, not interpreted"
    );
}
