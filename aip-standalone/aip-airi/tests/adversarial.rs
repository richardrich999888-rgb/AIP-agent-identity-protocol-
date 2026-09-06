//! Gate 3 — the adversarial matrix.
//!
//! Every test below asks the two questions Skill 15 demands be kept apart:
//!
//! > What does the actor **claim**?
//! > What can Vanian actually **establish**?
//!
//! The test name states the claim; the assertion states what may be
//! established. Where those differ, the difference is the finding.

use aip_airi::*;
use aip_observe::ObservationAvailability;

mod support;
use support::*;

/// Build the standard corroboration inputs around one event.
fn inputs<'a>(
    event: &'a AiriEvent,
    batches: &'a [&'a aip_observe::AttestedBatch],
    availability: &'a ObservationAvailability,
) -> CorroborationInputs<'a> {
    CorroborationInputs {
        event,
        batches,
        availability,
        expectation: None,
        window_tolerance_ms: 1_000,
    }
}

/// A signed tool-request event bound to `pid`, claiming an HTTP POST.
fn bound_tool_claim(a: &Agent, pid: u32) -> (AiriEvent, aip_types::ExecutionBinding) {
    let b = binding(&a.agent_id, pid);
    let mut ev = signed_tool_request(a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    ev.runtime_binding = Some(b.clone());
    (resign(a, ev), b)
}

// ═══ 1. The claim is corroborated ═══

#[test]
fn claim_corroborated_when_the_observer_saw_a_matching_kernel_event() {
    // CLAIM:       "I made an HTTP POST."
    // ESTABLISHED: the collector, off-host, recorded a kernel socket
    //              transition bound to that exact process instance.
    let a = agent("agent-1");
    let (ev, b) = bound_tool_claim(&a, 4321);
    let mut o = Observer::new();
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![socket_event(&b)]),
        10_000,
    );

    let avail = covered(0, 10_000);
    let c = corroborate(&inputs(&ev, &[&batch], &avail));
    assert!(c.is_corroborated(), "expected corroboration, got {c:?}");
}

#[test]
fn corroboration_never_yields_a_verdict_or_a_strength() {
    // The load-bearing negative. `Corroboration` has no field of type
    // `ReconciliationResult` or `EvidenceStrength`, so corroborating cannot
    // move a verdict. This test pins the *shape*; the compiler pins the rest.
    let a = agent("agent-1");
    let (ev, b) = bound_tool_claim(&a, 4321);
    let mut o = Observer::new();
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![socket_event(&b)]),
        10_000,
    );
    let avail = covered(0, 10_000);

    match corroborate(&inputs(&ev, &[&batch], &avail)) {
        Corroboration::Corroborated(seal) => {
            // The seal carries provenance — which batches, which window — and
            // nothing that resembles a conclusion.
            assert!(!seal.batch_sequences.is_empty());
        }
        other => panic!("expected Corroborated, got {other:?}"),
    }
}

// ═══ 2. Framework claims a tool call, observer sees nothing ═══

#[test]
fn framework_claims_a_tool_call_but_the_observer_saw_nothing() {
    // CLAIM:       "I called the payments API."
    // ESTABLISHED: the observer watched that instance throughout the window
    //              and recorded no network activity at all. This is the
    //              phantom-claim shape at the AI-stack level, and it is the
    //              whole reason AIRI exists.
    let a = agent("agent-1");
    let (ev, b) = bound_tool_claim(&a, 4321);
    let mut o = Observer::new();
    // The instance is observed alive, but nothing network-shaped happened.
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![presence_observation(&b)], vec![]),
        10_000,
    );
    let avail = covered(0, 10_000);

    let c = corroborate(&inputs(&ev, &[&batch], &avail));
    assert!(
        c.is_uncorroborated(),
        "a covered claim with no matching observation must be Uncorroborated, got {c:?}"
    );
    assert!(!c.is_corroborated());
}

#[test]
fn an_observation_of_the_wrong_class_does_not_corroborate() {
    // CLAIM:       "I made an HTTP POST."
    // OBSERVED:    that instance exec'd a binary. Real, kernel-pushed, and
    //              about something else entirely.
    let a = agent("agent-1");
    let (ev, b) = bound_tool_claim(&a, 4321);
    let mut o = Observer::new();
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![exec_event(&b)]),
        10_000,
    );
    let avail = covered(0, 10_000);

    let c = corroborate(&inputs(&ev, &[&batch], &avail));
    assert!(
        c.is_uncorroborated(),
        "an exec event must not corroborate a network claim, got {c:?}"
    );
}

#[test]
fn process_presence_alone_never_corroborates_an_act() {
    // Presence is a fact about the observer's sampling. Treating "the process
    // was alive" as evidence that it did the thing it claimed would make
    // every claim self-corroborating.
    let a = agent("agent-1");
    let (ev, b) = bound_tool_claim(&a, 4321);
    let mut o = Observer::new();
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![presence_observation(&b)], vec![]),
        10_000,
    );
    let avail = covered(0, 10_000);
    assert!(!corroborate(&inputs(&ev, &[&batch], &avail)).is_corroborated());
}

// ═══ 3. Instance substitution ═══

#[test]
fn an_observation_of_a_different_instance_does_not_corroborate() {
    // CLAIM:       agent claims to be pid 4321.
    // OBSERVED:    a socket transition by pid 9999.
    // A verifier that joined on "some socket happened in the window" would
    // accept this. Joining on the process *instance* is what stops it.
    let a = agent("agent-1");
    let (ev, _) = bound_tool_claim(&a, 4321);
    let other = binding(&a.agent_id, 9999);
    let mut o = Observer::new();
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![socket_event(&other)]),
        10_000,
    );
    let avail = covered(0, 10_000);

    let c = corroborate(&inputs(&ev, &[&batch], &avail));
    assert!(
        !c.is_corroborated(),
        "cross-instance corroboration accepted: {c:?}"
    );
    assert!(matches!(
        c,
        Corroboration::Uncorroborated {
            reason: UncorroboratedReason::InstanceNotObserved,
            ..
        }
    ));
}

#[test]
fn a_kernel_event_the_probe_could_not_bind_does_not_corroborate() {
    // An unbound kernel event names a pid. A pid is not an instance: it is
    // reused, and the whole ExecutionBinding design exists because of that.
    let a = agent("agent-1");
    let (ev, b) = bound_tool_claim(&a, 4321);
    let mut unbound = socket_event(&b);
    unbound.bound = None;
    let mut o = Observer::new();
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![unbound]),
        10_000,
    );
    let avail = covered(0, 10_000);

    assert!(
        !corroborate(&inputs(&ev, &[&batch], &avail)).is_corroborated(),
        "SECURITY: an unbound kernel event corroborated an instance claim"
    );
}

// ═══ 4. Observer unavailable / not covering ═══

#[test]
fn observer_unavailable_is_not_evaluated_and_is_not_a_finding() {
    // CLAIM:       "I called the API."
    // ESTABLISHED: nothing. The observer was down. Absence of evidence must
    //              not read as evidence of absence — reporting Uncorroborated
    //              here would manufacture accusations every time a sensor
    //              restarted, which is how detection systems get switched off.
    let a = agent("agent-1");
    let (ev, _) = bound_tool_claim(&a, 4321);
    let unavailable = aip_observe::no_observer();
    let c = corroborate(&inputs(&ev, &[], &unavailable));
    assert!(
        matches!(c, Corroboration::NotEvaluated(_)),
        "an unavailable observer must yield NotEvaluated, got {c:?}"
    );
    assert!(
        !c.is_uncorroborated(),
        "sensor downtime must not become an accusation"
    );
}

#[test]
fn no_observer_evidence_is_not_evaluated() {
    let a = agent("agent-1");
    let (ev, _) = bound_tool_claim(&a, 4321);
    let avail = covered(0, 10_000);
    let c = corroborate(&inputs(&ev, &[], &avail));
    assert!(matches!(c, Corroboration::NotEvaluated(_)), "got {c:?}");
}

#[test]
fn a_batch_outside_the_window_is_not_evaluated() {
    let a = agent("agent-1");
    let (ev, b) = bound_tool_claim(&a, 4321);
    let mut o = Observer::new();
    // Batch covers a window far from the claim's.
    let batch = attest(
        &mut o,
        raw_batch(1, 900_000, 999_000, vec![], vec![socket_event(&b)]),
        999_000,
    );
    let avail = covered(0, 10_000);
    let c = corroborate(&inputs(&ev, &[&batch], &avail));
    assert!(
        matches!(
            c,
            Corroboration::NotEvaluated(NotEvaluatedReason::WindowNotCovered)
        ),
        "got {c:?}"
    );
}

// ═══ 5. Claims that are not externally observable ═══

#[test]
fn a_model_invocation_is_never_corroborated_by_a_host_observer() {
    // CLAIM:       "I invoked claude-opus-5."
    // ESTABLISHED: nothing about the model. A host observer sees a socket, and
    //              that socket is the tool layer's evidence. Attributing it to
    //              the model layer would double-count one fact as two.
    let a = agent("agent-1");
    let b = binding(&a.agent_id, 4321);
    let mut ev = signed_model_request(&a, EXEC_A, Some(DECISION_A), "claude-opus-5", [0x11; 32]);
    ev.runtime_binding = Some(b.clone());
    let ev = resign(&a, ev);

    let mut o = Observer::new();
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![socket_event(&b)]),
        10_000,
    );
    let avail = covered(0, 10_000);

    let c = corroborate(&inputs(&ev, &[&batch], &avail));
    assert!(
        matches!(
            c,
            Corroboration::NotEvaluated(NotEvaluatedReason::NotExternallyObservable { .. })
        ),
        "a model claim must not be corroborated by a socket, got {c:?}"
    );
}

#[test]
fn a_claim_without_a_runtime_binding_cannot_be_joined() {
    let a = agent("agent-1");
    let ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    assert!(ev.runtime_binding.is_none());
    let mut o = Observer::new();
    let b = binding(&a.agent_id, 4321);
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![socket_event(&b)]),
        10_000,
    );
    let avail = covered(0, 10_000);
    assert!(matches!(
        corroborate(&inputs(&ev, &[&batch], &avail)),
        Corroboration::NotEvaluated(NotEvaluatedReason::NoRuntimeBinding)
    ));
}

#[test]
fn an_unmappable_action_class_is_not_evaluated_rather_than_accused() {
    // A tool this build has no observable mapping for must produce
    // NotEvaluated. Returning Uncorroborated would turn every vocabulary gap
    // into a phantom claim — the worst false positive this system can make.
    let a = agent("agent-1");
    let b = binding(&a.agent_id, 4321);
    let mut ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.weird", b"{}");
    ev.payload = AiriPayload::ToolInvocationRequested(ToolInvocation {
        tool_id: "tool.weird".into(),
        action_kind: "quantum.entangle".into(),
        parameter_commitment: commit(b"{}"),
        tool_call_id: None,
        target: None,
    });
    ev.runtime_binding = Some(b.clone());
    let ev = resign(&a, ev);

    let mut o = Observer::new();
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![socket_event(&b)]),
        10_000,
    );
    let avail = covered(0, 10_000);
    assert!(
        matches!(
            corroborate(&inputs(&ev, &[&batch], &avail)),
            Corroboration::NotEvaluated(NotEvaluatedReason::ActionClassNotComparable { .. })
        ),
        "an unknown action class must not be scored in either direction"
    );
}

// ═══ 6. The tool-response trap ═══

#[test]
fn a_successful_tool_response_is_not_evidence_of_the_external_effect() {
    // CLAIM:       "The API returned 200, so the refund was issued."
    // ESTABLISHED: bytes resembling a success reached this process. A proxy, a
    //              stub, a replayed cassette or a service that acknowledged
    //              and then failed all produce exactly this.
    //
    // The system must not collapse layer 2 (runtime execution) into layer 3
    // (external effect). Corroborating a *report* against a socket shows the
    // socket existed — never that the far side acted on it.
    let a = agent("agent-1");
    let b = binding(&a.agent_id, 4321);
    let mut ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    ev.payload = AiriPayload::ToolExecutionReported(ToolReport {
        tool_id: "http.post".into(),
        parameter_commitment: commit(b"{}"),
        outcome: ReportedOutcome::Success,
        result_commitment: Some(commit(b"{\"ok\":true}")),
        transport_status: Some(200),
    });
    ev.runtime_binding = Some(b.clone());
    let ev = resign(&a, ev);

    let mut o = Observer::new();
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![socket_event(&b)]),
        10_000,
    );
    let avail = covered(0, 10_000);

    let c = corroborate(&inputs(&ev, &[&batch], &avail));
    // Corroboration here means only "a socket consistent with this claim was
    // independently observed". There is no value this API can return that
    // means "the external effect occurred", and that absence is deliberate.
    match c {
        Corroboration::Corroborated(_) | Corroboration::Uncorroborated { .. } => {}
        other => panic!("unexpected {other:?}"),
    }
    // The type system carries the guarantee: no variant asserts external effect.
    assert!(
        !format!("{c:?}").contains("EffectProven"),
        "no corroboration outcome may assert an external effect"
    );
}

// ═══ 7. Cross-framework transplantation ═══

#[test]
fn a_claim_relabelled_to_another_framework_fails_verification() {
    // An attacker takes a genuine CrewAI event and presents it as LangGraph
    // output to a verifier that trusts LangGraph adapters more. The framework
    // identity is inside the signed preimage, so the relabel breaks it.
    let a = agent("agent-1");
    let (ev, _) = bound_tool_claim(&a, 4321);
    let mut relabelled = ev.clone();
    relabelled.framework = FrameworkIdentity {
        name: "crewai".into(),
        version: "0.1.0".into(),
        adapter_version: "vanian-airi-adapter/1".into(),
    };
    assert!(verify_airi_event(&relabelled, &a.public_key).is_err());
}

#[test]
fn no_framework_is_a_trust_anchor() {
    // Two events identical but for the framework name must be treated
    // identically. Nothing in this crate branches on `framework.name` to
    // grant anything, and this test fails if that ever changes.
    let a = agent("agent-1");
    let mut o = Observer::new();
    let b = binding(&a.agent_id, 4321);
    let batch = attest(
        &mut o,
        raw_batch(1, 0, 10_000, vec![], vec![socket_event(&b)]),
        10_000,
    );
    let avail = covered(0, 10_000);

    let mut outcomes = vec![];
    for fw in [
        "langgraph",
        "autogen",
        "crewai",
        "llamaindex",
        "totally-made-up",
    ] {
        let (mut ev, _) = bound_tool_claim(&a, 4321);
        ev.framework = FrameworkIdentity {
            name: fw.into(),
            version: "1.0".into(),
            adapter_version: "vanian-airi-adapter/1".into(),
        };
        let ev = resign(&a, ev);
        assert!(verify_airi_event(&ev, &a.public_key).is_ok());
        outcomes.push(corroborate(&inputs(&ev, &[&batch], &avail)).is_corroborated());
    }
    assert!(
        outcomes.windows(2).all(|w| w[0] == w[1]),
        "SECURITY: corroboration depends on which framework claimed it"
    );
}

// ═══ 8. Forged adapter events ═══

#[test]
fn a_forged_event_signed_by_a_key_the_verifier_does_not_anchor_fails() {
    // The attacker runs their own adapter and signs perfectly well-formed
    // events with their own key. Every structural rule passes. The event
    // fails only because the verifier anchors the agent's key, not theirs —
    // which is the correct and only reason it should fail.
    let real = agent("agent-1");
    let attacker = agent("agent-1"); // same claimed id, different key
    let ev = signed_tool_request(&attacker, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    assert!(verify_airi_event(&ev, &attacker.public_key).is_ok());
    assert!(
        verify_airi_event(&ev, &real.public_key).is_err(),
        "SECURITY: an event signed by an unanchored key verified"
    );
}

#[test]
fn an_event_signed_for_a_different_agent_id_is_refused() {
    // signature.signer_id must be the event's agent_id: an agent signs only
    // for itself. Without this a party could sign a statement *about* another
    // agent and have it verify under their own anchored key.
    let a = agent("agent-1");
    let mut ev = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "tool.http.post", b"{}");
    ev.agent_id = "victim-agent".into();
    // Re-sign under the attacker's key: the signature is now valid, but the
    // signer is not the subject.
    let preimage = ev.signing_preimage();
    ev.signature = aip_crypto::sign_ed25519(&a.private_key, &a.agent_id, &preimage).unwrap();
    assert!(matches!(
        verify_airi_event(&ev, &a.public_key),
        Err(AiriError::SignerIsNotTheAgent { .. })
    ));
}

// ═══ 9. Malformed provenance ═══

#[test]
fn a_malformed_commitment_cannot_be_smuggled_in_as_a_foreign_digest() {
    // A digest computed in another domain must not function as a parameter
    // commitment. This is what stops an attacker reusing, say, an observer
    // head or a packet hash as a "commitment" that happens to match.
    let foreign = aip_crypto::sha256(b"some other domain's bytes");
    let genuine = parameter_commitment(b"some other domain's bytes");
    assert_ne!(foreign, genuine);
}

#[test]
fn an_empty_framework_name_is_refused() {
    let a = agent("agent-1");
    let (mut ev, _) = bound_tool_claim(&a, 4321);
    ev.framework.name = String::new();
    let ev = resign(&a, ev);
    assert!(matches!(
        verify_airi_event(&ev, &a.public_key),
        Err(AiriError::MissingField("framework.name"))
    ));
}

#[test]
fn an_oversized_field_is_refused_rather_than_allocated() {
    let a = agent("agent-1");
    let (mut ev, _) = bound_tool_claim(&a, 4321);
    ev.framework.version = "x".repeat(100_000);
    let ev = resign(&a, ev);
    assert!(matches!(
        verify_airi_event(&ev, &a.public_key),
        Err(AiriError::FieldTooLong { .. })
    ));
}

// ═══ 10. Worker and subprocess handoff ═══

#[test]
fn a_handoff_binds_parent_and_child_executions() {
    // The parent declares the handoff and the child names its parent. Both
    // are self-reports; together they let a verifier reconstruct application
    // lineage and notice a child that claims a parent which never declared it.
    let a = agent("agent-1");
    let mut parent = signed_tool_request(&a, EXEC_A, Some(DECISION_A), "t", b"{}");
    parent.payload = AiriPayload::ExecutionContextPropagated(ContextPropagation {
        boundary: PropagationBoundary::Subprocess,
        to_execution_id: EXEC_B,
    });
    let parent = resign(&a, parent);

    let mut child = signed_tool_request(&a, EXEC_B, Some(DECISION_A), "t", b"{}");
    child.parent_execution_id = Some(EXEC_A);
    let child = resign(&a, child);

    assert!(verify_airi_event(&parent, &a.public_key).is_ok());
    assert!(verify_airi_event(&child, &a.public_key).is_ok());

    // The binding is in the signature: a child cannot silently reattach.
    let mut reattached = child.clone();
    reattached.parent_execution_id = Some([0xEE; 16]);
    assert!(verify_airi_event(&reattached, &a.public_key).is_err());
}

#[test]
fn application_lineage_is_not_identity_or_authority_lineage() {
    // parent_execution_id says "this run was spawned by that run". It says
    // nothing about delegation and nothing about identity parentage. Keeping
    // the three apart is what stops an agent laundering authority through a
    // subprocess it spawned itself.
    let a = agent("agent-1");
    let mut child = signed_tool_request(&a, EXEC_B, Some(DECISION_A), "t", b"{}");
    child.parent_execution_id = Some(EXEC_A);
    let child = resign(&a, child);
    // Same decision id as the parent — the child inherits no *additional*
    // authority from being a child; it carries the same expectation or none.
    assert_eq!(child.decision_id, Some(DECISION_A));
    // And nothing in this crate reads parent_execution_id to widen scope.
    assert!(verify_airi_event(&child, &a.public_key).is_ok());
}
