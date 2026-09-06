//! AI-stack provenance in a proof package, and its offline re-derivation.
//!
//! The mandate: a proof package must carry the AIRI evidence a reconciliation
//! rested on, and the offline verifier must *re-derive* it rather than
//! believe it. These tests hold the verifier to that in both directions —
//! that it accepts what it can re-derive, and that it refuses everything it
//! cannot, including a package that tries to choose which key it is judged
//! against.

mod common;

use aip_airi::*;
use aip_nexora::proof::*;
use aip_nexora::verify::*;
use aip_types::{ExecutionBinding, ProcessInstance, Signature};

const EXEC: [u8; 16] = [0xA1; 16];

struct Agent {
    id: String,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

fn agent(id: &str) -> Agent {
    let kp = aip_crypto::generate_ed25519_keypair();
    Agent {
        id: id.to_string(),
        private_key: kp.private_key,
        public_key: kp.public_key,
    }
}

fn framework() -> FrameworkIdentity {
    FrameworkIdentity {
        name: "langgraph".into(),
        version: "0.2.0".into(),
        adapter_version: "vanian-airi-adapter/1".into(),
    }
}

fn binding(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: aip_types::EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: 4321,
            pid_start_time_ticks: 4242,
            boot_id: [0x7; 16],
        },
        exe_content_sha256: [0x33; 32],
        exe_path: "/usr/bin/python3".into(),
        bound_at_ms: 1_000,
    }
}

fn empty_sig() -> Signature {
    Signature {
        algorithm: aip_types::AlgorithmId::Ed25519,
        signer_id: String::new(),
        timestamp: 0,
        nonce: [0u8; 16],
        payload_hash: [0u8; 32],
        signature_bytes: vec![],
    }
}

/// A chain of `n` signed tool-request events for one execution.
fn chain(a: &Agent, n: u64) -> Vec<AiriEvent> {
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for i in 0..n {
        let ev = AiriEvent {
            version: AIRI_EVENT_VERSION,
            agent_id: a.id.clone(),
            execution_id: EXEC,
            parent_execution_id: None,
            decision_id: None,
            sequence: i,
            prev_event_hash: prev,
            emitted_at_ms: 1_000 + i,
            framework: framework(),
            runtime_binding: Some(binding(&a.id)),
            payload: AiriPayload::ToolInvocationRequested(ToolInvocation {
                tool_id: "http.post".into(),
                action_kind: "http.post".into(),
                parameter_commitment: parameter_commitment(b"{\"amount\":5}"),
                tool_call_id: None,
                target: None,
            }),
            signature: empty_sig(),
        };
        let ev = sign_airi_event(&a.private_key, &a.id, ev).expect("sign");
        prev = ev.event_hash();
        out.push(ev);
    }
    out
}

/// A package for the scenario, optionally carrying an AIRI bundle.
fn package(s: &common::Scenario, airi: Option<(String, Vec<u8>, Vec<AiriEvent>)>) -> NexoraProof {
    let b = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        });
    match airi {
        Some((id, key, events)) => b.airi(id, key, events).build(),
        None => b.build(),
    }
}

/// Anchors for the scenario. `airi_agent` overrides the anchored agent key,
/// which is how the key-selection tests express what the verifier trusts.
fn anchors(s: &common::Scenario, airi_agent: Option<Vec<u8>>) -> VerifierAnchors {
    VerifierAnchors {
        decision_point: s.a.dp_anchors.clone(),
        observer: s.o.anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: s.a.issuer_keys.clone(),
        agent_public_key: airi_agent.or_else(|| Some(s.a.agent_kp.public_key.clone())),
    }
}

// ═══ The package carries it, and the verifier re-derives it ═══

#[test]
fn a_package_carrying_airi_events_has_them_re_derived() {
    let s = common::verified_execution();
    let a = agent("aip1airiagent");
    let events = chain(&a, 4);
    let p = package(&s, Some((a.id.clone(), a.public_key.clone(), events)));

    let v = verify_nexora_proof(&p, &anchors(&s, Some(a.public_key.clone())));
    assert_eq!(v.airi, ComponentVerdict::Verified, "{:?}", v.airi);
    assert_eq!(v.airi_events_verified, 4);
}

#[test]
fn a_package_without_airi_reports_absent_not_failure() {
    // Absent is not a pass and not a failure. A deployment running no
    // instrumented agents must not look like one that lost its evidence.
    let s = common::verified_execution();
    let p = package(&s, None);
    let v = verify_nexora_proof(&p, &anchors(&s, None));
    assert_eq!(v.airi, ComponentVerdict::Absent);
    assert_eq!(v.airi_events_verified, 0);
}

// ═══ Re-derivation is real: every tamper is caught ═══

#[test]
fn a_tampered_event_in_the_bundle_is_unverifiable() {
    let s = common::verified_execution();
    let a = agent("aip1airiagent");
    let mut events = chain(&a, 3);
    events[1].emitted_at_ms += 1; // signature no longer covers it
    let p = package(&s, Some((a.id.clone(), a.public_key.clone(), events)));

    let v = verify_nexora_proof(&p, &anchors(&s, Some(a.public_key.clone())));
    assert!(
        matches!(v.airi, ComponentVerdict::Unverifiable(_)),
        "SECURITY: a tampered AIRI event was accepted: {:?}",
        v.airi
    );
}

#[test]
fn a_reordered_bundle_is_unverifiable() {
    // Each signature is individually genuine; the order is the attack.
    let s = common::verified_execution();
    let a = agent("aip1airiagent");
    let c = chain(&a, 4);
    let events = vec![c[0].clone(), c[2].clone(), c[1].clone(), c[3].clone()];
    let p = package(&s, Some((a.id.clone(), a.public_key.clone(), events)));

    let v = verify_nexora_proof(&p, &anchors(&s, Some(a.public_key.clone())));
    assert!(
        matches!(v.airi, ComponentVerdict::Unverifiable(_)),
        "SECURITY: a reordered chain was accepted: {:?}",
        v.airi
    );
}

#[test]
fn a_bundle_with_an_event_removed_from_the_middle_is_unverifiable() {
    let s = common::verified_execution();
    let a = agent("aip1airiagent");
    let c = chain(&a, 4);
    let events = vec![c[0].clone(), c[1].clone(), c[3].clone()];
    let p = package(&s, Some((a.id.clone(), a.public_key.clone(), events)));

    let v = verify_nexora_proof(&p, &anchors(&s, Some(a.public_key.clone())));
    assert!(matches!(v.airi, ComponentVerdict::Unverifiable(_)));
}

#[test]
fn an_event_authored_by_another_agent_is_unverifiable() {
    // The bundle says these are agent A's events; one is agent B's, validly
    // signed by B. Without the agent_id check a verifier holding only A's
    // key would report a signature failure, which is the right refusal for
    // the wrong reason — this pins the specific one.
    let s = common::verified_execution();
    let a = agent("aip1airiagent");
    let b = agent("aip1otheragent");
    let mut events = chain(&a, 3);
    events[1] = chain(&b, 3)[1].clone();
    let p = package(&s, Some((a.id.clone(), a.public_key.clone(), events)));

    let v = verify_nexora_proof(&p, &anchors(&s, Some(a.public_key.clone())));
    match &v.airi {
        ComponentVerdict::Unverifiable(reason) => {
            assert!(
                reason.contains("authored by"),
                "expected an authorship refusal, got: {reason}"
            );
        }
        other => panic!("SECURITY: a foreign event was accepted: {other:?}"),
    }
}

#[test]
fn an_empty_bundle_is_unverifiable_rather_than_vacuously_verified() {
    // An empty list satisfies "every event verifies" trivially. Refusing it
    // keeps a package from claiming AI-stack provenance it does not carry.
    let s = common::verified_execution();
    let a = agent("aip1airiagent");
    let p = package(&s, Some((a.id.clone(), a.public_key.clone(), vec![])));
    let v = verify_nexora_proof(&p, &anchors(&s, Some(a.public_key.clone())));
    assert!(matches!(v.airi, ComponentVerdict::Unverifiable(_)));
}

// ═══ The package must not choose the key it is judged against ═══

#[test]
fn a_package_naming_a_key_the_verifier_does_not_anchor_is_refused() {
    // The attack: an assembler signs a fabricated event chain with its own
    // key and puts that key in the bundle. Every signature checks out
    // *against the key the package supplied*. A verifier that used the
    // package's key would report Verified.
    let s = common::verified_execution();
    let real = agent("aip1airiagent");
    let attacker = agent("aip1airiagent"); // same claimed id, different key
    let events = chain(&attacker, 3);
    let p = package(&s, Some((attacker.id.clone(), attacker.public_key.clone(), events)));

    // The verifier anchors the *real* agent's key.
    let v = verify_nexora_proof(&p, &anchors(&s, Some(real.public_key.clone())));
    match &v.airi {
        ComponentVerdict::Unverifiable(reason) => {
            assert!(
                reason.contains("does not anchor"),
                "expected a key-anchoring refusal, got: {reason}"
            );
        }
        other => panic!("SECURITY: the package chose which key it was judged against: {other:?}"),
    }
}

#[test]
fn a_malformed_agent_key_is_refused() {
    let s = common::verified_execution();
    let a = agent("aip1airiagent");
    let events = chain(&a, 2);
    let p = package(&s, Some((a.id.clone(), vec![0u8; 31], events)));
    let v = verify_nexora_proof(&p, &anchors(&s, Some(vec![0u8; 31])));
    assert!(matches!(v.airi, ComponentVerdict::Unverifiable(_)));
}

// ═══ AIRI cannot move the verdict, at this layer either ═══

#[test]
fn airi_evidence_does_not_change_the_re_derived_result_or_strength() {
    // The same property `aip-airi`'s composition tests establish against the
    // reconciler, now at the packaging layer: adding AI-stack provenance to
    // a package must not change what the verifier re-derives from it.
    let s = common::verified_execution();
    let a = agent("aip1airiagent");

    let without = verify_nexora_proof(&package(&s, None), &anchors(&s, None));
    let with = verify_nexora_proof(
        &package(&s, Some((a.id.clone(), a.public_key.clone(), chain(&a, 4)))),
        &anchors(&s, Some(a.public_key.clone())),
    );

    assert_eq!(
        without.result, with.result,
        "SECURITY: AIRI evidence changed the re-derived result"
    );
    assert_eq!(
        without.strength, with.strength,
        "SECURITY: AIRI evidence changed the re-derived strength"
    );
    // And the AIRI evidence really was present and verified — not a vacuous pass.
    assert_eq!(with.airi, ComponentVerdict::Verified);
    assert_eq!(with.airi_events_verified, 4);
}

#[test]
fn an_unverifiable_bundle_does_not_downgrade_the_re_derived_verdict_either() {
    // Symmetry matters. AIRI must not raise a verdict, and a *broken* AIRI
    // bundle must not lower one: the reconciliation rests on the observer's
    // evidence, and a defect in the agent's own account is recorded as its
    // own component verdict rather than leaking into the result.
    let s = common::verified_execution();
    let a = agent("aip1airiagent");
    let mut events = chain(&a, 3);
    events[1].emitted_at_ms += 1;

    let clean = verify_nexora_proof(&package(&s, None), &anchors(&s, None));
    let broken = verify_nexora_proof(
        &package(&s, Some((a.id.clone(), a.public_key.clone(), events))),
        &anchors(&s, Some(a.public_key.clone())),
    );

    assert!(matches!(broken.airi, ComponentVerdict::Unverifiable(_)));
    assert_eq!(clean.result, broken.result);
    assert_eq!(clean.strength, broken.strength);
}

// ═══ Committed bytes ═══

#[test]
fn the_bundle_is_inside_the_packages_canonical_bytes() {
    // If the bundle were outside the canonical encoding, an assembler could
    // swap the AI-stack evidence without changing the proof id, and any
    // commitment over that id would be committing to the wrong thing.
    let s = common::verified_execution();
    let a = agent("aip1airiagent");
    let with = package(&s, Some((a.id.clone(), a.public_key.clone(), chain(&a, 3))));
    let without = package(&s, None);
    assert_ne!(with.canonical_bytes(), without.canonical_bytes());
    assert_ne!(with.proof_id(), without.proof_id());
}

#[test]
fn two_different_bundles_give_two_different_proof_ids() {
    let s = common::verified_execution();
    let a = agent("aip1airiagent");
    let p3 = package(&s, Some((a.id.clone(), a.public_key.clone(), chain(&a, 3))));
    let p4 = package(&s, Some((a.id.clone(), a.public_key.clone(), chain(&a, 4))));
    assert_ne!(p3.proof_id(), p4.proof_id());
}

#[test]
fn the_package_version_is_two_and_a_v1_package_is_refused() {
    let s = common::verified_execution();
    let mut p = package(&s, None);
    assert_eq!(p.version, NEXORA_PROOF_VERSION);
    assert_eq!(NEXORA_PROOF_VERSION, 2);

    p.version = 1;
    let v = verify_nexora_proof(&p, &anchors(&s, None));
    assert!(
        matches!(
            v.verdict,
            ProofVerdict::Invalid(InvalidReason::UnsupportedVersion(1))
        ),
        "a v1 package must be refused, not reinterpreted: {:?}",
        v.verdict
    );
}
