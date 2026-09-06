//! Skill 10 Gate 9 — a warrant referenced, never recreated, RED.
//!
//! §7 fixes the shape: one canonical warrant model, no duplicate policy in
//! NEXORA. A proof may *carry* a warrant and the verifier may check its
//! signature and its binding to this record — and that is the whole of
//! NEXORA's involvement.
//!
//! ```text
//! warrant issuer → warrant signature → warrant verification
//!                → policy semantics → reconciliation binding
//! ```
//!
//! NEXORA sits at "verification" and nowhere else. It does not decide what
//! a warrant permits, does not re-evaluate the policy that produced it,
//! does not compare severity with strength, and authorises no containment:
//! a verified proof is a statement about the past, not permission to act.

mod common;

use aip_nexora::proof::*;
use aip_nexora::verify::*;

fn base(s: &common::Scenario) -> ProofBuilder {
    NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
}

fn anchors(s: &common::Scenario) -> VerifierAnchors {
    VerifierAnchors {
        decision_point: s.a.dp_anchors.clone(),
        observer: s.o.anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: s.a.issuer_keys.clone(),
        agent_public_key: Some(s.a.agent_kp.public_key.clone()),
        ..Default::default()
    }
}

#[test]
fn g9_01_a_carried_warrant_is_checked_against_the_verifiers_own_anchor() {
    let s = common::verified_execution();
    let (w, key) = common::warrant_and_key_for(&s.reconciliation, Some(&s.a.agent_id));

    // Without the anchor the verifier cannot establish it, and does not
    // pretend otherwise.
    let v = verify_nexora_proof(&base(&s).warrant(w.clone()).build(), &anchors(&s));
    assert!(
        matches!(v.warrant, ComponentVerdict::Unverifiable(_)),
        "{v:#?}"
    );
    assert_ne!(v.verdict, ProofVerdict::Valid);

    // With it, the warrant is established — and nothing else changes.
    let mut a = anchors(&s);
    a.warrant = aip_warrant::WarrantTrustAnchors::new().trust("warrant-authority", &key);
    let v = verify_nexora_proof(&base(&s).warrant(w).build(), &a);
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert_eq!(v.warrant, ComponentVerdict::Verified);
    assert_eq!(v.result, Some(s.reconciliation.result));
    assert_eq!(v.strength, Some(s.reconciliation.strength));
}

#[test]
fn g9_02_a_warrant_is_not_required_and_carrying_none_is_no_weaker() {
    let s = common::verified_execution();
    let v = verify_nexora_proof(&base(&s).build(), &anchors(&s));
    assert_eq!(v.verdict, ProofVerdict::Valid);
    assert_eq!(v.warrant, ComponentVerdict::Absent);
    // The evidence establishes exactly what it establishes, with or
    // without a warrant attached to it.
    let (w, key) = common::warrant_and_key_for(&s.reconciliation, Some(&s.a.agent_id));
    let mut a = anchors(&s);
    a.warrant = aip_warrant::WarrantTrustAnchors::new().trust("warrant-authority", &key);
    let with = verify_nexora_proof(&base(&s).warrant(w).build(), &a);
    assert_eq!(with.result, v.result);
    assert_eq!(with.strength, v.strength);
    assert_eq!(with.coverage, v.coverage);
}

#[test]
fn g9_03_nexora_reaches_no_conclusion_a_warrant_would_authorise() {
    let s = common::verified_execution();
    let (w, key) = common::warrant_and_key_for(&s.reconciliation, Some(&s.a.agent_id));
    let mut a = anchors(&s);
    a.warrant = aip_warrant::WarrantTrustAnchors::new().trust("warrant-authority", &key);
    let v = verify_nexora_proof(&base(&s).warrant(w).build(), &a);

    // The verifier's own output carries no response class, no severity, no
    // permission — nothing a containment boundary could read as authority.
    let json = serde_json::to_string(&v).unwrap().to_lowercase();
    for word in [
        "contain",
        "constrain",
        "severity",
        "autonomous",
        "authorised",
        "authorized",
        "permit",
    ] {
        assert!(
            !json.contains(word),
            "{word} appears in a verifier output: {json}"
        );
    }
    // And the type carries no field that could be mistaken for one.
    let value: serde_json::Value = serde_json::to_value(&v).unwrap();
    for key in ["response", "severity", "policy", "action"] {
        assert!(!value.as_object().unwrap().contains_key(key));
    }
}

#[test]
fn g9_04_the_warrant_must_rest_on_this_record_and_name_this_subject() {
    let s = common::verified_execution();
    let other = common::verified_execution();

    // A warrant for another record: refused by the binding checks, before
    // any signature is looked at.
    let (w, key) = common::warrant_and_key_for(&other.reconciliation, Some(&s.a.agent_id));
    let mut a = anchors(&s);
    a.warrant = aip_warrant::WarrantTrustAnchors::new().trust("warrant-authority", &key);
    let v = verify_nexora_proof(&base(&s).warrant(w).build(), &a);
    assert!(
        matches!(
            v.verdict,
            ProofVerdict::Invalid(InvalidReason::Binding(
                BindingFault::WarrantForAnotherRecord
            ))
        ),
        "{v:#?}"
    );

    // A warrant naming another subject.
    let (w, key) = common::warrant_and_key_for(&s.reconciliation, Some("aip1someone-else"));
    let mut a = anchors(&s);
    a.warrant = aip_warrant::WarrantTrustAnchors::new().trust("warrant-authority", &key);
    let v = verify_nexora_proof(&base(&s).warrant(w).build(), &a);
    assert!(matches!(
        v.verdict,
        ProofVerdict::Invalid(InvalidReason::Binding(
            BindingFault::WarrantForAnotherSubject { .. }
        ))
    ));
}

#[test]
fn g9_05_nexora_contains_no_warrant_policy_of_its_own() {
    // The mechanical form of "one canonical warrant model": nothing in the
    // crate's own sources evaluates a policy, weighs a severity against a
    // strength, or names a response class. The only warrant symbols it
    // uses are the type and its verifier.
    let src: String = [
        "proof.rs",
        "verify.rs",
        "commitment.rs",
        "merkle.rs",
        "lib.rs",
    ]
    .iter()
    .map(|f| std::fs::read_to_string(format!("src/{f}")).unwrap())
    .collect();
    for forbidden in [
        "WarrantPolicy",
        "ResponseClass",
        "Severity",
        "aip_warrant::evaluate",
        "autonomous_containment",
    ] {
        assert!(
            !src.contains(forbidden),
            "{forbidden} appears in aip-nexora: warrant policy belongs to aip-warrant alone"
        );
    }
    assert!(
        src.contains("verify_warrant"),
        "the warrant is verified through the one implementation that owns it"
    );
}
