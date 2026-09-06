//! Skill 10 Gate 8 — continuity in the proof, RED.
//!
//! A proof must not stay quietly valid across a break in the observer's own
//! record. §6 names the breaks: collector rollback, amnesia, sequence
//! reset, archive fork, key-version confusion, state truncation, restart
//! discontinuity. Each is a statement about the *observer*, not about the
//! workload — and none of them may be turned into a successful proof.
//!
//! Four outcomes, and the fourth is not a synonym for the third:
//!
//! | outcome        | meaning                                             |
//! |----------------|-----------------------------------------------------|
//! | `Continuous`   | the chain is unbroken across what the package carries |
//! | `Discontinuous`| a break is *established*: the collector said so, under its own key |
//! | `Unknown`      | the package carries nothing about continuity        |
//! | `CannotProve`  | something was carried and it does not settle the question |
//!
//! `Unknown` and `CannotProve` are kept apart because they license
//! different things: the first says nobody asked, the second says somebody
//! asked and the evidence did not answer.

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
    }
}

// ═══ Nothing carried is not the same as nothing wrong ═══

#[test]
fn g8_01_a_package_with_no_continuity_report_says_unknown() {
    let s = common::verified_execution();
    let v = verify_nexora_proof(&base(&s).build(), &anchors(&s));
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert_eq!(v.continuity_standing, ContinuityStanding::Unknown);
    assert!(
        !v.continuity_standing.asserts_unbroken(),
        "carrying nothing must never read as an unbroken chain"
    );
}

// ═══ Every break the collector can report ═══

#[test]
fn g8_02_each_break_the_collector_signs_is_reported_as_discontinuous() {
    let s = common::verified_execution();
    for brk in common::every_continuity_break() {
        let report = common::continuity_report_for(common::OBSERVER_ID, &s.o, brk.clone());
        let p = base(&s).continuity(report).build();
        let v = verify_nexora_proof(&p, &anchors(&s));
        assert_eq!(
            v.continuity,
            ComponentVerdict::Verified,
            "the report is the collector's own signed record: {v:#?}"
        );
        assert_eq!(
            v.continuity_standing,
            ContinuityStanding::Discontinuous,
            "{brk:?} must read as an established break"
        );
        assert!(!v.continuity_standing.asserts_unbroken());
    }
}

#[test]
fn g8_03_a_clean_restart_report_is_still_not_an_unbroken_chain() {
    // ArchiveTruncated is the mildest break: the collector kept its state
    // and reported that its archive was short. It is still a break, and a
    // proof must not present it as continuity.
    let s = common::verified_execution();
    let report = common::continuity_report_for(
        common::OBSERVER_ID,
        &s.o,
        aip_observe::ContinuityBreak::ArchiveTruncated {
            resumed_sequence: 4,
            archived_sequence: 2,
        },
    );
    let v = verify_nexora_proof(&base(&s).continuity(report).build(), &anchors(&s));
    assert_eq!(v.continuity_standing, ContinuityStanding::Discontinuous);
}

// ═══ A report the verifier cannot check settles nothing ═══

#[test]
fn g8_04_a_report_under_a_key_the_verifier_does_not_anchor_settles_nothing() {
    let s = common::verified_execution();
    // Signed by some other party claiming to be this observer.
    let report = common::continuity_report_of(common::OBSERVER_ID);
    let p = base(&s).continuity(report).build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(
        matches!(v.continuity, ComponentVerdict::Unverifiable(_)),
        "{v:#?}"
    );
    assert_eq!(
        v.continuity_standing,
        ContinuityStanding::CannotProve,
        "an unverifiable report is not an absence of one"
    );
    assert_ne!(v.continuity_standing, ContinuityStanding::Unknown);
    assert_ne!(v.verdict, ProofVerdict::Valid);
}

#[test]
fn g8_05_key_version_confusion_does_not_pass_as_continuity() {
    let s = common::verified_execution();
    let mut report =
        common::continuity_report_for(common::OBSERVER_ID, &s.o, common::amnesia_break());
    // The same observer, a key version the verifier holds no anchor for.
    report.report.key_version = 99;
    let p = base(&s).continuity(report).build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(matches!(v.continuity, ComponentVerdict::Unverifiable(_)));
    assert_eq!(v.continuity_standing, ContinuityStanding::CannotProve);
}

// ═══ The report is bound to the package ═══

#[test]
fn g8_06_a_report_altered_after_signing_is_refused() {
    let s = common::verified_execution();
    let mut report =
        common::continuity_report_for(common::OBSERVER_ID, &s.o, common::amnesia_break());
    report.report.refused = !report.report.refused;
    let v = verify_nexora_proof(&base(&s).continuity(report).build(), &anchors(&s));
    assert!(matches!(v.continuity, ComponentVerdict::Unverifiable(_)));
    assert_ne!(v.verdict, ProofVerdict::Valid);
}

#[test]
fn g8_07_continuity_is_inside_the_bytes_and_inside_the_seal() {
    let s = common::verified_execution();
    let report = common::continuity_report_for(common::OBSERVER_ID, &s.o, common::amnesia_break());
    let without = base(&s).build();
    let with = base(&s).continuity(report).build();
    assert_ne!(
        without.proof_id(),
        with.proof_id(),
        "carrying a continuity report changes the package's identity"
    );

    let kp = aip_crypto::generate_ed25519_keypair();
    let asm = ProofAssembler::new("asm", 1, &kp.private_key, &kp.public_key).unwrap();
    let sealed = asm.seal(with).unwrap();
    let a = aip_nexora::NexoraTrustAnchors::new().trust("asm", 1, &kp.public_key);
    assert!(verify_envelope(&sealed, &a).is_ok());
    // Dropping the report from a sealed package breaks the seal.
    let mut stripped = sealed.clone();
    stripped.continuity = None;
    assert!(verify_envelope(&stripped, &a).is_err());
}

// ═══ The vocabulary ═══

#[test]
fn g8_08_the_outcomes_are_closed_and_only_one_asserts_an_unbroken_chain() {
    let all = ContinuityStanding::ALL;
    assert_eq!(all.len(), 4);
    let mut codes: Vec<u8> = all.iter().map(|x| x.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), all.len());
    assert!(ContinuityStanding::Continuous.asserts_unbroken());
    for x in all {
        if x != ContinuityStanding::Continuous {
            assert!(!x.asserts_unbroken(), "{x:?} must not assert continuity");
        }
    }
    // Unknown and CannotProve are different answers to different questions.
    assert_ne!(ContinuityStanding::Unknown, ContinuityStanding::CannotProve);
}
