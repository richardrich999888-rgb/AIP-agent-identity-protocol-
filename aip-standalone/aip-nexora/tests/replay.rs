//! Skill 10 Gate 11 — replay semantics, RED.
//!
//! §11 asks for five things to be told apart. They are not five outcomes
//! of one check; they are answers to different questions, and two of them
//! are not NEXORA's to answer at all.
//!
//! | §11 term                    | who answers it | how |
//! |-----------------------------|----------------|-----|
//! | valid historical replay     | the verifier   | a valid proof *is* this: deterministic re-derivation of a past execution |
//! | proof of a previous execution | the verifier | the same thing said from the other side |
//! | stale authority             | the verifier   | `AuthorityStanding`, against a present time the verifier supplies |
//! | duplicate submission        | the consumer   | a ledger it keeps; verification stays pure |
//! | unauthorized reuse          | **nobody here**| presenting a proof as permission is the consumer's act; NEXORA can only make it impossible to mistake a proof for permission |
//!
//! The line that matters: **offline verification proves what a package
//! supports; it does not grant current authority.** A proof whose authority
//! expired years ago is still a true statement about what happened — and
//! is not a licence to do anything today. Those are different sentences and
//! the type system keeps them apart.

mod common;

use aip_nexora::export::*;
use aip_nexora::proof::*;
use aip_nexora::replay::*;
use aip_nexora::verify::*;

fn package(s: &common::Scenario) -> NexoraProof {
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
        .build()
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

// ═══ Stale authority does not make a past execution untrue ═══

#[test]
fn g11_01_without_a_present_time_staleness_is_not_assessed() {
    let s = common::verified_execution();
    let v = verify_nexora_proof(&package(&s), &anchors(&s));
    assert_eq!(v.verdict, ProofVerdict::Valid);
    assert_eq!(v.authority_standing, AuthorityStanding::NotAssessed);
    assert!(!v.authority_standing.grants_authority_now());
}

#[test]
fn g11_02_a_present_time_inside_the_window_reports_valid_now() {
    let s = common::verified_execution();
    let a = VerifierAnchors {
        present_time_ms: Some(s.a.ee.valid_until - 1),
        ..anchors(&s)
    };
    let v = verify_nexora_proof(&package(&s), &a);
    assert_eq!(v.verdict, ProofVerdict::Valid);
    assert_eq!(v.authority_standing, AuthorityStanding::ValidNow);
}

#[test]
fn g11_03_expired_authority_leaves_the_proof_valid_and_grants_nothing() {
    let s = common::verified_execution();
    let long_after = s.a.ee.valid_until + 365 * 24 * 3_600_000;
    let a = VerifierAnchors {
        present_time_ms: Some(long_after),
        ..anchors(&s)
    };
    let v = verify_nexora_proof(&package(&s), &a);
    assert_eq!(
        v.verdict,
        ProofVerdict::Valid,
        "a year later, what happened still happened: {v:#?}"
    );
    assert_eq!(
        v.authority_standing,
        AuthorityStanding::StaleSince {
            valid_until: s.a.ee.valid_until
        }
    );
    assert!(
        !v.authority_standing.grants_authority_now(),
        "stale authority must never read as present permission"
    );
    // The re-derived verdict is untouched: staleness is assessed against
    // the verifier's present, never fed into the reconciliation.
    assert_eq!(
        v.result,
        Some(aip_reconcile::ReconciliationResult::VerifiedExecution)
    );
    assert_eq!(v.rederived.unwrap().digest(), s.reconciliation.digest());
}

#[test]
fn g11_04_no_standing_whatsoever_grants_present_authority() {
    for standing in AuthorityStanding::ALL {
        assert!(
            !standing.grants_authority_now(),
            "{standing:?} must not grant authority: a proof is evidence, never permission"
        );
    }
}

// ═══ Duplicate submission is the consumer's ledger, not the verifier's ═══

#[test]
fn g11_05_a_second_submission_of_the_same_proof_is_a_duplicate() {
    let s = common::verified_execution();
    let v = verify_nexora_proof(&package(&s), &anchors(&s));
    let mut ledger = MemoryProofLedger::default();

    assert_eq!(
        record_submission(&mut ledger, &v).unwrap(),
        ReplayStanding::FirstSeen
    );
    match record_submission(&mut ledger, &v).unwrap() {
        ReplayStanding::DuplicateSubmission { .. } => {}
        other => panic!("a second submission must be a duplicate, got {other:?}"),
    }
    // A different proof is not a duplicate of it.
    let other = common::verified_execution();
    let ov = verify_nexora_proof(&package(&other), &anchors(&other));
    assert_eq!(
        record_submission(&mut ledger, &ov).unwrap(),
        ReplayStanding::FirstSeen
    );
}

#[test]
fn g11_06_the_ledger_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("nexora-ledger-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("submitted.proofs");
    let s = common::verified_execution();
    let v = verify_nexora_proof(&package(&s), &anchors(&s));
    {
        let mut ledger = FileProofLedger::open(&path).unwrap();
        assert_eq!(
            record_submission(&mut ledger, &v).unwrap(),
            ReplayStanding::FirstSeen
        );
    }
    let mut ledger = FileProofLedger::open(&path).unwrap();
    assert!(matches!(
        record_submission(&mut ledger, &v).unwrap(),
        ReplayStanding::DuplicateSubmission { .. }
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn g11_07_verification_stays_pure_and_a_duplicate_is_still_a_valid_proof() {
    // Submitting to a ledger is the consumer's act and changes nothing
    // about what the package supports: the same bytes verify identically
    // before and after, and being seen twice does not make a past
    // execution untrue.
    let s = common::verified_execution();
    let p = package(&s);
    let a = anchors(&s);
    let before = verify_nexora_proof(&p, &a);
    let mut ledger = MemoryProofLedger::default();
    record_submission(&mut ledger, &before).unwrap();
    record_submission(&mut ledger, &before).unwrap();
    let after = verify_nexora_proof(&p, &a);
    assert_eq!(
        before, after,
        "verification is a pure function of its inputs"
    );
    assert_eq!(after.verdict, ProofVerdict::Valid);
}

// ═══ A proof cannot be mistaken for permission ═══

#[test]
fn g11_08_nothing_in_the_api_turns_a_proof_into_authority() {
    let s = common::verified_execution();
    let v = verify_nexora_proof(&package(&s), &anchors(&s));
    // The output says what it supports and says the limit in the same
    // breath. There is no field a consumer could read as a licence.
    let json = serde_json::to_string(&v).unwrap().to_lowercase();
    for word in [
        "grant",
        "permit",
        "allow",
        "authorise",
        "authorize",
        "token",
    ] {
        assert!(!json.contains(word), "{word} appears in a verifier output");
    }
    // And the crate names the distinction where a reader will meet it.
    let src = std::fs::read_to_string("src/replay.rs").unwrap();
    assert!(
        src.contains("does not grant current authority") || src.contains("never permission"),
        "replay.rs must state the distinction it exists to keep"
    );
}

// ═══ Round trip: a proof stays a proof of a previous execution ═══

#[test]
fn g11_09_a_proof_carried_forward_in_time_still_proves_the_same_past() {
    let s = common::verified_execution();
    let bytes = export_proof(&package(&s)).unwrap();
    let back = import_proof(&bytes).unwrap();
    let much_later = s.a.ee.valid_until + 10 * 365 * 24 * 3_600_000;
    let a = VerifierAnchors {
        present_time_ms: Some(much_later),
        ..anchors(&s)
    };
    let v = verify_nexora_proof(&back, &a);
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert_eq!(
        v.result,
        Some(aip_reconcile::ReconciliationResult::VerifiedExecution)
    );
    assert!(matches!(
        v.authority_standing,
        AuthorityStanding::StaleSince { .. }
    ));
}
