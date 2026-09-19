//! R11 — the external witness, against a real `CommitmentLog`.
//!
//! The property under test is the one a commitment log cannot establish on
//! its own: that the log shown today is the log that existed yesterday.
//! Every test here works by *actually rewriting* a log — building a shorter
//! or different one and signing it with the same NEXORA key, exactly as an
//! operator with that key could — and then asking whether held receipts
//! catch it.

use aip_anchor::{
    audit, verify_receipt, verify_receipt_chain, AnchorStanding, Divergence, NotEvaluated, Witness,
    WitnessAnchors, WitnessError, WitnessReceipt, WITNESS_RECEIPT_VERSION,
};
use aip_crypto::generate_ed25519_keypair;
use aip_nexora::{CommitmentLog, LeafKind, NexoraSigner, NexoraTrustAnchors, SignedHead};

const LOG_ID: [u8; 16] = [7u8; 16];
const NEXORA_ID: &str = "nexora-1";
const WITNESS_ID: &str = "re-witness-1";
const T0: u64 = 1_700_000_000_000;

/// Everything a test needs: a log, its signer, and the anchors a witness
/// would be provisioned with.
struct Ctx {
    log: CommitmentLog,
    signer: NexoraSigner,
    log_anchors: NexoraTrustAnchors,
}

fn ctx() -> Ctx {
    let kp = generate_ed25519_keypair();
    let signer = NexoraSigner::new(NEXORA_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    Ctx {
        log: CommitmentLog::new(LOG_ID),
        signer,
        log_anchors: NexoraTrustAnchors::new().trust(NEXORA_ID, 1, &kp.public_key),
    }
}

/// A witness with its own key, distinct from the log's.
fn witness(log_anchors: &NexoraTrustAnchors) -> (Witness, WitnessAnchors) {
    let kp = generate_ed25519_keypair();
    (
        Witness::new(
            WITNESS_ID,
            3,
            &kp.private_key,
            &kp.public_key,
            log_anchors.clone(),
        )
        .unwrap(),
        WitnessAnchors::new().trust(WITNESS_ID, 3, &kp.public_key),
    )
}

fn append(log: &mut CommitmentLog, n: usize, tag: u8) {
    for i in 0..n {
        log.append(LeafKind::Reconciliation, &[tag, i as u8]);
    }
}

fn head(c: &Ctx, at_ms: u64) -> SignedHead {
    c.log.head(&c.signer, at_ms).unwrap()
}

// ─── The ordinary path ───

/// A log that only grows is witnessed at each head and audits clean.
#[test]
fn a_growing_log_is_witnessed_and_audits_consistent() {
    let mut c = ctx();
    let (mut w, anchors) = witness(&c.log_anchors);

    append(&mut c.log, 4, 0xA0);
    let h1 = head(&c, T0);
    let r1 = w.witness(&h1, None, T0 + 10).unwrap();
    verify_receipt(&r1, &anchors).unwrap();

    let before = c.log.size();
    append(&mut c.log, 3, 0xB0);
    let proof = c.log.consistency_since(before).unwrap();
    let h2 = head(&c, T0 + 1_000);
    let r2 = w.witness(&h2, Some(&proof), T0 + 1_010).unwrap();

    verify_receipt_chain(&[r1.clone(), r2.clone()], &anchors).unwrap();
    let standing = audit(&c.log, &[r1, r2], &anchors);
    assert!(standing.is_consistent(), "{}", standing.explain());
    match standing {
        AnchorStanding::Consistent {
            receipts,
            highest_witnessed_size,
            witnessed_at_ms,
        } => {
            assert_eq!(receipts, 2);
            assert_eq!(highest_witnessed_size, 7);
            // The witness's clock, not the log's.
            assert_eq!(witnessed_at_ms, T0 + 1_010);
        }
        other => panic!("{other:?}"),
    }
}

/// A log that has grown since the last receipt still audits clean, because
/// the audit makes it prove the witnessed root is a prefix.
#[test]
fn a_log_that_grew_after_the_last_receipt_still_audits_consistent() {
    let mut c = ctx();
    let (mut w, anchors) = witness(&c.log_anchors);
    append(&mut c.log, 5, 0xA0);
    let r1 = w.witness(&head(&c, T0), None, T0 + 10).unwrap();

    append(&mut c.log, 6, 0xC0);
    let standing = audit(&c.log, &[r1], &anchors);
    assert!(standing.is_consistent(), "{}", standing.explain());
}

// ─── Rewriting, which is the point ───

/// **The load-bearing test.** The operator holds the NEXORA key, builds a
/// shorter log, and signs a perfectly valid head over it. Every NEXORA
/// check passes. The receipt catches it.
#[test]
fn a_truncated_log_signed_with_the_real_key_is_caught_by_the_receipt() {
    let mut c = ctx();
    let (mut w, anchors) = witness(&c.log_anchors);
    append(&mut c.log, 9, 0xA0);
    let h = head(&c, T0);
    let r = w.witness(&h, None, T0 + 10).unwrap();
    assert_eq!(r.size, 9);

    // Rewrite: the same log id, the same signing key, four records instead
    // of nine. Nothing inside NEXORA objects.
    let mut shorter = CommitmentLog::new(LOG_ID);
    append(&mut shorter, 4, 0xA0);
    let forged = shorter.head(&c.signer, T0 + 5_000).unwrap();
    aip_nexora::verify_signed_head(&forged, &c.log_anchors)
        .expect("the rewritten head is validly signed: that is the problem");

    let standing = audit(&shorter, &[r], &anchors);
    assert_eq!(
        standing,
        AnchorStanding::Diverged(Divergence::Truncated {
            witnessed_size: 9,
            current_size: 4,
        })
    );
    assert!(
        standing.explain().contains("5 record(s) were removed"),
        "{}",
        standing.explain()
    );
}

/// History rewritten in place: the same number of records, different
/// content. Sizes match, so only the root comparison catches it.
#[test]
fn a_log_rewritten_in_place_at_the_same_size_is_caught() {
    let mut c = ctx();
    let (mut w, anchors) = witness(&c.log_anchors);
    append(&mut c.log, 6, 0xA0);
    let r = w.witness(&head(&c, T0), None, T0 + 10).unwrap();

    let mut rewritten = CommitmentLog::new(LOG_ID);
    append(&mut rewritten, 6, 0xFF); // same count, different records
    let standing = audit(&rewritten, &[r], &anchors);
    assert!(
        matches!(
            standing,
            AnchorStanding::Diverged(Divergence::RootChanged { size: 6, .. })
        ),
        "{standing:?}"
    );
}

/// A rewritten log that is also *longer* than the witnessed one cannot
/// produce a consistency proof carrying the witnessed root forward.
#[test]
fn a_longer_but_different_history_is_not_an_extension() {
    let mut c = ctx();
    let (mut w, anchors) = witness(&c.log_anchors);
    append(&mut c.log, 5, 0xA0);
    let r = w.witness(&head(&c, T0), None, T0 + 10).unwrap();

    let mut rewritten = CommitmentLog::new(LOG_ID);
    append(&mut rewritten, 12, 0xFF);
    let standing = audit(&rewritten, &[r], &anchors);
    assert!(
        matches!(
            standing,
            AnchorStanding::Diverged(Divergence::NotAnExtension {
                witnessed_size: 5,
                current_size: 12,
            })
        ),
        "{standing:?}"
    );
}

/// Receipts for one log say nothing about another.
#[test]
fn receipts_for_another_log_do_not_vouch_for_this_one() {
    let mut c = ctx();
    let (mut w, anchors) = witness(&c.log_anchors);
    append(&mut c.log, 3, 0xA0);
    let r = w.witness(&head(&c, T0), None, T0 + 10).unwrap();

    let mut other = CommitmentLog::new([9u8; 16]);
    append(&mut other, 3, 0xA0);
    assert!(matches!(
        audit(&other, &[r], &anchors),
        AnchorStanding::Diverged(Divergence::DifferentLog { .. })
    ));
}

// ─── Absence of evidence ───

/// **Never a pass.** An unanchored log must not read as a clean one: that
/// confusion is the entire reason this crate exists.
#[test]
fn a_log_with_no_receipts_is_not_evaluated_and_is_not_consistent() {
    let mut c = ctx();
    append(&mut c.log, 5, 0xA0);
    let standing = audit(&c.log, &[], &WitnessAnchors::new());
    assert_eq!(
        standing,
        AnchorStanding::NotEvaluated(NotEvaluated::NoReceipts)
    );
    assert!(!standing.is_consistent());
    assert!(
        standing.explain().contains("absence"),
        "the reviewer must not read this as clean: {}",
        standing.explain()
    );
}

/// Receipts under anchors the auditor does not hold establish nothing, and
/// in particular do not establish consistency.
#[test]
fn receipts_from_an_untrusted_witness_are_not_evaluated() {
    let mut c = ctx();
    let (mut w, _) = witness(&c.log_anchors);
    append(&mut c.log, 3, 0xA0);
    let r = w.witness(&head(&c, T0), None, T0 + 10).unwrap();

    let standing = audit(&c.log, std::slice::from_ref(&r), &WitnessAnchors::new());
    assert!(
        matches!(
            standing,
            AnchorStanding::NotEvaluated(NotEvaluated::ReceiptsUnusable(
                WitnessError::UntrustedWitness { .. }
            ))
        ),
        "{standing:?}"
    );
    assert!(!standing.is_consistent());

    // An impostor key for the right name is not the right key either.
    let impostor = generate_ed25519_keypair();
    let standing = audit(
        &c.log,
        &[r],
        &WitnessAnchors::new().trust(WITNESS_ID, 3, &impostor.public_key),
    );
    assert!(!standing.is_consistent(), "{standing:?}");
}

/// A receipt removed from the middle of the set breaks the chain, so a
/// witness cannot quietly drop the one that contradicts a rewrite.
#[test]
fn a_receipt_removed_from_the_set_breaks_the_chain() {
    let mut c = ctx();
    let (mut w, anchors) = witness(&c.log_anchors);
    let mut receipts = Vec::new();
    let mut prev_size = 0;
    for i in 0..3u64 {
        append(&mut c.log, 2, i as u8);
        let proof = (prev_size > 0).then(|| c.log.consistency_since(prev_size).unwrap());
        let h = head(&c, T0 + i * 1_000);
        receipts.push(w.witness(&h, proof.as_ref(), T0 + i * 1_000 + 10).unwrap());
        prev_size = c.log.size();
    }
    verify_receipt_chain(&receipts, &anchors).unwrap();

    let without_middle = vec![receipts[0].clone(), receipts[2].clone()];
    assert!(matches!(
        verify_receipt_chain(&without_middle, &anchors),
        Err(WitnessError::ReceiptChainBroken { .. })
    ));
    let standing = audit(&c.log, &without_middle, &anchors);
    assert!(!standing.is_consistent(), "{standing:?}");
}

/// A receipt edited after signing does not verify.
#[test]
fn an_edited_receipt_does_not_verify() {
    let mut c = ctx();
    let (mut w, anchors) = witness(&c.log_anchors);
    append(&mut c.log, 4, 0xA0);
    let r = w.witness(&head(&c, T0), None, T0 + 10).unwrap();

    for mutate in [
        (|r: &mut WitnessReceipt| r.size = 2) as fn(&mut WitnessReceipt),
        |r| r.root = [0u8; 32],
        |r| r.witnessed_at_ms = 0,
        |r| r.head_issued_at_ms = 0,
        |r| r.prev_receipt = [1u8; 32],
        |r| r.log_id = [0u8; 16],
    ] {
        let mut edited = r.clone();
        mutate(&mut edited);
        assert_eq!(
            verify_receipt(&edited, &anchors),
            Err(WitnessError::PayloadHashMismatch),
            "every field a reader relies on must be inside the signature"
        );
    }
}

// ─── What the witness refuses to sign ───

/// A witness signs nothing it cannot itself verify.
#[test]
fn a_head_the_witness_cannot_verify_is_not_countersigned() {
    let mut c = ctx();
    // A witness provisioned with no NEXORA anchors at all.
    let kp = generate_ed25519_keypair();
    let mut blind = Witness::new(
        WITNESS_ID,
        3,
        &kp.private_key,
        &kp.public_key,
        NexoraTrustAnchors::new(),
    )
    .unwrap();
    append(&mut c.log, 2, 0xA0);
    assert!(matches!(
        blind.witness(&head(&c, T0), None, T0 + 10),
        Err(WitnessError::HeadNotVerified(_))
    ));
    assert_eq!(blind.state().receipts_issued, 0);
}

/// The check that gives a receipt its meaning: a witness holding the log's
/// own key is not a second party.
#[test]
fn a_witness_holding_the_logs_key_is_refused_at_construction() {
    let kp = generate_ed25519_keypair();
    let anchors = NexoraTrustAnchors::new().trust(NEXORA_ID, 1, &kp.public_key);
    assert_eq!(
        Witness::new(WITNESS_ID, 3, &kp.private_key, &kp.public_key, anchors).err(),
        Some(WitnessError::WitnessKeyIsLogKey)
    );
}

/// The witness refuses a rollback at witness time, not only at audit time.
#[test]
fn the_witness_refuses_to_countersign_a_shorter_log() {
    let mut c = ctx();
    let (mut w, _) = witness(&c.log_anchors);
    append(&mut c.log, 8, 0xA0);
    w.witness(&head(&c, T0), None, T0 + 10).unwrap();

    let mut shorter = CommitmentLog::new(LOG_ID);
    append(&mut shorter, 3, 0xA0);
    let forged = shorter.head(&c.signer, T0 + 100).unwrap();
    assert!(matches!(
        w.witness(&forged, None, T0 + 110),
        Err(WitnessError::NotAnExtension {
            witnessed: 8,
            offered: 3
        })
    ));
    // A refusal leaves no trace that could be mistaken for acceptance.
    assert_eq!(w.state().receipts_issued, 1);
    assert_eq!(w.state().last_size, 8);
}

/// Two roots at one size is a fork, refused rather than countersigned.
#[test]
fn the_witness_refuses_a_second_root_at_a_size_it_has_seen() {
    let mut c = ctx();
    let (mut w, _) = witness(&c.log_anchors);
    append(&mut c.log, 5, 0xA0);
    w.witness(&head(&c, T0), None, T0 + 10).unwrap();

    let mut sibling = CommitmentLog::new(LOG_ID);
    append(&mut sibling, 5, 0xFF);
    let other = sibling.head(&c.signer, T0 + 100).unwrap();
    assert!(matches!(
        w.witness(&other, None, T0 + 110),
        Err(WitnessError::Fork { size: 5, .. })
    ));
}

/// An extension without a consistency proof is a claim, and the witness
/// does not countersign claims.
#[test]
fn an_extension_without_a_consistency_proof_is_refused() {
    let mut c = ctx();
    let (mut w, _) = witness(&c.log_anchors);
    append(&mut c.log, 4, 0xA0);
    w.witness(&head(&c, T0), None, T0 + 10).unwrap();

    append(&mut c.log, 4, 0xB0);
    let h2 = head(&c, T0 + 1_000);
    assert!(matches!(
        w.witness(&h2, None, T0 + 1_010),
        Err(WitnessError::ConsistencyMissing { from: 4, to: 8 })
    ));

    // With the real proof it is accepted.
    let proof = c.log.consistency_since(4).unwrap();
    w.witness(&h2, Some(&proof), T0 + 1_010).unwrap();
}

/// A head dated materially in the witness's future is refused: a witness
/// cannot corroborate a time it has not reached.
#[test]
fn a_head_from_the_witnesss_future_is_refused() {
    let mut c = ctx();
    let (mut w, _) = witness(&c.log_anchors);
    append(&mut c.log, 2, 0xA0);
    let h = head(&c, T0 + 3_600_000);
    assert!(matches!(
        w.witness(&h, None, T0),
        Err(WitnessError::HeadFromTheFuture { .. })
    ));

    // Inside the stated tolerance it is accepted, and the skew is visible
    // in the receipt rather than smoothed away.
    let h2 = head(&c, T0 + 2_000);
    let r = w.witness(&h2, None, T0).unwrap();
    assert_eq!(r.log_clock_ahead_by_ms(), Some(2_000));
    assert_eq!(r.witnessed_at_ms, T0);
}

/// The head chain is checked too: a head that does not name the previously
/// witnessed head as its predecessor is a second history.
#[test]
fn a_head_that_does_not_chain_to_the_witnessed_one_is_refused() {
    let mut c = ctx();
    let (mut w, _) = witness(&c.log_anchors);
    append(&mut c.log, 3, 0xA0);
    w.witness(&head(&c, T0), None, T0 + 10).unwrap();

    // A parallel log that grew independently: valid consistency inside
    // itself, but its head does not follow the one that was witnessed.
    let mut parallel = CommitmentLog::new(LOG_ID);
    append(&mut parallel, 3, 0xA0);
    append(&mut parallel, 2, 0xB0);
    let h = parallel.head(&c.signer, T0 + 500).unwrap();
    let proof = parallel.consistency_since(3).unwrap();
    assert!(matches!(
        w.witness(&h, Some(&proof), T0 + 510),
        Err(WitnessError::HeadChainBroken)
    ));
}

/// A receipt of an unknown version is refused rather than interpreted.
#[test]
fn an_unknown_receipt_version_is_refused() {
    let mut c = ctx();
    let (mut w, anchors) = witness(&c.log_anchors);
    append(&mut c.log, 2, 0xA0);
    let mut r = w.witness(&head(&c, T0), None, T0 + 10).unwrap();
    r.version = WITNESS_RECEIPT_VERSION + 1;
    assert_eq!(
        verify_receipt(&r, &anchors),
        Err(WitnessError::UnsupportedVersion(
            WITNESS_RECEIPT_VERSION + 1
        ))
    );
}

/// Receipts are JSON, because they are what an institution hands a third
/// party and a format only this crate can read is one that can be lost
/// with it.
#[test]
fn a_receipt_round_trips_through_json() {
    let mut c = ctx();
    let (mut w, anchors) = witness(&c.log_anchors);
    append(&mut c.log, 2, 0xA0);
    let r = w.witness(&head(&c, T0), None, T0 + 10).unwrap();
    let back: WitnessReceipt = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
    verify_receipt(&back, &anchors).unwrap();
}
