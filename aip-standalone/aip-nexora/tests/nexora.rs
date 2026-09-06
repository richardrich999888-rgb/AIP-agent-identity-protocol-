//! Gate 7 — NEXORA: the proof layer over the commitment, RED.
//!
//! ```text
//! records (attested batches, signed health, reconciliation records,
//!          warrants, expectations — each already signed by its own authority)
//!     │  append, in order, as domain-separated leaves
//!     ▼
//! CommitmentLog ── head(signer) ──▶ SignedHead   (log id, size, root, prev head,
//!     │                                           time; NEXORA's own key)
//!     └── proof_for(index, head) ──▶ ProofObject  (head + kind + record bytes
//!                                                 + inclusion path)
//!                                        │
//!                    verify_proof(proof, anchors) — offline, no log access —
//!                    ▶ VerifiedInclusion { log, size, root, index, kind, digest }
//!
//! HeadTracker: what an offline party remembers about one log — the last
//! head it accepted — and the only way forward: a newer head with a
//! consistency proof from the remembered size. Rollback, fork and a broken
//! head chain are refusals; the same head twice is not an advance.
//! AnchorSink: where heads go so that a party outside NEXORA holds them —
//! without that, a prefix of the log verifies as well as the whole.
//! ```
//!
//! What NEXORA is not (`NEXORA_BOUNDARY.md`, rule 17): a `VerifiedInclusion`
//! says a record was committed at a position under a head signed by a key
//! the verifier anchors. It says nothing about whether the record's own
//! claims hold — a committed `CANNOT_PROVE` is exactly as committed as a
//! committed `VERIFIED_EXECUTION` — and it authorizes nothing. No "replay"
//! of anything is claimed: the record bytes are what was committed, and the
//! offline verifier re-derives their digest and hands them back for the
//! record's own verifier.

use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_nexora::commitment::*;
use aip_nexora::merkle::{ConsistencyProof, LeafKind};

const LOG_A: [u8; 16] = [0xa1; 16];
const LOG_B: [u8; 16] = [0xb2; 16];
const T0: u64 = 1_788_000_000_000;

struct Nexora {
    signer: NexoraSigner,
    anchors: NexoraTrustAnchors,
}

fn nexora(id: &str) -> Nexora {
    let kp = generate_ed25519_keypair();
    let signer = NexoraSigner::new(id, 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = NexoraTrustAnchors::new().trust(id, 1, &kp.public_key);
    Nexora { signer, anchors }
}

fn rec(i: u32) -> Vec<u8> {
    format!("reconciliation-record-{i}").into_bytes()
}

fn log_with(id: [u8; 16], n: u32) -> CommitmentLog {
    let mut log = CommitmentLog::new(id);
    for i in 0..n {
        log.append(LeafKind::Reconciliation, &rec(i));
    }
    log
}

// ═══ Signed heads ═══

#[test]
fn x01_a_head_signs_the_log_size_root_and_previous_head_under_nexoras_own_key() {
    let nx = nexora("nexora-1");
    let mut log = log_with(LOG_A, 3);
    let h1 = log.head(&nx.signer, T0).unwrap();
    assert_eq!(NEXORA_VERSION, 1);
    assert_eq!(h1.version, NEXORA_VERSION);
    assert_eq!(h1.log_id, LOG_A);
    assert_eq!(h1.size, 3);
    assert_eq!(h1.root, log.root());
    assert_eq!(
        h1.prev_head, [0u8; 32],
        "the first head of a log chains from zero"
    );
    assert_eq!(h1.issued_at_ms, T0);
    assert_eq!(h1.signer_id, "nexora-1");
    assert_eq!(h1.key_version, 1);
    verify_signed_head(&h1, &nx.anchors).unwrap();
    // The preimage is domain-tagged and the digest deterministic.
    let pre = h1.signing_preimage();
    assert!(pre
        .windows(HEAD_DOMAIN.len())
        .any(|w| w == HEAD_DOMAIN.as_bytes()));
    assert!(HEAD_DOMAIN.starts_with("SYNTRIASS/NEXORA/"));
    assert_eq!(h1.digest(), sha256(&pre));
    // The next head chains from this one.
    log.append(LeafKind::Warrant, b"warrant-1");
    let h2 = log.head(&nx.signer, T0 + 1).unwrap();
    assert_eq!(h2.prev_head, h1.digest());
    assert_eq!(h2.size, 4);
    verify_signed_head(&h2, &nx.anchors).unwrap();
    assert_eq!(log.last_head().map(|h| h.digest()), Some(h2.digest()));
}

#[test]
fn x02_a_head_altered_after_signing_or_signed_by_an_unanchored_key_is_refused() {
    let nx = nexora("nexora-1");
    let log = log_with(LOG_A, 5);
    let h = log.head(&nx.signer, T0).unwrap();
    let mut t = h.clone();
    t.size = 4;
    assert!(matches!(
        verify_signed_head(&t, &nx.anchors),
        Err(NexoraError::PayloadHashMismatch)
    ));
    let mut t = h.clone();
    t.root[0] ^= 1;
    assert!(verify_signed_head(&t, &nx.anchors).is_err());
    let mut t = h.clone();
    t.prev_head[0] ^= 1;
    assert!(verify_signed_head(&t, &nx.anchors).is_err());
    let mut t = h.clone();
    t.log_id = LOG_B;
    assert!(verify_signed_head(&t, &nx.anchors).is_err());
    let mut t = h.clone();
    t.issued_at_ms += 1;
    assert!(verify_signed_head(&t, &nx.anchors).is_err());
    let mut t = h.clone();
    t.signer_id = "nexora-2".into();
    assert!(verify_signed_head(&t, &nx.anchors).is_err());
    // A signer id the verifier does not anchor at all.
    let stranger = nexora("nexora-9");
    assert!(matches!(
        verify_signed_head(&h, &stranger.anchors),
        Err(NexoraError::UntrustedKey { .. })
    ));
    // The same signer id under a key the verifier does not hold: the
    // anchored key is consulted and the signature fails against it.
    let impostor = nexora("nexora-1");
    let h_impostor = log.head(&impostor.signer, T0).unwrap();
    assert!(matches!(
        verify_signed_head(&h_impostor, &nx.anchors),
        Err(NexoraError::SignatureInvalid)
    ));
}

#[test]
fn x03_the_empty_log_has_a_head_and_no_proofs() {
    let nx = nexora("nexora-1");
    let log = CommitmentLog::new(LOG_A);
    let h = log.head(&nx.signer, T0).unwrap();
    assert_eq!(h.size, 0);
    assert_eq!(h.root, aip_crypto::merkle_empty());
    verify_signed_head(&h, &nx.anchors).unwrap();
    assert!(matches!(
        log.proof_for(0, &h),
        Err(NexoraError::IndexOutOfRange { .. })
    ));
}

// ═══ Proof objects and the offline verifier ═══

#[test]
fn x04_a_proof_object_verifies_offline_and_yields_what_was_committed_and_nothing_more() {
    let nx = nexora("nexora-1");
    let mut log = log_with(LOG_A, 7);
    log.append(LeafKind::AttestedBatch, b"batch-bytes");
    let h = log.head(&nx.signer, T0).unwrap();
    let p = log.proof_for(7, &h).unwrap();
    assert_eq!(p.version, NEXORA_VERSION);
    assert_eq!(p.log_id, LOG_A);
    assert_eq!(p.kind, LeafKind::AttestedBatch);
    assert_eq!(p.record, b"batch-bytes");
    assert_eq!(p.inclusion.index, 7);
    assert_eq!(p.inclusion.size, 8);
    assert_eq!(p.head.digest(), h.digest());
    // Offline: only the proof and the anchors.
    let v = verify_proof(&p, &nx.anchors).unwrap();
    assert_eq!(v.log_id, LOG_A);
    assert_eq!(v.size, 8);
    assert_eq!(v.root, h.root);
    assert_eq!(v.index, 7);
    assert_eq!(v.kind, LeafKind::AttestedBatch);
    assert_eq!(v.record_digest, sha256(b"batch-bytes"));
    assert_eq!(v.head_digest, h.digest());
    // Nothing in the verified result speaks of authorization or truth.
    let json = serde_json::to_string(&v).unwrap().to_lowercase();
    for forbidden in [
        "verified_execution",
        "permitted",
        "authorized",
        "trusted",
        "valid_action",
    ] {
        assert!(!json.contains(forbidden), "{forbidden} in {json}");
    }
    // The proof object travels as bytes and comes back whole.
    let back: ProofObject = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
    assert_eq!(back, p);
    assert_eq!(back.digest(), p.digest());
    assert!(PROOF_DOMAIN.starts_with("SYNTRIASS/NEXORA/"));
    assert_ne!(p.digest(), h.digest());
}

#[test]
fn x05_a_committed_cannot_prove_is_exactly_as_committed_as_anything_else() {
    // NEXORA commits records; it does not judge them (rule 17).
    let nx = nexora("nexora-1");
    let mut log = CommitmentLog::new(LOG_A);
    log.append(
        LeafKind::Reconciliation,
        b"result=CANNOT_PROVE reason=NoObserverEvidence",
    );
    log.append(LeafKind::Reconciliation, b"result=VERIFIED_EXECUTION");
    let h = log.head(&nx.signer, T0).unwrap();
    for i in 0..2 {
        let p = log.proof_for(i, &h).unwrap();
        let v = verify_proof(&p, &nx.anchors).unwrap();
        assert_eq!(v.index, i);
        assert_eq!(v.kind, LeafKind::Reconciliation);
    }
}

#[test]
fn x06_a_changed_record_or_a_changed_kind_is_not_included() {
    let nx = nexora("nexora-1");
    let log = log_with(LOG_A, 6);
    let h = log.head(&nx.signer, T0).unwrap();
    let p = log.proof_for(2, &h).unwrap();
    let mut t = p.clone();
    t.record.push(b' ');
    assert!(matches!(
        verify_proof(&t, &nx.anchors),
        Err(NexoraError::LeafNotIncluded)
    ));
    let mut t = p.clone();
    t.kind = LeafKind::Warrant;
    assert!(matches!(
        verify_proof(&t, &nx.anchors),
        Err(NexoraError::LeafNotIncluded)
    ));
    let mut t = p.clone();
    t.inclusion.index = 3;
    assert!(verify_proof(&t, &nx.anchors).is_err());
}

#[test]
fn x07_a_proof_cannot_be_transplanted_to_another_log_or_another_head() {
    let nx = nexora("nexora-1");
    let a = log_with(LOG_A, 6);
    let mut b = CommitmentLog::new(LOG_B);
    for i in [9u32, 2, 8] {
        b.append(LeafKind::Reconciliation, &rec(i));
    }
    let ha = a.head(&nx.signer, T0).unwrap();
    let hb = b.head(&nx.signer, T0).unwrap();
    let pa = a.proof_for(2, &ha).unwrap();
    // Same leaf exists in B at index 1; A's proof with B's head.
    let mut t = pa.clone();
    t.head = hb.clone();
    assert!(matches!(
        verify_proof(&t, &nx.anchors),
        Err(NexoraError::LogMismatch { .. })
    ));
    let mut t = pa.clone();
    t.log_id = LOG_B;
    t.head = hb.clone();
    assert!(
        verify_proof(&t, &nx.anchors).is_err(),
        "B's head does not carry A's path"
    );
    // A proof made for a head of size 6 against a later head of size 7.
    let mut a2 = a.clone();
    a2.append(LeafKind::Reconciliation, &rec(6));
    let ha2 = a2.head(&nx.signer, T0 + 1).unwrap();
    let mut t = pa.clone();
    t.head = ha2;
    assert!(matches!(
        verify_proof(&t, &nx.anchors),
        Err(NexoraError::SizeMismatch { .. })
    ));
    // proof_for refuses a head that is not the log's current state.
    assert!(matches!(
        a2.proof_for(2, &ha),
        Err(NexoraError::SizeMismatch { .. })
    ));
}

#[test]
fn x08_a_proof_under_a_tampered_or_unanchored_head_is_refused_before_anything_else() {
    let nx = nexora("nexora-1");
    let log = log_with(LOG_A, 4);
    let h = log.head(&nx.signer, T0).unwrap();
    let p = log.proof_for(1, &h).unwrap();
    let mut t = p.clone();
    t.head.root[5] ^= 0x40;
    assert!(matches!(
        verify_proof(&t, &nx.anchors),
        Err(NexoraError::PayloadHashMismatch)
    ));
    let stranger = nexora("nexora-9");
    assert!(matches!(
        verify_proof(&p, &stranger.anchors),
        Err(NexoraError::UntrustedKey { .. })
    ));
    let impostor = nexora("nexora-1");
    assert!(matches!(
        verify_proof(&p, &impostor.anchors),
        Err(NexoraError::SignatureInvalid)
    ));
    let mut t = p.clone();
    t.version = 2;
    assert!(matches!(
        verify_proof(&t, &nx.anchors),
        Err(NexoraError::UnsupportedVersion(2))
    ));
}

// ═══ The offline party's memory: HeadTracker ═══

#[test]
fn x09_a_tracker_advances_only_forward_with_a_consistency_proof() {
    let nx = nexora("nexora-1");
    let mut log = log_with(LOG_A, 3);
    let h3 = log.head(&nx.signer, T0).unwrap();
    let mut tracker = HeadTracker::new();
    assert_eq!(
        tracker.advance(&h3, None, &nx.anchors).unwrap(),
        Advance::First
    );
    assert_eq!(tracker.size(), Some(3));
    // Grow to 5.
    log.append(LeafKind::Reconciliation, &rec(3));
    log.append(LeafKind::Reconciliation, &rec(4));
    let h5 = log.head(&nx.signer, T0 + 1).unwrap();
    let c = log.consistency_since(3).unwrap();
    assert!(matches!(
        tracker.advance(&h5, None, &nx.anchors),
        Err(NexoraError::ConsistencyMissing)
    ));
    assert_eq!(
        tracker.advance(&h5, Some(&c), &nx.anchors).unwrap(),
        Advance::Extended { from: 3, to: 5 }
    );
    assert_eq!(tracker.head().map(|h| h.digest()), Some(h5.digest()));
    // The same head again: not an advance, not an error.
    assert_eq!(
        tracker.advance(&h5, None, &nx.anchors).unwrap(),
        Advance::Same
    );
}

#[test]
fn x10_rollback_is_refused() {
    let nx = nexora("nexora-1");
    let mut log = log_with(LOG_A, 4);
    let h4 = log.head(&nx.signer, T0).unwrap();
    log.append(LeafKind::Reconciliation, &rec(4));
    let h5 = log.head(&nx.signer, T0 + 1).unwrap();
    let c = log.consistency_since(4).unwrap();
    let mut tracker = HeadTracker::new();
    tracker.advance(&h4, None, &nx.anchors).unwrap();
    tracker.advance(&h5, Some(&c), &nx.anchors).unwrap();
    // Offered the older head again, even with its valid signature.
    assert!(matches!(
        tracker.advance(&h4, None, &nx.anchors),
        Err(NexoraError::Rollback { from: 5, to: 4 })
    ));
    assert_eq!(tracker.size(), Some(5), "the tracker keeps the larger size");
}

#[test]
fn x11_a_fork_is_refused() {
    let nx = nexora("nexora-1");
    let base = log_with(LOG_A, 4);
    let mut a = base.clone();
    a.append(LeafKind::Reconciliation, &rec(4));
    let mut b = base.clone();
    b.append(LeafKind::Reconciliation, b"a different fifth record");
    let h4 = base.head(&nx.signer, T0).unwrap();
    a.set_last_head(h4.clone());
    b.set_last_head(h4.clone());
    let ha = a.head(&nx.signer, T0 + 1).unwrap();
    let hb = b.head(&nx.signer, T0 + 1).unwrap();
    assert_eq!(ha.size, hb.size);
    assert_ne!(ha.root, hb.root);
    let mut tracker = HeadTracker::new();
    tracker.advance(&h4, None, &nx.anchors).unwrap();
    tracker
        .advance(&ha, Some(&a.consistency_since(4).unwrap()), &nx.anchors)
        .unwrap();
    assert!(matches!(
        tracker.advance(&hb, Some(&b.consistency_since(4).unwrap()), &nx.anchors),
        Err(NexoraError::Fork { size: 5 })
    ));
    // Even from a fresh tracker at h4, B's proof does not reach A's head.
    let mut fresh = HeadTracker::new();
    fresh.advance(&h4, None, &nx.anchors).unwrap();
    assert!(matches!(
        fresh.advance(&ha, Some(&b.consistency_since(4).unwrap()), &nx.anchors),
        Err(NexoraError::ConsistencyInvalid)
    ));
}

#[test]
fn x12_a_broken_head_chain_is_refused() {
    let nx = nexora("nexora-1");
    let mut log = log_with(LOG_A, 2);
    let h2 = log.head(&nx.signer, T0).unwrap();
    log.append(LeafKind::Reconciliation, &rec(2));
    let mut h3 = log.head(&nx.signer, T0 + 1).unwrap();
    // A head re-signed with the wrong predecessor.
    h3.prev_head = [0x55; 32];
    let h3 = nx.signer.resign(h3).unwrap();
    verify_signed_head(&h3, &nx.anchors).unwrap();
    let mut tracker = HeadTracker::new();
    tracker.advance(&h2, None, &nx.anchors).unwrap();
    assert!(matches!(
        tracker.advance(&h3, Some(&log.consistency_since(2).unwrap()), &nx.anchors),
        Err(NexoraError::HeadChainBroken)
    ));
}

#[test]
fn x13_a_consistency_proof_that_does_not_fit_is_refused() {
    let nx = nexora("nexora-1");
    let mut log = log_with(LOG_A, 3);
    let h3 = log.head(&nx.signer, T0).unwrap();
    log.append(LeafKind::Reconciliation, &rec(3));
    let h4 = log.head(&nx.signer, T0 + 1).unwrap();
    let mut tracker = HeadTracker::new();
    tracker.advance(&h3, None, &nx.anchors).unwrap();
    let wrong = ConsistencyProof {
        old_size: 2,
        new_size: 4,
        path: log.consistency_since(2).unwrap().path,
    };
    assert!(matches!(
        tracker.advance(&h4, Some(&wrong), &nx.anchors),
        Err(NexoraError::ConsistencyInvalid)
    ));
    let mut bad = log.consistency_since(3).unwrap();
    bad.path.push([0u8; 32]);
    assert!(matches!(
        tracker.advance(&h4, Some(&bad), &nx.anchors),
        Err(NexoraError::ConsistencyInvalid)
    ));
    // A head of another log never advances this tracker.
    let other = log_with(LOG_B, 4).head(&nx.signer, T0 + 2).unwrap();
    assert!(matches!(
        tracker.advance(&other, None, &nx.anchors),
        Err(NexoraError::LogMismatch { .. })
    ));
}

// ═══ Anchoring interface ═══

#[test]
fn x14_heads_are_published_to_an_anchor_outside_the_log_and_tracked_from_there() {
    let nx = nexora("nexora-1");
    let mut sink = MemoryAnchor::default();
    let mut log = log_with(LOG_A, 2);
    let h2 = log.head(&nx.signer, T0).unwrap();
    sink.publish(&h2).unwrap();
    log.append(LeafKind::Reconciliation, &rec(2));
    let h3 = log.head(&nx.signer, T0 + 1).unwrap();
    sink.publish(&h3).unwrap();
    assert_eq!(sink.heads().len(), 2);
    // A party holding only the anchor and the proofs can follow the log.
    let mut tracker = HeadTracker::new();
    let heads = sink.heads().to_vec();
    tracker.advance(&heads[0], None, &nx.anchors).unwrap();
    tracker
        .advance(
            &heads[1],
            Some(&log.consistency_since(2).unwrap()),
            &nx.anchors,
        )
        .unwrap();
    // A truncated log (a later head of smaller size) is refused by that party.
    let truncated = log_with(LOG_A, 1).head(&nx.signer, T0 + 2).unwrap();
    assert!(matches!(
        tracker.advance(&truncated, None, &nx.anchors),
        Err(NexoraError::Rollback { .. })
    ));
    // The sink refuses to anchor a head that does not verify.
    let mut bad = h3.clone();
    bad.size = 9;
    assert!(sink.publish_verified(&bad, &nx.anchors).is_err());
}

// ═══ Real records ═══

#[test]
fn x15_a_real_reconciliation_record_is_committed_by_its_canonical_bytes_and_read_back_by_its_own_digest(
) {
    use aip_observe::{ObservationAvailability, UnavailableReason};
    use aip_reconcile::{
        ActionComparison, DecisionId, EvidenceStrength, IdentityComparison, LineageComparison,
        ReasonCode, Reconciliation, ReconciliationResult, TemporalComparison, WireCorroboration,
        RECONCILIATION_VERSION,
    };
    let r = {
        let mut r = Reconciliation::fixture_default();
        r.version = RECONCILIATION_VERSION;
        r.result = ReconciliationResult::CannotProve;
        r.strength = EvidenceStrength::Heuristic;
        r.reason = ReasonCode::NoObserverEvidence;
        r.decision_id = Some(DecisionId::from_bytes([0x11; 16]));
        r.availability = ObservationAvailability::Unavailable {
            reason: UnavailableReason::NoObserver,
        };
        r.identity = IdentityComparison::NoReference;
        r.action = ActionComparison::Unobservable;
        r.temporal = TemporalComparison::Indeterminate;
        r.lineage = LineageComparison::NotEvaluated;
        r.wire = WireCorroboration::NotEvaluated;
        r.replay_detected = false;
        r.evidence = vec![];
        r.verification_time_ms = T0;
        r
    };
    let nx = nexora("nexora-1");
    let mut log = CommitmentLog::new(LOG_A);
    let i = log.append(LeafKind::Reconciliation, &r.canonical_bytes());
    let h = log.head(&nx.signer, T0).unwrap();
    let p = log.proof_for(i, &h).unwrap();
    let v = verify_proof(&p, &nx.anchors).unwrap();
    assert_eq!(
        v.record_digest,
        r.digest(),
        "the record's own digest, recomputed"
    );
    // The verifier reads the record from the bytes it holds, never from the
    // proof's word: the bytes decode to the same record.
    assert_eq!(p.record, r.canonical_bytes());
    assert_eq!(v.kind, LeafKind::Reconciliation);
}
