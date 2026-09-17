//! SD-10 — a signed verdict committed to NEXORA, checked offline.
//!
//! The verdicts here come from the real reconciliation engine (`common`), are
//! signed by a reconciler authority (SD-09), committed as a
//! `SignedReconciliation` leaf, and verified by a party holding nothing but
//! the proof, the signed verdict, and its own anchors. Every refusal is pinned
//! by an attack that would otherwise let a bare, tampered, or foreign verdict
//! pass as a committed, attributed one.

mod common;

use aip_crypto::generate_ed25519_keypair;
use aip_nexora::{
    commit_signed_verdict, verify_committed_verdict, CommitmentLog, CommittedVerdictError,
    LeafKind, NexoraSigner, NexoraTrustAnchors,
};
use aip_reconcile::{
    ReconcilerSigner, ReconcilerTrustAnchors, ReconciliationAttestationError, ReconciliationResult,
    SignedReconciliation, RECONCILIATION_ATTESTATION_VERSION,
};

const LOG: [u8; 16] = [0x5d; 16];
const T0: u64 = 1_700_000_300_000;
const NX: &str = "nexora-1";
const RC: &str = "reconciler-1";

fn nexora() -> (NexoraSigner, NexoraTrustAnchors) {
    let kp = generate_ed25519_keypair();
    let signer = NexoraSigner::new(NX, 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = NexoraTrustAnchors::new().trust(NX, 1, &kp.public_key);
    (signer, anchors)
}

fn reconciler() -> (ReconcilerSigner, ReconcilerTrustAnchors) {
    let kp = generate_ed25519_keypair();
    let signer = ReconcilerSigner::new(RC, 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = ReconcilerTrustAnchors::new().trust(RC, 1, &kp.public_key);
    (signer, anchors)
}

#[test]
fn c01_a_signed_real_verdict_commits_and_verifies_offline() {
    let s = common::verified_execution();
    let (rc, rc_anchors) = reconciler();
    let (nx, nx_anchors) = nexora();

    let signed = rc.sign(&s.reconciliation).unwrap();
    let mut log = CommitmentLog::new(LOG);
    let i = commit_signed_verdict(&mut log, &signed);
    let head = log.head(&nx, T0).unwrap();
    let proof = log.proof_for(i, &head).unwrap();

    let v = verify_committed_verdict(&signed, &proof, &nx_anchors, &rc_anchors).unwrap();
    assert_eq!(v.inclusion.kind, LeafKind::SignedReconciliation);
    assert_eq!(v.inclusion.index, i);
    assert_eq!(v.reconciler_id, RC);
    assert_eq!(v.key_version, 1);
    // Carried verbatim from the engine's verdict — never restated or raised.
    assert_eq!(v.result, s.reconciliation.result);
    assert_eq!(v.strength, s.reconciliation.strength);
    assert_eq!(v.result, ReconciliationResult::VerifiedExecution);
    // The committed bytes are the signed verdict's canonical bytes, and the
    // verifier recomputed them from the struct it holds.
    assert_eq!(proof.record, signed.canonical_bytes());
    assert_eq!(v.inclusion.record_digest, signed.digest());
}

#[test]
fn c02_committed_bytes_are_not_the_signing_preimage() {
    // Domain separation between what the reconciler signed and what NEXORA
    // stores: the stored bytes carry the signature and a different domain, so
    // they can never be presented as a signing preimage.
    let s = common::verified_execution();
    let (rc, _) = reconciler();
    let signed = rc.sign(&s.reconciliation).unwrap();
    let preimage = SignedReconciliation::signing_preimage(
        RECONCILIATION_ATTESTATION_VERSION,
        RC,
        1,
        &s.reconciliation,
    );
    assert_ne!(signed.canonical_bytes(), preimage);
    // And neither is the bare verdict's own encoding.
    assert_ne!(signed.canonical_bytes(), s.reconciliation.canonical_bytes());
}

#[test]
fn c03_a_bare_reconciliation_leaf_is_not_a_signed_verdict() {
    // A bare (unsigned) verdict committed under the old leaf kind, presented
    // alongside a valid signed verdict: the proof verifies as a commitment, but
    // it is not a commitment of an *attributed* verdict.
    let s = common::verified_execution();
    let (rc, rc_anchors) = reconciler();
    let (nx, nx_anchors) = nexora();
    let signed = rc.sign(&s.reconciliation).unwrap();

    let mut log = CommitmentLog::new(LOG);
    let i = log.append(
        LeafKind::Reconciliation,
        &s.reconciliation.canonical_bytes(),
    );
    let head = log.head(&nx, T0).unwrap();
    let proof = log.proof_for(i, &head).unwrap();

    assert!(matches!(
        verify_committed_verdict(&signed, &proof, &nx_anchors, &rc_anchors),
        Err(CommittedVerdictError::WrongLeafKind(
            LeafKind::Reconciliation
        ))
    ));
}

#[test]
fn c04_a_proof_for_another_verdict_does_not_bind() {
    // Two genuine, differently-signed verdicts. A proof for A offered with
    // signed verdict B: B's attestation and A's commitment both verify on
    // their own, but the bytes do not bind — refused.
    let a = common::verified_execution();
    let b = common::cannot_prove();
    let (rc, rc_anchors) = reconciler();
    let (nx, nx_anchors) = nexora();
    let signed_a = rc.sign(&a.reconciliation).unwrap();
    let signed_b = rc.sign(&b.reconciliation).unwrap();
    assert_ne!(signed_a.canonical_bytes(), signed_b.canonical_bytes());

    let mut log = CommitmentLog::new(LOG);
    let i = commit_signed_verdict(&mut log, &signed_a);
    let head = log.head(&nx, T0).unwrap();
    let proof_a = log.proof_for(i, &head).unwrap();

    assert!(matches!(
        verify_committed_verdict(&signed_b, &proof_a, &nx_anchors, &rc_anchors),
        Err(CommittedVerdictError::RecordMismatch)
    ));
}

#[test]
fn c05_an_untrusted_reconciler_is_refused_before_the_log_is_consulted() {
    let s = common::verified_execution();
    let (rc, _) = reconciler();
    let (nx, nx_anchors) = nexora();
    let signed = rc.sign(&s.reconciliation).unwrap();
    let mut log = CommitmentLog::new(LOG);
    let i = commit_signed_verdict(&mut log, &signed);
    let head = log.head(&nx, T0).unwrap();
    let proof = log.proof_for(i, &head).unwrap();

    // The verifier anchors no reconciler at all.
    let none = ReconcilerTrustAnchors::new();
    assert!(matches!(
        verify_committed_verdict(&signed, &proof, &nx_anchors, &none),
        Err(CommittedVerdictError::Attestation(
            ReconciliationAttestationError::UntrustedReconciler { .. }
        ))
    ));
}

#[test]
fn c06_a_verdict_tampered_after_commit_is_refused() {
    let s = common::verified_execution();
    let (rc, rc_anchors) = reconciler();
    let (nx, nx_anchors) = nexora();
    let mut signed = rc.sign(&s.reconciliation).unwrap();
    let mut log = CommitmentLog::new(LOG);
    let i = commit_signed_verdict(&mut log, &signed);
    let head = log.head(&nx, T0).unwrap();
    let proof = log.proof_for(i, &head).unwrap();

    // Relabel the committed verdict as the strongest ghost signal.
    signed.reconciliation.result = ReconciliationResult::UnattributedEffect;
    assert!(matches!(
        verify_committed_verdict(&signed, &proof, &nx_anchors, &rc_anchors),
        Err(CommittedVerdictError::Attestation(
            ReconciliationAttestationError::PayloadHashMismatch
        ))
    ));
}

#[test]
fn c07_a_head_the_verifier_does_not_anchor_is_refused() {
    let s = common::verified_execution();
    let (rc, rc_anchors) = reconciler();
    let (nx, _) = nexora();
    let signed = rc.sign(&s.reconciliation).unwrap();
    let mut log = CommitmentLog::new(LOG);
    let i = commit_signed_verdict(&mut log, &signed);
    let head = log.head(&nx, T0).unwrap();
    let proof = log.proof_for(i, &head).unwrap();

    // The verifier anchors no NEXORA signer.
    let none = NexoraTrustAnchors::new();
    assert!(matches!(
        verify_committed_verdict(&signed, &proof, &none, &rc_anchors),
        Err(CommittedVerdictError::Commitment(_))
    ));
}
