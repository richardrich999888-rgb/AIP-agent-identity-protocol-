//! Phase 14 — NEXORA and the reconciler are reused, and neither is changed.
//!
//! # The non-change, stated explicitly
//!
//! Skill 22 required **no code change to `aip-nexora` and none to
//! `aip-reconcile`.** This test is the evidence for that claim: it commits the
//! artifacts of a real reference run to a real `CommitmentLog`, using only
//! leaf kinds that already existed, and verifies an inclusion proof offline
//! against a signed head — with no new leaf kind, no new anchor and no new
//! entry point.
//!
//! # Why the `EdgeReference` report is not itself committed
//!
//! It could be. It has domain-tagged, injective canonical bytes and a digest,
//! for exactly that purpose. Committing it would require a tenth `LeafKind`,
//! and that is a schema change to the commitment layer for the sake of a
//! *report* — a projection of artifacts that are already committed
//! individually. A verifier that holds the batches, the health record, the
//! expectation and the reconciliation can recompute everything the report
//! says. Adding a leaf kind so a summary can be committed alongside its own
//! inputs buys nothing and costs a permanent wire commitment.
//!
//! So the report's digest exists and nothing in this build commits it. That is
//! a deliberate non-change, recorded here rather than left as an absence
//! someone later reads as an oversight.

mod common;

use aip_edge::orchestrate::Scenario;
use aip_nexora::{verify_proof, CommitmentLog, LeafKind, NexoraSigner, NexoraTrustAnchors};

use common::run_scenario;

#[test]
fn a_real_run_commits_to_nexora_with_no_new_leaf_kind() {
    let o = run_scenario("nexora", Scenario::Honest);

    let kp = aip_crypto::generate_ed25519_keypair();
    let signer = NexoraSigner::new("edge-reference-log", 1, &kp.private_key, &kp.public_key)
        .expect("signer");
    let anchors = NexoraTrustAnchors::new().trust("edge-reference-log", 1, &kp.public_key);

    let mut log = CommitmentLog::new([0x22; 16]);

    // Every leaf below uses a kind that existed at baseline. Codes 0x01-0x05
    // are frozen; nothing here appends to that list.
    let expectation_index = log.append(LeafKind::Expectation, &o.expectation.signing_preimage());
    let reconciliation_index = log.append(
        LeafKind::Reconciliation,
        &o.reference.reconciliation.canonical_bytes(),
    );
    let mut batch_indices = Vec::new();
    for b in &o.batches {
        batch_indices.push(log.append(LeafKind::AttestedBatch, &b.batch.canonical_bytes()));
    }
    for h in &o.health {
        log.append(LeafKind::SignedHealth, &h.health.canonical_bytes());
    }

    let head = log.head(&signer, 1_000).expect("head");
    assert!(log.size() >= 4, "the run must produce something to commit");

    // An offline verifier, holding only the anchors, checks inclusion.
    for index in [expectation_index, reconciliation_index] {
        let proof = log.proof_for(index, &head).expect("proof");
        let verified = verify_proof(&proof, &anchors).expect("inclusion");
        assert_eq!(verified.index, index);
        assert_eq!(verified.root, head.root);
    }
    for index in batch_indices {
        let proof = log.proof_for(index, &head).expect("proof");
        verify_proof(&proof, &anchors).expect("inclusion");
    }
}

#[test]
fn an_unanchored_head_proves_nothing() {
    let o = run_scenario("nexora-neg", Scenario::Honest);
    let kp = aip_crypto::generate_ed25519_keypair();
    let signer = NexoraSigner::new("edge-reference-log", 1, &kp.private_key, &kp.public_key)
        .expect("signer");
    // The verifier anchors a different signer entirely.
    let other = aip_crypto::generate_ed25519_keypair();
    let anchors = NexoraTrustAnchors::new().trust("someone-else", 1, &other.public_key);

    let mut log = CommitmentLog::new([0x22; 16]);
    let index = log.append(
        LeafKind::Reconciliation,
        &o.reference.reconciliation.canonical_bytes(),
    );
    let head = log.head(&signer, 1_000).expect("head");
    let proof = log.proof_for(index, &head).expect("proof");
    assert!(
        verify_proof(&proof, &anchors).is_err(),
        "a head signed by a party the verifier never anchored must establish nothing"
    );
}

#[test]
fn nexora_and_reconcile_were_not_modified_by_skill_22() {
    // A structural statement about the change set, checkable from the source:
    // the reference introduces no leaf kind and no reconciliation entry point.
    // If a future change adds either, this test names the file to look at.
    assert_eq!(
        LeafKind::ALL.len(),
        11,
        "Skill 22 must add no leaf kind; codes 0x01-0x05 are frozen and the list stands at \
         eleven (the tenth, `SignedReconciliation`, is SD-10's signed verdict leaf; the \
         eleventh, `AccessLedger`, is R3's per-agent ledger — neither is the edge reference's)"
    );
    let merkle = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../aip-nexora/src/merkle.rs"
    ))
    .expect("merkle source");
    assert!(
        !merkle.contains("EdgeReference"),
        "the commitment layer must not know the reference report exists"
    );
    let reconcile = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../aip-reconcile/src/reconcile.rs"
    ))
    .expect("reconcile source");
    for name in [
        "aip_edge",
        "EdgeReference",
        "ObservationRecord",
        "EffectAssessment",
    ] {
        assert!(
            !reconcile.contains(name),
            "the reconciliation engine must not know about {name}: the dependency points one \
             way, and a description layer the verdict layer can see is a description layer \
             that can cause a semantic regression in it"
        );
    }
}
