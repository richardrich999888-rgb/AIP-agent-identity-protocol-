//! R3 — the access ledger over a real-engine scenario, committed to NEXORA
//! and verified offline.
//!
//! The scenario is `common::verified_execution()`: a real decision point
//! authorises a real chain, a real collector attests a kernel-pushed connect
//! initiation claimed for the agent, and the real reconciler returns
//! `VERIFIED_EXECUTION · Attested`. The ledger names the endpoint as the
//! institution's registry names it, cites the reconciler's signed verdict to
//! that row through the decision the observation claimed, and is committed as
//! its own leaf.

mod common;

use aip_crypto::generate_ed25519_keypair;
use aip_ledger::{
    AccessLedger, AccessLedgerBuilder, LedgerSigner, LedgerTrustAnchors, ResourceRef, Standing,
};
use aip_nexora::{
    commit_access_ledger, commit_signed_verdict, verify_committed_ledger, CommitmentLog,
    CommittedLedgerError, LeafKind, NexoraSigner, NexoraTrustAnchors,
};
use aip_reconcile::{ReconcilerSigner, ReconcilerTrustAnchors, ReconciliationResult};
use aip_registry::{
    AddressRange, Criticality, PortRange, Protocol, RegistryTrustAnchors, ResourceEntry,
    ResourceRegistry,
};
use aip_types::CoverageWindow;
use common::{verified_execution, Scenario, PORT, REMOTE};

const RC: &str = "reconciler-1";

fn registry() -> (ResourceRegistry, RegistryTrustAnchors) {
    let kp = generate_ed25519_keypair();
    let reg = ResourceRegistry::sign(
        "bank/dc1",
        "bank.example",
        &kp.private_key,
        9,
        1_600_000_000_000,
        vec![ResourceEntry {
            id: "core-banking-api".into(),
            display_name: "Core banking API".into(),
            criticality: Criticality::TransactionCritical,
            protocol: Protocol::Tcp,
            addresses: vec![AddressRange::v4_host(REMOTE)],
            ports: vec![PortRange::single(PORT)],
        }],
    )
    .unwrap();
    (
        reg,
        RegistryTrustAnchors::new().trust("bank.example", &kp.public_key),
    )
}

struct Built {
    ledger: AccessLedger,
    ledger_anchors: LedgerTrustAnchors,
}

fn ledger_over(s: &Scenario) -> Built {
    let (reg, reg_anchors) = registry();
    let window = CoverageWindow {
        from_ms: s.a.now - 60_000,
        to_ms: s.at + 60_000,
    };
    let mut b = AccessLedgerBuilder::new(&s.a.agent_id, window, &reg, &reg_anchors).unwrap();
    for batch in &s.evidence.batches {
        b.observe(batch, &s.o.anchors).unwrap();
    }
    let rkp = generate_ed25519_keypair();
    let rsigner = ReconcilerSigner::new(RC, 1, &rkp.private_key, &rkp.public_key).unwrap();
    let ranchors = ReconcilerTrustAnchors::new().trust(RC, 1, &rkp.public_key);
    let signed = rsigner.sign(&s.reconciliation).unwrap();
    b.cite(&signed, &ranchors).unwrap();
    let lkp = generate_ed25519_keypair();
    let lsigner = LedgerSigner::new("ledger-1", 1, &lkp.private_key, &lkp.public_key);
    let ledger = b.build_and_sign(&lsigner, s.at + 90_000).unwrap();
    Built {
        ledger,
        ledger_anchors: LedgerTrustAnchors::new().trust("ledger-1", 1, &lkp.public_key),
    }
}

#[test]
fn a_real_verified_execution_becomes_a_named_verified_row() {
    let s = verified_execution();
    assert_eq!(
        s.reconciliation.result,
        ReconciliationResult::VerifiedExecution
    );
    let b = ledger_over(&s);
    assert_eq!(b.ledger.verify(&b.ledger_anchors), Ok(()));

    let rows: Vec<_> = b
        .ledger
        .entries
        .iter()
        .filter(|e| e.endpoint.port == PORT)
        .collect();
    assert_eq!(rows.len(), 1, "{:#?}", b.ledger.entries);
    let row = rows[0];
    assert_eq!(
        row.resource,
        ResourceRef::Named {
            id: "core-banking-api".into(),
            criticality: Criticality::TransactionCritical.code(),
        }
    );
    assert_eq!(row.standing, Standing::Verified);
    assert_eq!(row.verdicts.len(), 1);
    let v = &row.verdicts[0];
    assert_eq!(v.result, ReconciliationResult::VerifiedExecution.code());
    assert_eq!(v.reconciler_id, RC);
    assert_eq!(v.decision_id, Some(s.a.ee.decision_id));
    assert_eq!(b.ledger.unmatched_verdicts, 0);
    assert_eq!(b.ledger.registry_revision, 9);
}

#[test]
fn the_ledger_commits_as_its_own_leaf_and_verifies_offline() {
    let s = verified_execution();
    let b = ledger_over(&s);
    let kp = generate_ed25519_keypair();
    let nsigner = NexoraSigner::new("nexora-1", 1, &kp.private_key, &kp.public_key).unwrap();
    let nanchors = NexoraTrustAnchors::new().trust("nexora-1", 1, &kp.public_key);
    let mut log = CommitmentLog::new([0x7c; 16]);
    let idx = commit_access_ledger(&mut log, &b.ledger);
    let head = log.head(&nsigner, s.at + 100_000).unwrap();
    let proof = log.proof_for(idx, &head).unwrap();

    let c = verify_committed_ledger(&b.ledger, &proof, &nanchors, &b.ledger_anchors).unwrap();
    assert_eq!(c.inclusion.kind, LeafKind::AccessLedger);
    assert_eq!(c.agent_id, s.a.agent_id);
    assert_eq!(c.registry_revision, 9);
    assert_eq!(c.entries, b.ledger.entries.len());
}

#[test]
fn a_ledger_relabelled_as_another_leaf_kind_is_refused() {
    let s = verified_execution();
    let b = ledger_over(&s);
    let kp = generate_ed25519_keypair();
    let nsigner = NexoraSigner::new("nexora-1", 1, &kp.private_key, &kp.public_key).unwrap();
    let nanchors = NexoraTrustAnchors::new().trust("nexora-1", 1, &kp.public_key);
    let mut log = CommitmentLog::new([0x7d; 16]);
    // Commit the ledger's bytes under the bare-reconciliation kind.
    let idx = log.append(LeafKind::Reconciliation, &b.ledger.canonical_bytes());
    let head = log.head(&nsigner, s.at + 100_000).unwrap();
    let proof = log.proof_for(idx, &head).unwrap();
    assert!(matches!(
        verify_committed_ledger(&b.ledger, &proof, &nanchors, &b.ledger_anchors),
        Err(CommittedLedgerError::WrongLeafKind(
            LeafKind::Reconciliation
        ))
    ));
}

#[test]
fn a_proof_for_a_different_ledger_is_a_record_mismatch() {
    let s = verified_execution();
    let b1 = ledger_over(&s);
    let b2 = ledger_over(&s); // same scenario, different signer key and issue time
    let kp = generate_ed25519_keypair();
    let nsigner = NexoraSigner::new("nexora-1", 1, &kp.private_key, &kp.public_key).unwrap();
    let nanchors = NexoraTrustAnchors::new().trust("nexora-1", 1, &kp.public_key);
    let mut log = CommitmentLog::new([0x7e; 16]);
    let idx = commit_access_ledger(&mut log, &b2.ledger);
    let head = log.head(&nsigner, s.at + 100_000).unwrap();
    let proof = log.proof_for(idx, &head).unwrap();
    assert!(matches!(
        verify_committed_ledger(&b1.ledger, &proof, &nanchors, &b1.ledger_anchors),
        Err(CommittedLedgerError::RecordMismatch)
    ));
}

#[test]
fn a_tampered_ledger_is_refused_before_the_log_is_consulted() {
    let s = verified_execution();
    let mut b = ledger_over(&s);
    let kp = generate_ed25519_keypair();
    let nsigner = NexoraSigner::new("nexora-1", 1, &kp.private_key, &kp.public_key).unwrap();
    let nanchors = NexoraTrustAnchors::new().trust("nexora-1", 1, &kp.public_key);
    let mut log = CommitmentLog::new([0x7f; 16]);
    let idx = commit_access_ledger(&mut log, &b.ledger);
    let head = log.head(&nsigner, s.at + 100_000).unwrap();
    let proof = log.proof_for(idx, &head).unwrap();
    // Raise the row's standing after signing.
    let i = b
        .ledger
        .entries
        .iter()
        .position(|e| e.endpoint.port == PORT)
        .unwrap();
    b.ledger.entries[i].verdicts.clear();
    b.ledger.entries[i].standing = Standing::Verified;
    assert!(matches!(
        verify_committed_ledger(&b.ledger, &proof, &nanchors, &b.ledger_anchors),
        Err(CommittedLedgerError::Ledger(_))
    ));
}

#[test]
fn the_signed_verdict_and_the_ledger_can_share_one_log() {
    // Both artefacts about one execution live in one commitment log under
    // distinct leaf kinds; neither can be presented as the other.
    let s = verified_execution();
    let b = ledger_over(&s);
    let rkp = generate_ed25519_keypair();
    let rsigner = ReconcilerSigner::new(RC, 1, &rkp.private_key, &rkp.public_key).unwrap();
    let signed = rsigner.sign(&s.reconciliation).unwrap();
    let mut log = CommitmentLog::new([0x70; 16]);
    let i_verdict = commit_signed_verdict(&mut log, &signed);
    let i_ledger = commit_access_ledger(&mut log, &b.ledger);
    assert_ne!(i_verdict, i_ledger);
    assert_eq!(log.kind(i_verdict), Some(LeafKind::SignedReconciliation));
    assert_eq!(log.kind(i_ledger), Some(LeafKind::AccessLedger));
}
