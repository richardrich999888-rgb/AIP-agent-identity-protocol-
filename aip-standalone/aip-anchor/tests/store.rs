//! R11 — persistence, and what a restart must not allow.
//!
//! The witness's value depends on it remembering. A witness that forgets
//! what it countersigned will happily countersign a shorter log after a
//! restart, and the operator gets a clean receipt for a truncated history.

use aip_anchor::store::FileReceiptStore;
use aip_anchor::{verify_receipt_chain, Witness, WitnessAnchors, WitnessError};
use aip_crypto::generate_ed25519_keypair;
use aip_nexora::{CommitmentLog, LeafKind, NexoraSigner, NexoraTrustAnchors};

const LOG_ID: [u8; 16] = [7u8; 16];
const T0: u64 = 1_700_000_000_000;

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("aip-anchor-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }

    fn file(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn append(log: &mut CommitmentLog, n: usize, tag: u8) {
    for i in 0..n {
        log.append(LeafKind::Reconciliation, &[tag, i as u8]);
    }
}

/// A witness, its anchors, and the NEXORA side of a fresh setup.
struct Setup {
    log: CommitmentLog,
    signer: NexoraSigner,
    log_anchors: NexoraTrustAnchors,
    witness_private: Vec<u8>,
    witness_public: Vec<u8>,
    anchors: WitnessAnchors,
}

fn setup() -> Setup {
    let nk = generate_ed25519_keypair();
    let wk = generate_ed25519_keypair();
    Setup {
        log: CommitmentLog::new(LOG_ID),
        signer: NexoraSigner::new("nexora-1", 1, &nk.private_key, &nk.public_key).unwrap(),
        log_anchors: NexoraTrustAnchors::new().trust("nexora-1", 1, &nk.public_key),
        witness_private: wk.private_key.clone(),
        witness_public: wk.public_key.clone(),
        anchors: WitnessAnchors::new().trust("w1", 1, &wk.public_key),
    }
}

impl Setup {
    /// A witness resumed from whatever the store holds — the way the
    /// command line builds one on every invocation.
    fn resumed(&self, store: &FileReceiptStore) -> Witness {
        Witness::new(
            "w1",
            1,
            &self.witness_private,
            &self.witness_public,
            self.log_anchors.clone(),
        )
        .unwrap()
        .resume(store.resume_state().unwrap())
    }
}

/// Receipts survive a round trip and still verify.
#[test]
fn receipts_persist_and_reload() {
    let s = Scratch::new("persist");
    let store = FileReceiptStore::new(s.file("receipts.jsonl"));
    let mut env = setup();

    let mut prev = 0u64;
    for i in 0..3u64 {
        append(&mut env.log, 2, i as u8);
        let proof = (prev > 0).then(|| env.log.consistency_since(prev).unwrap());
        let head = env.log.head(&env.signer, T0 + i * 1_000).unwrap();
        let mut w = env.resumed(&store);
        let r = w
            .witness(&head, proof.as_ref(), T0 + i * 1_000 + 10)
            .unwrap();
        store.append(&r).unwrap();
        prev = env.log.size();
    }

    let loaded = store.load().unwrap();
    assert_eq!(loaded.len(), 3);
    assert_eq!(loaded[2].size, 6);
    verify_receipt_chain(&loaded, &env.anchors).unwrap();
}

/// **The restart test.** A witness rebuilt from the receipt file refuses a
/// rollback exactly as the one that issued them would have.
#[test]
fn a_restarted_witness_still_refuses_a_rollback() {
    let s = Scratch::new("restart");
    let store = FileReceiptStore::new(s.file("receipts.jsonl"));
    let mut env = setup();

    append(&mut env.log, 9, 0xA0);
    let head = env.log.head(&env.signer, T0).unwrap();
    let r = env.resumed(&store).witness(&head, None, T0 + 10).unwrap();
    store.append(&r).unwrap();

    // Process restarts. All it has is the file.
    let mut restarted = env.resumed(&store);
    assert_eq!(restarted.state().last_size, 9);

    let mut shorter = CommitmentLog::new(LOG_ID);
    append(&mut shorter, 3, 0xA0);
    let forged = shorter.head(&env.signer, T0 + 5_000).unwrap();
    assert!(matches!(
        restarted.witness(&forged, None, T0 + 5_010),
        Err(WitnessError::NotAnExtension {
            witnessed: 9,
            offered: 3
        })
    ));
    // And nothing was written for the refused head.
    assert_eq!(store.load().unwrap().len(), 1);
}

/// State is derived from the receipts, not stored beside them, so it can
/// never disagree with the evidence.
#[test]
fn state_is_replayed_from_the_receipts() {
    let s = Scratch::new("state");
    let store = FileReceiptStore::new(s.file("receipts.jsonl"));
    let mut env = setup();
    assert_eq!(store.resume_state().unwrap().log_id, None);

    append(&mut env.log, 4, 0xA0);
    let head = env.log.head(&env.signer, T0).unwrap();
    let r = env.resumed(&store).witness(&head, None, T0 + 10).unwrap();
    store.append(&r).unwrap();

    let state = store.resume_state().unwrap();
    assert_eq!(state.log_id, Some(LOG_ID));
    assert_eq!(state.last_size, 4);
    assert_eq!(state.last_root, r.root);
    assert_eq!(state.last_receipt_digest, r.digest());
    assert_eq!(state.receipts_issued, 1);
}

/// A corrupt line is reported, never skipped. Skipping would silently
/// discard a countersignature and let the witness forget a size it had
/// already seen.
#[test]
fn a_corrupt_receipt_line_is_reported_not_skipped() {
    let s = Scratch::new("corrupt");
    let path = s.file("receipts.jsonl");
    let store = FileReceiptStore::new(&path);
    let mut env = setup();
    append(&mut env.log, 4, 0xA0);
    let head = env.log.head(&env.signer, T0).unwrap();
    let r = env.resumed(&store).witness(&head, None, T0 + 10).unwrap();
    store.append(&r).unwrap();

    std::fs::write(
        &path,
        format!(
            "{}\n{{\"not\":\"a receipt\"}}\n",
            serde_json::to_string(&r).unwrap()
        ),
    )
    .unwrap();

    let err = store.load().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("line 2"), "{msg}");
    assert!(msg.contains("refusing to continue"), "{msg}");
    assert!(store.resume_state().is_err(), "state must refuse too");
}

/// A missing file is an empty witness, not an error: a witness that has
/// countersigned nothing is a real and ordinary state.
#[test]
fn a_missing_receipt_file_reads_as_no_receipts() {
    let s = Scratch::new("missing");
    let store = FileReceiptStore::new(s.file("nothing-here.jsonl"));
    assert!(store.load().unwrap().is_empty());
    assert_eq!(store.resume_state().unwrap().receipts_issued, 0);
}
