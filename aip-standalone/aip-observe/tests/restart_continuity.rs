//! Collector restart continuity — RED. Harvested design: PR #3
//! `ot-sentinel/src/state.rs` (`6cc439f`), the four-way classification of a
//! resumed state against an independently held archive of the observer's
//! own sealed records. Rebuilt here over the collector's signed health
//! records, which already carry `(observer_id, sequence, head)` under the
//! collector's key.
//!
//! What main already has: a probe restart sends the ledger to `Unverified`
//! and coverage to `None`, and a restart never implies continuity. What it
//! lacks: the collector cannot carry its own chain position across a
//! process restart, so a restarted collector begins a second chain at
//! sequence 1 under the same key — indistinguishable, to a verifier, from a
//! fork — and there is no arithmetic that catches a collector resumed from a
//! rolled-back or edited state file.

use aip_crypto::generate_ed25519_keypair;
use aip_observe::*;
use aip_types::KeyPair;

const NOW: u64 = 1_700_001_000_000;
const OBSERVER: &str = "collector-r";

fn keys() -> KeyPair {
    generate_ed25519_keypair()
}

fn signer(kp: &KeyPair) -> CollectorSigner {
    CollectorSigner::new(OBSERVER, 1, &kp.private_key, &kp.public_key).unwrap()
}

fn anchors(kp: &KeyPair) -> ObserverTrustAnchors {
    ObserverTrustAnchors::new().trust(OBSERVER, 1, &kp.public_key)
}

/// Attest `n` empty batches, emitting a signed health record after each;
/// returns the archive of health records.
fn run(signer: &mut CollectorSigner, n: u8, start: u8) -> Vec<SignedSensorHealth> {
    let mut probe = ProcfsProbe::new("probe-r");
    let mut archive = Vec::new();
    for i in 0..n {
        let k = start + i;
        let b = probe.batch(
            [k; 16],
            NOW + u64::from(k) * 1_000,
            NOW + u64::from(k) * 1_000 + 500,
            vec![],
        );
        signer
            .attest_at(b, NOW + u64::from(k) * 1_000 + 600)
            .unwrap();
        archive.push(signer.health(NOW + u64::from(k) * 1_000 + 700).unwrap());
    }
    archive
}

/// rc01 — a snapshot taken after `n` batches, resumed against the archive
/// those batches produced, is not a break; the resumed collector continues
/// the same chain (next sequence, matching `prev_head`) and a verifier
/// accepts the next batch as this observer's. Immediately after resume the
/// signed health says continuity is *unverified*: a restart never implies
/// continuity, even a correct one.
#[test]
fn rc01_correct_resume_continues_one_chain_without_claiming_continuity() {
    let kp = keys();
    let mut s = signer(&kp);
    let archive = run(&mut s, 3, 1);
    let snap = s.snapshot();
    assert_eq!(snap.sequence, Some(3));
    assert_eq!(snap.observer_id, OBSERVER);

    let (mut resumed, brk) =
        CollectorSigner::resume(&snap, OBSERVER, &kp.private_key, &kp.public_key, &archive).unwrap();
    assert_eq!(brk, None);
    assert_eq!(resumed.ledger().next_sequence(), 4);
    assert_eq!(resumed.ledger().last_head(), snap.head);

    let h = resumed.health(NOW + 10_000).unwrap();
    assert_eq!(h.health.continuity, ContinuityStatus::Unverified);
    assert_ne!(h.health.state, ObserverState::Active);

    // The chain continues: sequence 4 links to the snapshot head.
    let mut probe = ProcfsProbe::new("probe-r");
    let b = probe.batch([9; 16], NOW + 9_000, NOW + 9_500, vec![]);
    let att = resumed.attest_at(b, NOW + 9_600).unwrap();
    assert_eq!(att.sequence, 4);
    assert_eq!(att.prev_head, snap.head.unwrap());
    assert_eq!(verify_attested_batch(&att, &anchors(&kp)), Ok(()));
}

/// rc02 — amnesia: no state at all, but the archive holds this observer's
/// sealed history. Reported as `Amnesia`; the resumed collector adopts the
/// archive head so that it does not start a second chain under the same key;
/// continuity is unverified.
#[test]
fn rc02_amnesia_is_reported_and_the_archive_head_is_adopted() {
    let kp = keys();
    let mut s = signer(&kp);
    let archive = run(&mut s, 2, 1);
    let lost = CollectorSnapshot::fresh(OBSERVER, 1);
    let (resumed, brk) =
        CollectorSigner::resume(&lost, OBSERVER, &kp.private_key, &kp.public_key, &archive).unwrap();
    assert_eq!(
        brk,
        Some(ContinuityBreak::Amnesia {
            archived_sequence: 2,
            archived_head: archive[1].health.head,
        })
    );
    assert_eq!(resumed.ledger().next_sequence(), 3);
    assert_eq!(resumed.ledger().last_head(), Some(archive[1].health.head));
    assert_eq!(
        resumed.health(NOW + 10_000).unwrap().health.continuity,
        ContinuityStatus::Unverified
    );
    assert!(!resumed.ledger().is_quarantined(), "loss is not forgery");
}

/// rc03 — rollback: a snapshot older than the archive (a restored state
/// file). Reported as `RolledBack`; the archive head is adopted; unverified.
#[test]
fn rc03_rolled_back_state_is_reported_and_the_archive_head_is_adopted() {
    let kp = keys();
    let mut s = signer(&kp);
    let mut archive = run(&mut s, 1, 1);
    let old = s.snapshot();
    archive.extend(run(&mut s, 2, 2));
    assert_eq!(old.sequence, Some(1));

    let (resumed, brk) =
        CollectorSigner::resume(&old, OBSERVER, &kp.private_key, &kp.public_key, &archive).unwrap();
    assert_eq!(
        brk,
        Some(ContinuityBreak::RolledBack {
            resumed_sequence: 1,
            archived_sequence: 3,
        })
    );
    assert_eq!(resumed.ledger().next_sequence(), 4);
    assert_eq!(resumed.ledger().last_head(), Some(archive[2].health.head));
}

/// rc04 — fork: a snapshot at the archive's sequence with a different head.
/// Two heads at one sequence under one key is an integrity failure of the
/// observer's own record: the resumed collector is quarantined and its
/// health says so. Nothing about any workload is concluded.
#[test]
fn rc04_forked_state_quarantines_the_collector() {
    let kp = keys();
    let mut s = signer(&kp);
    let archive = run(&mut s, 2, 1);
    let mut snap = s.snapshot();
    let mut edited = snap.head.unwrap();
    edited[0] ^= 0xff;
    snap.head = Some(edited);

    let (resumed, brk) =
        CollectorSigner::resume(&snap, OBSERVER, &kp.private_key, &kp.public_key, &archive).unwrap();
    assert_eq!(
        brk,
        Some(ContinuityBreak::Forked {
            sequence: 2,
            resumed_head: edited,
            archived_head: archive[1].health.head,
        })
    );
    assert!(resumed.ledger().is_quarantined());
    let h = resumed.health(NOW + 10_000).unwrap();
    assert_eq!(h.health.state, ObserverState::Quarantined);
    assert_eq!(h.health.continuity, ContinuityStatus::Broken);
    assert!(h.health.attested_coverage.is_none());
}

/// rc05 — archive truncated: the state is ahead of the archive (a crash
/// between state write and archive append, or a shortened archive).
/// Reported; the state is kept; continuity unverified; not quarantined.
#[test]
fn rc05_truncated_archive_is_reported_and_the_state_is_kept() {
    let kp = keys();
    let mut s = signer(&kp);
    let archive = run(&mut s, 3, 1);
    let snap = s.snapshot();
    let short = &archive[..1];

    let (resumed, brk) =
        CollectorSigner::resume(&snap, OBSERVER, &kp.private_key, &kp.public_key, short).unwrap();
    assert_eq!(
        brk,
        Some(ContinuityBreak::ArchiveTruncated {
            resumed_sequence: 3,
            archived_sequence: 1,
        })
    );
    assert_eq!(resumed.ledger().next_sequence(), 4);
    assert!(!resumed.ledger().is_quarantined());
    assert_eq!(
        resumed.health(NOW + 10_000).unwrap().health.continuity,
        ContinuityStatus::Unverified
    );

    // An empty archive with a non-empty state is the same finding.
    let (_, brk) = CollectorSigner::resume(&snap, OBSERVER, &kp.private_key, &kp.public_key, &[]).unwrap();
    assert_eq!(
        brk,
        Some(ContinuityBreak::ArchiveTruncated {
            resumed_sequence: 3,
            archived_sequence: 0,
        })
    );
}

/// rc06 — a fresh deployment (no state, no archive) is not a break; state
/// from another observer is refused rather than spliced onto this one.
#[test]
fn rc06_fresh_start_is_clean_and_foreign_state_is_refused() {
    let kp = keys();
    let fresh = CollectorSnapshot::fresh(OBSERVER, 1);
    let (c, brk) =
        CollectorSigner::resume(&fresh, OBSERVER, &kp.private_key, &kp.public_key, &[]).unwrap();
    assert_eq!(brk, None);
    assert_eq!(c.ledger().next_sequence(), 1);

    let mut other = signer(&kp);
    other.attest_at(
        ProcfsProbe::new("p").batch([1; 16], NOW, NOW + 1, vec![]),
        NOW + 2,
    )
    .unwrap();
    let mut foreign = other.snapshot();
    foreign.observer_id = "collector-other".into();
    assert_eq!(
        CollectorSigner::resume(&foreign, OBSERVER, &kp.private_key, &kp.public_key, &[])
            .err(),
        Some(AttestError::ForeignState {
            expected: OBSERVER.into(),
            got: "collector-other".into(),
        })
    );
}

/// rc07 — the archive is checked, not trusted: records of other observers
/// and records whose signature does not verify under this collector's key
/// are ignored, so a forged record cannot manufacture a break or move the
/// adopted head.
#[test]
fn rc07_forged_or_foreign_archive_records_are_ignored() {
    let kp = keys();
    let mut s = signer(&kp);
    let mut archive = run(&mut s, 2, 1);
    let snap = s.snapshot();

    // A forged "later" record: higher sequence, other head, bad signature.
    let mut forged = archive[1].clone();
    forged.health.sequence = 9;
    forged.health.head = [0xee; 32];
    archive.push(forged);
    // A genuine record of a different observer at a higher sequence.
    let other_kp = keys();
    let mut other = CollectorSigner::new("collector-z", 1, &other_kp.private_key, &other_kp.public_key).unwrap();
    let _ = run(&mut other, 5, 1);
    archive.push(other.health(NOW + 99_000).unwrap());

    let (resumed, brk) =
        CollectorSigner::resume(&snap, OBSERVER, &kp.private_key, &kp.public_key, &archive).unwrap();
    assert_eq!(brk, None, "forged and foreign records must not count");
    assert_eq!(resumed.ledger().next_sequence(), 3);
    assert_eq!(
        verify_continuity(&snap, &archive, &kp.public_key),
        None
    );
}

/// rc08 — a `ContinuityBreak` is about the observer's own record and names
/// no agent, decision, process or action.
#[test]
fn rc08_a_break_names_no_subject() {
    let kp = keys();
    let mut s = signer(&kp);
    let archive = run(&mut s, 1, 1);
    let lost = CollectorSnapshot::fresh(OBSERVER, 1);
    let (_, brk) =
        CollectorSigner::resume(&lost, OBSERVER, &kp.private_key, &kp.public_key, &archive).unwrap();
    let text = serde_json::to_string(&brk.unwrap()).unwrap().to_ascii_lowercase();
    for f in ["agent", "decision", "pid", "process", "action", "aip1"] {
        assert!(!text.contains(f), "a break must not carry `{f}`: {text}");
    }
}
