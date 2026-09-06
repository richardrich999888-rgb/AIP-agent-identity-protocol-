//! Gate 8 — strict continuity runtime semantics, RED.
//!
//! What exists (Skill 6, PR #3 harvest): `CollectorSigner::resume` classifies
//! a carried snapshot against the archive of the collector's own signed
//! health records as `Amnesia`, `RolledBack`, `Forked` or
//! `ArchiveTruncated`, adopts or quarantines accordingly, and stays
//! `Recovering` until a contiguous batch. Fixture-tested (rc01–rc08).
//!
//! What is missing, and what this suite defines:
//!
//! - **durable state** — a store the collector writes its snapshot to after
//!   every signature and appends every health record to, so a *process*
//!   can restart, not only a struct;
//! - **a policy that is a policy** — `Strict` refuses to sign again after
//!   amnesia, rollback or fork (an operator must act); `Advisory` runs and
//!   reports; a fork is quarantined under both;
//! - **the break as signed evidence** — a `ContinuityReport` under the
//!   collector's own key naming the break, the resumed and archived
//!   positions and the time, appended to the store, so that "the collector
//!   was restored from an old state file" is a record a verifier can hold,
//!   not a log line;
//! - **restart tests** — the same directory, a new runtime, each break
//!   produced by doing to the files what an attacker or an outage would do.
//!
//! A restart never implies continuity: every resumed runtime is
//! `Recovering` until a contiguous batch is admitted, whatever the policy.

use aip_crypto::generate_ed25519_keypair;
use aip_observe::*;
use aip_types::KeyPair;

const NOW: u64 = 1_700_002_000_000;
const OBSERVER: &str = "collector-rt";

fn keys() -> KeyPair {
    generate_ed25519_keypair()
}

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "ghost-cr-{tag}-{}-{}",
        std::process::id(),
        NOW % 1000 + rand_suffix()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn rand_suffix() -> u64 {
    let kp = generate_ed25519_keypair();
    u64::from_le_bytes(kp.public_key[..8].try_into().unwrap())
}

fn anchors(kp: &KeyPair) -> ObserverTrustAnchors {
    ObserverTrustAnchors::new().trust(OBSERVER, 1, &kp.public_key)
}

fn start(d: &std::path::Path, kp: &KeyPair, policy: ContinuityPolicy) -> Started {
    let store = CollectorStore::open(d).unwrap();
    CollectorRuntime::start(store, OBSERVER, 1, &kp.private_key, &kp.public_key, policy).unwrap()
}

fn running(s: Started) -> (CollectorRuntime, StartOutcome) {
    match s {
        Started::Running(rt, outcome) => (rt, outcome),
        Started::Refused(b) => panic!("refused: {b:?}"),
    }
}

/// Attest `n` empty batches with a health record after each, starting at
/// batch number `first`, through the runtime (which persists as it goes).
fn work(rt: &mut CollectorRuntime, n: u8, first: u8) -> Vec<SignedSensorHealth> {
    let mut probe = ProcfsProbe::new("probe-rt");
    let mut out = Vec::new();
    for i in 0..n {
        let k = first + i;
        let b = probe.batch(
            [k; 16],
            NOW + u64::from(k) * 1_000,
            NOW + u64::from(k) * 1_000 + 500,
            vec![],
        );
        rt.attest_at(b, NOW + u64::from(k) * 1_000 + 600).unwrap();
        out.push(rt.health(NOW + u64::from(k) * 1_000 + 700).unwrap());
    }
    out
}

// ═══ Fresh start and durable state ═══

#[test]
fn cr01_a_fresh_directory_starts_a_fresh_chain_and_persists_every_signature() {
    let d = dir("cr01");
    let kp = keys();
    let (mut rt, outcome) = running(start(&d, &kp, ContinuityPolicy::Strict));
    assert_eq!(outcome, StartOutcome::Fresh);
    assert_eq!(rt.policy(), ContinuityPolicy::Strict);
    let healths = work(&mut rt, 3, 1);
    assert_eq!(healths.len(), 3);
    assert_eq!(rt.state(), ObserverState::Active);
    let store = CollectorStore::open(&d).unwrap();
    let snap = store.load_snapshot().unwrap().expect("snapshot written");
    assert_eq!(snap.observer_id, OBSERVER);
    assert_eq!(snap.sequence, Some(3));
    assert_eq!(snap.head, Some(healths[2].health.head));
    assert!(!snap.quarantined);
    let archive = store.load_archive().unwrap();
    assert_eq!(archive.len(), 3);
    assert_eq!(archive[2].health.sequence, 3);
    assert!(
        store.load_reports().unwrap().is_empty(),
        "no break, no report"
    );
    // The snapshot is written after every signature, not only at shutdown.
    let mut probe = ProcfsProbe::new("probe-rt");
    rt.attest_at(
        probe.batch([9; 16], NOW + 9_000, NOW + 9_500, vec![]),
        NOW + 9_600,
    )
    .unwrap();
    assert_eq!(store.load_snapshot().unwrap().unwrap().sequence, Some(4));
}

#[test]
fn cr02_a_clean_restart_continues_one_chain_and_does_not_claim_continuity() {
    let d = dir("cr02");
    let kp = keys();
    let (mut rt, _) = running(start(&d, &kp, ContinuityPolicy::Strict));
    let before = work(&mut rt, 3, 1);
    drop(rt);
    let (mut rt2, outcome) = running(start(&d, &kp, ContinuityPolicy::Strict));
    assert_eq!(
        outcome,
        StartOutcome::Resumed {
            continuity_break: None
        }
    );
    assert_eq!(
        rt2.state(),
        ObserverState::Recovering,
        "a restart never implies continuity"
    );
    let after = work(&mut rt2, 2, 4);
    assert_eq!(after[0].health.sequence, 4, "the same chain continues");
    // The first batch after resume links to the archived head; a verifier
    // accepts the whole chain as one observer's.
    let store = CollectorStore::open(&d).unwrap();
    let archive = store.load_archive().unwrap();
    assert_eq!(archive.len(), 5);
    for h in &archive {
        verify_signed_health(h, &anchors(&kp)).unwrap();
    }
    assert_eq!(before[2].health.head, archive[2].health.head);
    // Contiguous batches re-establish continuity; the second is Active.
    assert_eq!(after[1].health.state, ObserverState::Active);
    assert!(store.load_reports().unwrap().is_empty());
}

// ═══ Each break, produced by doing to the files what an outage or an
// attacker would do ═══

#[test]
fn cr03_amnesia_strict_refuses_advisory_adopts_the_archive_head_and_reports() {
    let d = dir("cr03");
    let kp = keys();
    let (mut rt, _) = running(start(&d, &kp, ContinuityPolicy::Strict));
    let healths = work(&mut rt, 3, 1);
    drop(rt);
    std::fs::remove_file(CollectorStore::open(&d).unwrap().snapshot_path()).unwrap();
    // Strict: the collector forgot; it must not sign until an operator acts.
    match start(&d, &kp, ContinuityPolicy::Strict) {
        Started::Refused(ContinuityBreak::Amnesia {
            archived_sequence, ..
        }) => assert_eq!(archived_sequence, 3),
        other => panic!("{other:?}"),
    }
    // Advisory: adopt the archive head, report, run Recovering.
    let (mut rt2, outcome) = running(start(&d, &kp, ContinuityPolicy::Advisory));
    assert!(matches!(
        outcome,
        StartOutcome::Resumed {
            continuity_break: Some(ContinuityBreak::Amnesia { .. })
        }
    ));
    assert_eq!(rt2.state(), ObserverState::Recovering);
    let after = work(&mut rt2, 1, 4);
    assert_eq!(
        after[0].health.sequence, 4,
        "the archive head was adopted, not genesis"
    );
    let store = CollectorStore::open(&d).unwrap();
    let reports = store.load_reports().unwrap();
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    verify_continuity_report(r, &anchors(&kp)).unwrap();
    assert_eq!(r.report.observer_id, OBSERVER);
    assert!(matches!(
        r.report.continuity_break,
        ContinuityBreak::Amnesia {
            archived_sequence: 3,
            ..
        }
    ));
    assert_eq!(r.report.archived_head, Some(healths[2].health.head));
    assert_eq!(r.report.policy, ContinuityPolicy::Advisory);
}

#[test]
fn cr04_rollback_strict_refuses_advisory_adopts_the_archive_head_and_reports() {
    let d = dir("cr04");
    let kp = keys();
    let (mut rt, _) = running(start(&d, &kp, ContinuityPolicy::Strict));
    work(&mut rt, 2, 1);
    let store = CollectorStore::open(&d).unwrap();
    let old = std::fs::read(store.snapshot_path()).unwrap();
    work(&mut rt, 2, 3);
    drop(rt);
    // Restore the older state file.
    std::fs::write(store.snapshot_path(), &old).unwrap();
    match start(&d, &kp, ContinuityPolicy::Strict) {
        Started::Refused(ContinuityBreak::RolledBack {
            resumed_sequence,
            archived_sequence,
        }) => assert_eq!((resumed_sequence, archived_sequence), (2, 4)),
        other => panic!("{other:?}"),
    }
    // Refusal writes a report too: the refusal is itself evidence.
    let reports = store.load_reports().unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].report.policy, ContinuityPolicy::Strict);
    assert!(reports[0].report.refused);
    let (mut rt2, outcome) = running(start(&d, &kp, ContinuityPolicy::Advisory));
    assert!(matches!(
        outcome,
        StartOutcome::Resumed {
            continuity_break: Some(ContinuityBreak::RolledBack { .. })
        }
    ));
    let after = work(&mut rt2, 1, 5);
    assert_eq!(after[0].health.sequence, 5);
    assert_eq!(store.load_reports().unwrap().len(), 2);
    assert!(!store.load_reports().unwrap()[1].report.refused);
}

#[test]
fn cr05_fork_is_quarantined_under_every_policy_and_never_signs_a_batch_again() {
    let d = dir("cr05");
    let kp = keys();
    let (mut rt, _) = running(start(&d, &kp, ContinuityPolicy::Strict));
    work(&mut rt, 3, 1);
    drop(rt);
    let store = CollectorStore::open(&d).unwrap();
    let mut snap = store.load_snapshot().unwrap().unwrap();
    snap.head = Some([0x5a; 32]);
    store.save_snapshot(&snap).unwrap();
    match start(&d, &kp, ContinuityPolicy::Strict) {
        Started::Refused(ContinuityBreak::Forked { sequence, .. }) => assert_eq!(sequence, 3),
        other => panic!("{other:?}"),
    }
    let (mut rt2, outcome) = running(start(&d, &kp, ContinuityPolicy::Advisory));
    assert!(matches!(
        outcome,
        StartOutcome::Resumed {
            continuity_break: Some(ContinuityBreak::Forked { .. })
        }
    ));
    assert_eq!(rt2.state(), ObserverState::Quarantined);
    let mut probe = ProcfsProbe::new("probe-rt");
    let b = probe.batch([7; 16], NOW + 7_000, NOW + 7_500, vec![]);
    assert!(matches!(
        rt2.attest_at(b, NOW + 7_600),
        Err(RuntimeError::Attest(AttestError::Quarantined))
    ));
    // Health can still be emitted: a signed statement of quarantine.
    let h = rt2.health(NOW + 7_700).unwrap();
    assert_eq!(h.health.state, ObserverState::Quarantined);
    assert_eq!(store.load_reports().unwrap().len(), 2);
}

#[test]
fn cr06_a_truncated_archive_keeps_the_state_reports_and_runs_recovering() {
    let d = dir("cr06");
    let kp = keys();
    let (mut rt, _) = running(start(&d, &kp, ContinuityPolicy::Strict));
    work(&mut rt, 3, 1);
    drop(rt);
    let store = CollectorStore::open(&d).unwrap();
    let text = std::fs::read_to_string(store.archive_path()).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.pop();
    std::fs::write(store.archive_path(), format!("{}\n", lines.join("\n"))).unwrap();
    assert_eq!(store.load_archive().unwrap().len(), 2);
    let (mut rt2, outcome) = running(start(&d, &kp, ContinuityPolicy::Strict));
    match outcome {
        StartOutcome::Resumed {
            continuity_break:
                Some(ContinuityBreak::ArchiveTruncated {
                    resumed_sequence,
                    archived_sequence,
                }),
        } => assert_eq!((resumed_sequence, archived_sequence), (3, 2)),
        other => panic!("{other:?}"),
    }
    assert_eq!(rt2.state(), ObserverState::Recovering);
    let after = work(&mut rt2, 1, 4);
    assert_eq!(after[0].health.sequence, 4, "the state was kept");
    let reports = store.load_reports().unwrap();
    assert_eq!(reports.len(), 1);
    assert!(!reports[0].report.refused);
    assert_eq!(reports[0].report.resumed_sequence, Some(3));
    assert_eq!(reports[0].report.archived_sequence, Some(2));
}

// ═══ Refusals that are not breaks ═══

#[test]
fn cr07_foreign_state_and_corrupt_files_are_errors_never_a_fresh_chain() {
    let d = dir("cr07");
    let kp = keys();
    let (mut rt, _) = running(start(&d, &kp, ContinuityPolicy::Strict));
    work(&mut rt, 2, 1);
    drop(rt);
    let store = CollectorStore::open(&d).unwrap();
    // Another observer's state in this directory.
    let mut snap = store.load_snapshot().unwrap().unwrap();
    snap.observer_id = "someone-else".into();
    store.save_snapshot(&snap).unwrap();
    assert!(matches!(
        CollectorRuntime::start(
            CollectorStore::open(&d).unwrap(),
            OBSERVER,
            1,
            &kp.private_key,
            &kp.public_key,
            ContinuityPolicy::Advisory
        ),
        Err(RuntimeError::Attest(AttestError::ForeignState { .. }))
    ));
    // A state file that is not a snapshot is corrupt, not absent.
    std::fs::write(store.snapshot_path(), b"{ not json").unwrap();
    assert!(matches!(
        CollectorRuntime::start(
            CollectorStore::open(&d).unwrap(),
            OBSERVER,
            1,
            &kp.private_key,
            &kp.public_key,
            ContinuityPolicy::Advisory
        ),
        Err(RuntimeError::Store(StoreError::Corrupt { .. }))
    ));
    // Likewise a corrupt archive line.
    std::fs::remove_file(store.snapshot_path()).unwrap();
    let mut text = std::fs::read_to_string(store.archive_path()).unwrap();
    text.push_str("garbage\n");
    std::fs::write(store.archive_path(), text).unwrap();
    assert!(matches!(
        store.load_archive(),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn cr08_forged_archive_records_are_ignored_so_amnesia_is_still_detected_from_the_real_ones() {
    let d = dir("cr08");
    let kp = keys();
    let (mut rt, _) = running(start(&d, &kp, ContinuityPolicy::Strict));
    work(&mut rt, 2, 1);
    drop(rt);
    let store = CollectorStore::open(&d).unwrap();
    // A forged record claiming sequence 99 under another key.
    let other = keys();
    let mut forger =
        CollectorSigner::new(OBSERVER, 1, &other.private_key, &other.public_key).unwrap();
    let mut probe = ProcfsProbe::new("probe-x");
    for k in 1..=99u8 {
        forger
            .attest_at(
                probe.batch([k; 16], NOW + u64::from(k), NOW + u64::from(k) + 1, vec![]),
                NOW + u64::from(k) + 2,
            )
            .unwrap();
    }
    let forged = forger.health(NOW + 200).unwrap();
    assert_eq!(forged.health.sequence, 99);
    store.append_health(&forged).unwrap();
    std::fs::remove_file(store.snapshot_path()).unwrap();
    match start(&d, &kp, ContinuityPolicy::Strict) {
        Started::Refused(ContinuityBreak::Amnesia {
            archived_sequence, ..
        }) => assert_eq!(archived_sequence, 2, "the forged record did not count"),
        other => panic!("{other:?}"),
    }
}

// ═══ The report ═══

#[test]
fn cr09_a_continuity_report_is_signed_domain_separated_and_names_no_subject() {
    let d = dir("cr09");
    let kp = keys();
    let (mut rt, _) = running(start(&d, &kp, ContinuityPolicy::Strict));
    work(&mut rt, 2, 1);
    drop(rt);
    std::fs::remove_file(CollectorStore::open(&d).unwrap().snapshot_path()).unwrap();
    let _ = start(&d, &kp, ContinuityPolicy::Strict);
    let store = CollectorStore::open(&d).unwrap();
    let r = store.load_reports().unwrap().remove(0);
    verify_continuity_report(&r, &anchors(&kp)).unwrap();
    assert!(CONTINUITY_REPORT_DOMAIN.starts_with("SYNTRIASS/GHOST/"));
    let pre = r.report.canonical_bytes();
    assert!(pre
        .windows(CONTINUITY_REPORT_DOMAIN.len())
        .any(|w| w == CONTINUITY_REPORT_DOMAIN.as_bytes()));
    // Altered after signing: refused.
    let mut t = r.clone();
    t.report.refused = false;
    assert!(verify_continuity_report(&t, &anchors(&kp)).is_err());
    let mut t = r.clone();
    t.report.emitted_at_ms += 1;
    assert!(verify_continuity_report(&t, &anchors(&kp)).is_err());
    // Under a key the verifier does not anchor: refused.
    assert!(verify_continuity_report(&r, &anchors(&keys())).is_err());
    // It is about the observer's own record: no agent, decision or workload.
    let json = serde_json::to_string(&r).unwrap().to_lowercase();
    for forbidden in ["agent", "decision", "workload", "malicious", "contain"] {
        assert!(!json.contains(forbidden), "{forbidden} in {json}");
    }
    let back: SignedContinuityReport =
        serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
}

#[test]
fn cr10_policy_and_outcome_vocabulary() {
    assert_ne!(ContinuityPolicy::Strict, ContinuityPolicy::Advisory);
    assert_eq!(
        ContinuityPolicy::default(),
        ContinuityPolicy::Strict,
        "strict by default"
    );
    let json = serde_json::to_string(&StartOutcome::Fresh)
        .unwrap()
        .to_lowercase();
    assert!(!json.contains("trusted"));
}
