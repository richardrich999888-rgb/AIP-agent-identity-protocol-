//! End-to-end tests for the offline verifier, against a real attested chain.
//!
//! Every test builds an actual collector runtime, attests real batches, and
//! writes real archive files. Nothing is hand-forged JSON: a fixture that the
//! test author wrote by hand can agree with a verifier that is wrong in the
//! same way, and this crate's whole value is that it disagrees when it should.
//!
//! The negative tests matter more than the positive one. A verifier that
//! passes good evidence and also passes tampered evidence is worse than no
//! verifier, because it converts a suspicion into a clean bill of health.

use std::path::PathBuf;
use std::process::Command;

use aip_observe::{
    AttestedBatch, AttestedClock, CollectorKey, CollectorRuntime, CollectorStore, ContinuityPolicy,
    ProcfsProbe, SignedSensorHealth, Started,
};
use aip_observe_verify::report::Finding;
use aip_observe_verify::verify::{parse_jsonl, verify_archives};

const OBSERVER_ID: &str = "collector.test";
const KEY_VERSION: u32 = 1;

/// A disciplined clock, 16 ms error bound, as the collector would sign it.
const CLOCK: AttestedClock = AttestedClock {
    synchronized: true,
    max_error_us: 16_000,
    state: 0,
};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aip-observe-verify-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A live chain: `n` attested batches and a signed health record after each,
/// plus the public key that anchors them.
struct Chain {
    batches: Vec<AttestedBatch>,
    health: Vec<SignedSensorHealth>,
    public_key: Vec<u8>,
    _dir: PathBuf,
}

fn build_chain(tag: &str, n: usize) -> Chain {
    let dir = scratch(tag);
    let store = CollectorStore::open(&dir).unwrap();
    let key = CollectorKey::development();
    let public_key = key.public_key().to_vec();
    let started = CollectorRuntime::start_with_custodian(
        store,
        OBSERVER_ID,
        KEY_VERSION,
        key.into_custodian(),
        ContinuityPolicy::Strict,
    )
    .unwrap();
    let mut rt = match started {
        Started::Running(rt, _) => rt,
        Started::Refused(b) => panic!("fresh runtime refused: {b:?}"),
    };

    let mut probe = ProcfsProbe::new("probe-1");
    let mut batches = Vec::new();
    let mut health = Vec::new();
    for i in 0..n {
        let base = 1_000 + (i as u64) * 100;
        let batch = probe.batch([i as u8; 16], base, base + 50, vec![]);
        batches.push(rt.attest(batch).unwrap());
        // Protocol 12: every health record carries a clock reading, as the
        // daemon emits them. A fixture without one would leave the clock
        // half of the report untested against real signed bytes.
        health.push(rt.health_with_clock(base + 60, Some(CLOCK)).unwrap());
    }
    Chain {
        batches,
        health,
        public_key,
        _dir: dir,
    }
}

fn jsonl<T: serde::Serialize>(records: &[T]) -> String {
    records
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn verify(chain: &Chain, batch_text: &str, health_text: Option<&str>) -> Vec<Finding> {
    verify_archives(
        OBSERVER_ID,
        KEY_VERSION,
        &chain.public_key,
        Some(parse_jsonl::<AttestedBatch>(batch_text)),
        health_text.map(parse_jsonl::<SignedSensorHealth>),
    )
    .findings
}

// ── The gate itself ──────────────────────────────────────────────────────

/// The Phase 1 exit gate, from the auditor's side: given the archives and
/// nothing but the anchored public key, the verifier accepts.
#[test]
fn a_real_attested_chain_verifies_from_its_archives_and_a_public_key() {
    let c = build_chain("good", 4);
    let report = verify_archives(
        OBSERVER_ID,
        KEY_VERSION,
        &c.public_key,
        Some(parse_jsonl::<AttestedBatch>(&jsonl(&c.batches))),
        Some(parse_jsonl::<SignedSensorHealth>(&jsonl(&c.health))),
    );
    assert!(
        report.ok(),
        "clean chain must verify: {:?}",
        report.findings
    );
    let b = report.batches.unwrap();
    assert_eq!(b.records, 4);
    assert_eq!((b.first_sequence, b.last_sequence), (Some(1), Some(4)));
    assert_eq!(
        b.start,
        Some(aip_observe_verify::report::ChainStart::Epoch),
        "a chain built from a fresh store starts at the epoch"
    );
    let h = report.health.unwrap();
    assert_eq!(h.records, 4);
    // Every health record after a batch names that batch's position, so all
    // four are checked against the batch archive rather than merely parsed.
    assert_eq!(h.cross_checked_against_batches, 4);
}

// ── What must be refused ─────────────────────────────────────────────────

#[test]
fn a_batch_signed_by_another_key_is_refused() {
    let c = build_chain("wrong-key", 2);
    let other = build_chain("wrong-key-other", 1);
    let findings = verify_archives(
        OBSERVER_ID,
        KEY_VERSION,
        &other.public_key, // anchor a different observer's key
        Some(parse_jsonl::<AttestedBatch>(&jsonl(&c.batches))),
        None,
    )
    .findings;
    assert_eq!(findings.len(), 2, "both records are rejected: {findings:?}");
    assert!(matches!(findings[0], Finding::SignatureRejected { .. }));
}

#[test]
fn an_edited_observation_no_longer_verifies() {
    let c = build_chain("edited", 2);
    let mut tampered = c.batches.clone();
    // Change one byte of the attested content. The attestation covers the
    // batch's canonical bytes, so this is the minimal real tamper.
    tampered[0].batch.probe_id = "probe-2".into();
    let findings = verify(&c, &jsonl(&tampered), None);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, Finding::SignatureRejected { line: 1, .. })),
        "{findings:?}"
    );
}

/// Deleting a record from the middle is the attack an append-only file is
/// supposed to make visible. It must not merely shorten the archive quietly.
#[test]
fn a_record_removed_from_the_middle_breaks_the_chain() {
    let c = build_chain("deleted", 4);
    let kept: Vec<AttestedBatch> = c
        .batches
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, b)| b.clone())
        .collect();
    let findings = verify(&c, &jsonl(&kept), None);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, Finding::SequenceNotContiguous { .. })),
        "a gap in chain positions must be reported: {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, Finding::ChainBroken { .. })),
        "and the prev_head link must break: {findings:?}"
    );
}

/// Reordering keeps every signature valid — each record is individually
/// authentic. Only the chain check catches it.
#[test]
fn reordered_records_are_caught_by_the_chain_even_though_each_signature_is_valid() {
    let c = build_chain("reordered", 3);
    let mut swapped = c.batches.clone();
    swapped.swap(0, 1);
    let findings = verify(&c, &jsonl(&swapped), None);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, Finding::SignatureRejected { .. })),
        "the signatures are genuine; that is the point: {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, Finding::SequenceNotContiguous { .. })),
        "{findings:?}"
    );
}

#[test]
fn a_duplicated_record_is_refused() {
    let c = build_chain("dup", 2);
    let mut dup = c.batches.clone();
    dup.insert(1, c.batches[0].clone());
    let findings = verify(&c, &jsonl(&dup), None);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, Finding::SequenceNotContiguous { .. })),
        "{findings:?}"
    );
}

#[test]
fn a_corrupt_line_is_reported_not_skipped() {
    let c = build_chain("corrupt", 2);
    let text = format!("{}{{not json\n", jsonl(&c.batches));
    let findings = verify(&c, &text, None);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, Finding::Unparseable { line: 3, .. })),
        "{findings:?}"
    );
}

#[test]
fn an_empty_archive_does_not_pass() {
    let c = build_chain("empty", 1);
    let findings = verify(&c, "", None);
    assert_eq!(findings, vec![Finding::Empty { what: "batches" }]);
}

/// The cross-check: a health record and a batch that disagree about one chain
/// position. Both signatures are valid in isolation; only comparing them
/// across the two archives exposes it. Constructed by keeping a health record
/// from a *different* chain at the same position.
#[test]
fn a_health_head_that_disagrees_with_the_batch_at_that_position_is_caught() {
    let c = build_chain("crosscheck", 2);
    // Re-anchor the same key on a second chain is not possible (different
    // dev key per runtime), so instead alter the batch content in a way that
    // changes its recomputed head while leaving the health record intact --
    // and anchor nothing else. The signature finding and the head mismatch
    // are both expected; the mismatch is what this test is about.
    let mut tampered = c.batches.clone();
    tampered[1].attested_at_ms += 1;
    let findings = verify(&c, &jsonl(&tampered), Some(&jsonl(&c.health)));
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, Finding::HealthHeadMismatch { sequence: 2, .. })),
        "the health record and the batch must be compared, not just parsed: {findings:?}"
    );
}

/// A window onto a longer chain is verifiable, and is reported as a window.
/// Claiming the chain is complete from its origin when the file starts at
/// sequence 3 would be the verifier overstating its own evidence.
#[test]
fn a_mid_chain_window_verifies_and_says_it_is_a_window() {
    let c = build_chain("window", 4);
    let report = verify_archives(
        OBSERVER_ID,
        KEY_VERSION,
        &c.public_key,
        Some(parse_jsonl::<AttestedBatch>(&jsonl(&c.batches[2..]))),
        None,
    );
    assert!(report.ok(), "{:?}", report.findings);
    assert_eq!(
        report.batches.unwrap().start,
        Some(aip_observe_verify::report::ChainStart::MidChain)
    );
}

// ── The binary, as an auditor runs it ────────────────────────────────────

#[test]
fn the_binary_exits_zero_on_a_clean_chain_and_one_on_a_tampered_one() {
    let c = build_chain("cli", 3);
    let dir = scratch("cli-files");
    let batches = dir.join("attested.archive.jsonl");
    let health = dir.join("health.archive.jsonl");
    let pubfile = dir.join("observer.pub");
    std::fs::write(&batches, jsonl(&c.batches)).unwrap();
    std::fs::write(&health, jsonl(&c.health)).unwrap();
    std::fs::write(&pubfile, format!("{}\n", hex::encode(&c.public_key))).unwrap();

    let invoke = |b: &PathBuf| {
        Command::new(env!("CARGO_BIN_EXE_aip-observe-verify"))
            .args([
                "--observer-id",
                OBSERVER_ID,
                "--key-version",
                "1",
                "--pubkey-file",
                pubfile.to_str().unwrap(),
                "--batches",
                b.to_str().unwrap(),
                "--health",
                health.to_str().unwrap(),
            ])
            .output()
            .expect("run aip-observe-verify")
    };

    let out = invoke(&batches);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success(), "clean chain must exit 0:\n{text}");
    assert!(text.contains("VERIFIED"), "{text}");

    // The same archive with one byte of one record changed.
    let mut lines: Vec<String> = std::fs::read_to_string(&batches)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    lines[1] = lines[1].replace("\"sequence\":2", "\"sequence\":7");
    let bad = dir.join("tampered.jsonl");
    std::fs::write(&bad, lines.join("\n") + "\n").unwrap();
    let out = invoke(&bad);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        out.status.code(),
        Some(1),
        "tampered chain must exit 1:\n{text}"
    );
    assert!(text.contains("NOT VERIFIED"), "{text}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_binary_exits_two_when_the_arguments_cannot_be_used() {
    let out = Command::new(env!("CARGO_BIN_EXE_aip-observe-verify"))
        .args(["--observer-id", "o"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

// ── Protocol 12: the clock reading the collector signed ──────────────────

/// The verifier reports what the collector claimed about its own clock, and
/// keeps "said nothing" apart from "said it was adrift". Reported, never
/// judged: what error bound is acceptable is the institution's policy.
#[test]
fn the_clock_discipline_in_the_signed_bytes_is_reported() {
    let c = build_chain("clock", 3);
    let report = verify_archives(
        OBSERVER_ID,
        KEY_VERSION,
        &c.public_key,
        None,
        Some(parse_jsonl::<SignedSensorHealth>(&jsonl(&c.health))),
    );
    assert!(report.ok(), "{:?}", report.findings);
    let h = report.health.unwrap();
    assert_eq!(h.clock_synchronised, 3);
    assert_eq!(h.clock_unsynchronised, 0);
    assert_eq!(h.clock_not_stated, 0);
    assert_eq!(h.clock_worst_max_error_us, Some(16_000));
}

/// A record whose signed bytes carry no reading is counted as such, never
/// folded into the synchronised count. Otherwise a collector that never
/// looked at its clock would read as one that looked and found it fine.
#[test]
fn a_record_with_no_clock_reading_is_counted_apart_from_a_good_one() {
    let dir = scratch("clock-absent");
    let store = CollectorStore::open(&dir).unwrap();
    let key = CollectorKey::development();
    let public_key = key.public_key().to_vec();
    let mut rt = match CollectorRuntime::start_with_custodian(
        store,
        OBSERVER_ID,
        KEY_VERSION,
        key.into_custodian(),
        ContinuityPolicy::Strict,
    )
    .unwrap()
    {
        Started::Running(rt, _) => rt,
        Started::Refused(b) => panic!("refused: {b:?}"),
    };
    let mut probe = ProcfsProbe::new("probe-1");
    rt.attest(probe.batch([1u8; 16], 1_000, 1_050, vec![]))
        .unwrap();
    let with = rt.health_with_clock(1_100, Some(CLOCK)).unwrap();
    let adrift = rt
        .health_with_clock(
            1_200,
            Some(AttestedClock {
                synchronized: false,
                ..CLOCK
            }),
        )
        .unwrap();
    let without = rt.health(1_300).unwrap();

    let report = verify_archives(
        OBSERVER_ID,
        KEY_VERSION,
        &public_key,
        None,
        Some(parse_jsonl::<SignedSensorHealth>(&jsonl(&[
            with, adrift, without,
        ]))),
    );
    assert!(report.ok(), "{:?}", report.findings);
    let h = report.health.unwrap();
    assert_eq!(
        (
            h.clock_synchronised,
            h.clock_unsynchronised,
            h.clock_not_stated
        ),
        (1, 1, 1),
        "the three facts stay three facts"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
