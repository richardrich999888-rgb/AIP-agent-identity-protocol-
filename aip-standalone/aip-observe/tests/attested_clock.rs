//! Protocol 12 — the collector's clock discipline inside the signed bytes.
//!
//! # The gap this closes
//!
//! The collector stamps `attested_at_ms` on every batch and `emitted_at_ms`
//! on every health record. Those stamps are the evidence's placement in time.
//! Until protocol 12 nothing signed said whether the clock producing them was
//! being steered by anything: the daemon read `ntp_adjtime` at start and on
//! each health cycle and wrote the answer to its log, and a log is not
//! evidence a verifier holds. An auditor reading a sealed archive could not
//! confirm it, which is the difference between a control and an assumption.
//!
//! The failure mode is specific and is why this is worth a protocol bump: an
//! undisciplined collector does not produce one wrong timestamp. It produces
//! an archive that is wrong *together* and perfectly self-consistent, and
//! nothing inside the sealed bytes reveals it.
//!
//! # What these tests pin
//!
//! That the reading is covered by the signature (so it cannot be edited or
//! dropped after signing), that absence is distinguishable from a good
//! reading (so silence is never read as "fine"), and that the budget
//! predicate a verifier applies is the same one the daemon's startup gate
//! applies.

use aip_observe::{
    verify_signed_health, AttestedClock, CollectorKey, CollectorRuntime, CollectorStore,
    ContinuityPolicy, ObserverTrustAnchors, Started, VerifyError,
};

const OBSERVER_ID: &str = "collector.clock";
const KEY_VERSION: u32 = 1;

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aip-attested-clock-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fixture {
    rt: CollectorRuntime,
    public_key: Vec<u8>,
    _dir: std::path::PathBuf,
}

fn fixture(tag: &str) -> Fixture {
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
    let rt = match started {
        Started::Running(rt, _) => rt,
        Started::Refused(b) => panic!("fresh runtime refused: {b:?}"),
    };
    Fixture {
        rt,
        public_key,
        _dir: dir,
    }
}

fn anchors(f: &Fixture) -> ObserverTrustAnchors {
    ObserverTrustAnchors::new().trust(OBSERVER_ID, KEY_VERSION, &f.public_key)
}

const DISCIPLINED: AttestedClock = AttestedClock {
    synchronized: true,
    max_error_us: 16_000, // 16 ms
    state: 0,
};

/// The attested clock arrived in protocol 12 and is in every later version.
/// The pin on the *current* version moved to `tests/cgroup_wire.rs` with
/// protocol 13, the change that owns it.
const _: () = assert!(aip_observe::OBSERVE_PROTOCOL_VERSION >= 12);

// ── The reading is evidence, not commentary ──────────────────────────────

#[test]
fn a_disciplined_clock_is_signed_and_verifies() {
    let f = fixture("good");
    let h = f.rt.health_with_clock(1_000, Some(DISCIPLINED)).unwrap();
    assert_eq!(h.health.clock, Some(DISCIPLINED));
    assert_eq!(verify_signed_health(&h, &anchors(&f)), Ok(()));
}

/// The point of putting it in the attested bytes. Editing the reading after
/// signing must break the signature; otherwise the operator could export an
/// archive whose clock claims are whatever suits them.
#[test]
fn editing_the_clock_reading_after_signing_breaks_the_signature() {
    let f = fixture("edit");
    let h = f.rt.health_with_clock(1_000, Some(DISCIPLINED)).unwrap();

    let mut tampered = h.clone();
    tampered.health.clock = Some(AttestedClock {
        synchronized: true,
        max_error_us: 1, // a much better clock than the one that was read
        state: 0,
    });
    assert_eq!(
        verify_signed_health(&tampered, &anchors(&f)),
        Err(VerifyError::PayloadHashMismatch)
    );
}

/// Dropping it is the same attack in the other direction: an operator whose
/// clock was undisciplined removes the field so the record says nothing.
#[test]
fn dropping_the_clock_reading_after_signing_breaks_the_signature() {
    let f = fixture("drop");
    let h = f.rt.health_with_clock(1_000, Some(DISCIPLINED)).unwrap();

    let mut stripped = h.clone();
    stripped.health.clock = None;
    assert_eq!(
        verify_signed_health(&stripped, &anchors(&f)),
        Err(VerifyError::PayloadHashMismatch)
    );
}

/// And forging one into a record that carried none.
#[test]
fn inserting_a_clock_reading_into_a_record_that_had_none_breaks_the_signature() {
    let f = fixture("insert");
    let h = f.rt.health(1_000).unwrap();
    assert_eq!(h.health.clock, None);

    let mut forged = h.clone();
    forged.health.clock = Some(DISCIPLINED);
    assert_eq!(
        verify_signed_health(&forged, &anchors(&f)),
        Err(VerifyError::PayloadHashMismatch)
    );
}

// ── Absence is not "fine" ────────────────────────────────────────────────

/// A record with no reading and a record with a good reading must not be the
/// same bytes. If they were, a collector that never read its clock would be
/// indistinguishable from one that read it and found it disciplined, and the
/// control would be worth nothing.
#[test]
fn a_record_with_no_reading_differs_from_one_with_a_reading() {
    let f = fixture("absent-differs");
    let none = f.rt.health(1_000).unwrap();
    let some = f.rt.health_with_clock(1_000, Some(DISCIPLINED)).unwrap();
    assert_ne!(
        none.health.canonical_bytes(),
        some.health.canonical_bytes(),
        "absence of a clock reading must be encoded, not omitted"
    );
}

/// An unsynchronised reading must also be distinguishable from a
/// synchronised one with the same error bound: it is the `STA_UNSYNC` flag,
/// not the number, that says whether anything is steering the clock.
#[test]
fn an_unsynchronised_reading_is_distinguishable_from_a_synchronised_one() {
    let f = fixture("unsync");
    let synced = f.rt.health_with_clock(1_000, Some(DISCIPLINED)).unwrap();
    let unsynced =
        f.rt.health_with_clock(
            1_000,
            Some(AttestedClock {
                synchronized: false,
                ..DISCIPLINED
            }),
        )
        .unwrap();
    assert_ne!(
        synced.health.canonical_bytes(),
        unsynced.health.canonical_bytes()
    );
}

// ── The predicate a verifier applies ─────────────────────────────────────

#[test]
fn the_budget_predicate_requires_both_synchronisation_and_the_bound() {
    // Inside the budget and steered: passes.
    assert!(DISCIPLINED.within(50));
    // Inside the budget but nothing is steering it: fails. A stale bound on
    // an abandoned clock is not evidence of accuracy, however small.
    assert!(!AttestedClock {
        synchronized: false,
        ..DISCIPLINED
    }
    .within(50));
    // Steered but outside the budget: fails.
    assert!(!DISCIPLINED.within(1));
    // Boundary: the budget is inclusive, in milliseconds against a
    // microsecond bound.
    assert!(DISCIPLINED.within(16));
    assert!(!DISCIPLINED.within(15));
}

/// `maxerror` is a `c_long` and the kernel may report a negative value. The
/// encoding must round-trip it rather than silently saturating, and the
/// budget predicate must treat it as "better than any budget" rather than
/// wrapping to an enormous positive.
#[test]
fn a_negative_error_bound_encodes_and_compares_as_a_negative() {
    let f = fixture("negative");
    let negative = AttestedClock {
        synchronized: true,
        max_error_us: -1,
        state: 0,
    };
    let h = f.rt.health_with_clock(1_000, Some(negative)).unwrap();
    assert_eq!(h.health.clock, Some(negative));
    assert_eq!(verify_signed_health(&h, &anchors(&f)), Ok(()));
    assert!(negative.within(0));
    assert_ne!(
        h.health.canonical_bytes(),
        f.rt.health_with_clock(
            1_000,
            Some(AttestedClock {
                max_error_us: i64::MAX,
                ..negative
            })
        )
        .unwrap()
        .health
        .canonical_bytes()
    );
}

// ── The live reading ─────────────────────────────────────────────────────

/// This host's real clock, read through `ntp_adjtime`, signed and verified.
/// It asserts nothing about whether the clock is disciplined -- a build host
/// may legitimately have no time daemon -- only that a real reading survives
/// the round trip into signed evidence. Skipped where the syscall is not
/// available, which is reported rather than silently passing.
#[test]
#[cfg(target_os = "linux")]
fn this_hosts_real_clock_reading_round_trips_into_signed_evidence() {
    let Ok(d) = aip_observe::clock::clock_discipline() else {
        eprintln!("skipped: ntp_adjtime unavailable on this host");
        return;
    };
    let f = fixture("live");
    let attested = AttestedClock::from(d);
    let h = f.rt.health_with_clock(1_000, Some(attested)).unwrap();
    assert_eq!(verify_signed_health(&h, &anchors(&f)), Ok(()));
    let signed = h.health.clock.expect("the reading is in the record");
    assert_eq!(signed.synchronized, d.synchronized);
    assert_eq!(signed.max_error_us, d.max_error_us);
    assert_eq!(signed.state, d.state);
    eprintln!("this host, signed: {}", d.summary());
}
