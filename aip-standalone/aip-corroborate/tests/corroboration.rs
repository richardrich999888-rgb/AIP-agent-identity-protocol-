//! The properties that make a corroboration report worth reading.
//!
//! The danger with a tool like this is not that it crashes; it is that it
//! quietly flatters the system it is checking. These tests are aimed squarely
//! at that: that a real AIP gap is reported, that a loose window cannot make
//! disagreement disappear, that a missing clock anchor is refused rather than
//! guessed, and that the window restriction cannot be used to excuse AIP for
//! something it claimed to be watching.

use aip_corroborate::*;
use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_types::ProcessInstance;

const OBSERVER_ID: &str = "collector-x";
const PROBE_ID: &str = "probe-x";
const ANCHOR_MONO_NS: u64 = 500_000_000_000;
const ANCHOR_WALL_MS: u64 = 1_700_000_000_000;

fn signer() -> CollectorSigner {
    let kp = generate_ed25519_keypair();
    let mut s = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    s.register_probe(PROBE_ID, &SourceMechanism::ALL);
    s
}

fn anchor() -> BootClockAnchor {
    BootClockAnchor {
        realtime_ms: ANCHOR_WALL_MS,
        boottime_ns: ANCHOR_MONO_NS,
        monotonic_ns: ANCHOR_MONO_NS,
        clk_tck: 100,
    }
}

fn bound(pid: u32) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: 1_000,
            boot_id: [3; 16],
        },
        exe_content_sha256: sha256(b"image"),
        exe_path: "/bin/thing".into(),
        container: None,
    }
}

/// An AIP exec event `offset_ms` after the anchor's wall time.
fn exec(seq: u64, pid: u32, offset_ms: i64) -> KernelLifecycleEvent {
    let ns = (ANCHOR_MONO_NS as i128 + offset_ms as i128 * 1_000_000) as u64;
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessExec {
            pid,
            old_pid: pid,
            filename: "/bin/thing".into(),
        },
        cpu: 0,
        kernel_timestamp_ns: ns,
        probe_seq: seq,
        bound: Some(bound(pid)),
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

/// A batch claiming coverage of [anchor-10s, anchor+10s].
fn batch(events: Vec<KernelLifecycleEvent>, with_anchor: bool) -> AttestedBatch {
    signer()
        .attest_at(
            ObservationBatch {
                version: OBSERVE_PROTOCOL_VERSION,
                probe_id: PROBE_ID.into(),
                batch_id: [1; 16],
                probe_run_id: [2; 16],
                probe_seq_first: 1,
                probe_seq_last: events.len().max(1) as u64,
                dropped_events: Some(0),
                active_mechanisms: SourceMechanism::canonical_set(vec![
                    SourceMechanism::SchedTracepoint,
                ]),
                mechanism_integrity: Vec::new(),
                claimed_from_ms: ANCHOR_WALL_MS - 10_000,
                claimed_to_ms: ANCHOR_WALL_MS + 10_000,
                observations: vec![],
                kernel_events: events,
                clock_anchor: with_anchor.then(anchor),
            },
            ANCHOR_WALL_MS + 10_500,
        )
        .unwrap()
}

/// A third-party (auditd, wall-clock) exec at `offset_ms` from the anchor.
fn ext(pid: u32, offset_ms: i64) -> ExternalExec {
    ExternalExec {
        source: ExternalSource::Auditd,
        pid,
        monotonic_ns: None,
        wall_ms: Some(ANCHOR_WALL_MS as i64 + offset_ms),
        image: "/bin/thing".into(),
        outcome: ExecOutcome::Succeeded,
    }
}

/// A failed execve ATTEMPT, as auditd records during a `$PATH` search.
fn ext_failed(pid: u32, offset_ms: i64) -> ExternalExec {
    ExternalExec {
        outcome: ExecOutcome::Failed,
        ..ext(pid, offset_ms)
    }
}

const FULL: Option<(i64, i64)> = Some((
    ANCHOR_WALL_MS as i64 - 10_000,
    ANCHOR_WALL_MS as i64 + 10_000,
));

// ── agreement ────────────────────────────────────────────────────────────

#[test]
fn x01_both_observers_seeing_the_same_execs_is_full_agreement() {
    let b = batch(vec![exec(1, 10, -500), exec(2, 11, -400)], true);
    let e = vec![ext(10, -498), ext(11, -401)];
    let c = corroborate(&[b], &e, FULL, DEFAULT_MATCH_WINDOW_MS, 0).unwrap();
    assert_eq!(c.agreed.len(), 2, "{c:?}");
    assert!(c.aip_only.is_empty());
    assert!(c.external_only.is_empty());
    assert!(c.no_aip_blind_spot());
}

// ── the finding that costs us something ──────────────────────────────────

#[test]
fn x02_an_exec_the_third_party_saw_and_aip_missed_is_reported_as_a_blind_spot() {
    // AIP recorded one exec; the independent observer recorded two, inside a
    // window AIP claims to have covered. The second is an AIP gap.
    let b = batch(vec![exec(1, 10, -500)], true);
    let e = vec![ext(10, -499), ext(99, -300)];
    let c = corroborate(&[b], &e, FULL, DEFAULT_MATCH_WINDOW_MS, 0).unwrap();
    assert_eq!(c.agreed.len(), 1);
    assert_eq!(c.external_only.len(), 1, "the gap must be reported: {c:?}");
    assert_eq!(c.external_only[0].pid, 99);
    assert!(!c.no_aip_blind_spot(), "must not claim a clean result");
}

#[test]
fn x03_aip_only_is_reported_but_is_not_a_blind_spot() {
    let b = batch(vec![exec(1, 10, -500), exec(2, 11, -400)], true);
    let e = vec![ext(10, -499)];
    let c = corroborate(&[b], &e, FULL, DEFAULT_MATCH_WINDOW_MS, 0).unwrap();
    assert_eq!(c.aip_only.len(), 1);
    assert!(c.no_aip_blind_spot(), "AIP seeing more is not an AIP gap");
}

// ── the window cannot be used to rig the result ──────────────────────────

#[test]
fn x04_a_different_pid_never_matches_however_close_in_time() {
    // Pid is part of the join. Two different processes executing in the same
    // millisecond must not be paired into a false agreement.
    let b = batch(vec![exec(1, 10, -500)], true);
    let e = vec![ext(11, -500)];
    let c = corroborate(&[b], &e, FULL, 10_000, 0).unwrap();
    assert!(c.agreed.is_empty(), "different pids must not pair: {c:?}");
    assert_eq!(c.external_only.len(), 1);
    assert_eq!(c.aip_only.len(), 1);
}

#[test]
fn x05_an_event_outside_the_pairing_tolerance_does_not_match() {
    let b = batch(vec![exec(1, 10, -5_000)], true);
    let e = vec![ext(10, 0)]; // 5 s apart
    let c = corroborate(&[b], &e, FULL, 250, 0).unwrap();
    assert!(c.agreed.is_empty());
    assert_eq!(c.external_only.len(), 1);
}

#[test]
fn x06_one_aip_event_cannot_absorb_two_third_party_events() {
    // Two genuine executions of a recycled pid; AIP recorded one. Without
    // single-claim matching the second would be silently absorbed and the gap
    // would vanish from the report.
    let b = batch(vec![exec(1, 10, -500)], true);
    let e = vec![ext(10, -500), ext(10, -450)];
    let c = corroborate(&[b], &e, FULL, 250, 0).unwrap();
    assert_eq!(c.agreed.len(), 1);
    assert_eq!(c.external_only.len(), 1, "the second must survive: {c:?}");
}

// ── fail closed ──────────────────────────────────────────────────────────

#[test]
fn x07_a_batch_without_a_clock_anchor_is_refused_not_guessed() {
    let b = batch(vec![exec(1, 10, -500)], false);
    let e = vec![ext(10, -500)];
    let err = corroborate(&[b], &e, FULL, 250, 0).unwrap_err();
    assert!(
        matches!(err, CorroborateError::NoClockAnchor { .. }),
        "a missing time domain must refuse, never guess: {err:?}"
    );
}

#[test]
fn x08_non_overlapping_runs_are_refused_not_reported_as_agreement() {
    let b = batch(vec![exec(1, 10, -500)], true);
    let e = vec![ext(10, -500)];
    // The observer's run is a day later; the intersection is empty.
    let far = Some((
        ANCHOR_WALL_MS as i64 + 86_400_000,
        ANCHOR_WALL_MS as i64 + 86_500_000,
    ));
    let err = corroborate(&[b], &e, far, 250, 0).unwrap_err();
    assert_eq!(err, CorroborateError::NoOverlap);
}

#[test]
fn x09_an_observer_that_produced_nothing_is_refused() {
    let b = batch(vec![exec(1, 10, -500)], true);
    let err = corroborate(&[b], &[], FULL, 250, 0).unwrap_err();
    assert_eq!(err, CorroborateError::NoExternalEvents);
}

// ── the window restriction cannot excuse AIP ─────────────────────────────

#[test]
fn x10_a_gap_inside_aips_claimed_coverage_is_not_excused_by_the_observer_window() {
    // The third-party observer ran for the whole of AIP's claimed window, and
    // saw an exec AIP did not. Narrowing to the intersection must not drop it.
    let b = batch(vec![], true);
    let e = vec![ext(77, 0)];
    let c = corroborate(&[b], &e, FULL, 250, 0).unwrap();
    assert_eq!(
        c.external_only.len(),
        1,
        "a gap in claimed coverage stands: {c:?}"
    );
}

#[test]
fn x11_an_event_outside_aips_claimed_coverage_is_not_counted_against_it() {
    // AIP never claimed to be watching then, so this is not a blind spot.
    let b = batch(vec![], true);
    let e = vec![ext(77, 60_000)]; // a minute past claimed_to_ms
    let wide = Some((
        ANCHOR_WALL_MS as i64 - 10_000,
        ANCHOR_WALL_MS as i64 + 120_000,
    ));
    let err = corroborate(&[b], &e, wide, 250, 0);
    // Nothing left in the intersection -> report with no findings either way.
    let c = err.unwrap();
    assert!(
        c.external_only.is_empty(),
        "outside claimed coverage is not a gap"
    );
    assert!(c.agreed.is_empty());
}

// ── independence classes are not interchangeable ─────────────────────────

#[test]
fn x12_auditd_and_bpftrace_carry_different_independence_strength() {
    assert_eq!(
        ExternalSource::Auditd.independence(),
        IndependenceClass::DifferentMechanism,
        "auditd reaches the kernel by another subsystem"
    );
    assert_eq!(
        ExternalSource::Bpftrace.independence(),
        IndependenceClass::SameMechanism,
        "bpftrace shares the tracepoint a gate would blind"
    );
}

#[test]
fn x13_unparsed_observer_lines_are_carried_into_the_report() {
    let b = batch(vec![exec(1, 10, -500)], true);
    let e = vec![ext(10, -500)];
    let c = corroborate(&[b], &e, FULL, 250, 7).unwrap();
    assert_eq!(
        c.external_unparsed, 7,
        "incompleteness must reach the reader"
    );
}

#[test]
fn x14_matching_is_deterministic_regardless_of_input_order() {
    let b = batch(vec![exec(1, 10, -500), exec(2, 10, -300)], true);
    let fwd = vec![ext(10, -499), ext(10, -301)];
    let rev = vec![ext(10, -301), ext(10, -499)];
    let a = corroborate(std::slice::from_ref(&b), &fwd, FULL, 250, 0).unwrap();
    let z = corroborate(&[b], &rev, FULL, 250, 0).unwrap();
    assert_eq!(a.agreed.len(), z.agreed.len());
    assert_eq!(a.agreed[0].aip.wall_ms, z.agreed[0].aip.wall_ms);
    assert_eq!(a.external_only.len(), z.external_only.len());
}

// ── the live run found this one; it is locked here ───────────────────────

/// Discovered by the first live run against auditd. `/usr/bin/env true` makes
/// `env` search `$PATH`, and every miss is an execve that returns ENOENT.
/// auditd records all of them; AIP's `sched:sched_process_exec` fires only on
/// success. Counting the failures as AIP blind spots reported 275 fabricated
/// defects against a system that was behaving exactly correctly.
#[test]
fn x15_a_failed_execve_attempt_is_not_an_aip_blind_spot() {
    let b = batch(vec![exec(1, 10, -500)], true);
    // One real execution, and eleven failed attempts by the same process.
    let mut e = vec![ext(10, -499)];
    for i in 0..11 {
        e.push(ext_failed(10, -499 + i));
    }
    let c = corroborate(&[b], &e, FULL, DEFAULT_MATCH_WINDOW_MS, 0).unwrap();
    assert_eq!(c.agreed.len(), 1);
    assert!(
        c.external_only.is_empty(),
        "a failed execve never executed; demanding AIP record it is a comparison bug: {c:?}"
    );
    assert!(c.no_aip_blind_spot());
    assert_eq!(
        c.external_failed_attempts, 11,
        "the attempts must still be counted and reported, not silently dropped"
    );
}

/// The exclusion must not become a way to hide a real gap: a SUCCESSFUL exec
/// that AIP missed is still reported, alongside any failed attempts.
#[test]
fn x16_excluding_failures_does_not_hide_a_real_successful_gap() {
    let b = batch(vec![], true);
    let e = vec![ext_failed(10, -400), ext(77, -300), ext_failed(10, -390)];
    let c = corroborate(&[b], &e, FULL, DEFAULT_MATCH_WINDOW_MS, 0).unwrap();
    assert_eq!(c.external_only.len(), 1, "the successful one must survive");
    assert_eq!(c.external_only[0].pid, 77);
    assert_eq!(c.external_failed_attempts, 2);
    assert!(!c.no_aip_blind_spot());
}

/// An auditd record whose outcome cannot be read is treated as a failed
/// attempt, never as an execution AIP must account for.
#[test]
fn x17_an_unreadable_outcome_is_not_demanded_of_aip() {
    let log = r#"type=SYSCALL msg=audit(1700000000.500:9): arch=c000003e syscall=59 ppid=1 pid=42 comm="x" exe="/bin/x""#;
    let p = parse_auditd(log);
    assert_eq!(p.events.len(), 1);
    assert_eq!(
        p.events[0].outcome,
        ExecOutcome::Failed,
        "no success= field => not an execution"
    );
}
