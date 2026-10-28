//! The properties that make this cross-check worth citing.
//!
//! The failure mode to fear is not a crash; it is a comparison that quietly
//! reports agreement it did not establish. Every test here is aimed at that:
//! that a missing digest selector is never agreement, that a reused pid is
//! never agreement, that a mismatch is reported, and that the agent's own
//! account never enters the decision.

use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_spiffe::*;
use aip_types::ProcessInstance;

const OBSERVER: &str = "collector-s2";
const PROBE: &str = "probe-s2";
const SPIFFE_ID: &str = "spiffe://aip.local/workload/demo";
const ANCHOR_MONO_NS: u64 = 400_000_000_000;
const ANCHOR_WALL_MS: u64 = 1_700_000_000_000;
const CLK_TCK: u32 = 100;
const TICK_NS: u64 = 1_000_000_000 / CLK_TCK as u64;
const PID: u32 = 4242;

fn anchor() -> BootClockAnchor {
    BootClockAnchor {
        realtime_ms: ANCHOR_WALL_MS,
        boottime_ns: ANCHOR_MONO_NS,
        monotonic_ns: ANCHOR_MONO_NS,
        clk_tck: CLK_TCK,
    }
}

/// A process instance whose start maps to `offset_ms` from the anchor's wall time.
fn proc_at(pid: u32, start_offset_ms: i64, image: &[u8]) -> ObservedProcess {
    let start_ns = (ANCHOR_MONO_NS as i128 + start_offset_ms as i128 * 1_000_000) as u64;
    ObservedProcess {
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: start_ns / TICK_NS,
            boot_id: [7; 16],
        },
        exe_content_sha256: sha256(image),
        exe_path: "/opt/workload".into(),
        container: None,
    }
}

fn event(seq: u64, bound: ObservedProcess) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        cgroup: aip_observe::CgroupSample::NotSampled,
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessExec {
            pid: bound.process.pid,
            old_pid: bound.process.pid,
            filename: "/opt/workload".into(),
        },
        cpu: 0,
        kernel_timestamp_ns: ANCHOR_MONO_NS,
        probe_seq: seq,
        bound: Some(bound),
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

fn batch(events: Vec<KernelLifecycleEvent>, with_anchor: bool) -> AttestedBatch {
    let kp = generate_ed25519_keypair();
    let mut s = CollectorSigner::new(OBSERVER, 1, &kp.private_key, &kp.public_key).unwrap();
    s.register_probe(PROBE, &SourceMechanism::ALL);
    s.attest_at(
        ObservationBatch {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: PROBE.into(),
            batch_id: [1; 16],
            probe_run_id: [2; 16],
            probe_seq_first: 1,
            probe_seq_last: events.len().max(1) as u64,
            dropped_events: Some(0),
            active_mechanisms: SourceMechanism::canonical_set(vec![
                SourceMechanism::SchedTracepoint,
            ]),
            mechanism_integrity: Vec::new(),
            claimed_from_ms: ANCHOR_WALL_MS - 60_000,
            claimed_to_ms: ANCHOR_WALL_MS + 60_000,
            observations: vec![],
            kernel_events: events,
            clock_anchor: with_anchor.then(anchor),
        },
        ANCHOR_WALL_MS + 61_000,
    )
    .unwrap()
}

fn registry_with(selectors: &str) -> Registry {
    parse_entry_show(&format!(
        "Entry ID : e1\nSPIFFE ID : {SPIFFE_ID}\nParent ID : spiffe://aip.local/spire/agent/x\n{selectors}\n"
    ))
}

fn digest_selector(image: &[u8]) -> String {
    let d = sha256(image);
    let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
    format!("Selector : unix:sha256:{hex}")
}

/// An SVID issued 5 s after the anchor, observed 1 s later, valid for an hour.
fn assertion(pid: u32) -> WorkloadIdentityAssertion {
    WorkloadIdentityAssertion {
        spiffe_id: SPIFFE_ID.into(),
        pid,
        not_before_ms: ANCHOR_WALL_MS as i64 + 5_000,
        not_after_ms: ANCHOR_WALL_MS as i64 + 3_600_000,
        observed_at_ms: ANCHOR_WALL_MS as i64 + 6_000,
        serial: "1".into(),
        trust_domain: "aip.local".into(),
        svid_chain_pem: String::new(),
        bundle_pem: String::new(),
    }
}

// ── the honest path ──────────────────────────────────────────────────────

#[test]
fn s01_two_authorities_measuring_the_same_binary_agree() {
    let b = batch(vec![event(1, proc_at(PID, 0, b"real workload"))], true);
    let r = registry_with(&format!(
        "{}\nSelector : unix:uid:0",
        digest_selector(b"real workload")
    ));
    let out = compare_workload_identity(&assertion(PID), &r, &[b]);
    assert!(out.agrees(), "{out:?}");
    if let WorkloadIdentityComparison::Agrees {
        other_selectors, ..
    } = &out
    {
        assert_eq!(
            other_selectors,
            &vec!["unix:uid:0".to_string()],
            "uncorroborated selectors must be surfaced, not hidden"
        );
    }
}

// ── the finding ──────────────────────────────────────────────────────────

#[test]
fn s02_a_different_binary_under_the_same_identity_diverges() {
    // SPIRE's entry requires the digest of the authorised image; AIP measured
    // something else running under that identity.
    let b = batch(vec![event(1, proc_at(PID, 0, b"substituted binary"))], true);
    let r = registry_with(&digest_selector(b"real workload"));
    let out = compare_workload_identity(&assertion(PID), &r, &[b]);
    assert!(
        out.diverges(),
        "a substituted image must be a finding: {out:?}"
    );
    match out {
        WorkloadIdentityComparison::Diverges {
            divergence:
                IdentityDivergence::DigestMismatch {
                    spire_required_hex,
                    aip_measured_hex,
                    ..
                },
        } => assert_ne!(spire_required_hex, aip_measured_hex),
        other => panic!("expected DigestMismatch, got {other:?}"),
    }
}

// ── the case that must never read as agreement ───────────────────────────

#[test]
fn s03_an_identity_that_never_rested_on_code_is_not_comparable_not_agreement() {
    // uid-only entry: SPIRE never made a claim about the workload's code, so
    // there is nothing for AIP to confirm. Reporting this as agreement would
    // be the single most damaging bug this crate could have.
    let b = batch(vec![event(1, proc_at(PID, 0, b"anything at all"))], true);
    let r = registry_with("Selector : unix:uid:0");
    let out = compare_workload_identity(&assertion(PID), &r, &[b]);
    assert!(
        !out.agrees(),
        "no code requirement can never be agreement: {out:?}"
    );
    match out {
        WorkloadIdentityComparison::NotComparable {
            reason:
                NotComparableReason::NoDigestSelector {
                    other_selectors, ..
                },
        } => assert_eq!(other_selectors, vec!["unix:uid:0".to_string()]),
        other => panic!("expected NoDigestSelector, got {other:?}"),
    }
}

// ── pid reuse ────────────────────────────────────────────────────────────

#[test]
fn s04_an_instance_that_started_after_attestation_is_a_reused_pid_not_a_match() {
    // Same pid, same image — but this instance began well AFTER SPIRE attested
    // the caller, so it cannot be that caller. Matching digests must not
    // rescue it. (Reference is the fetch, not notBefore: SPIRE pre-mints.)
    let b = batch(vec![event(1, proc_at(PID, 35_000, b"real workload"))], true);
    let r = registry_with(&digest_selector(b"real workload"));
    let out = compare_workload_identity(&assertion(PID), &r, &[b]);
    assert!(
        !out.agrees(),
        "a later instance is not the attested one: {out:?}"
    );
    assert!(
        matches!(
            out,
            WorkloadIdentityComparison::Diverges {
                divergence: IdentityDivergence::InstanceStartedAfterAttestation { .. }
            }
        ),
        "{out:?}"
    );
}

#[test]
fn s05_an_instance_that_started_before_attestation_is_fine() {
    let b = batch(
        vec![event(1, proc_at(PID, -20_000, b"real workload"))],
        true,
    );
    let r = registry_with(&digest_selector(b"real workload"));
    assert!(compare_workload_identity(&assertion(PID), &r, &[b]).agrees());
}

// ── refusals ─────────────────────────────────────────────────────────────

#[test]
fn s06_no_aip_measurement_of_that_pid_is_refused() {
    let b = batch(vec![event(1, proc_at(9999, 0, b"real workload"))], true);
    let r = registry_with(&digest_selector(b"real workload"));
    let out = compare_workload_identity(&assertion(PID), &r, &[b]);
    assert!(
        matches!(
            out,
            WorkloadIdentityComparison::NotComparable {
                reason: NotComparableReason::NoAipMeasurement { .. }
            }
        ),
        "{out:?}"
    );
}

#[test]
fn s07_two_instances_at_one_pid_are_ambiguous_never_a_verdict() {
    let b = batch(
        vec![
            event(1, proc_at(PID, -20_000, b"real workload")),
            event(2, proc_at(PID, -10_000, b"real workload")),
        ],
        true,
    );
    let r = registry_with(&digest_selector(b"real workload"));
    let out = compare_workload_identity(&assertion(PID), &r, &[b]);
    assert!(
        matches!(
            out,
            WorkloadIdentityComparison::NotComparable {
                reason: NotComparableReason::AmbiguousProcessInstance { instances: 2, .. }
            }
        ),
        "{out:?}"
    );
}

#[test]
fn s08_no_clock_anchor_refuses_rather_than_skipping_the_reuse_check() {
    let b = batch(vec![event(1, proc_at(PID, 0, b"real workload"))], false);
    let r = registry_with(&digest_selector(b"real workload"));
    let out = compare_workload_identity(&assertion(PID), &r, &[b]);
    assert!(
        matches!(
            out,
            WorkloadIdentityComparison::NotComparable {
                reason: NotComparableReason::NoClockAnchor
            }
        ),
        "without an anchor the pid-reuse check cannot run: {out:?}"
    );
}

#[test]
fn s09_an_svid_observed_outside_its_validity_attests_nothing() {
    let b = batch(vec![event(1, proc_at(PID, 0, b"real workload"))], true);
    let r = registry_with(&digest_selector(b"real workload"));
    let mut a = assertion(PID);
    a.observed_at_ms = a.not_after_ms + 1;
    let out = compare_workload_identity(&a, &r, &[b]);
    assert!(
        matches!(
            out,
            WorkloadIdentityComparison::NotComparable {
                reason: NotComparableReason::SvidOutsideValidity { .. }
            }
        ),
        "{out:?}"
    );
}

#[test]
fn s10_an_unregistered_spiffe_id_is_refused() {
    let b = batch(vec![event(1, proc_at(PID, 0, b"real workload"))], true);
    let r = parse_entry_show(
        "Entry ID : e\nSPIFFE ID : spiffe://aip.local/other\nSelector : unix:uid:0\n",
    );
    let out = compare_workload_identity(&assertion(PID), &r, &[b]);
    assert!(
        matches!(
            out,
            WorkloadIdentityComparison::NotComparable {
                reason: NotComparableReason::UnknownSpiffeId { .. }
            }
        ),
        "{out:?}"
    );
}

#[test]
fn s11_contradictory_digest_selectors_are_refused_not_guessed() {
    let b = batch(vec![event(1, proc_at(PID, 0, b"real workload"))], true);
    let r = registry_with(&format!(
        "{}\n{}",
        digest_selector(b"real workload"),
        digest_selector(b"some other image")
    ));
    let out = compare_workload_identity(&assertion(PID), &r, &[b]);
    assert!(
        matches!(
            out,
            WorkloadIdentityComparison::NotComparable {
                reason: NotComparableReason::ContradictoryDigestSelectors { count: 2, .. }
            }
        ),
        "{out:?}"
    );
}

#[test]
fn s12_an_empty_spiffe_id_is_no_svid() {
    let b = batch(vec![event(1, proc_at(PID, 0, b"real workload"))], true);
    let r = registry_with(&digest_selector(b"real workload"));
    let mut a = assertion(PID);
    a.spiffe_id = String::new();
    assert!(matches!(
        compare_workload_identity(&a, &r, &[b]),
        WorkloadIdentityComparison::NotComparable {
            reason: NotComparableReason::NoSvid
        }
    ));
}

// ── the structural guarantee ─────────────────────────────────────────────

/// The comparison takes SPIRE's assertion, SPIRE's registry and AIP's attested
/// evidence. There is no parameter through which the workload's own account of
/// itself could enter, and this test exists so that stays true: adding one
/// would not compile without changing this call.
#[test]
fn s13_the_workload_never_testifies_about_itself() {
    let b = batch(vec![event(1, proc_at(PID, 0, b"real workload"))], true);
    let r = registry_with(&digest_selector(b"real workload"));
    let out: WorkloadIdentityComparison = compare_workload_identity(&assertion(PID), &r, &[b]);
    assert!(out.agrees());
}

// ── the bug the first live run found ─────────────────────────────────────

/// SPIRE's agent **pre-mints** SVIDs for registered entries before any workload
/// asks for one. A certificate's `notBefore` therefore records when it was
/// minted, and can precede the workload's own start by many seconds.
///
/// The first live joint run reported a perfectly healthy workload as a reused
/// pid for exactly this reason: the process began ~12 s after `notBefore`. The
/// instant SPIRE actually attested *this caller* is the fetch. Anchoring the
/// guard to `notBefore` makes the tool cry wolf on every normal deployment,
/// which is the fastest way to have a control switched off in production.
#[test]
fn s14_a_pre_minted_svid_does_not_make_a_healthy_workload_look_like_a_reused_pid() {
    // notBefore 60 s before the anchor; the process starts at the anchor and
    // fetches 6 s later. That is the ordinary case, not a reuse.
    let b = batch(vec![event(1, proc_at(PID, 0, b"real workload"))], true);
    let r = registry_with(&digest_selector(b"real workload"));
    let mut a = assertion(PID);
    a.not_before_ms = ANCHOR_WALL_MS as i64 - 60_000;
    assert!(
        a.observed_at_ms > ANCHOR_WALL_MS as i64,
        "fetch must follow the start"
    );

    let out = compare_workload_identity(&a, &r, &[b]);
    assert!(
        out.agrees(),
        "a pre-minted SVID is normal SPIRE behaviour, not a reused pid: {out:?}"
    );
}

/// The guard must still fire when it should: same pre-minted SVID, but the
/// instance began after the fetch.
#[test]
fn s15_the_reuse_guard_still_fires_against_the_attestation_instant() {
    let b = batch(vec![event(1, proc_at(PID, 40_000, b"real workload"))], true);
    let r = registry_with(&digest_selector(b"real workload"));
    let mut a = assertion(PID);
    a.not_before_ms = ANCHOR_WALL_MS as i64 - 60_000; // pre-minted, as in the wild
    let out = compare_workload_identity(&a, &r, &[b]);
    assert!(
        matches!(
            out,
            WorkloadIdentityComparison::Diverges {
                divergence: IdentityDivergence::InstanceStartedAfterAttestation { .. }
            }
        ),
        "{out:?}"
    );
}
