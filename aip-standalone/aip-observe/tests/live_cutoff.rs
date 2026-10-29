//! Common-cutoff batching regressions. Synthetic events reproduce exact
//! historical shapes/timestamps; original signed archives are never altered.
use aip_observe::{
    detect_cross_sensor_divergence_default, BootClockAnchor, CgroupSample, KernelLifecycleKind,
    MechanismIntegrity, ObservationBatch, ProcEvent, ProcfsProbe, SourceMechanism,
};

fn probe() -> ProcfsProbe {
    let mut probe = ProcfsProbe::new("cutoff-test");
    for mechanism in [
        SourceMechanism::SchedTracepoint,
        SourceMechanism::ProcConnector,
    ] {
        probe.declare_source(mechanism);
        probe.declare_mechanism_integrity(mechanism, MechanismIntegrity::Verified);
    }
    probe.enable_loss_counter();
    probe
}

fn anchor(probe: &mut ProcfsProbe, cutoff_ns: u64, close_ms: u64) {
    probe.declare_clock_anchor(BootClockAnchor {
        realtime_ms: close_ms + 50,
        boottime_ns: cutoff_ns + 50_000_000,
        monotonic_ns: cutoff_ns + 50_000_000,
        clk_tck: 100,
    });
}

fn exec(probe: &mut ProcfsProbe, connector: bool, pid: u32, stamp: u64) {
    let event = ProcEvent {
        cgroup: CgroupSample::NotSampled,
        kind: if connector {
            KernelLifecycleKind::Exec { pid, tgid: pid }
        } else {
            KernelLifecycleKind::ProcessExec {
                pid,
                old_pid: pid,
                filename: "/synthetic/agent".into(),
            }
        },
        cpu: 0,
        timestamp_ns: stamp,
    };
    if connector {
        probe.ingest_kernel_event(event);
    } else {
        probe.ingest_sched_event(event);
    }
}

fn finish(
    probe: &mut ProcfsProbe,
    counter: u8,
    from: u64,
    close: u64,
    cutoff: u64,
) -> ObservationBatch {
    anchor(probe, cutoff, close);
    probe.batch_through([counter; 16], from, close, Some(cutoff))
}

fn unknown(batch: &ObservationBatch) -> bool {
    batch
        .mechanism_integrity
        .iter()
        .any(|report| report.integrity == MechanismIntegrity::Unverifiable)
}

#[test]
fn exact_signed_run_event_shapes_survive_forward_and_reverse_drain_splits() {
    // PR8 seq4/5, seq14/15 and the combined run seq32/33. The scheduler
    // counterpart exists 9–29 microseconds before each connector event.
    let cases = [
        (6790, 214_135_315_498, 214_135_303_535),
        (6808, 228_099_515_677, 228_099_501_490),
        (6809, 228_795_022_665, 228_794_993_891),
        (6810, 228_821_449_426, 228_821_439_748),
        (6811, 228_849_272_219, 228_849_258_844),
        (6841, 221_339_445_596, 221_339_432_992),
    ];
    for (pid, connector, sched) in cases {
        for connector_first in [true, false] {
            let mut p = probe();
            let cutoff = sched - 100_000_000;
            exec(
                &mut p,
                connector_first,
                pid,
                if connector_first { connector } else { sched },
            );
            let captured = p.pending_kernel_events()[0].clone();
            let first = finish(&mut p, 1, 900, 1000, cutoff);
            assert!(first.kernel_events.is_empty());
            assert_eq!(p.pending_kernel_events(), &[captured]);
            assert!(!unknown(&first));
            exec(
                &mut p,
                !connector_first,
                pid,
                if connector_first { sched } else { connector },
            );
            let second = finish(&mut p, 2, first.claimed_to_ms, 2000, cutoff + 1_000_000_000);
            assert_eq!(second.kernel_events.len(), 2);
            assert!(detect_cross_sensor_divergence_default(&second).is_empty());
            assert!(!unknown(&second));
            assert_eq!((second.probe_seq_first, second.probe_seq_last), (1, 2));
            assert_eq!(
                second
                    .kernel_events
                    .iter()
                    .map(|e| e.probe_seq)
                    .collect::<Vec<_>>(),
                [1, 2]
            );
            assert!(p.pending_kernel_events().is_empty());
        }
    }
}

#[test]
fn pair_retreat_keeps_every_retained_record_outside_inclusive_ms_coverage() {
    let mut p = probe();
    p.declare_clock_anchor(BootClockAnchor {
        realtime_ms: 1000,
        monotonic_ns: 200_500_000,
        boottime_ns: 200_500_000,
        clk_tck: 100,
    });
    // One pair crosses the natural cutoff. A third record falls just after
    // its retreated frontier in the SAME wall millisecond (the rounding trap).
    exec(&mut p, false, u32::MAX, 140_100_000);
    exec(&mut p, true, u32::MAX, 150_500_001);
    exec(&mut p, false, u32::MAX - 1, 139_200_000);
    let first = p.batch_through([1; 16], 900, 950, Some(150_500_000));
    assert!(!unknown(&first));
    assert!(first.kernel_events.is_empty());
    assert_eq!(p.pending_kernel_events().len(), 3);
    let clock = first.clock_anchor.unwrap();
    assert!(p
        .pending_kernel_events()
        .iter()
        .all(|event| clock.wall_ms(event.kernel_timestamp_ns) > first.claimed_to_ms));
    let second = finish(&mut p, 2, first.claimed_to_ms, 1100, 300_500_000);
    assert_eq!(second.kernel_events.len(), 3);
    assert!(detect_cross_sensor_divergence_default(&second).is_empty());
    assert_eq!((second.probe_seq_first, second.probe_seq_last), (1, 3));
}

#[test]
fn true_missing_scheduler_path_still_triggers_the_unchanged_strict_detector() {
    let mut p = probe();
    exec(&mut p, true, u32::MAX, 100_000_000);
    let batch = finish(&mut p, 1, 900, 1000, 200_000_000);
    assert_eq!(batch.kernel_events.len(), 1);
    assert_eq!(
        detect_cross_sensor_divergence_default(&batch)
            .divergences
            .len(),
        1
    );
}

#[test]
fn late_before_finalized_cutoff_and_clock_failure_are_explicit_uncertainty() {
    let mut p = probe();
    let first = finish(&mut p, 1, 900, 1000, 200_000_000);
    exec(&mut p, true, u32::MAX, 150_000_000);
    exec(&mut p, false, u32::MAX, 150_000_001);
    let second = finish(&mut p, 2, first.claimed_to_ms, 2000, 1_200_000_000);
    assert!(unknown(&second));
    assert_eq!(second.kernel_events.len(), 2);
    exec(&mut p, true, u32::MAX - 1, 1_300_000_000);
    let no_clock = p.batch_through([3; 16], 2000, 2100, None);
    assert!(unknown(&no_clock));
    assert_eq!(no_clock.kernel_events.len(), 1);
    assert_eq!(no_clock.probe_seq_first, 3);
}

#[test]
fn capacity_and_read_failures_retain_records_and_override_clean_gate_readings() {
    let mut p = probe();
    let mut captured = 0;
    while p.live_event_capacity_available() {
        exec(&mut p, false, u32::MAX, 2_000_000_000 + captured);
        captured += 1;
    }
    assert!(captured > 0 && captured <= 4096);
    p.record_source_fault(SourceMechanism::SchedTracepoint);
    // A clean gate query later in this cycle must not erase incomplete drain.
    p.declare_mechanism_integrity(
        SourceMechanism::SchedTracepoint,
        MechanismIntegrity::Verified,
    );
    let deferred = finish(&mut p, 1, 900, 1000, 1_000_000_000);
    assert!(unknown(&deferred));
    assert_eq!(p.pending_kernel_events().len(), captured as usize);
    let flushed = finish(&mut p, 2, deferred.claimed_to_ms, 3000, 3_000_000_000);
    assert_eq!(flushed.kernel_events.len(), captured as usize);
    assert_eq!(flushed.probe_seq_last, captured);
    assert!(p.pending_kernel_events().is_empty());
}

#[test]
fn deferred_records_do_not_cross_probe_restart_and_loss_is_never_erased() {
    let mut old = probe();
    exec(&mut old, true, u32::MAX, 500_000_000);
    let old_run = old.run_id();
    let held = finish(&mut old, 1, 900, 1000, 200_000_000);
    assert!(held.kernel_events.is_empty());
    let mut restarted = probe();
    assert_ne!(old_run, restarted.run_id());
    assert!(restarted.pending_kernel_events().is_empty());
    restarted.record_lost_events(3);
    let batch = finish(&mut restarted, 1, 1000, 2000, 1_200_000_000);
    assert_eq!(batch.dropped_events, Some(3));
    // Still retain the original old-run record; no restart copies it into a
    // different stream or claims it was durably acknowledged.
    assert_eq!(old.pending_kernel_events().len(), 1);
}

#[test]
fn reverse_timestamp_straddle_and_overlapping_pairs_retreat_to_a_fixed_point() {
    let mut p = probe();
    // Connector-first timestamps, not merely connector-first drain order.
    exec(&mut p, true, u32::MAX, 140_100_000);
    exec(&mut p, false, u32::MAX, 150_500_001);
    // Retreat for the first pair now crosses this second pair as well.
    exec(&mut p, false, u32::MAX - 1, 130_100_000);
    exec(&mut p, true, u32::MAX - 1, 139_200_000);
    let first = finish(&mut p, 1, 900, 950, 150_500_000);
    assert!(first.kernel_events.is_empty());
    assert!(!unknown(&first));
    assert_eq!(p.pending_kernel_events().len(), 4);
    let clock = first.clock_anchor.unwrap();
    assert!(p
        .pending_kernel_events()
        .iter()
        .all(|e| clock.wall_ms(e.kernel_timestamp_ns) > first.claimed_to_ms));
    let second = finish(&mut p, 2, first.claimed_to_ms, 1050, 250_500_000);
    assert_eq!(second.kernel_events.len(), 4);
    assert!(detect_cross_sensor_divergence_default(&second).is_empty());
}

#[test]
fn boot_origin_rounding_that_cannot_represent_a_safe_frontier_is_unknown() {
    let mut p = probe();
    p.declare_clock_anchor(BootClockAnchor {
        realtime_ms: 1000,
        monotonic_ns: 10_500_000,
        boottime_ns: 10_500_000,
        clk_tck: 100,
    });
    exec(&mut p, false, u32::MAX, 100_000);
    let batch = p.batch_through([1; 16], 900, 990, Some(0));
    assert!(batch.kernel_events.is_empty());
    assert!(unknown(&batch));
    assert_eq!(p.pending_kernel_events().len(), 1);
}

#[test]
fn publication_reorders_only_by_finalized_window_and_preserves_captured_fields() {
    let mut p = probe();
    exec(&mut p, false, u32::MAX, 500_000_000);
    let original = p.pending_kernel_events()[0].clone();
    exec(&mut p, false, u32::MAX - 1, 100_000_000);
    let first = finish(&mut p, 1, 900, 1000, 200_000_000);
    assert_eq!(first.kernel_events.len(), 1);
    assert_eq!(first.kernel_events[0].probe_seq, 1);
    let second = finish(&mut p, 2, first.claimed_to_ms, 2000, 1_200_000_000);
    assert_eq!(second.kernel_events.len(), 1);
    let mut expected = original;
    expected.probe_seq = 2;
    assert_eq!(second.kernel_events[0], expected);
    let third = finish(&mut p, 3, second.claimed_to_ms, 3000, 2_200_000_000);
    assert!(third.kernel_events.is_empty());
    assert_eq!((third.probe_seq_first, third.probe_seq_last), (2, 2));
}

#[test]
fn explicit_successful_read_recovery_never_backfills_the_failed_window() {
    use aip_observe::{CollectorSigner, ObserverAttestor, ObserverState};
    let key = aip_crypto::generate_ed25519_keypair();
    let mut signer =
        CollectorSigner::new("cutoff-collector", 1, &key.private_key, &key.public_key).unwrap();
    signer.register_probe("cutoff-test", &SourceMechanism::ALL);
    let mut p = probe();
    let first = finish(&mut p, 1, 1000, 1100, 200_000_000);
    signer.attest(first).unwrap();
    let second = finish(&mut p, 2, 1100, 1200, 300_000_000);
    signer.attest(second).unwrap();
    assert_eq!(
        signer.health(1200).unwrap().health.state,
        ObserverState::Active
    );
    p.record_source_fault(SourceMechanism::ProcConnector);
    let failed = finish(&mut p, 3, 1200, 1300, 400_000_000);
    signer.attest(failed).unwrap();
    let failed_health = signer.health(1300).unwrap().health;
    assert_eq!(failed_health.state, ObserverState::IntegrityUnknown);
    assert!(failed_health.attested_coverage.is_none());
    // Models the driver's explicit Ok(None), no-loss, no-cap/error reading.
    p.declare_mechanism_integrity(SourceMechanism::ProcConnector, MechanismIntegrity::Verified);
    let recovered = finish(&mut p, 4, 1300, 1400, 500_000_000);
    signer.attest(recovered).unwrap();
    let healthy = signer.health(1400).unwrap().health;
    assert_eq!(healthy.state, ObserverState::Active);
    assert_eq!(healthy.attested_coverage.unwrap().from_ms, 1300);
}

#[test]
fn empty_deferred_flushed_empty_published_ranges_keep_collector_continuity() {
    use aip_observe::{CollectorSigner, ContinuityStatus, ObserverAttestor, ObserverState};
    let key = aip_crypto::generate_ed25519_keypair();
    let mut signer =
        CollectorSigner::new("cutoff-collector", 1, &key.private_key, &key.public_key).unwrap();
    signer.register_probe("cutoff-test", &SourceMechanism::ALL);
    let mut p = probe();
    exec(&mut p, true, u32::MAX, 500_000_010);
    exec(&mut p, false, u32::MAX, 500_000_000);
    let deferred = finish(&mut p, 1, 900, 1000, 200_000_000);
    assert_eq!((deferred.probe_seq_first, deferred.probe_seq_last), (0, 0));
    signer.attest(deferred.clone()).unwrap();
    let flushed = finish(&mut p, 2, deferred.claimed_to_ms, 2000, 1_200_000_000);
    assert_eq!((flushed.probe_seq_first, flushed.probe_seq_last), (1, 2));
    assert!(detect_cross_sensor_divergence_default(&flushed).is_empty());
    signer.attest(flushed.clone()).unwrap();
    let empty = finish(&mut p, 3, flushed.claimed_to_ms, 3000, 2_200_000_000);
    assert!(empty.kernel_events.is_empty());
    assert_eq!((empty.probe_seq_first, empty.probe_seq_last), (2, 2));
    signer.attest(empty.clone()).unwrap();
    exec(&mut p, false, u32::MAX - 1, 3_000_000_000);
    let next = finish(&mut p, 4, empty.claimed_to_ms, 4000, 3_200_000_000);
    assert_eq!((next.probe_seq_first, next.probe_seq_last), (3, 3));
    signer.attest(next.clone()).unwrap();
    let health = signer.health(4000).unwrap().health;
    assert_eq!(health.state, ObserverState::Active);
    assert_eq!(health.continuity, ContinuityStatus::Verified);
    assert_eq!(
        health.attested_coverage.unwrap().from_ms,
        flushed.claimed_from_ms
    );
    assert_eq!(health.attested_coverage.unwrap().to_ms, next.claimed_to_ms);
}
