//! Exercise live publication ranges through the actual daemon sink, including
//! its strict divergence and required-integrity-report checks.
use std::sync::{Arc, Mutex};

use aip_collector::sink::RuntimeSink;
use aip_observe::{
    BootClockAnchor, CgroupSample, CollectorKey, CollectorRuntime, CollectorStore,
    ContinuityPolicy, ContinuityStatus, KernelLifecycleKind, MechanismIntegrity, ObservationBatch,
    ObserverState, ProcEvent, ProcfsProbe, SourceMechanism, Started,
};
use aip_transport::BatchSink;

fn finish(
    probe: &mut ProcfsProbe,
    seq: u8,
    from: u64,
    close: u64,
    cutoff: u64,
) -> ObservationBatch {
    probe.declare_clock_anchor(BootClockAnchor {
        realtime_ms: close + 50,
        boottime_ns: cutoff + 50_000_000,
        monotonic_ns: cutoff + 50_000_000,
        clk_tck: 100,
    });
    probe.batch_through([seq; 16], from, close, Some(cutoff))
}

#[test]
fn live_empty_deferred_flushed_ranges_survive_the_runtime_sink_and_faults_never_backfill() {
    let dir = std::env::temp_dir().join(format!(
        "aip-cutoff-sink-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let started = CollectorRuntime::start_with_custodian(
        CollectorStore::open(&dir).unwrap(),
        "cutoff-observer",
        1,
        CollectorKey::development().into_custodian(),
        ContinuityPolicy::Strict,
    )
    .unwrap();
    let Started::Running(mut runtime, _) = started else {
        panic!("fresh cutoff runtime refused");
    };
    runtime
        .signer_mut()
        .register_probe("cutoff-test", &SourceMechanism::ALL);
    let runtime = Arc::new(Mutex::new(runtime));
    let mut sink = RuntimeSink::new(Arc::clone(&runtime));
    let mut probe = ProcfsProbe::new("cutoff-test");
    for mechanism in [
        SourceMechanism::SchedTracepoint,
        SourceMechanism::ProcConnector,
    ] {
        probe.declare_source(mechanism);
        probe.declare_mechanism_integrity(mechanism, MechanismIntegrity::Verified);
    }
    probe.enable_loss_counter();
    let event = |timestamp_ns| ProcEvent {
        cgroup: CgroupSample::NotSampled,
        kind: KernelLifecycleKind::Exec {
            pid: u32::MAX,
            tgid: u32::MAX,
        },
        cpu: 0,
        timestamp_ns,
    };
    probe.ingest_kernel_event(event(500_000_010));
    probe.ingest_sched_event(event(500_000_000));

    let deferred = finish(&mut probe, 1, 900, 1000, 200_000_000);
    let flushed = finish(&mut probe, 2, deferred.claimed_to_ms, 2000, 1_200_000_000);
    let empty = finish(&mut probe, 3, flushed.claimed_to_ms, 3000, 2_200_000_000);
    assert_eq!((deferred.probe_seq_first, deferred.probe_seq_last), (0, 0));
    assert_eq!((flushed.probe_seq_first, flushed.probe_seq_last), (1, 2));
    assert_eq!((empty.probe_seq_first, empty.probe_seq_last), (2, 2));
    assert_eq!(flushed.kernel_events.len(), 2);
    for (index, batch) in [&deferred, &flushed, &empty].into_iter().enumerate() {
        let ack = sink
            .accept_batch(
                "cutoff-test",
                index as u64 + 1,
                &serde_json::to_vec(batch).unwrap(),
            )
            .unwrap();
        assert_eq!(ack.attested_sequence, index as u64 + 1);
    }
    let health = runtime.lock().unwrap().health(3000).unwrap().health;
    assert_eq!(health.state, ObserverState::Active);
    assert_eq!(health.continuity, ContinuityStatus::Verified);
    assert_eq!(
        health.attested_coverage.unwrap().from_ms,
        flushed.claimed_from_ms
    );
    assert_eq!(health.attested_coverage.unwrap().to_ms, empty.claimed_to_ms);

    probe.record_source_fault(SourceMechanism::ProcConnector);
    let failed = finish(&mut probe, 4, empty.claimed_to_ms, 4000, 3_200_000_000);
    sink.accept_batch("cutoff-test", 4, &serde_json::to_vec(&failed).unwrap())
        .unwrap();
    let health = runtime.lock().unwrap().health(4000).unwrap().health;
    assert_eq!(health.state, ObserverState::IntegrityUnknown);
    assert!(health.attested_coverage.is_none());

    // Only a subsequent explicit successful source reading clears this fault.
    probe.declare_mechanism_integrity(SourceMechanism::ProcConnector, MechanismIntegrity::Verified);
    let recovered = finish(&mut probe, 5, failed.claimed_to_ms, 5000, 4_200_000_000);
    sink.accept_batch("cutoff-test", 5, &serde_json::to_vec(&recovered).unwrap())
        .unwrap();
    let health = runtime.lock().unwrap().health(5000).unwrap().health;
    assert_eq!(health.state, ObserverState::Active);
    assert_eq!(health.continuity, ContinuityStatus::Verified);
    assert_eq!(
        health.attested_coverage.unwrap().from_ms,
        recovered.claimed_from_ms
    );
    assert_eq!(
        health.attested_coverage.unwrap().to_ms,
        recovered.claimed_to_ms
    );
    drop(sink);
    drop(runtime);
    std::fs::remove_dir_all(dir).unwrap();
}
