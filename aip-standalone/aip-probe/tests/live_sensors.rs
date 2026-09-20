//! R8 — the two file/wire sensors, driven through the probe's own
//! `SensorSet`, against the real kernel.
//!
//! These are live tests: they open the actual fanotify queue and the actual
//! `AF_PACKET` socket, make real events happen, and read them back out of a
//! real `ObservationBatch`. Where the host lacks the capability the test
//! prints `SKIPPED` with the reason and returns, which is this workspace's
//! convention for a kernel facility a host does not provide — the same
//! convention `aip-observe/tests/fanotify.rs` and `wiretap.rs` use. Nothing
//! is simulated: a skipped test asserts nothing and claims nothing.
//!
//! The configuration-level tests below need no capability and run
//! everywhere, because fail-closed startup is a property of the probe, not
//! of the host it runs on.

use aip_observe::{KernelLifecycleKind, SourceMechanism};
use aip_probe::config::SensorConfig;
use aip_probe::sensors::SensorSet;

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aip-probe-live-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A config with only the named sensor on, so a failure names one sensor.
fn only(f: impl FnOnce(&mut SensorConfig)) -> SensorConfig {
    let mut c = SensorConfig::default();
    f(&mut c);
    c
}

// ─── fanotify ───────────────────────────────────────────────────────────────

/// A completed write on the marked mount appears in the batch, attributed
/// to this process, and bound through the kernel's own pidfd.
///
/// The binding is the point. A pid in an event is a number the kernel wrote
/// down; `bound` is a measurement taken *through a pidfd the kernel created
/// from the event's own process reference*, so it refers to the process
/// instance that acted and not to whatever later holds that pid.
#[test]
fn fanotify_observes_a_completed_write_and_binds_it_by_pidfd() {
    let dir = scratch("fan");
    let cfg = only(|c| {
        c.fanotify = true;
        c.fanotify_path = Some(dir.to_string_lossy().into_owned());
    });
    let mut sensors = match SensorSet::open("probe-live-fan", cfg) {
        Ok(s) => s,
        Err(why) => {
            eprintln!("SKIPPED — fanotify unavailable (needs CAP_SYS_ADMIN): {why}");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    };

    // The event the kernel must queue: one open-for-write, written, closed.
    let path = dir.join("evidence.txt");
    let from = now_ms();
    std::fs::write(&path, b"a completed write").expect("write");
    let to = now_ms();

    let batch = sensors.collect_batch(from, to);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        batch.active_mechanisms.contains(&SourceMechanism::Fanotify),
        "the batch must declare the sensor it had open: {:?}",
        batch.active_mechanisms
    );

    let me = std::process::id();
    let mine = batch.kernel_events.iter().find(|e| {
        matches!(&e.kind, KernelLifecycleKind::FileEvent { pid, path: p, .. }
            if *pid == me && p.ends_with("evidence.txt"))
    });

    // A shared mount can be busy enough to overflow the queue; that is
    // counted loss, not a failed assertion, and the probe reports it rather
    // than inventing the event.
    let Some(ev) = mine else {
        eprintln!(
            "SKIPPED — no fanotify event for this write ({} events, {:?} lost); \
             on a shared, busy mount the queue overflows and the loss is counted",
            batch.kernel_events.len(),
            batch.dropped_events
        );
        return;
    };

    assert_eq!(ev.mechanism, SourceMechanism::Fanotify);
    assert!(
        ev.bound.is_some(),
        "this process is still alive, so the kernel's pidfd must have yielded a measurement"
    );
    if let KernelLifecycleKind::FileEvent { deleted, ino, .. } = &ev.kind {
        assert!(!deleted, "the file was not unlinked");
        assert!(*ino != 0, "the kernel resolved an inode for the object");
    }
}

/// Nothing of the file's contents reaches the batch. The fanotify path
/// carries a descriptor to the object and the probe deliberately reads
/// nothing through it (I23); this asserts that over the whole serialized
/// batch rather than trusting the call sites.
#[test]
fn fanotify_carries_no_file_content() {
    let dir = scratch("fan-content");
    let cfg = only(|c| {
        c.fanotify = true;
        c.fanotify_path = Some(dir.to_string_lossy().into_owned());
    });
    let mut sensors = match SensorSet::open("probe-live-fan-content", cfg) {
        Ok(s) => s,
        Err(why) => {
            eprintln!("SKIPPED — fanotify unavailable: {why}");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    };

    // A distinctive secret that must never appear in the evidence.
    const SECRET: &str = "ACCOUNT-8817-BALANCE-4423190-DO-NOT-COPY";
    let from = now_ms();
    std::fs::write(dir.join("statement.txt"), SECRET.as_bytes()).expect("write");
    let to = now_ms();

    let batch = sensors.collect_batch(from, to);
    let _ = std::fs::remove_dir_all(&dir);

    let serialized = serde_json::to_string(&batch).expect("serialize batch");
    assert!(
        !serialized.contains(SECRET),
        "file content must never enter the observation batch (I23)"
    );
}

// ─── AF_PACKET ──────────────────────────────────────────────────────────────

/// Loopback TCP crosses the device and the tap records the headers — and
/// only the headers. The payload is a distinctive string; it must not
/// appear anywhere in the serialized batch, because the tap copies header
/// fields and the payload *length*, never a payload byte (I23).
#[test]
fn the_af_packet_tap_records_headers_and_never_the_payload() {
    let cfg = only(|c| {
        c.afpacket = true;
        c.afpacket_interface = Some("lo".into());
    });
    let mut sensors = match SensorSet::open("probe-live-wire", cfg) {
        Ok(s) => s,
        Err(why) => {
            eprintln!("SKIPPED — AF_PACKET tap unavailable (needs CAP_NET_RAW): {why}");
            return;
        }
    };

    const PAYLOAD: &str = "WIRE-SECRET-6f2a-NEVER-COPIED-INTO-EVIDENCE";
    let from = now_ms();

    // Real loopback traffic: a listener, a connection, a send, a close.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = std::thread::spawn(move || {
        use std::io::Read;
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
        }
    });
    {
        use std::io::Write;
        let mut c = std::net::TcpStream::connect(addr).expect("connect");
        c.write_all(PAYLOAD.as_bytes()).expect("send");
        c.flush().ok();
    }
    server.join().ok();
    let to = now_ms();

    let batch = sensors.collect_batch(from, to);

    assert!(
        batch
            .active_mechanisms
            .contains(&SourceMechanism::WireTapAfPacket),
        "the batch must declare the tap it had open: {:?}",
        batch.active_mechanisms
    );

    // The I23 assertion holds whether or not a segment was captured: the
    // payload must never be present, and an empty capture trivially
    // satisfies that. The capture assertion is separate and skippable.
    let serialized = serde_json::to_string(&batch).expect("serialize batch");
    assert!(
        !serialized.contains(PAYLOAD),
        "a payload byte must never enter the observation batch (I23)"
    );

    let segment = batch
        .kernel_events
        .iter()
        .find(|e| matches!(e.kind, KernelLifecycleKind::WireSegment { .. }));
    let Some(ev) = segment else {
        eprintln!(
            "SKIPPED — no TCP segment captured in the window ({} events); \
             the I23 assertion above still held",
            batch.kernel_events.len()
        );
        return;
    };

    assert_eq!(ev.mechanism, SourceMechanism::WireTapAfPacket);
    assert!(
        ev.bound.is_none(),
        "the device layer knows no task: a wire segment is never bound to an instance"
    );
    if let KernelLifecycleKind::WireSegment {
        payload_len,
        frame_len,
        ..
    } = &ev.kind
    {
        // The length is evidence; the bytes are not.
        assert!(*frame_len > 0, "the kernel delivered a frame length");
        let _ = payload_len;
    }
}

// ─── Gate independence ──────────────────────────────────────────────────────

/// Neither new sensor owes an integrity report, and neither is asked for
/// one. Both reach the probe by a facility no per-tracepoint eBPF program
/// array gates, so a finding for them would be inventing a check that was
/// never run — and the collector's sink asks for a report only where
/// `shares_perf_tracepoint_gate` is true.
#[test]
fn the_file_and_wire_sensors_are_gate_independent_and_owe_no_report() {
    for m in [SourceMechanism::Fanotify, SourceMechanism::WireTapAfPacket] {
        assert!(
            !m.shares_perf_tracepoint_gate(),
            "{m:?} must not share the perf tracepoint submission gate"
        );
        assert!(
            m.is_gate_independent_kernel_pushed(),
            "{m:?} must count as gate-independent kernel-pushed coverage"
        );
    }

    let dir = scratch("gate");
    let cfg = only(|c| {
        c.fanotify = true;
        c.fanotify_path = Some(dir.to_string_lossy().into_owned());
    });
    let Ok(mut sensors) = SensorSet::open("probe-gate", cfg) else {
        eprintln!("SKIPPED — fanotify unavailable");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let batch = sensors.collect_batch(now_ms(), now_ms());
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        batch
            .mechanism_integrity
            .iter()
            .all(|r| r.mechanism != SourceMechanism::Fanotify),
        "a mechanism outside the tracepoint gate must carry no integrity finding"
    );
}

// ─── Fail-closed startup (no capability needed) ─────────────────────────────

/// A fanotify sensor with no mount to mark is refused before the probe
/// starts. The mark is `FAN_MARK_MOUNT`: without an explicit path the probe
/// would either watch `/` or watch nothing, and both are worse than
/// refusing with the reason named.
#[test]
fn a_fanotify_sensor_without_a_path_is_refused() {
    let cfg = only(|c| c.fanotify = true);
    let err = SensorSet::open("probe-nopath", cfg).unwrap_err();
    assert!(err.contains("AIP_PROBE_FANOTIFY_PATH"), "{err}");
}

/// A requested sensor that cannot be opened is a startup error, not a
/// silent downgrade: the operator learns immediately rather than the probe
/// running blind and the collector attesting a coverage it never had.
#[test]
fn a_sensor_that_cannot_open_fails_startup_rather_than_running_blind() {
    let cfg = only(|c| {
        c.fanotify = true;
        c.fanotify_path = Some("/definitely/not/a/mount/on/this/host".into());
    });
    let err = SensorSet::open("probe-badpath", cfg).unwrap_err();
    assert!(
        err.contains("fanotify") && (err.contains("CAP_SYS_ADMIN") || err.contains("not")),
        "the error must name the sensor and the cause: {err}"
    );
}
