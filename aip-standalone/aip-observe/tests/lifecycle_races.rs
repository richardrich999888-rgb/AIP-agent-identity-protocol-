//! Real procfs/pidfd measurements with SYNTHETIC connector event stimuli.
//! These regressions do not establish live netlink capture, PID-reuse frequency,
//! executable-image atomicity, or logical-agent attribution.
#![cfg(target_os = "linux")]

use aip_crypto::generate_ed25519_keypair;
use aip_observe::*;
use std::process::{Child, Command};

struct Workload(Child);

impl Workload {
    fn start() -> Self {
        Self(Command::new("sleep").arg("60").spawn().unwrap())
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
    fn stop(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}

impl Drop for Workload {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn probe() -> ProcfsProbe {
    let mut p = ProcfsProbe::new("synthetic-lifecycle-stimulus");
    p.declare_clock_anchor(boot_clock_anchor().unwrap());
    p
}

fn event(kind: KernelLifecycleKind, timestamp_ns: u64) -> ProcEvent {
    ProcEvent {
        cgroup: CgroupSample::NotSampled,
        kind,
        cpu: 0,
        timestamp_ns,
    }
}

fn exec(pid: u32, ts: u64) -> ProcEvent {
    event(KernelLifecycleKind::Exec { pid, tgid: pid }, ts)
}

fn exit(pid: u32, ts: u64) -> ProcEvent {
    event(
        KernelLifecycleKind::Exit {
            pid,
            tgid: pid,
            exit_code: 0,
            exit_signal: 0,
        },
        ts,
    )
}

fn now() -> u64 {
    boot_clock_anchor().unwrap().monotonic_ns
}

#[test]
fn delayed_exec_before_instance_start_is_unbound() {
    let mut p = probe();
    let pid = std::process::id();
    assert!(
        p.measure_anchored(pid)
            .unwrap()
            .process
            .process
            .pid_start_time_ticks
            > 0
    );
    let e = p.ingest_kernel_event(exec(pid, 0));
    assert!(
        e.bound.is_none(),
        "the current PID cannot identify an older event"
    );
    assert_eq!(e.kernel_timestamp_ns, 0, "retain the original event");
    assert!(p.ingest_kernel_event(exit(pid, now())).bound.is_none());
}

#[test]
fn delayed_fork_before_child_start_is_unbound() {
    let child = Workload::start();
    let mut p = probe();
    assert!(p.measure_anchored(child.pid()).is_ok());
    let e = p.ingest_kernel_event(event(
        KernelLifecycleKind::Fork {
            parent_pid: std::process::id(),
            parent_tgid: std::process::id(),
            child_pid: child.pid(),
            child_tgid: child.pid(),
        },
        0,
    ));
    assert!(
        e.bound.is_none(),
        "parent ancestry cannot bind a stale child event"
    );
}

#[test]
fn stale_exit_does_not_consume_a_later_exec_binding() {
    let mut p = probe();
    let pid = std::process::id();
    let ts = now();
    let bound = p.ingest_kernel_event(exec(pid, ts)).bound.clone();
    assert!(bound.is_some());
    for stale in [0, ts - 1, ts] {
        assert!(p.ingest_kernel_event(exit(pid, stale)).bound.is_none());
    }
    assert_eq!(p.ingest_kernel_event(exit(pid, ts + 1)).bound, bound);
    assert!(p.ingest_kernel_event(exit(pid, ts + 2)).bound.is_none());
}

#[test]
fn stale_or_equal_exec_cannot_replace_a_later_binding() {
    let mut p = probe();
    let pid = std::process::id();
    let ts = now();
    let bound = p.ingest_kernel_event(exec(pid, ts)).bound.clone();
    assert!(bound.is_some());
    for stale in [ts - 1, ts] {
        assert!(p.ingest_kernel_event(exec(pid, stale)).bound.is_none());
    }
    assert_eq!(p.ingest_kernel_event(exit(pid, ts + 1)).bound, bound);
}

#[test]
fn failed_new_measurement_invalidates_old_exit_binding() {
    let mut child = Workload::start();
    let mut p = probe();
    let ts = now();
    assert!(p.ingest_kernel_event(exec(child.pid(), ts)).bound.is_some());
    child.stop();
    assert!(p
        .ingest_kernel_event(exec(child.pid(), now()))
        .bound
        .is_none());
    assert!(
        p.ingest_kernel_event(exit(child.pid(), now()))
            .bound
            .is_none(),
        "a newer unmeasurable exec must not leave the old image cached"
    );
}

#[test]
fn concurrent_siblings_keep_distinct_instances_without_agent_identity() {
    let a = Workload::start();
    let b = Workload::start();
    let mut p = probe();
    let first = p.ingest_kernel_event(exec(a.pid(), now())).clone();
    let second = p.ingest_kernel_event(exec(b.pid(), now())).clone();
    assert_ne!(
        first.bound.as_ref().unwrap().process,
        second.bound.as_ref().unwrap().process
    );
    assert_eq!(first.attribution, AgentAttribution::NotEstablished);
    assert_eq!(second.attribution, AgentAttribution::NotEstablished);
    assert_eq!(
        p.ingest_kernel_event(exit(a.pid(), now())).bound,
        first.bound
    );
    assert_eq!(
        p.ingest_kernel_event(exit(b.pid(), now())).bound,
        second.bound
    );
}

#[test]
fn loss_still_invalidates_a_live_binding() {
    let mut p = probe();
    let pid = std::process::id();
    assert!(p.ingest_kernel_event(exec(pid, now())).bound.is_some());
    p.record_lost_events(1);
    assert!(p.ingest_kernel_event(exit(pid, now())).bound.is_none());
}

#[test]
fn signing_keeps_stale_events_unbound_and_preserves_originals() {
    let mut p = probe();
    let pid = std::process::id();
    let ts = now();
    p.ingest_kernel_event(exec(pid, 0));
    p.ingest_kernel_event(exec(pid, ts));
    p.ingest_kernel_event(exit(pid, ts - 1));
    p.ingest_kernel_event(exit(pid, ts + 1));
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(
        "synthetic-test-collector",
        1,
        &kp.private_key,
        &kp.public_key,
    )
    .unwrap();
    signer.register_probe(
        "synthetic-lifecycle-stimulus",
        &[SourceMechanism::ProcConnector],
    );
    let anchor = boot_clock_anchor().unwrap();
    let batch = signer
        .attest(p.batch([3; 16], anchor.realtime_ms, anchor.realtime_ms, vec![]))
        .unwrap();
    let anchors = ObserverTrustAnchors::new().trust("synthetic-test-collector", 1, &kp.public_key);
    verify_attested_batch(&batch, &anchors).unwrap();
    let events = &batch.batch.kernel_events;
    assert_eq!(events.len(), 4);
    assert_eq!(
        events.iter().map(|e| e.bound.is_some()).collect::<Vec<_>>(),
        vec![false, true, false, true]
    );
    assert_eq!(
        events
            .iter()
            .map(|e| e.kernel_timestamp_ns)
            .collect::<Vec<_>>(),
        vec![0, ts, ts - 1, ts + 1]
    );
    assert!(events
        .iter()
        .all(|e| e.attribution == AgentAttribution::NotEstablished));
    if let Ok(root) = std::env::var("P0_048_LIFECYCLE_RETAIN_DIR") {
        let root = std::path::Path::new(&root);
        std::fs::create_dir(root).expect("refuse to overwrite original evidence");
        std::fs::write(
            root.join("batches.jsonl"),
            format!("{}\n", serde_json::to_string(&batch).unwrap()),
        )
        .unwrap();
        let scope = serde_json::json!({
            "scope": "SYNTHETIC event stimuli; real local procfs/pidfd measurement; signature integrity only",
            "live_connector_capture": false, "independent_administration": false,
            "execution_verdict": "NOT_EVALUATED", "coverage": "NOT_ESTABLISHED",
            "logical_agent_identity": "NOT_ESTABLISHED", "observed_pid": pid,
            "observer_id": "synthetic-test-collector", "key_version": 1,
            "public_key": kp.public_key, "expected_bound": [false, true, false, true]
        });
        std::fs::write(
            root.join("scope-and-anchor.json"),
            serde_json::to_vec_pretty(&scope).unwrap(),
        )
        .unwrap();
    }
}
