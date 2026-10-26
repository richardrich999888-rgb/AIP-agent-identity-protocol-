//! End to end on the running kernel: a signed decision is placed, a shell
//! spawns short-lived children inside the placement, the observer's own
//! tracers feed its own probe, the collector attests the batch — and the
//! **signed** exec events carry the placement's cgroup id, while the
//! placement's creation names the creating process instance.
//!
//! This is the XI-H2 shape through the full evidence path. It is not the M4
//! measurement: one run, one host, no load.

#![cfg(target_os = "linux")]

mod common;

use aip_observe::{
    boot_clock_anchor, verify_attested_batch, CgroupSample, CgroupTracer, CollectorSigner,
    KernelLifecycleKind, ObserverAttestor, ObserverTrustAnchors, ProcessTracer, ProcfsProbe,
    SourceMechanism,
};
use aip_placement::{spawn_into, PlacementRoot};
use std::time::{Duration, Instant};

const ROOT_NAME: &str = "aip-placement-signed-attribution";
const CHILDREN: usize = 50;
const SETTLE: Duration = Duration::from_millis(400);
const POLL_MS: i32 = 20;
const PROBE_ID: &str = "probe-signed-attribution";
const OBSERVER: &str = "collector.signed-attribution";

#[test]
fn signed_exec_events_carry_the_placement_and_its_creator_is_an_instance() {
    let root = match PlacementRoot::ensure(ROOT_NAME) {
        Ok(r) => r,
        Err(e) => return common::skip("signed_attribution", &format!("no placement root: {e}")),
    };
    let (mut sched, mut cgroups) = match (ProcessTracer::open(), CgroupTracer::open()) {
        (Ok(s), Ok(c)) => (s, c),
        (s, c) => {
            return common::skip(
                "signed_attribution",
                &format!(
                    "tracers unavailable: sched {:?}, cgroup {:?}",
                    s.err(),
                    c.err()
                ),
            )
        }
    };
    assert!(
        sched.samples_cgroup(),
        "this kernel samples cgroup ids (kernel_facts)"
    );

    let mut probe = ProcfsProbe::new(PROBE_ID);
    probe.declare_source(SourceMechanism::SchedTracepoint);
    probe.declare_source(SourceMechanism::CgroupTracepoint);
    probe.enable_loss_counter();
    probe.declare_clock_anchor(boot_clock_anchor().unwrap());

    let a = common::authorised();
    let cg = root.place(&a.expectation(), &a.authority(), a.now).unwrap();
    let path = cg.path().to_path_buf();
    let script = format!("i=0; while [ $i -lt {CHILDREN} ]; do /bin/true; i=$((i+1)); done");
    let child = spawn_into(&cg, c"/bin/sh", &["sh", "-c", &script], &[]).unwrap();
    assert_eq!(child.wait().unwrap(), 0);

    // Drain both sources until quiet.
    let mut quiet_since = Instant::now();
    while quiet_since.elapsed() < SETTLE {
        let mut got = false;
        if let Some(ev) = sched.next_event(POLL_MS).unwrap() {
            probe.ingest_sched_event(ev);
            got = true;
        }
        if let Some(ev) = cgroups.next_event(POLL_MS).unwrap() {
            probe.ingest_cgroup_event(ev);
            got = true;
        }
        if got {
            quiet_since = Instant::now();
        }
    }
    let lost = sched.take_lost() + cgroups.take_lost();
    assert_eq!(lost, 0, "kernel reported loss; result not interpretable");

    let kp = aip_crypto::generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(
        PROBE_ID,
        &[
            SourceMechanism::SchedTracepoint,
            SourceMechanism::CgroupTracepoint,
            SourceMechanism::PidFdAnchored,
        ],
    );
    let batch = probe.batch([7; 16], a.now, a.now + 1, vec![]);
    let attested = signer.attest(batch).unwrap();
    let anchors = ObserverTrustAnchors::new().trust(OBSERVER, 1, &kp.public_key);
    assert_eq!(verify_attested_batch(&attested, &anchors), Ok(()));
    let events = &attested.batch.kernel_events;

    // Every exec of a short-lived child carries the placement, in signed bytes.
    let in_placement = |c: &CgroupSample| *c == CgroupSample::Sampled { cgroup_id: cg.id() };
    let trues = events
        .iter()
        .filter(|e| matches!(&e.kind, KernelLifecycleKind::ProcessExec { filename, .. } if filename == "/bin/true"))
        .filter(|e| in_placement(&e.cgroup))
        .count();
    assert_eq!(
        trues, CHILDREN,
        "every short-lived child's exec is attributed in the signed batch"
    );

    // The placement's creation names this test's process *instance*.
    let created: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.kind, KernelLifecycleKind::CgroupCreated { cgroup_id, .. } if cgroup_id == cg.id()))
        .collect();
    assert_eq!(created.len(), 1);
    let creator = created[0]
        .bound
        .as_ref()
        .expect("the creator was anchored as an instance");
    assert_eq!(creator.process.pid, std::process::id());
    assert_eq!(created[0].mechanism, SourceMechanism::CgroupTracepoint);

    // Placement by CLONE_INTO_CGROUP left no migration in the signed record.
    assert!(!events.iter().any(|e| matches!(e.kind,
        KernelLifecycleKind::CgroupAttach { dst_cgroup_id, .. } if dst_cgroup_id == cg.id())));

    std::fs::remove_dir(&path).unwrap();
}
