//! Gate 9 live — the cgroup v2 freezer on this host. Root and a cgroup2
//! mount required; otherwise the test records why and returns.
//!
//! A child that writes a byte to a pipe every 20 ms is the target. Frozen,
//! the pipe goes quiet and the kernel reports `frozen 1` in the cgroup's
//! events file; released, the bytes resume. Then the adversarial cases the
//! mandate names for the actuator itself: a root that is not a cgroup2
//! hierarchy, a cgroup that already exists and holds another process, and
//! a target that is gone by the time the actuator acts.

#![cfg(target_os = "linux")]

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use aip_containment::*;
use aip_core::execution_binding::collect_binding_for_pid;
use aip_crypto::generate_ed25519_keypair;
use aip_observe::{
    CollectorSigner, CoverageWindow, ObservationAvailability, ObserverAttestor,
    ObserverTrustAnchors, ProcfsProbe, SignedSensorHealth,
};
use aip_reconcile::{
    ActionComparison, DecisionId, DecisionPointId, EvidenceRef, EvidenceStrength,
    IdentityComparison, LineageComparison, ObserverId, ObserverSequence, ReasonCode,
    Reconciliation, ReconciliationResult, TemporalComparison, WireCorroboration,
    RECONCILIATION_VERSION,
};
use aip_types::{ExecutionBinding, KeyPair};
use aip_warrant::{
    evaluate, Finding, ResponseClass, Severity, Warrant, WarrantAuthority, WarrantPolicy,
    WarrantTrustAnchors,
};

const NOW: u64 = 1_700_004_000_000;
const AGENT: &str = "aip1agent";
const OBSERVER: &str = "obs-1";

struct Ticker {
    child: Child,
    stdout: std::process::ChildStdout,
}

impl Ticker {
    fn spawn() -> Self {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("while :; do printf x; sleep 0.02; done")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn ticker");
        let stdout = child.stdout.take().unwrap();
        Self { child, stdout }
    }

    /// Bytes received in `window`. Non-blocking drain via a reader thread
    /// would be cleaner; here the pipe is read with a small buffer under a
    /// deadline using `O_NONBLOCK`.
    fn bytes_in(&mut self, window: Duration) -> usize {
        set_nonblocking(&self.stdout);
        let deadline = Instant::now() + window;
        let mut n = 0;
        let mut buf = [0u8; 256];
        while Instant::now() < deadline {
            match self.stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        n
    }
}

fn set_nonblocking(f: &std::process::ChildStdout) {
    use std::os::fd::AsRawFd;
    let fd = f.as_raw_fd();
    // SAFETY: fcntl on a descriptor this process owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

impl Drop for Ticker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Keys {
    warrant: KeyPair,
    containment: KeyPair,
    observer: KeyPair,
}

fn fixture(binding_pid: u32) -> (Keys, Warrant, SignedSensorHealth, ExecutionBinding) {
    let k = Keys {
        warrant: generate_ed25519_keypair(),
        containment: generate_ed25519_keypair(),
        observer: generate_ed25519_keypair(),
    };
    let rec = {
        let mut r = Reconciliation::fixture_default();
        r.version = RECONCILIATION_VERSION;
        r.result = ReconciliationResult::PhantomClaim;
        r.strength = EvidenceStrength::Proven;
        r.reason = ReasonCode::ActionEvidenceUnavailable;
        r.decision_id = Some(DecisionId::from_bytes([0x11; 16]));
        r.availability = ObservationAvailability::Covered {
            window: CoverageWindow {
                from_ms: NOW - 60_000,
                to_ms: NOW,
            },
        };
        r.identity = IdentityComparison::NoReference;
        r.action = ActionComparison::Unobservable;
        r.temporal = TemporalComparison::Indeterminate;
        r.lineage = LineageComparison::NotEvaluated;
        r.wire = WireCorroboration::NotEvaluated;
        r.replay_detected = false;
        r.evidence = vec![
            EvidenceRef::Expected {
                decision_point_id: DecisionPointId("aip1dp".into()),
                decision_id: DecisionId::from_bytes([0x11; 16]),
            },
            EvidenceRef::Health {
                observer_id: ObserverId(OBSERVER.into()),
                sequence: ObserverSequence(2),
                emitted_at_ms: NOW - 1_000,
            },
        ];
        r.verification_time_ms = NOW - 1;
        r
    };
    let policy = WarrantPolicy {
        autonomous_containment: true,
        ..WarrantPolicy::default()
    }
    .with_severity(ReconciliationResult::PhantomClaim, Severity::Critical);
    let w = evaluate(
        &Finding {
            finding_id: [0xf2; 16],
            reconciliation: rec,
            subject_agent: Some(AGENT.into()),
        },
        &policy,
        NOW - 10_000,
    )
    .unwrap();
    assert_eq!(w.response, ResponseClass::Contain);
    let w = WarrantAuthority::new("wa", &k.warrant.private_key, &k.warrant.public_key)
        .unwrap()
        .sign(w)
        .unwrap();
    let mut s =
        CollectorSigner::new(OBSERVER, 1, &k.observer.private_key, &k.observer.public_key).unwrap();
    let mut probe = ProcfsProbe::new("p");
    for i in 1..=2u8 {
        s.attest_at(
            probe.batch([i; 16], NOW - 50_000, NOW - 40_000, vec![]),
            NOW - 30_000,
        )
        .unwrap();
    }
    let h = s.health(NOW).unwrap();
    let binding = collect_binding_for_pid(AGENT, binding_pid).unwrap();
    (k, w, h, binding)
}

fn anchors(k: &Keys) -> ContainmentAnchors {
    ContainmentAnchors {
        warrant: WarrantTrustAnchors::new().trust("wa", &k.warrant.public_key),
        observer: ObserverTrustAnchors::new().trust(OBSERVER, 1, &k.observer.public_key),
    }
}

fn policy() -> ContainmentPolicy {
    ContainmentPolicy {
        mode: ContainmentMode::AutonomousEnabled,
        action: ContainmentAction::FreezeProcess,
        ..ContainmentPolicy::default()
    }
}

fn freezer() -> Option<CgroupV2Freezer> {
    if let Some(root) = std::env::var_os("AIP_TEST_CGROUP_ROOT") {
        let root = std::path::PathBuf::from(root);
        // An explicitly provisioned CI hierarchy is required, never skipped.
        assert!(root.join("cgroup.controllers").is_file());
        assert!(root.join("cgroup.procs").is_file());
        return Some(CgroupV2Freezer::at(&root));
    }
    match CgroupV2Freezer::detect() {
        Ok(f) => Some(f),
        Err(e) => {
            eprintln!("cgroup v2 freezer unavailable on this host: {e}");
            None
        }
    }
}

#[test]
fn f_p_a_proven_warrant_freezes_the_bound_process_and_release_thaws_it() {
    let Some(mut fz) = freezer() else { return };
    let mut t = Ticker::spawn();
    std::thread::sleep(Duration::from_millis(100));
    assert!(t.bytes_in(Duration::from_millis(200)) > 0, "ticker runs");
    let (k, w, h, binding) = fixture(t.child.id());
    let authority =
        ContainmentAuthority::new("ca", &k.containment.private_key, &k.containment.public_key)
            .unwrap();
    let mut ledger = MemoryReplayLedger::default();
    let req = ContainmentRequest {
        warrant: &w,
        target: &binding,
        observer_health: Some(&h),
        operator_ack: None,
    };
    let c = contain(
        &req,
        &policy(),
        &anchors(&k),
        &mut ledger,
        &mut fz,
        &authority,
        NOW,
    )
    .unwrap();
    assert!(c.actuated(), "{:?}", c.record.record.outcome);
    let Outcome::Applied { mechanism, handle } = &c.record.record.outcome else {
        unreachable!()
    };
    assert_eq!(*mechanism, Mechanism::CgroupV2Freeze);
    // The kernel says so, in the cgroup the record names.
    let events = std::fs::read_to_string(format!("{handle}/cgroup.events")).unwrap();
    assert!(events.contains("frozen 1"), "{events}");
    // Drain what was buffered before the freeze, then the pipe is silent.
    let _ = t.bytes_in(Duration::from_millis(100));
    assert_eq!(
        t.bytes_in(Duration::from_millis(300)),
        0,
        "a frozen process produces nothing"
    );
    // Release: thawed, bytes resume, the cgroup is gone.
    let hold = c.hold.unwrap();
    let rec = release(hold, &mut fz, &authority, NOW + 1).unwrap();
    assert!(matches!(rec.record.outcome, Outcome::Released { .. }));
    assert!(t.bytes_in(Duration::from_millis(300)) > 0, "thawed");
    assert!(
        !std::path::Path::new(handle).exists(),
        "the containment cgroup is removed on release"
    );
    verify_containment_record(
        &c.record,
        &ContainmentTrustAnchors::new().trust("ca", &k.containment.public_key),
    )
    .unwrap();
}

#[test]
fn f_a_a_root_that_is_not_a_cgroup2_hierarchy_fails_open() {
    if freezer().is_none() {
        return;
    }
    let mut t = Ticker::spawn();
    std::thread::sleep(Duration::from_millis(50));
    let dir = std::env::temp_dir().join(format!("ghost-not-cgroup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut fz = CgroupV2Freezer::at(&dir);
    let (k, w, h, binding) = fixture(t.child.id());
    let authority =
        ContainmentAuthority::new("ca", &k.containment.private_key, &k.containment.public_key)
            .unwrap();
    let mut ledger = MemoryReplayLedger::default();
    let req = ContainmentRequest {
        warrant: &w,
        target: &binding,
        observer_health: Some(&h),
        operator_ack: None,
    };
    let c = contain(
        &req,
        &policy(),
        &anchors(&k),
        &mut ledger,
        &mut fz,
        &authority,
        NOW,
    )
    .unwrap();
    assert!(
        matches!(c.record.record.outcome, Outcome::Failed(_)),
        "{:?}",
        c.record.record.outcome
    );
    assert!(
        t.bytes_in(Duration::from_millis(200)) > 0,
        "nothing was frozen"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f_b_a_pre_existing_cgroup_holding_another_process_is_refused_and_nothing_is_frozen() {
    let Some(mut fz) = freezer() else { return };
    let mut t = Ticker::spawn();
    let mut bystander = Ticker::spawn();
    std::thread::sleep(Duration::from_millis(50));
    let (k, w, h, binding) = fixture(t.child.id());
    // The attacker (or a stale run) pre-creates the cgroup this decision
    // would use and parks another process in it.
    let path = fz.cgroup_path_for(&binding.process);
    std::fs::create_dir(&path).unwrap();
    std::fs::write(
        format!("{}/cgroup.procs", path.display()),
        bystander.child.id().to_string(),
    )
    .unwrap();
    let authority =
        ContainmentAuthority::new("ca", &k.containment.private_key, &k.containment.public_key)
            .unwrap();
    let mut ledger = MemoryReplayLedger::default();
    let req = ContainmentRequest {
        warrant: &w,
        target: &binding,
        observer_health: Some(&h),
        operator_ack: None,
    };
    let c = contain(
        &req,
        &policy(),
        &anchors(&k),
        &mut ledger,
        &mut fz,
        &authority,
        NOW,
    )
    .unwrap();
    assert!(
        matches!(
            c.record.record.outcome,
            Outcome::Failed(ActuationFailure::WrongCgroup { .. })
        ),
        "{:?}",
        c.record.record.outcome
    );
    assert!(
        t.bytes_in(Duration::from_millis(200)) > 0,
        "target not frozen"
    );
    assert!(
        bystander.bytes_in(Duration::from_millis(200)) > 0,
        "bystander not frozen"
    );
    let events = std::fs::read_to_string(format!("{}/cgroup.events", path.display())).unwrap();
    assert!(events.contains("frozen 0"));
    // Clean up: move the bystander back to the root and remove the cgroup.
    std::fs::write(
        format!("{}/cgroup.procs", fz.root().display()),
        bystander.child.id().to_string(),
    )
    .unwrap();
    drop(bystander);
    std::thread::sleep(Duration::from_millis(50));
    let _ = std::fs::remove_dir(&path);
}

#[test]
fn f_c_a_target_that_exits_before_actuation_is_a_failure_not_a_containment() {
    let Some(mut fz) = freezer() else { return };
    let mut t = Ticker::spawn();
    std::thread::sleep(Duration::from_millis(50));
    let (k, w, h, binding) = fixture(t.child.id());
    let authority =
        ContainmentAuthority::new("ca", &k.containment.private_key, &k.containment.public_key)
            .unwrap();
    let mut ledger = MemoryReplayLedger::default();
    // Attribution succeeds against the live process; then it is gone.
    let attributed = attribute(&binding).unwrap();
    let _ = t.child.kill();
    let _ = t.child.wait();
    let r = fz.apply(&attributed, ContainmentAction::FreezeProcess);
    assert!(matches!(r, Err(ActuationFailure::TargetGone)), "{r:?}");
    // And through the full path, with the process gone before attribution:
    let req = ContainmentRequest {
        warrant: &w,
        target: &binding,
        observer_health: Some(&h),
        operator_ack: None,
    };
    let c = contain(
        &req,
        &policy(),
        &anchors(&k),
        &mut ledger,
        &mut fz,
        &authority,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        c.record.record.outcome,
        Outcome::Refused(Refusal::Attribution(_))
    ));
    assert!(!ledger.is_consumed(&w.warrant_id), "nothing was decided");
}
