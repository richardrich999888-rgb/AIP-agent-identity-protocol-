//! Skill 6.5 adversarial tests — the Sniffer Dog evidence path.
//!
//! Numbered after the stage brief's twenty required cases. Live tests that
//! need the kernel process-event connector skip themselves, loudly, when the
//! environment cannot open it (no CAP_NET_ADMIN, or a non-initial network
//! namespace); every property those tests establish is then simply not
//! established in that environment, which the report states.
//!
//! Failure classes are kept distinct throughout:
//!   provenance/identity  → `AttestError::{UnregisteredProbe, MechanismNotProvisioned}`,
//!                          `VerifyError::ObserverKeyIsAgentKey`, unbound events
//!   integrity            → `VerifyError::{PayloadHashMismatch, SignatureInvalid}`
//!   continuity           → `ContinuityFault`, `ProbeStreamFault`
//!   availability         → `ObservationAvailability::Unavailable`
//!   authorization        → does not exist in this crate, by design

use aip_crypto::{generate_ed25519_keypair, sha256, sign_ed25519};
use aip_observe::*;
use aip_types::{ExecutionBinding, KeyPair, ProcessInstance, EXECUTION_BINDING_VERSION};

const OBSERVER_ID: &str = "collector.syntriass.example";
const PROBE_ID: &str = "probe-host-1";

struct Fx {
    signer: CollectorSigner,
    observer_kp: KeyPair,
    agent_kp: KeyPair,
    anchors: ObserverTrustAnchors,
    probe: ProcfsProbe,
}

fn fixture() -> Fx {
    let observer_kp = generate_ed25519_keypair();
    let agent_kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(
        OBSERVER_ID,
        1,
        &observer_kp.private_key,
        &observer_kp.public_key,
    )
    .unwrap();
    signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
    let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &observer_kp.public_key);
    Fx {
        signer,
        observer_kp,
        agent_kp,
        anchors,
        probe: ProcfsProbe::new(PROBE_ID),
    }
}

fn process(pid: u32, start: u64, boot: u8, exe: u8) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: start,
            boot_id: [boot; 16],
        },
        exe_content_sha256: [exe; 32],
        exe_path: "/opt/agent/bin/payments-agent".into(),

        container: None,
    }
}

fn binding(agent_id: &str, pid: u32, start: u64, boot: u8, exe: u8) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.into(),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: start,
            boot_id: [boot; 16],
        },
        exe_content_sha256: [exe; 32],
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1,
        container: None,
    }
}

fn kernel_exec(pid: u32, ts: u64) -> ProcEvent {
    ProcEvent {
        cgroup: aip_observe::CgroupSample::NotSampled,
        kind: KernelLifecycleKind::Exec { pid, tgid: pid },
        cpu: 0,
        timestamp_ns: ts,
    }
}

fn kernel_exit(pid: u32, ts: u64) -> ProcEvent {
    ProcEvent {
        cgroup: aip_observe::CgroupSample::NotSampled,
        kind: KernelLifecycleKind::Exit {
            pid,
            tgid: pid,
            exit_code: 0,
            exit_signal: 0,
        },
        cpu: 0,
        timestamp_ns: ts,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(target_os = "linux")]
fn connector_or_skip(test: &str) -> Option<ProcConnector> {
    match ProcConnector::open() {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("SKIP {test}: process-event connector unavailable here ({e}); property NOT established in this environment");
            None
        }
    }
}

// ─── 1. Fake kernel event injection ───

#[test]
fn t01_a_host_side_party_cannot_label_its_report_as_kernel_provenance() {
    // Probe provisioned for polling only.
    let observer_kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(
        OBSERVER_ID,
        1,
        &observer_kp.private_key,
        &observer_kp.public_key,
    )
    .unwrap();
    signer.register_probe(PROBE_ID, &[SourceMechanism::ProcfsPoll]);

    let mut probe = ProcfsProbe::new(PROBE_ID);
    // "I saw the kernel say pid 4242 exec'd" — but this probe has no connector.
    probe.ingest_kernel_event(kernel_exec(4242, 1));
    let b = probe.batch([1u8; 16], 1, 2, vec![]);
    assert_eq!(
        signer.attest(b),
        Err(AttestError::MechanismNotProvisioned {
            probe_id: PROBE_ID.into(),
            mechanism: SourceMechanism::ProcConnector
        })
    );

    // Same for a polled observation relabelled as pidfd-anchored.
    let o = probe.observation_with(
        process(1, 1, 1, 1),
        ObservedEffect::ProcessPresent,
        SourceMechanism::PidFdAnchored,
        None,
        1,
    );
    let b = probe.batch([2u8; 16], 1, 2, vec![o]);
    assert!(matches!(
        signer.attest(b),
        Err(AttestError::MechanismNotProvisioned {
            mechanism: SourceMechanism::PidFdAnchored,
            ..
        })
    ));

    // An unknown probe id is refused before anything is inspected.
    let mut rogue = ProcfsProbe::new("agent-run-probe");
    let o = rogue.observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 1);
    let b = rogue.batch([3u8; 16], 1, 2, vec![o]);
    assert_eq!(
        signer.attest(b),
        Err(AttestError::UnregisteredProbe("agent-run-probe".into()))
    );

    // The regime is visible in signed health.
    let h = signer.health(5).unwrap();
    assert_eq!(h.health.probe_policy, ProbePolicy::RegisteredOnly);
}

#[test]
fn t01b_open_policy_is_a_visible_deployment_assumption_not_a_hidden_default() {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    let mut rogue = ProcfsProbe::new("anyone");
    rogue.ingest_kernel_event(kernel_exec(1, 1));
    let b = rogue.batch([1u8; 16], 1, 2, vec![]);
    // Open policy accepts it — and says so in every signed health record, so a
    // verifier can refuse to treat Open-regime evidence as kernel-sourced.
    assert!(signer.attest(b).is_ok());
    let h = signer.health(1).unwrap();
    assert_eq!(h.health.probe_policy, ProbePolicy::Open);
    let json = serde_json::to_string(&h).unwrap();
    assert!(json.contains("\"probe_policy\":\"Open\""));
}

// ─── 2. Forged observation re-signed by the agent ───

#[test]
fn t02_agent_resigned_forgery_of_a_kernel_event_batch_is_rejected() {
    let mut f = fixture();
    f.probe.ingest_kernel_event(kernel_exec(4242, 10));
    let b = f.probe.batch([1u8; 16], 1, 2, vec![]);
    let good = f.signer.attest(b).unwrap();
    assert_eq!(verify_attested_batch(&good, &f.anchors), Ok(()));

    let mut forged = good.clone();
    forged.batch.kernel_events[0].kind = KernelLifecycleKind::Exec {
        pid: 9999,
        tgid: 9999,
    };
    let pre = forged.signing_preimage();
    forged.attestation = sign_ed25519(&f.agent_kp.private_key, OBSERVER_ID, &pre).unwrap();
    assert_eq!(
        verify_attested_batch(&forged, &f.anchors),
        Err(VerifyError::SignatureInvalid)
    );
    let tricked = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &f.agent_kp.public_key);
    assert_eq!(
        verify_attested_batch_independent_of_agent(&forged, &tricked, &f.agent_kp.public_key),
        Err(VerifyError::ObserverKeyIsAgentKey)
    );
}

// ─── 3. Reuse of an old observation ───

#[test]
fn t03_a_resubmitted_probe_batch_is_a_visible_discontinuity() {
    let mut f = fixture();
    let o1 = f
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 1);
    let b1 = f.probe.batch([1u8; 16], 1, 2, vec![o1]);
    let o2 = f
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 2);
    let b2 = f.probe.batch([2u8; 16], 2, 3, vec![o2]);
    f.signer.attest(b1.clone()).unwrap();
    f.signer.attest(b2).unwrap();
    assert_eq!(f.signer.state(), ObserverState::Active);

    // The host replays the probe's first batch. The collector's chain accepts
    // it as a *new* chain position (it is new bytes to the chain), but the
    // probe stream shows sequence 1 after sequence 2: a discontinuity.
    f.signer.attest(b1).unwrap();
    assert!(matches!(
        f.signer.probe_faults().last(),
        Some(ProbeStreamFault::SequenceDiscontinuity {
            expected_first: 3,
            got_first: 1
        })
    ));
    assert_eq!(f.signer.state(), ObserverState::Degraded);
    let h = f.signer.health(10).unwrap();
    assert_eq!(h.health.attested_coverage, None);
}

// ─── 4/5. Sequence rollback and gap ───

#[test]
fn t04_t05_probe_sequence_rollback_and_gap_degrade_and_never_backfill() {
    let mut f = fixture();
    let o1 = f
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 1);
    let o2 = f
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 2);
    f.signer
        .attest(f.probe.batch([1u8; 16], 1, 2, vec![o1, o2]))
        .unwrap();
    // seq 3 is produced and *discarded* by the host.
    let _dropped =
        f.probe
            .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 3);
    let o4 = f
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 4);
    f.signer
        .attest(f.probe.batch([2u8; 16], 3, 4, vec![o4]))
        .unwrap();
    assert!(matches!(
        f.signer.probe_faults().last(),
        Some(ProbeStreamFault::SequenceDiscontinuity {
            expected_first: 3,
            got_first: 4
        })
    ));
    assert_eq!(f.signer.state(), ObserverState::Degraded);

    // A later perfectly contiguous batch does not erase the gap.
    let o5 = f
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 5);
    f.signer
        .attest(f.probe.batch([3u8; 16], 4, 5, vec![o5]))
        .unwrap();
    assert_eq!(f.signer.state(), ObserverState::Degraded);
    assert_eq!(f.signer.health(6).unwrap().health.attested_coverage, None);

    // Rollback: a hand-built batch whose range moves backwards.
    let mut g = fixture();
    let o1 = g
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 1);
    let o2 = g
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 2);
    g.signer
        .attest(g.probe.batch([1u8; 16], 1, 2, vec![o1.clone(), o2]))
        .unwrap();
    let mut rolled = g.probe.batch([2u8; 16], 2, 3, vec![o1]);
    assert_eq!((rolled.probe_seq_first, rolled.probe_seq_last), (1, 1));
    g.signer.attest(rolled.clone()).unwrap();
    assert_eq!(g.signer.state(), ObserverState::Degraded);

    // An impossible range is refused outright.
    rolled.probe_seq_first = 9;
    rolled.probe_seq_last = 3;
    assert_eq!(
        g.signer.attest(rolled),
        Err(AttestError::MalformedBatch(
            "probe_seq_first > probe_seq_last"
        ))
    );
}

// ─── 6/7. Duplication and reordering ───

#[test]
fn t06_t07_duplicated_or_reordered_kernel_events_break_the_attestation() {
    let mut f = fixture();
    f.probe.ingest_kernel_event(kernel_exec(1, 100));
    f.probe.ingest_kernel_event(kernel_exit(1, 200));
    let b = f.probe.batch([1u8; 16], 1, 2, vec![]);
    let good = f.signer.attest(b).unwrap();
    assert_eq!(
        good.batch.kernel_events[0].probe_seq + 1,
        good.batch.kernel_events[1].probe_seq
    );

    let mut dup = good.clone();
    let e = dup.batch.kernel_events[0].clone();
    dup.batch.kernel_events.push(e);
    assert_eq!(
        verify_attested_batch(&dup, &f.anchors),
        Err(VerifyError::PayloadHashMismatch)
    );

    let mut reordered = good.clone();
    reordered.batch.kernel_events.swap(0, 1);
    assert_eq!(
        verify_attested_batch(&reordered, &f.anchors),
        Err(VerifyError::PayloadHashMismatch)
    );
    // The kernel's own timestamps ride along untouched; the probe never
    // rewrites them.
    assert_eq!(good.batch.kernel_events[0].kernel_timestamp_ns, 100);
    assert_eq!(good.batch.kernel_events[1].kernel_timestamp_ns, 200);
}

// ─── 8. PID reuse ───

#[test]
fn t08_pid_reuse_never_transfers_identity_through_kernel_events() {
    let mut f = fixture();
    // An exit for a pid the probe never bound: existence attested, identity not.
    let ev = f.probe.ingest_kernel_event(kernel_exit(4242, 5)).clone();
    assert_eq!(ev.bound, None);
    assert_eq!(ev.subject_identity_digest(), None);
    let b = binding("aip1agent", 4242, 1000, 0xb0, 0xe0);
    assert!(!ev.matches_process_of(&b), "a bare pid matches no binding");

    // Two instances behind one pid are different identities.
    let first = process(4242, 1000, 0xb0, 0xe0);
    let reused = process(4242, 2000, 0xb0, 0xe0);
    assert!(first.matches_process_of(&b));
    assert!(!reused.matches_process_of(&b));
    assert_ne!(first.identity_digest(), reused.identity_digest());
}

// ─── 9. Start/exit race — the kernel sees what polling cannot ───

#[cfg(target_os = "linux")]
#[test]
fn t09_live_short_lived_process_is_seen_by_the_kernel_connector() {
    let Some(conn) = connector_or_skip("t09") else {
        return;
    };
    let mut f = fixture();
    f.probe.enable_loss_counter();

    let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();

    // Polling cannot see it any more (blind-spot B)...
    assert_eq!(
        f.probe.measure(pid),
        Err(ProbeError::ProcessNotVisible { pid })
    );

    // ...but the kernel told us about it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let (mut saw_exec, mut saw_exit) = (false, false);
    while std::time::Instant::now() < deadline && !(saw_exec && saw_exit) {
        match conn.next_event(200) {
            Ok(Some(ev)) => {
                if ev.kind.subject_pid() == Some(pid) {
                    match ev.kind {
                        KernelLifecycleKind::Exec { .. } => saw_exec = true,
                        KernelLifecycleKind::Exit { .. } => saw_exit = true,
                        _ => {}
                    }
                    f.probe.ingest_kernel_event(ev);
                }
            }
            Ok(None) => {}
            Err(SourceError::EventsLost) => f.probe.record_lost_events(1),
            Err(e) => panic!("connector error: {e}"),
        }
    }
    assert!(
        saw_exec && saw_exit,
        "kernel exec+exit for pid {pid} not delivered"
    );

    let b = f.probe.batch([9u8; 16], 1, 2, vec![]);
    let attested = f.signer.attest(b).unwrap();
    assert_eq!(verify_attested_batch(&attested, &f.anchors), Ok(()));
    let exit = attested
        .batch
        .kernel_events
        .iter()
        .find(|e| matches!(e.kind, KernelLifecycleKind::Exit { .. }))
        .unwrap();
    assert_eq!(exit.mechanism, SourceMechanism::ProcConnector);
    assert!(exit.kernel_timestamp_ns > 0);
    // The process was gone before we could anchor it: identity is honestly
    // absent, not guessed.
    if exit.bound.is_none() {
        assert_eq!(exit.subject_identity_digest(), None);
    }
}

// ─── 10. Executable replacement is a kernel event ───

#[cfg(target_os = "linux")]
#[test]
fn t10_live_exec_replacement_is_delivered_as_a_kernel_exec_event() {
    let Some(conn) = connector_or_skip("t10") else {
        return;
    };
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "exec /bin/sleep 30"])
        .spawn()
        .unwrap();
    let pid = child.id();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut execs = 0;
    while std::time::Instant::now() < deadline && execs < 2 {
        if let Ok(Some(ev)) = conn.next_event(200) {
            if ev.kind.subject_pid() == Some(pid)
                && matches!(ev.kind, KernelLifecycleKind::Exec { .. })
            {
                execs += 1;
            }
        }
    }
    // Two execs for one pid: the shell, then the binary that replaced it.
    // Blind-spot D saw only the before/after states; the kernel saw the event.
    assert_eq!(execs, 2, "expected exec(sh) then exec(sleep) for pid {pid}");

    let probe = ProcfsProbe::new(PROBE_ID);
    let anchored = probe.measure_anchored(pid).unwrap();
    let sleep_hash = sha256(&std::fs::read("/bin/sleep").unwrap());
    assert_eq!(anchored.process.exe_content_sha256, sleep_hash);
    child.kill().unwrap();
    child.wait().unwrap();
    // And the pidfd reports the instance's end — not a pid's.
    assert!(anchored.wait_exit(2000).unwrap());
}

// ─── 11. Network effect without expectation ───

#[cfg(target_os = "linux")]
#[test]
fn t11_socket_observation_is_socket_level_metadata_with_no_authorization() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut f = fixture();

    let (me, effects, _malformed) = f.probe.observe_sockets(std::process::id()).unwrap();
    let listening = effects
        .iter()
        .find(|e| matches!(e, ObservedEffect::SocketObserved { local, .. } if local.port == port))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "listener port {port} not found among {} socket effects of pid {} (inodes {:?}): {effects:?}",
                effects.len(),
                std::process::id(),
                socket_inodes_of(std::process::id())
            )
        });
    match &listening {
        ObservedEffect::SocketObserved {
            protocol,
            local,
            state,
            ..
        } => {
            assert_eq!(*protocol, SocketProtocol::Tcp);
            assert_eq!(&local.addr[..4], &[127, 0, 0, 1]);
            assert!(!local.is_v6);
            assert_eq!(*state, 0x0a, "LISTEN");
        }
        _ => unreachable!(),
    }
    let o = f
        .probe
        .observation_with(me, listening, SourceMechanism::ProcNetTable, None, now_ms());
    let b = f.probe.batch([11u8; 16], 1, 2, vec![o]);
    let attested = f.signer.attest(b).unwrap();
    assert_eq!(verify_attested_batch(&attested, &f.anchors), Ok(()));

    // Socket-level only: the *observation* carries no application payload,
    // no packet, no wire data — and no authorization. (Checked on the
    // observation itself: the AIP signature envelope around the batch has a
    // `payload_hash` field that names the signed bytes, not traffic.)
    let json = serde_json::to_string(&attested.batch.observations[0])
        .unwrap()
        .to_lowercase();
    for forbidden in [
        "payload",
        "packet",
        "xdp",
        "permitted",
        "authorized",
        "allowed",
        "expected",
    ] {
        assert!(!json.contains(forbidden), "`{forbidden}` in {json}");
    }
    drop(listener);
}

// ─── 12. Expected execution without observed effect ───

#[test]
fn t12_no_observation_is_never_a_phantom_claim() {
    let mut f = fixture();
    let empty = f.probe.batch([12u8; 16], 100, 200, vec![]);
    let attested = f.signer.attest(empty).unwrap();
    assert!(attested.batch.observations.is_empty() && attested.batch.kernel_events.is_empty());
    let h = f.signer.health(200).unwrap();
    // The only things this crate can say about the window:
    let a = h.availability_for(
        &CoverageWindow {
            from_ms: 100,
            to_ms: 200,
        },
        200,
        60_000,
    );
    assert!(matches!(
        a,
        ObservationAvailability::Unavailable { .. } | ObservationAvailability::Covered { .. }
    ));
    let json = serde_json::to_string(&(attested, h, a))
        .unwrap()
        .to_lowercase();
    for forbidden in [
        "phantom",
        "did_not",
        "not_executed",
        "expectedexecution",
        "verdict",
    ] {
        assert!(!json.contains(forbidden), "`{forbidden}` in {json}");
    }
}

// ─── 13. Collector restart ───

#[test]
fn t13_collector_restart_cannot_silently_continue_the_chain() {
    let mut f = fixture();
    for i in 1..=2u8 {
        let o = f
            .probe
            .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 1);
        f.signer
            .attest(f.probe.batch([i; 16], i as u64, i as u64 + 1, vec![o]))
            .unwrap();
    }
    let old_head = f.signer.ledger().last_head().unwrap();
    assert_eq!(f.signer.state(), ObserverState::Active);

    // The collector process restarts: in-memory ledger gone, same key.
    let mut restarted = CollectorSigner::new(
        OBSERVER_ID,
        1,
        &f.observer_kp.private_key,
        &f.observer_kp.public_key,
    )
    .unwrap();
    restarted.register_probe(PROBE_ID, &SourceMechanism::ALL);
    let o = f
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 3);
    let a = restarted
        .attest(f.probe.batch([3u8; 16], 3, 4, vec![o]))
        .unwrap();
    assert_eq!(a.sequence, 1, "a fresh epoch, not sequence 3");
    assert_eq!(a.prev_head, [0u8; 32], "no link to the lost chain");
    assert_ne!(a.prev_head, old_head);
    assert_eq!(restarted.state(), ObserverState::ContinuityUnverified);
    assert_eq!(restarted.health(5).unwrap().health.attested_coverage, None);
}

// ─── 14. Host reboot ───

#[test]
fn t14_host_reboot_changes_instance_identity_and_uncouples_kernel_time() {
    let before = process(4242, 1000, 0xb0, 0xe0);
    let after = process(4242, 1000, 0xb1, 0xe0);
    assert_ne!(before.identity_digest(), after.identity_digest());
    let b = binding("aip1agent", 4242, 1000, 0xb0, 0xe0);
    assert!(before.matches_process_of(&b));
    assert!(!after.matches_process_of(&b));
    // Kernel timestamps are "ns since boot": two events with equal
    // timestamps from different boots are not simultaneous, and nothing in
    // the type pretends otherwise — comparison across boot ids is the
    // reconciler's problem to refuse.
    let e1 = kernel_exec(1, 500);
    let e2 = kernel_exec(1, 500);
    assert_eq!(e1.timestamp_ns, e2.timestamp_ns);
}

// ─── 15. Event loss ───

#[cfg(target_os = "linux")]
#[test]
fn t15_live_kernel_event_loss_is_signalled_and_degrades_coverage() {
    let Some(conn) = connector_or_skip("t15") else {
        return;
    };
    // Starve the receive queue, then create a burst of events.
    conn.set_receive_buffer(1).unwrap();
    for _ in 0..400 {
        std::process::Command::new("/bin/true")
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
    }
    let mut f = fixture();
    f.probe.enable_loss_counter();
    let mut lost = 0u64;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match conn.next_event(50) {
            Err(SourceError::EventsLost) => {
                lost += 1;
                f.probe.record_lost_events(1);
                break;
            }
            Ok(Some(ev)) => {
                f.probe.ingest_kernel_event(ev);
            }
            Ok(None) => break,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(
        lost > 0,
        "expected ENOBUFS after starving a 1-byte receive buffer"
    );

    let b = f.probe.batch([15u8; 16], 1, 2, vec![]);
    assert!(matches!(b.dropped_events, Some(n) if n > 0));
    f.signer.attest(b).unwrap();
    assert!(matches!(
        f.signer.probe_faults().last(),
        Some(ProbeStreamFault::EventsLost { .. })
    ));
    assert_eq!(f.signer.state(), ObserverState::Degraded);
    let h = f.signer.health(3).unwrap();
    assert_eq!(h.health.attested_coverage, None);
    assert_eq!(
        h.availability_for(
            &CoverageWindow {
                from_ms: 1,
                to_ms: 2
            },
            3,
            60_000
        ),
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::ObserverDegraded
        }
    );
}

#[test]
fn t15b_reported_loss_degrades_even_without_a_live_connector() {
    let mut f = fixture();
    f.probe.enable_loss_counter();
    let o = f
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 1);
    f.signer
        .attest(f.probe.batch([1u8; 16], 1, 2, vec![o]))
        .unwrap();
    let o = f
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 2);
    f.signer
        .attest(f.probe.batch([2u8; 16], 2, 3, vec![o]))
        .unwrap();
    assert_eq!(f.signer.state(), ObserverState::Active);
    assert!(f
        .signer
        .health(3)
        .unwrap()
        .health
        .attested_coverage
        .is_some());

    f.probe.record_lost_events(7);
    let o = f
        .probe
        .observation(process(1, 1, 1, 1), ObservedEffect::ProcessPresent, None, 3);
    let b = f.probe.batch([3u8; 16], 3, 4, vec![o]);
    assert_eq!(b.dropped_events, Some(7));
    f.signer.attest(b).unwrap();
    assert_eq!(f.signer.state(), ObserverState::Degraded);
    assert_eq!(f.signer.health(4).unwrap().health.attested_coverage, None);
}

/// Regression for the startup-loss defect: at the kernel default receive
/// buffer the pilot's first batch always lost a connector event, so the
/// honest path could never be `Active`. The probe now enlarges the buffer at
/// open. This proves the enlargement takes effect (the kernel reports at
/// least what was asked) and that the same burst t15 uses to force `ENOBUFS`
/// is then received without loss. It does not prove overflow is impossible —
/// a large enough burst still overflows, and is still counted (t15).
#[cfg(target_os = "linux")]
#[test]
fn t15c_an_enlarged_connector_buffer_absorbs_the_burst_that_overflows_a_small_one() {
    let Some(conn) = connector_or_skip("t15c") else {
        return;
    };
    let want: i32 = 8 * 1024 * 1024;
    let got = match conn.enlarge_receive_buffer(want) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("SKIP t15c: cannot enlarge receive buffer here ({e}); property NOT established in this environment");
            return;
        }
    };
    if got < want {
        eprintln!("SKIP t15c: kernel granted only {got} of {want} bytes (no CAP_NET_ADMIN for SO_RCVBUFFORCE, clamped by rmem_max); property NOT established in this environment");
        return;
    }
    for _ in 0..400 {
        std::process::Command::new("/bin/true")
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
    }
    let mut received = 0u64;
    loop {
        match conn.next_event(200) {
            Ok(Some(_)) => received += 1,
            Ok(None) => break,
            Err(SourceError::EventsLost) => {
                panic!("ENOBUFS with a {got}-byte receive buffer after {received} events")
            }
            Err(e) => panic!("{e}"),
        }
    }
    // fork + exec + exit for each of 400 children, at least.
    assert!(received >= 1200, "received only {received} events");
}

// ─── 16/17. Observer key substitution and compromise boundary ───

#[test]
fn t16_observer_key_substitution_is_a_signature_failure() {
    let mut f = fixture();
    f.probe.ingest_kernel_event(kernel_exec(1, 1));
    let a = f
        .signer
        .attest(f.probe.batch([1u8; 16], 1, 2, vec![]))
        .unwrap();
    let other = generate_ed25519_keypair();
    let wrong = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &other.public_key);
    assert_eq!(
        verify_attested_batch(&a, &wrong),
        Err(VerifyError::SignatureInvalid)
    );
}

#[test]
fn t17_a_stolen_collector_key_forges_history_until_revoked() {
    let f = fixture();
    // The attacker holds the collector key. Their batches verify: nothing in
    // this crate can tell the two signers apart. This is the boundary.
    let mut thief = CollectorSigner::new(
        OBSERVER_ID,
        1,
        &f.observer_kp.private_key,
        &f.observer_kp.public_key,
    )
    .unwrap();
    let mut probe = ProcfsProbe::new("invented");
    probe.ingest_kernel_event(kernel_exec(1, 1));
    let forged = thief.attest(probe.batch([1u8; 16], 1, 2, vec![])).unwrap();
    assert_eq!(verify_attested_batch(&forged, &f.anchors), Ok(()));

    // The only remedy is revocation of that key version.
    let mut anchors = f.anchors.clone();
    anchors.revoke(OBSERVER_ID, 1);
    assert_eq!(
        verify_attested_batch(&forged, &anchors),
        Err(VerifyError::UntrustedObserverKey {
            observer_id: OBSERVER_ID.into(),
            key_version: 1
        })
    );
}

// ─── 18/19. Malformed kernel input and identifiers ───

#[test]
fn t18_malformed_kernel_event_bytes_never_panic_and_are_never_interpreted() {
    let mut seed = 0x9e37_79b9u32;
    for len in 0..300usize {
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (seed >> 24) as u8;
        }
        let r = std::panic::catch_unwind(|| parse_proc_event(&buf));
        assert!(r.is_ok(), "panicked on {len} random bytes");
    }
    // An unknown event type is recorded as Other, never mapped to a lifecycle.
    let mut probe = ProcfsProbe::new(PROBE_ID);
    let ev = probe
        .ingest_kernel_event(ProcEvent {
            cgroup: aip_observe::CgroupSample::NotSampled,
            kind: KernelLifecycleKind::Other { what: 0x40 },
            cpu: 0,
            timestamp_ns: 1,
        })
        .clone();
    assert_eq!(ev.kind, KernelLifecycleKind::Other { what: 0x40 });
    assert_eq!(ev.bound, None);
}

#[test]
fn t19_malformed_identifiers_never_panic() {
    let garbage = "hdr\n\
        :::\n\
        0: 0100007F:871D 00000000:0000 0A\n\
        0: GGGGGGGG:ZZZZ 00000000:0000 0A 0 0 0 0 0 0 0 0\n\
        0: 0100007F:871D 00000000:0000 XX 00000000:00000000 00:00000000 00000000 0 0 notanumber 2 x\n\
        \u{0}\u{0}\u{0}\n";
    for proto in [
        SocketProtocol::Tcp,
        SocketProtocol::Tcp6,
        SocketProtocol::Udp6,
    ] {
        let r = std::panic::catch_unwind(|| parse_proc_net_table(garbage, proto));
        assert!(r.is_ok());
        let (rows, malformed) = r.unwrap();
        assert!(rows.is_empty());
        assert!(malformed >= 4);
    }
    for s in [
        "socket:[",
        "socket:[]",
        "socket:[-1]",
        "socket:[99999999999999999999]",
        "anon_inode:[eventpoll]",
        "",
    ] {
        assert_eq!(parse_socket_link(s), None, "{s:?}");
    }
    let probe = ProcfsProbe::new("");
    #[cfg(target_os = "linux")]
    assert_eq!(
        probe.measure(0),
        Err(ProbeError::ProcessNotVisible { pid: 0 })
    );
    let _ = probe;
}

// ─── 20. Canonical encoding collisions ───

#[test]
fn t20_new_encodings_are_injective() {
    let mut p = ProcfsProbe::new("ab");
    let mut q = ProcfsProbe::new("a");
    let ca = AgentClaim {
        agent_id: "c".into(),
        claim_source: "x".into(),
        decision_id: None,
    };
    let cb = AgentClaim {
        agent_id: "bc".into(),
        claim_source: "x".into(),
        decision_id: None,
    };
    let oa = p.observation(
        process(1, 1, 1, 1),
        ObservedEffect::ProcessPresent,
        Some(&ca),
        1,
    );
    let ob = q.observation(
        process(1, 1, 1, 1),
        ObservedEffect::ProcessPresent,
        Some(&cb),
        1,
    );
    assert_ne!(oa.canonical_bytes(), ob.canonical_bytes());

    // Same numbers, different provenance.
    let mut o2 = oa.clone();
    o2.mechanism = SourceMechanism::PidFdAnchored;
    assert_ne!(oa.canonical_bytes(), o2.canonical_bytes());

    // A batch with one observation vs one kernel event carrying "the same"
    // process: different domains, different bytes.
    let mut f = fixture();
    let o = f
        .probe
        .observation(process(5, 5, 5, 5), ObservedEffect::ProcessPresent, None, 1);
    let b_obs = f.probe.batch([1u8; 16], 1, 2, vec![o]);
    let mut g = fixture();
    g.probe.ingest_kernel_event(kernel_exec(5, 5));
    let b_ev = g.probe.batch([1u8; 16], 1, 2, vec![]);
    assert_ne!(b_obs.digest(), b_ev.digest());

    // Loss: unknown vs counted zero.
    let mut b0 = b_obs.clone();
    b0.dropped_events = None;
    let mut b1 = b_obs.clone();
    b1.dropped_events = Some(0);
    assert_ne!(b0.digest(), b1.digest());

    // Run id and sequence range are inside the bytes.
    let mut b2 = b_obs.clone();
    b2.probe_run_id[0] ^= 1;
    assert_ne!(b2.digest(), b_obs.digest());
    let mut b3 = b_obs.clone();
    b3.probe_seq_last += 1;
    assert_ne!(b3.digest(), b_obs.digest());
}

// ─── Mutation of every Stage 6.5 field is detected ───

#[test]
fn every_new_attested_field_mutation_is_detected() {
    let mut f = fixture();
    f.probe.enable_loss_counter();
    let listener_like = ObservedEffect::SocketObserved {
        protocol: SocketProtocol::Tcp,
        local: SocketEndpoint {
            addr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_v6: false,
            port: 8080,
        },
        remote: SocketEndpoint {
            addr: [0; 16],
            is_v6: false,
            port: 0,
        },
        state: 0x0a,
        inode: 4242,
    };
    let o = f.probe.observation_with(
        process(1, 1, 1, 1),
        listener_like,
        SourceMechanism::ProcNetTable,
        None,
        1,
    );
    f.probe.ingest_kernel_event(kernel_exec(1, 1));
    let good = f
        .signer
        .attest(f.probe.batch([1u8; 16], 1, 2, vec![o]))
        .unwrap();

    type M = (&'static str, fn(&mut AttestedBatch));
    let muts: Vec<M> = vec![
        ("probe_run_id", |a| a.batch.probe_run_id[0] ^= 1),
        ("probe_seq_first", |a| a.batch.probe_seq_first = 0),
        ("probe_seq_last", |a| a.batch.probe_seq_last += 1),
        ("dropped_events", |a| a.batch.dropped_events = Some(9)),
        ("mechanism", |a| {
            a.batch.observations[0].mechanism = SourceMechanism::ProcfsPoll
        }),
        ("socket.port", |a| {
            if let ObservedEffect::SocketObserved { local, .. } =
                &mut a.batch.observations[0].effect
            {
                local.port += 1;
            }
        }),
        ("socket.state", |a| {
            if let ObservedEffect::SocketObserved { state, .. } =
                &mut a.batch.observations[0].effect
            {
                *state = 0x01;
            }
        }),
        ("socket.inode", |a| {
            if let ObservedEffect::SocketObserved { inode, .. } =
                &mut a.batch.observations[0].effect
            {
                *inode += 1;
            }
        }),
        ("socket.remote.is_v6", |a| {
            if let ObservedEffect::SocketObserved { remote, .. } =
                &mut a.batch.observations[0].effect
            {
                remote.is_v6 = true;
            }
        }),
        ("kev.kind", |a| {
            a.batch.kernel_events[0].kind = KernelLifecycleKind::Exec { pid: 2, tgid: 2 }
        }),
        ("kev.cpu", |a| a.batch.kernel_events[0].cpu += 1),
        ("kev.kernel_timestamp", |a| {
            a.batch.kernel_events[0].kernel_timestamp_ns += 1
        }),
        ("kev.probe_seq", |a| a.batch.kernel_events[0].probe_seq += 1),
        ("kev.mechanism", |a| {
            a.batch.kernel_events[0].mechanism = SourceMechanism::ProcfsPoll
        }),
        ("kev.bound", |a| {
            a.batch.kernel_events[0].bound = Some(process(1, 1, 1, 1))
        }),
        ("kev.attribution", |a| {
            a.batch.kernel_events[0].attribution = AgentAttribution::Claimed {
                agent_id: "aip1x".into(),
                claim_source: "y".into(),
            }
        }),
        ("kev.dropped", |a| {
            a.batch.kernel_events.clear();
        }),
    ];
    for (name, m) in muts {
        let mut bad = good.clone();
        m(&mut bad);
        assert_eq!(
            verify_attested_batch(&bad, &f.anchors),
            Err(VerifyError::PayloadHashMismatch),
            "mutating {name} was not detected"
        );
    }
}

// ─── Failure classes stay distinct; authorization does not exist here ───

#[test]
fn failure_classes_are_distinct_and_no_authorization_class_exists() {
    let provenance = format!(
        "{:?} {:?} {:?}",
        AttestError::UnregisteredProbe("x".into()),
        AttestError::MechanismNotProvisioned {
            probe_id: "x".into(),
            mechanism: SourceMechanism::ProcConnector
        },
        VerifyError::ObserverKeyIsAgentKey
    );
    let integrity = format!(
        "{:?} {:?}",
        VerifyError::PayloadHashMismatch,
        VerifyError::SignatureInvalid
    );
    let continuity = format!(
        "{:?} {:?}",
        ContinuityFault::Replay { sequence: 1 },
        ProbeStreamFault::EventsLost { n: 1 }
    );
    let availability = format!("{:?}", no_observer());
    for s in [&provenance, &integrity, &continuity, &availability] {
        let l = s.to_lowercase();
        for forbidden in [
            "authoriz",
            "permitted",
            "allowed",
            "malicious",
            "verdict",
            "phantom",
        ] {
            assert!(!l.contains(forbidden), "{s} must not name `{forbidden}`");
        }
    }
    // And they really are different types, not one boolean.
    assert_ne!(provenance, integrity);
    assert_ne!(integrity, continuity);
    assert_ne!(continuity, availability);
}
