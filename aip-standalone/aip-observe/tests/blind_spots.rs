//! Skill 6.5 red-team phase: characterization of the observation blind spots
//! in the Stage 3 (Skill 6) observer, written and run BEFORE any Sniffer Dog
//! change. Each test names the case from the stage brief (A–J) and the
//! classification the report records for it.
//!
//! These tests describe the procfs-polling mechanism. That mechanism survives
//! Stage 6.5 as one provenance among several, so every fact asserted here is
//! meant to remain true afterwards: the blind spots are closed by *adding*
//! kernel-mediated sources, not by pretending polling can do more than it can.

use aip_crypto::generate_ed25519_keypair;
use aip_observe::*;
use aip_types::ProcessInstance;
use std::process::Command;

fn collector() -> (CollectorSigner, ObserverTrustAnchors) {
    let kp = generate_ed25519_keypair();
    let signer = CollectorSigner::new("collector", 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = ObserverTrustAnchors::new().trust("collector", 1, &kp.public_key);
    (signer, anchors)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// ─── A / J: procfs content is host-supplied; the collector cannot tell ───
//
// Classification: PROVEN blind spot (collector attests receipt, not truth);
// root-resistance on the content axis: DEPLOYMENT ASSUMPTION.

#[test]
fn a_fabricated_measurement_is_indistinguishable_from_a_real_one_at_the_collector() {
    let (mut signer, anchors) = collector();
    let mut probe = ProcfsProbe::new("probe");

    // A real measurement of this process...
    #[cfg(target_os = "linux")]
    let real = probe.measure(std::process::id()).unwrap();
    #[cfg(not(target_os = "linux"))]
    let real = ObservedProcess {
        process: ProcessInstance {
            pid: 1,
            pid_start_time_ticks: 1,
            boot_id: [1; 16],
        },
        exe_content_sha256: [1; 32],
        exe_path: "/x".into(),
    };

    // ...and a fabrication a root attacker could feed the probe (or submit as
    // if it were the probe): a process that does not exist, running a binary
    // that was never on this host.
    let fabricated = ObservedProcess {
        process: ProcessInstance {
            pid: 4_000_000,
            pid_start_time_ticks: 12_345,
            boot_id: real.process.boot_id,
        },
        exe_content_sha256: [0x5a; 32],
        exe_path: "/usr/bin/payments-agent".into(),
    };

    let o1 = probe.observation(real, ObservedEffect::ProcessPresent, None, now_ms());
    let o2 = probe.observation(fabricated, ObservedEffect::ProcessPresent, None, now_ms());
    let b = probe.batch([1u8; 16], now_ms() - 10, now_ms(), vec![o1, o2]);
    let attested = signer.attest(b).unwrap();

    // Both attest. Both verify. Nothing in the record marks either as
    // kernel-mediated: a polled observation carries no kernel provenance, so
    // the collector attests receipt of both, not the truth of either.
    assert_eq!(verify_attested_batch(&attested, &anchors), Ok(()));
    let json = serde_json::to_string(&attested).unwrap();
    for kernel_marker in ["ProcConnector", "PidFdAnchored", "kernel_timestamp"] {
        assert!(
            !json.contains(kernel_marker),
            "a polled observation must not carry kernel provenance `{kernel_marker}`: {json}"
        );
    }
}

// ─── B: a process that starts and exits between polls leaves no record ───
//
// Classification: PROVEN blind spot; NOT_IMPLEMENTED (no kernel exec/exit
// event source). Absence of a record is CANNOT_PROVE about the execution.

#[cfg(target_os = "linux")]
#[test]
fn b_a_short_lived_process_is_invisible_to_polling() {
    let probe = ProcfsProbe::new("probe");
    let child = Command::new("/bin/true").spawn().unwrap();
    let pid = child.id();
    let mut child = child;
    child.wait().unwrap();

    // The process ran. Polling afterwards finds nothing, and there is no
    // event source that would have told us it existed.
    assert_eq!(
        probe.measure(pid),
        Err(ProbeError::ProcessNotVisible { pid })
    );
    // Nothing in the v1 API can turn this into "it did not run" — and nothing
    // can turn it into "it ran" either. That is CANNOT_PROVE.
}

// ─── C: polling has no liveness anchor across its own reads ───
//
// Classification: CANNOT_PROVE (the window between reading `stat` and
// reading `exe` is unanchored; PID reuse inside it is undetectable by v1).

#[cfg(target_os = "linux")]
#[test]
fn c_polling_after_exit_yields_no_instance_linkage() {
    let probe = ProcfsProbe::new("probe");
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let pid = child.id();
    let before = probe.measure(pid).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();

    // After exit the same PID is simply gone; v1 has no kernel-mediated
    // "this instance ended" fact, so a later occupant of the PID cannot be
    // distinguished from the original by anything but the start ticks the
    // poller happens to read — and it has no anchor proving the two reads
    // belong to one instance.
    assert_eq!(
        probe.measure(pid),
        Err(ProbeError::ProcessNotVisible { pid })
    );
    assert_ne!(before.process.pid_start_time_ticks, 0);
}

// ─── D: executable replacement between polls is not itself observed ───
//
// Classification: PROVEN partial — Stage 1 identity detects the change
// *if both sides are polled*; the exec event itself is NOT_IMPLEMENTED.

#[cfg(target_os = "linux")]
#[test]
fn d_exec_between_polls_changes_identity_but_the_event_is_unseen() {
    let probe = ProcfsProbe::new("probe");
    // The shell replaces itself with `sleep` after 0.7 s: same PID, new binary.
    let mut child = Command::new("/bin/sh")
        .args(["-c", "sleep 0.7; exec /bin/sleep 30"])
        .spawn()
        .unwrap();
    let pid = child.id();
    let as_shell = probe.measure(pid).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let as_sleep = probe.measure(pid).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();

    assert_eq!(as_shell.process, as_sleep.process, "same process instance");
    assert_ne!(
        as_shell.exe_content_sha256, as_sleep.exe_content_sha256,
        "Stage 1 identity distinguishes the two binaries"
    );
    assert_ne!(as_shell.identity_digest(), as_sleep.identity_digest());
    // But v1 has no exec *event*: had the second poll been skipped, the
    // replacement would never have been recorded.
}

// ─── E / F: network and syscall effects are invisible ───
//
// Classification: NOT_IMPLEMENTED in v1 (no socket, packet, or syscall
// observation path). A polling observation of a process with an open
// listening socket carries no network information at all.

#[cfg(target_os = "linux")]
#[test]
fn e_open_socket_is_invisible_to_the_polling_observation() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let (mut signer, anchors) = collector();
    let mut probe = ProcfsProbe::new("probe");
    let me = probe.measure(std::process::id()).unwrap();
    let o = probe.observation(me, ObservedEffect::ProcessPresent, None, now_ms());
    let b = probe.batch([2u8; 16], now_ms() - 10, now_ms(), vec![o]);
    let attested = signer.attest(b).unwrap();
    assert_eq!(verify_attested_batch(&attested, &anchors), Ok(()));

    let json = serde_json::to_string(&attested).unwrap().to_lowercase();
    assert!(
        !json.contains("socket"),
        "polling observation carries no socket facts"
    );
    assert!(!json.contains(&format!(":{port}")) && !json.contains(&format!("{port:x}")));
    drop(listener);
}

#[test]
fn f_no_syscall_or_effect_observation_path_exists() {
    // The only effects v1 can express are process presence/absence.
    for e in [
        ObservedEffect::ProcessPresent,
        ObservedEffect::ProcessNoLongerPresent,
    ] {
        let json = serde_json::to_string(&e).unwrap().to_lowercase();
        assert!(!json.contains("syscall") && !json.contains("file") && !json.contains("socket"));
    }
}

// ─── G: observer restart vs execution continuity ───
//
// Classification: PROVEN handled by Skill 6 for the *observer's* continuity
// (restart → Recovering, no back-fill). Execution continuity across the gap:
// CANNOT_PROVE.

#[test]
fn g_restart_leaves_the_outage_uncovered_and_says_nothing_about_execution() {
    let (mut signer, _anchors) = collector();
    let mut probe = ProcfsProbe::new("probe");
    let p = ObservedProcess {
        process: ProcessInstance {
            pid: 7,
            pid_start_time_ticks: 7,
            boot_id: [7; 16],
        },
        exe_content_sha256: [7; 32],
        exe_path: "/x".into(),
    };
    for (id, from, to) in [(1u8, 100u64, 200u64), (2, 200, 300)] {
        let o = probe.observation(p.clone(), ObservedEffect::ProcessPresent, None, from);
        signer
            .attest(probe.batch([id; 16], from, to, vec![o]))
            .unwrap();
    }
    assert_eq!(signer.state(), ObserverState::Active);
    signer.note_probe_restart();
    let o = probe.observation(p, ObservedEffect::ProcessPresent, None, 500);
    signer
        .attest(probe.batch([3; 16], 500, 600, vec![o]))
        .unwrap();
    let h = signer.health(600).unwrap();
    let outage = h.availability_for(
        &CoverageWindow {
            from_ms: 300,
            to_ms: 500,
        },
        600,
        60_000,
    );
    assert!(!outage.is_covered());
}

// ─── H: dropped events have no counter in the polling model ───
//
// Classification: NOT_IMPLEMENTED (polling has no notion of an event queue
// and therefore no loss signal; "no loss" is CANNOT_PROVE).

#[test]
fn h_polling_exposes_no_loss_counter() {
    let probe = ProcfsProbe::new("probe");
    let b = probe.batch([1u8; 16], 1, 2, vec![]);
    let json = serde_json::to_string(&b).unwrap();
    // Either the field does not exist (v1) or it is explicitly absent (None):
    // a polling batch can never claim a counted zero loss.
    assert!(
        !json.contains("\"dropped_events\":") || json.contains("\"dropped_events\":null"),
        "{json}"
    );
}

// ─── I: ordering rests on the collector sequence and a host clock ───
//
// Classification: PROVEN handled for collector order (Skill 6); kernel
// event ordering NOT_IMPLEMENTED; host wall clock is contextual only.

#[test]
fn i_observation_time_is_host_supplied_and_carries_no_kernel_timestamp() {
    let mut probe = ProcfsProbe::new("probe");
    let p = ObservedProcess {
        process: ProcessInstance {
            pid: 1,
            pid_start_time_ticks: 1,
            boot_id: [1; 16],
        },
        exe_content_sha256: [1; 32],
        exe_path: "/x".into(),
    };
    // The probe records whatever wall clock it is handed; a host clock set to
    // the year 2000 is faithfully sealed.
    let o = probe.observation(p, ObservedEffect::ProcessPresent, None, 946_684_800_000);
    assert_eq!(o.host_wall_clock_ms, 946_684_800_000);
    let json = serde_json::to_string(&o).unwrap();
    assert!(
        !json.contains("kernel_timestamp"),
        "v1 polling has no kernel timestamp"
    );
}
