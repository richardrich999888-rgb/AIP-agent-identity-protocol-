//! Phase 9 — restart, PID change, namespaces, and what continuity is not.
//!
//! The rule this file exists to enforce: **any continuity that cannot be
//! established must remain unknown.** Nothing below infers that two things are
//! the same because their names look alike.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use aip_edge::correlate::records_for_subject;
use aip_edge::identity::{IdentityKind, IdentityStability};
use aip_edge::orchestrate::Scenario;

use common::{run_scenario, scratch};

// ─── 6. Workload restart ───

#[test]
fn t6_a_restarted_workload_is_a_different_execution_and_inherits_no_evidence() {
    let first = run_scenario("restart-1", Scenario::Honest);
    let second = run_scenario("restart-2", Scenario::Honest);

    assert_ne!(
        first.workload_pid, second.workload_pid,
        "two runs must be two process instances"
    );
    assert_ne!(
        first.subject.execution_id, second.subject.execution_id,
        "a restart is a new AIRI execution; carrying the old id across would be \
         manufactured continuity"
    );

    // The decisive check: evidence from the first run, offered against the
    // second run's subject, must correlate to nothing. The batches are real and
    // verify perfectly; they are simply about another execution.
    let mut carried = 0usize;
    for batch in &first.batches {
        let records = records_for_subject(batch, &first.observer_anchors, &second.subject)
            .expect("the batch still verifies under its own anchors");
        carried += records.len();
    }
    assert_eq!(
        carried, 0,
        "evidence from a previous instance became evidence about the new one"
    );

    // And the platform *does* survive, because the host did not reboot. The
    // two facts together are the point: some identities carry across a restart
    // and some do not, and the model says which.
    assert_eq!(
        IdentityKind::Process.across_workload_restart(),
        IdentityStability::Changes
    );
    assert_eq!(
        IdentityKind::Platform.across_workload_restart(),
        IdentityStability::Survives
    );
}

#[test]
fn t6b_the_observer_restarting_does_not_change_the_workloads_identity() {
    // An observer restart is a coverage event, not an identity event. The
    // architecture already refuses to extend coverage across the gap
    // (`aip-observe`'s continuity ledger); what must not happen is the
    // workload's identity being treated as changed because the witness blinked.
    for k in [
        IdentityKind::Process,
        IdentityKind::Platform,
        IdentityKind::System,
    ] {
        assert_eq!(
            k.across_observer_restart(),
            IdentityStability::Survives,
            "{k:?} is a property of the subject, not of the witness"
        );
    }
    // And the observer really is lost in that scenario, conservatively.
    let o = run_scenario("obs-restart", Scenario::ObserverLost);
    assert_eq!(o.reference.observations_offered, 0);
    assert!(!o.reference.finding.asserts_non_occurrence());
}

// ─── Namespaces (Phase 13) ───
//
// **Linux namespace reference, not mandatory product architecture.** `unshare`
// is used because it is util-linux, already present, and needs no daemon.
// Docker is not a dependency of anything here.

/// Whether this host permits a new PID namespace. Named so a skip says which
/// capability was missing rather than "unavailable".
fn unshare_available() -> Result<(), String> {
    let out = Command::new("unshare")
        .args(["--pid", "--fork", "/bin/true"])
        .output()
        .map_err(|e| format!("unshare is not installed or not runnable: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "unshare --pid --fork failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[test]
fn t_container_a_namespaced_workload_reports_a_pid_that_is_not_its_identity() {
    if let Err(why) = unshare_available() {
        // The codebase's existing convention for a kernel facility a host does
        // not provide: say what is missing, simulate nothing.
        println!("SKIPPED: {why}");
        return;
    }
    let dir = scratch("ns");
    std::fs::create_dir_all(&dir).expect("state dir");
    let workload = aip_edge::transport::sibling_binary("aip-edge-workload").expect("workload");

    // The workload runs as PID 1 of a fresh PID namespace. Its own
    // `getpid()` therefore returns 1 — a completely honest answer to a
    // question whose answer means something different inside than outside.
    let mut child = Command::new("unshare")
        .arg("--pid")
        .arg("--fork")
        .arg(&workload)
        .arg("--dir")
        .arg(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn namespaced workload");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    writeln!(stdin, "identity").expect("write");
    stdin.flush().expect("flush");
    let mut reply = String::new();
    stdout.read_line(&mut reply).expect("reply");
    assert!(reply.starts_with("ok "), "workload said: {reply}");

    let announcement: aip_edge_contract::WorkloadAnnouncement =
        aip_edge::transport::read_json(&dir.join(aip_edge_contract::WORKLOAD_ANNOUNCEMENT))
            .expect("announcement");

    writeln!(stdin, "quit").ok();
    let _ = stdin.flush();
    drop(stdin);
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        announcement.self_reported_pid, 1,
        "in a fresh PID namespace the workload is pid 1; that is the point of the test"
    );
    // PID 1 on this host is init. A verifier that correlated on the
    // subject's self-reported pid would be measuring init, not the workload.
    // That is why the reference correlates on the instance the *decision
    // point* bound and the *observer* measured, and never on a reported
    // number.
    assert_ne!(
        announcement.self_reported_pid,
        std::process::id(),
        "the test process is not pid 1"
    );
}

#[test]
fn t_container_namespace_change_establishes_no_new_identity() {
    // A container is a set of namespaces and a cgroup. No mechanism in
    // `aip-observe` measures either, and a namespace inode number is reused
    // after the namespace is freed. Deriving an identity from one would import
    // an orchestrator's label into a signed record.
    assert_eq!(
        IdentityKind::Container.across_namespace_change(),
        IdentityStability::NotEstablished
    );
    assert!(
        !IdentityKind::Container.independently_established(),
        "no mechanism in this build measures a container"
    );
    assert!(
        !IdentityKind::Container
            .across_workload_restart()
            .asserts_continuity(),
        "`we cannot tell` must never be read as `it is the same one`"
    );
    // What *does* change is the process instance, and it changes because it is
    // a new process — not because the namespace changed.
    assert_eq!(
        IdentityKind::Process.across_namespace_change(),
        IdentityStability::Changes
    );
    assert_eq!(
        IdentityKind::Platform.across_namespace_change(),
        IdentityStability::Survives,
        "namespaces do not reboot the host"
    );
}

// ─── Reboot semantics, as far as is practical ───

#[test]
fn a_host_reboot_changes_the_platform_identity_and_the_registry_stops_applying() {
    // Rebooting the test host is not practical, and simulating one would be
    // manufacturing the very continuity this file refuses. What *is* checkable
    // is the model's answer and the mechanism behind it: the boot id is the
    // registry key, a reboot produces a new one, and an unregistered boot
    // resolves to `Unregistered` rather than to the previous platform.
    assert_eq!(
        IdentityKind::Platform.across_host_reboot(),
        IdentityStability::Changes
    );
    assert_eq!(
        IdentityKind::System.across_host_reboot(),
        IdentityStability::Survives,
        "the system is the thing the reboot happened to"
    );
    assert_eq!(
        IdentityKind::Hardware.across_host_reboot(),
        IdentityStability::NotEstablished,
        "ADR-002 is PROPOSED; hardware replacement is not detectable here (gap G1)"
    );

    // The mechanism, exercised: a boot the registry does not cover is unknown,
    // never wrong, and never the old platform.
    let o = run_scenario("reboot", Scenario::Honest);
    let mut other_boot = o.subject.boot_id;
    other_boot[0] ^= 0xFF;
    assert!(
        o.registry.resolve(&other_boot, 1_000).is_none(),
        "a boot the verifier never registered must not resolve to anything"
    );
    assert!(
        o.registry.resolve(&o.subject.boot_id, 1_000).is_some(),
        "and the registered one must, or the previous assertion is vacuous"
    );
}

// ─── The identity table itself ───

#[test]
fn every_identity_kind_that_is_not_independently_established_stays_unknown() {
    for k in IdentityKind::ALL {
        if k.independently_established() {
            continue;
        }
        // `System` is declared rather than measured, and declared identities
        // legitimately survive: the deployment asserts them, exactly as it
        // asserts which observer keys it trusts.
        if matches!(k, IdentityKind::System) {
            continue;
        }
        for stability in [
            k.across_workload_restart(),
            k.across_observer_restart(),
            k.across_namespace_change(),
            k.across_host_reboot(),
        ] {
            assert_eq!(
                stability,
                IdentityStability::NotEstablished,
                "{k:?} is not independently established, so no event may be answered with \
                 anything but `unknown`"
            );
        }
    }
}
