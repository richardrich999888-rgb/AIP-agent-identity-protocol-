//! B3 — the observer's own reading of container placement (protocol 11).
//!
//! `ExecutionBinding` has carried container identity since v2, but only the
//! party that *authorized* the execution filled it in. Until now the
//! observer could not assert the placement independently, so a claim that
//! two workloads sat in different containers rested on one side's word.
//! `ObservedProcess::container` is the observer's reading of the same
//! kernel facts.
//!
//! The delicate part is not recording it — it is refusing to turn a read
//! failure into an accusation. An observer that cannot read
//! `/proc/<pid>/ns/*` records `None`, and `None` must never compare as a
//! difference. These tests pin that.

use aip_observe::{
    AgentAttribution, ObservedEffect, ObservedExecution, ObservedProcess, SourceMechanism,
    OBSERVE_PROTOCOL_VERSION,
};
use aip_types::{ContainerIdentity, ExecutionMatch, ProcessInstance};

fn container(pid_ns: u64, mnt_ns: u64, net_ns: u64) -> ContainerIdentity {
    ContainerIdentity {
        pid_ns_inode: pid_ns,
        mnt_ns_inode: mnt_ns,
        net_ns_inode: net_ns,
        cgroup_id: Some(4242),
    }
}

fn process(container: Option<ContainerIdentity>) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: 1234,
            pid_start_time_ticks: 99,
            boot_id: [7u8; 16],
        },
        exe_content_sha256: [3u8; 32],
        exe_path: "/usr/bin/agent".into(),
        container,
    }
}

/// The protocol version carries the change, and the file's own changelog
/// says what 11 added. A verifier refuses anything else, so this constant
/// is the compatibility boundary.
#[test]
fn the_protocol_version_records_the_change() {
    assert_eq!(OBSERVE_PROTOCOL_VERSION, 11);
}

/// Two observers that both read the placement and agree: `Same`.
#[test]
fn two_readings_of_one_container_agree() {
    let a = process(Some(container(1, 2, 3)));
    let b = process(Some(container(1, 2, 3)));
    assert_eq!(a.compare_container(&b), ExecutionMatch::Same);
}

/// Two observers that both read the placement and disagree: a **positive
/// finding**. These are two workloads, and a v1 binding could not have told
/// them apart.
#[test]
fn different_namespaces_are_a_positive_finding() {
    let a = process(Some(container(1, 2, 3)));
    let b = process(Some(container(9, 2, 3)));
    assert_eq!(a.compare_container(&b), ExecutionMatch::DifferentContainer);
    // Any of the three namespaces differing is enough.
    let c = process(Some(container(1, 2, 99)));
    assert_eq!(a.compare_container(&c), ExecutionMatch::DifferentContainer);
}

/// **The one that matters.** Exactly one side read the placement: not
/// comparable, never a difference. A degraded observer has told us about
/// its own blindness, not about the process, and must not be able to
/// manufacture an accusation out of it.
#[test]
fn one_side_blind_is_not_comparable_and_never_a_difference() {
    let seeing = process(Some(container(1, 2, 3)));
    let blind = process(None);
    assert_eq!(
        seeing.compare_container(&blind),
        ExecutionMatch::ContainerNotComparable
    );
    assert_eq!(
        blind.compare_container(&seeing),
        ExecutionMatch::ContainerNotComparable
    );
    assert_ne!(
        seeing.compare_container(&blind),
        ExecutionMatch::DifferentContainer
    );
}

/// Neither side read it: nothing to compare, and still not a difference.
#[test]
fn neither_side_reading_it_is_not_a_difference() {
    assert_eq!(
        process(None).compare_container(&process(None)),
        ExecutionMatch::Same
    );
}

/// The cgroup id is context, not identity: two readings that agree on the
/// namespaces but differ on the cgroup are the same container. A process
/// moved between cgroups is not a different workload, and a cgroup-v1-only
/// host exposes none at all.
#[test]
fn the_cgroup_id_is_context_and_does_not_make_a_difference() {
    let mut a_id = container(1, 2, 3);
    a_id.cgroup_id = Some(111);
    let mut b_id = container(1, 2, 3);
    b_id.cgroup_id = Some(222);
    assert_eq!(
        process(Some(a_id)).compare_container(&process(Some(b_id))),
        ExecutionMatch::Same
    );
    let mut none_id = container(1, 2, 3);
    none_id.cgroup_id = None;
    assert_eq!(
        process(Some(container(1, 2, 3))).compare_container(&process(Some(none_id))),
        ExecutionMatch::Same
    );
}

/// The placement is **not** in the identity digest, and this is the reason:
/// an observer that could read the namespaces and one that could not would
/// otherwise produce different digests for the very same process,
/// manufacturing a divergence out of a read failure. `compare_container`
/// exists to answer that case honestly instead.
#[test]
fn the_identity_digest_does_not_move_when_only_the_placement_differs() {
    let seeing = process(Some(container(1, 2, 3)));
    let blind = process(None);
    let other = process(Some(container(9, 9, 9)));
    assert_eq!(seeing.identity_digest(), blind.identity_digest());
    assert_eq!(seeing.identity_digest(), other.identity_digest());
}

/// The placement **is** attested: it rides inside the canonical encoding
/// of the observation, so what the observer saw — including that it saw
/// nothing — is signed and non-repudiable. Changing it changes the bytes.
#[test]
fn the_placement_is_inside_the_canonical_bytes() {
    /// Wrap a process in the observation that actually gets signed.
    fn bytes_of(p: ObservedProcess) -> Vec<u8> {
        ObservedExecution {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe-b3".into(),
            observed: p,
            attribution: AgentAttribution::NotEstablished,
            effect: ObservedEffect::ProcessPresent,
            mechanism: SourceMechanism::PidFdAnchored,
            claimed_decision_id: None,
            host_wall_clock_ms: 1_700_000_000_000,
            probe_monotonic_ns: 42,
        }
        .canonical_bytes()
    }

    let b_seeing = bytes_of(process(Some(container(1, 2, 3))));
    let b_blind = bytes_of(process(None));
    let b_other = bytes_of(process(Some(container(9, 9, 9))));

    assert_ne!(
        b_seeing, b_blind,
        "an observer that read the placement must not encode identically to one that did not"
    );
    assert_ne!(
        b_seeing, b_other,
        "a different placement is different bytes"
    );

    // The cgroup id is context for comparison, but it is still attested.
    let mut with_cgroup = container(1, 2, 3);
    with_cgroup.cgroup_id = Some(777);
    assert_ne!(
        bytes_of(process(Some(with_cgroup))),
        b_seeing,
        "the cgroup id is context for comparison but is still signed"
    );
}

/// A batch from a v10 probe deserializes with no placement rather than
/// failing: the field defaults to "not observed", which is exactly what a
/// probe that never recorded one was saying.
#[test]
fn an_observation_without_the_field_deserializes_as_not_observed() {
    let json = r#"{
        "process": {"pid": 1, "pid_start_time_ticks": 2, "boot_id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},
        "exe_content_sha256": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "exe_path": "/bin/true"
    }"#;
    let p: ObservedProcess = serde_json::from_str(json).expect("deserialize");
    assert!(
        p.container.is_none(),
        "a missing field means not observed, not a parse failure"
    );
}

// ─── Live: the observer reads the real kernel ───────────────────────────────

/// The observer reads the placement of a real process from the real kernel,
/// not from anything the observed side told it. This is the whole point of
/// B3: the reading is the observer's own.
///
/// On a host that withholds `/proc/<pid>/ns/*` the measurement records
/// `None` and the test says so rather than asserting a placement it could
/// not see.
#[cfg(target_os = "linux")]
#[test]
fn the_observer_reads_a_real_processs_placement_itself() {
    use aip_observe::ProcfsProbe;

    let probe = ProcfsProbe::new("probe-b3-live");
    let me = std::process::id();
    let observed = probe.measure(me).expect("measure this process");

    let Some(c) = observed.container else {
        eprintln!("SKIPPED — this host withholds /proc/<pid>/ns/*; the observer recorded None");
        return;
    };

    // Namespace inodes are real inode numbers, never zero.
    assert!(c.pid_ns_inode != 0, "pid namespace inode");
    assert!(c.mnt_ns_inode != 0, "mnt namespace inode");
    assert!(c.net_ns_inode != 0, "net namespace inode");

    // Measuring the same process twice must agree — the placement is a fact
    // about the process, not about the moment of reading.
    let again = probe.measure(me).expect("measure again");
    assert_eq!(
        observed.compare_container(&again),
        ExecutionMatch::Same,
        "two readings of one live process must agree"
    );
}
