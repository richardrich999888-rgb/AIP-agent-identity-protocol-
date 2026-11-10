//! R5 — container identity in the execution binding.
//!
//! The case these tests exist for: two containers on one host, running the
//! same image, whose processes the kernel gave the same PID in different PID
//! namespaces and which started within the same clock tick. Under the v1
//! identity every field agrees and the two workloads are indistinguishable.
//! A payments agent and a reporting agent would reconcile against each
//! other's evidence.

use aip_types::{
    ContainerIdentity, ExecutionBinding, ExecutionMatch, ProcessInstance, EXECUTION_BINDING_VERSION,
};

const BOOT: [u8; 16] = [0x0c; 16];

fn container(cgroup: u64, pid_ns: u64, mnt_ns: u64, net_ns: u64) -> ContainerIdentity {
    ContainerIdentity {
        pid_ns_inode: pid_ns,
        mnt_ns_inode: mnt_ns,
        net_ns_inode: net_ns,
        cgroup_id: Some(cgroup),
    }
}

/// A binding whose every v1 field is fixed, so the only thing a test varies
/// is what it means to vary.
fn binding(agent: &str, container: Option<ContainerIdentity>) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent.to_string(),
        process: ProcessInstance {
            // The same pid in two PID namespaces, started in the same tick.
            pid: 1,
            pid_start_time_ticks: 433_843,
            boot_id: BOOT,
        },
        // The same image in both containers.
        exe_content_sha256: [0x33; 32],
        exe_path: "/usr/local/bin/agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container,
    }
}

// ─── The failure v1 could not see ───

#[test]
fn two_containers_sharing_a_pid_view_are_distinct_executions() {
    let payments = binding(
        "aip1Agent",
        Some(container(91, 4_026_532_100, 4_026_532_101, 4_026_532_102)),
    );
    let reporting = binding(
        "aip1Agent",
        Some(container(92, 4_026_532_200, 4_026_532_201, 4_026_532_202)),
    );

    // Every v1 field is identical. This is the point.
    assert_eq!(payments.process, reporting.process);
    assert_eq!(payments.exe_content_sha256, reporting.exe_content_sha256);
    assert_eq!(payments.agent_id, reporting.agent_id);

    assert!(
        !payments.same_execution(&reporting),
        "two containers must not share one execution identity"
    );
    assert_eq!(
        payments.compare_execution(&reporting),
        ExecutionMatch::DifferentContainer
    );
    assert_ne!(payments.identity_bytes(), reporting.identity_bytes());
}

/// One namespace differing is enough. A runtime that shares the network
/// namespace but not the mount namespace still yields two workloads.
#[test]
fn any_single_namespace_difference_separates_two_bindings() {
    let base = container(91, 10, 20, 30);
    let a = binding("aip1Agent", Some(base));
    for other in [
        container(91, 11, 20, 30),
        container(91, 10, 21, 30),
        container(91, 10, 20, 31),
    ] {
        let b = binding("aip1Agent", Some(other));
        assert_eq!(
            a.compare_execution(&b),
            ExecutionMatch::DifferentContainer,
            "{base:?} vs {other:?}"
        );
    }
}

/// The cgroup id is context. A process migrated between cgroups is the same
/// execution, and a verifier must not read the move as a change of workload.
#[test]
fn a_cgroup_move_within_the_same_namespaces_is_the_same_execution() {
    let before = binding("aip1Agent", Some(container(91, 10, 20, 30)));
    let after = binding("aip1Agent", Some(container(92, 10, 20, 30)));
    assert_eq!(after.compare_execution(&before), ExecutionMatch::Same);
    assert!(after.same_execution(&before));
    // It is still recorded, so an auditor reading the full encoding sees it.
    assert_ne!(after.canonical_bytes(), before.canonical_bytes());
    // A host with no cgroup v2 records none, and that is not a difference.
    let v1_host = binding(
        "aip1Agent",
        Some(ContainerIdentity {
            cgroup_id: None,
            ..container(91, 10, 20, 30)
        }),
    );
    assert_eq!(v1_host.compare_execution(&before), ExecutionMatch::Same);
}

#[test]
fn the_same_container_is_the_same_execution() {
    let c = container(91, 10, 20, 30);
    let a = binding("aip1Agent", Some(c));
    let mut b = binding("aip1Agent", Some(c));
    // Context fields differ; identity does not.
    b.exe_path = "/opt/agent".into();
    b.bound_at_ms += 5_000;
    assert!(a.same_execution(&b));
    assert_eq!(a.compare_execution(&b), ExecutionMatch::Same);
}

// ─── Absence is not difference ───

/// The rule that keeps a blind collector from manufacturing divergences.
#[test]
fn one_side_without_a_container_identity_is_not_comparable_not_different() {
    let seen = binding("aip1Agent", Some(container(91, 10, 20, 30)));
    let blind = binding("aip1Agent", None);

    assert_eq!(
        seen.compare_execution(&blind),
        ExecutionMatch::ContainerNotComparable
    );
    assert_eq!(
        blind.compare_execution(&seen),
        ExecutionMatch::ContainerNotComparable,
        "the answer must not depend on which side is asked"
    );
    // It is emphatically not the positive finding.
    assert_ne!(
        seen.compare_execution(&blind),
        ExecutionMatch::DifferentContainer
    );
    // And byte equality still says "not the same", which is why the
    // three-valued answer exists at all: a consumer reading only
    // `same_execution` learns nothing about why.
    assert!(!seen.same_execution(&blind));
}

#[test]
fn two_collectors_that_both_saw_nothing_agree_rather_than_colliding() {
    let a = binding("aip1Agent", None);
    let b = binding("aip1Agent", None);
    assert!(a.same_execution(&b));
    assert_eq!(a.compare_execution(&b), ExecutionMatch::Same);
}

/// Zeros are a real container, not an absence. A collector that defaulted a
/// failed read to zero would make every blind host agree with the root
/// cgroup, which is the bug this distinction prevents.
#[test]
fn an_all_zero_container_identity_is_not_the_same_as_none() {
    let zeroed = binding("aip1Agent", Some(container(0, 0, 0, 0)));
    let absent = binding("aip1Agent", None);
    assert_ne!(zeroed.identity_bytes(), absent.identity_bytes());
    assert_eq!(
        zeroed.compare_execution(&absent),
        ExecutionMatch::ContainerNotComparable
    );
}

// ─── The comparison names the first real difference ───

#[test]
fn a_coarser_difference_outranks_a_container_difference() {
    let c1 = Some(container(91, 10, 20, 30));
    let c2 = Some(container(92, 11, 21, 31));

    let mut other_agent = binding("aip1Other", c2);
    assert_eq!(
        binding("aip1Agent", c1).compare_execution(&other_agent),
        ExecutionMatch::DifferentAgent,
        "a different agent is not reported as a container difference"
    );

    other_agent.agent_id = "aip1Agent".into();
    other_agent.process.pid = 2;
    assert_eq!(
        binding("aip1Agent", c1).compare_execution(&other_agent),
        ExecutionMatch::DifferentProcessInstance
    );

    other_agent.process.pid = 1;
    other_agent.exe_content_sha256 = [0x44; 32];
    assert_eq!(
        binding("aip1Agent", c1).compare_execution(&other_agent),
        ExecutionMatch::DifferentExecutable
    );
}

#[test]
fn bindings_of_different_structure_versions_are_not_compared_field_by_field() {
    let a = binding("aip1Agent", None);
    let mut old = binding("aip1Agent", None);
    old.version = EXECUTION_BINDING_VERSION - 1;
    assert_eq!(a.compare_execution(&old), ExecutionMatch::VersionMismatch);
    // And the version is inside both encodings, so the bytes differ too.
    assert_ne!(a.identity_bytes(), old.identity_bytes());
    assert_ne!(a.canonical_bytes(), old.canonical_bytes());
}

// ─── Encoding ───

#[test]
fn the_namespaces_are_inside_both_encodings_and_the_cgroup_id_only_in_the_full_one() {
    let a = binding("aip1Agent", Some(container(91, 10, 20, 30)));
    let b = binding("aip1Agent", Some(container(91, 10, 20, 31)));
    assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    assert_ne!(a.identity_bytes(), b.identity_bytes());

    let moved = binding("aip1Agent", Some(container(92, 10, 20, 30)));
    assert_ne!(a.canonical_bytes(), moved.canonical_bytes());
    assert_eq!(
        a.identity_bytes(),
        moved.identity_bytes(),
        "the join key must not move when the cgroup does"
    );
}

/// The presence byte, checked the way an injectivity bug would show up: a
/// `None` binding's identity must not be a prefix of, or equal to, any
/// `Some` binding's.
#[test]
fn presence_is_encoded_so_absent_and_present_never_collide() {
    let absent = binding("aip1Agent", None).identity_bytes();
    let present = binding("aip1Agent", Some(container(0, 0, 0, 0))).identity_bytes();
    assert_ne!(absent, present);
    assert_eq!(
        present.len(),
        absent.len() + 24,
        "three namespace inodes follow the presence byte both encodings carry"
    );
    // The two are identical up to the presence byte, and differ at it.
    let n = absent.len() - 1;
    assert_eq!(&present[..n], &absent[..n]);
    assert_eq!(absent[n], 0);
    assert_eq!(present[n], 1);
}

#[test]
fn the_binding_round_trips_through_json_with_its_container() {
    let a = binding("aip1Agent", Some(container(91, 10, 20, 30)));
    let json = serde_json::to_string(&a).unwrap();
    let back: ExecutionBinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
    assert_eq!(back.identity_bytes(), a.identity_bytes());
}
