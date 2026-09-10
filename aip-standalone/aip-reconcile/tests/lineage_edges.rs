//! Phase C — process lineage edges, RED.
//!
//! A `LineageEdge` is the reconciler's derivation "bound instance P forked
//! bound instance C, which executed image H", from collector-signed kernel
//! events. It exists only when both ends are bound and the child's start
//! tick was verified against the clock anchor; anything less is not lineage.
//! No probe, collector or agent statement about ancestry is ever consulted.

use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_reconcile::*;
use aip_types::ProcessInstance;

const OBSERVER_ID: &str = "collector-l";
const PROBE_ID: &str = "probe-l";
const RUN: [u8; 16] = [0x4c; 16];
const PARENT_PID: u32 = 4_100_001;
const CHILD_PID: u32 = 4_100_002;
const ANCHOR_BOOT_NS: u64 = 200_000_000_000;
const CLK_TCK: u32 = 100;
const TICK_NS: u64 = 10_000_000;
const NOW: u64 = 1_700_000_500_000;

fn signer() -> CollectorSigner {
    let kp = generate_ed25519_keypair();
    let mut s = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    s.register_probe(PROBE_ID, &SourceMechanism::ALL);
    s
}

fn parent() -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: PARENT_PID,
            pid_start_time_ticks: 1_000_000,
            boot_id: [0x5e; 16],
        },
        exe_content_sha256: sha256(b"orchestrator binary"),
        exe_path: "/opt/agent/bin/orchestrator".into(),
    }
}

fn child(start_ticks: u64) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: CHILD_PID,
            pid_start_time_ticks: start_ticks,
            boot_id: [0x5e; 16],
        },
        exe_content_sha256: sha256(b"worker binary"),
        exe_path: "/opt/agent/bin/worker".into(),
    }
}

fn spawn(seq: u64, ts_ns: u64, bound: Option<ObservedProcess>) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessSpawn {
            parent_pid: PARENT_PID,
            child_pid: CHILD_PID,
            parent_comm: "orch".into(),
            child_comm: "orch".into(),
        },
        cpu: 0,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

fn exec(seq: u64, ts_ns: u64, bound: Option<ObservedProcess>) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessExec {
            pid: CHILD_PID,
            old_pid: CHILD_PID,
            filename: "/opt/agent/bin/worker".into(),
        },
        cpu: 1,
        kernel_timestamp_ns: ts_ns,
        probe_seq: seq,
        bound,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    }
}

fn anchor() -> BootClockAnchor {
    BootClockAnchor {
        realtime_ms: NOW - 10_000,
        boottime_ns: ANCHOR_BOOT_NS,
        monotonic_ns: ANCHOR_BOOT_NS,
        clk_tck: CLK_TCK,
    }
}

fn batch(events: Vec<KernelLifecycleEvent>, with_anchor: bool) -> AttestedBatch {
    let last = events.len() as u64;
    signer()
        .attest_at(
            ObservationBatch {
                version: OBSERVE_PROTOCOL_VERSION,
                probe_id: PROBE_ID.into(),
                batch_id: [7; 16],
                probe_run_id: RUN,
                probe_seq_first: 1,
                probe_seq_last: last.max(1),
                dropped_events: Some(0),
                active_mechanisms: SourceMechanism::canonical_set(vec![
                    SourceMechanism::PidFdAnchored,
                    SourceMechanism::SchedTracepoint,
                ]),
                claimed_from_ms: NOW,
                claimed_to_ms: NOW + 2_000,
                observations: vec![],
                kernel_events: events,
                clock_anchor: with_anchor.then(anchor),
            },
            NOW + 2_500,
        )
        .unwrap()
}

/// Fork at +1 s after the anchor; the child starts in that tick and execs
/// 3 ms later.
const FORK_NS: u64 = ANCHOR_BOOT_NS + 1_000_000_000;

fn edges(b: &AttestedBatch) -> Vec<LineageEdge> {
    derive_lineage_edges([b])
}

/// le01 — both ends bound, anchored, child start inside the fork tick: one
/// edge, and it carries exactly the two bound instances, the kernel
/// positions and the executed image.
#[test]
fn le01_bound_fork_and_bound_exec_with_verified_start_is_one_edge() {
    let c = child(FORK_NS / TICK_NS);
    let b = batch(
        vec![
            spawn(1, FORK_NS, Some(parent())),
            exec(2, FORK_NS + 3_000_000, Some(c.clone())),
        ],
        true,
    );
    let e = edges(&b);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].parent, parent());
    assert_eq!(e[0].child, c);
    assert_eq!(e[0].fork.kernel_timestamp_ns, FORK_NS);
    assert_eq!(e[0].exec.kernel_timestamp_ns, FORK_NS + 3_000_000);
    assert_eq!(e[0].image_sha256, sha256(b"worker binary"));
    assert_eq!(e[0].filename, "/opt/agent/bin/worker");
    assert_eq!(e[0].mechanism, SourceMechanism::SchedTracepoint);
    assert_eq!(e[0].batch_sequence, e[0].fork.batch_sequence);
}

/// le02 — a fork with no exec is an attempt, not lineage: there is no child
/// image and nothing to bind the child to.
#[test]
fn le02_fork_without_exec_is_not_an_edge() {
    let b = batch(vec![spawn(1, FORK_NS, Some(parent()))], true);
    assert!(edges(&b).is_empty());
}

/// le03 — either end unbound → no edge. A pid is a reference, never an
/// identity; an edge with an unbound end would be a pid-level claim.
#[test]
fn le03_an_unbound_end_is_never_lineage() {
    let c = child(FORK_NS / TICK_NS);
    let unbound_parent = batch(
        vec![
            spawn(1, FORK_NS, None),
            exec(2, FORK_NS + 3_000_000, Some(c)),
        ],
        true,
    );
    assert!(edges(&unbound_parent).is_empty());

    let unbound_child = batch(
        vec![
            spawn(1, FORK_NS, Some(parent())),
            exec(2, FORK_NS + 3_000_000, None),
        ],
        true,
    );
    assert!(edges(&unbound_child).is_empty());
}

/// le04 — without a clock anchor the child's start tick cannot be checked
/// against the fork; the pairing is unverified and no edge is derived.
#[test]
fn le04_unanchored_pairing_is_not_an_edge() {
    let c = child(FORK_NS / TICK_NS);
    let b = batch(
        vec![
            spawn(1, FORK_NS, Some(parent())),
            exec(2, FORK_NS + 3_000_000, Some(c)),
        ],
        false,
    );
    assert!(edges(&b).is_empty());
}

/// le05 — a child whose start tick lies outside `[fork − tick, exec]` is a
/// recycled pid, not this fork's child. No edge.
#[test]
fn le05_recycled_child_pid_is_not_an_edge() {
    let recycled = child(FORK_NS / TICK_NS + 500); // 5 s after the fork
    let b = batch(
        vec![
            spawn(1, FORK_NS, Some(parent())),
            exec(2, FORK_NS + 3_000_000, Some(recycled)),
        ],
        true,
    );
    assert!(edges(&b).is_empty());
}

/// le06 — the exec must not precede the fork in kernel time.
#[test]
fn le06_exec_before_fork_is_not_an_edge() {
    let c = child(FORK_NS / TICK_NS);
    let b = batch(
        vec![
            spawn(2, FORK_NS, Some(parent())),
            exec(1, FORK_NS - 1_000_000, Some(c)),
        ],
        true,
    );
    assert!(edges(&b).is_empty());
}

/// le07 — an edge is derived from kernel events alone. Any attribution or
/// decision claim on the events is irrelevant to whether the edge exists;
/// which *agent* either end is remains a separate question for the profile.
#[test]
fn le07_edges_carry_no_agent_identity() {
    let c = child(FORK_NS / TICK_NS);
    let mut s = spawn(1, FORK_NS, Some(parent()));
    s.attribution = AgentAttribution::Claimed {
        agent_id: "aip1someone".into(),
        claim_source: "orchestrator".into(),
    };
    s.claimed_decision_id = Some([9; 16]);
    let b = batch(vec![s, exec(2, FORK_NS + 3_000_000, Some(c))], true);
    let e = edges(&b);
    assert_eq!(e.len(), 1);
    let v = serde_json::to_value(&e[0]).unwrap();
    let text = v.to_string();
    assert!(!text.contains("aip1someone"));
    assert!(!text.contains("agent_id"));
    assert!(!text.contains("decision"));
}
