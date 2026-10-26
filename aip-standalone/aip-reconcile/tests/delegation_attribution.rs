//! Phase 3 exit gate — delegation-chain attribution.
//!
//! The reconciler's verdict logic over lineage (consistent, contradicted,
//! incomplete, ambiguous) is exercised exhaustively in `lineage_violation.rs`
//! and the edge-derivation preconditions in `lineage_edges.rs`. This file
//! proves the two guarantees that define the phase, at the derivation layer
//! and against **real agent evidence**:
//!
//!   1. When the lineage is observable, exactly one correctly-attributed
//!      parent->child edge is derived — attributed to the kernel-bound
//!      forking instance, never a claimed one.
//!   2. When the fork is dropped, NO edge is fabricated. The engine offers
//!      the reconciler nothing to attribute, which is why the verdict is
//!      CANNOT_PROVE and never a guess at a parent.
//!
//! and, tying it to Phase 1's genuine LangGraph run:
//!
//!   3. The delegation chain derived from the real, collector-signed archive
//!      verifies under the anchor first, yields start-verified edges, and
//!      contains a genuine multi-level chain (a child that is itself a
//!      parent).

use aip_crypto::{generate_ed25519_keypair, sha256};
use aip_observe::*;
use aip_reconcile::*;
use aip_types::ProcessInstance;

const OBSERVER_ID: &str = "collector-da";
const PROBE_ID: &str = "probe-da";
const RUN: [u8; 16] = [0xda; 16];
const PARENT_PID: u32 = 5_200_001;
const CHILD_PID: u32 = 5_200_002;
const OTHER_PARENT_PID: u32 = 5_200_003;
const ANCHOR_BOOT_NS: u64 = 200_000_000_000;
const CLK_TCK: u32 = 100;
const TICK_NS: u64 = 1_000_000_000 / CLK_TCK as u64; // 10 ms per tick at 100 Hz
const NOW: u64 = 1_700_000_500_000;
const FORK_NS: u64 = ANCHOR_BOOT_NS + 1_000_000_000;

fn signer() -> CollectorSigner {
    let kp = generate_ed25519_keypair();
    let mut s = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    s.register_probe(PROBE_ID, &SourceMechanism::ALL);
    s
}

fn parent(pid: u32) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: 1_000_000,
            boot_id: [0x5e; 16],
        },
        exe_content_sha256: sha256(b"orchestrator binary"),
        exe_path: "/opt/agent/bin/orchestrator".into(),
        container: None,
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
        container: None,
    }
}

/// A ProcessSpawn whose kernel parent_pid is `parent_pid`, bound to `bound`.
fn spawn(
    seq: u64,
    ts_ns: u64,
    parent_pid: u32,
    bound: Option<ObservedProcess>,
) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        cgroup: aip_observe::CgroupSample::NotSampled,
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE_ID.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessSpawn {
            parent_pid,
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
        cgroup: aip_observe::CgroupSample::NotSampled,
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

fn batch(events: Vec<KernelLifecycleEvent>) -> AttestedBatch {
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
                mechanism_integrity: Vec::new(),
                claimed_from_ms: NOW,
                claimed_to_ms: NOW + 2_000,
                observations: vec![],
                kernel_events: events,
                clock_anchor: Some(anchor()),
            },
            NOW + 2_500,
        )
        .unwrap()
}

/// The child starts inside the fork tick (so the start-tick check passes) and
/// execs a few ms later.
fn child_start_ticks() -> u64 {
    // The anchor maps ticks to ns as `ticks * (1e9 / CLK_TCK)`. For the child's
    // anchored start to lie within `[fork - tick, exec]`, the start tick must
    // map back to the fork instant: `FORK_NS / TICK_NS`.
    FORK_NS / TICK_NS
}

// ── 1. Observable lineage: one correctly-attributed edge ──────────────────

#[test]
fn da01_observable_lineage_is_one_correctly_attributed_edge() {
    let c = child(child_start_ticks());
    let b = batch(vec![
        spawn(1, FORK_NS, PARENT_PID, Some(parent(PARENT_PID))),
        exec(2, FORK_NS + 3_000_000, Some(c.clone())),
    ]);
    let edges = derive_lineage_edges([&b]);
    assert_eq!(
        edges.len(),
        1,
        "one observable fork+exec is one edge: {edges:?}"
    );
    let e = &edges[0];
    assert_eq!(
        e.parent.process.pid, PARENT_PID,
        "parent is the forking instance"
    );
    assert_eq!(
        e.child.process.pid, CHILD_PID,
        "child is the execed instance"
    );
    assert_eq!(
        e.image_sha256,
        sha256(b"worker binary"),
        "the edge carries the executed image content hash"
    );
}

// ── 2. Dropped fork: no fabricated edge (the CANNOT_PROVE guarantee) ───────

#[test]
fn da02_a_dropped_fork_fabricates_no_edge() {
    // The exec is present and bound; the fork (ProcessSpawn) was dropped —
    // exactly the blinding case. The engine must not invent a parent.
    let c = child(child_start_ticks());
    let b = batch(vec![exec(1, FORK_NS + 3_000_000, Some(c))]);
    let edges = derive_lineage_edges([&b]);
    assert!(
        edges.is_empty(),
        "a dropped fork must yield NO edge, never a fabricated parent: {edges:?}"
    );
}

// ── 3. Attribution follows the kernel-bound forking instance ──────────────

#[test]
fn da03_the_edge_names_the_bound_forking_instance_not_a_decoy() {
    // Two spawns of the same child pid exist in the batch, bound to two
    // different parent instances. Only the fork that actually precedes and
    // pairs with the exec (by kernel time and the start-tick check) yields an
    // edge, and its parent is that bound instance — there is no path by which
    // the *other* process present in the batch is credited with the fork.
    let c = child(child_start_ticks());
    let real_fork = spawn(1, FORK_NS, PARENT_PID, Some(parent(PARENT_PID)));
    // A later, unbound spawn naming a different parent: not lineage (unbound),
    // and even bound it is later than the exec so it cannot pair.
    let decoy = spawn(
        3,
        FORK_NS + 9_000_000,
        OTHER_PARENT_PID,
        Some(parent(OTHER_PARENT_PID)),
    );
    let b = batch(vec![
        real_fork,
        exec(2, FORK_NS + 3_000_000, Some(c)),
        decoy,
    ]);
    let edges = derive_lineage_edges([&b]);
    assert_eq!(
        edges.len(),
        1,
        "only the pairing fork yields an edge: {edges:?}"
    );
    assert_eq!(
        edges[0].parent.process.pid, PARENT_PID,
        "attribution is to the forking instance that pairs with the exec, \
         not another process present in the same batch"
    );
    assert_ne!(edges[0].parent.process.pid, OTHER_PARENT_PID);
}

// ── 4. The real-agent join: Phase 1's genuine sealed archive ──────────────

#[test]
fn da04_the_real_langgraph_archive_yields_a_verified_multi_level_chain() {
    use aip_observe_verify::verify::{parse_jsonl, verify_archives, Parsed};

    let root = env!("CARGO_MANIFEST_DIR");
    let base = format!("{root}/../../integrations/agents/results/sealed");
    let archive = std::fs::read_to_string(format!("{base}/attested.archive.jsonl"))
        .expect("the committed Phase-1 attested archive must be present");
    let pubkey_hex = std::fs::read_to_string(format!("{base}/observer.pub"))
        .expect("the committed observer public key must be present");
    let pubkey = hex_decode_32(pubkey_hex.trim());

    let parsed: Vec<Parsed<AttestedBatch>> = parse_jsonl(&archive);
    let verified: Vec<AttestedBatch> = parsed
        .iter()
        .filter_map(|p| match p {
            Parsed::Ok(l) => Some(l.record.clone()),
            Parsed::Failed { .. } => None,
        })
        .collect();

    // Fail closed: derive nothing unless the archive verifies under the anchor.
    let report = verify_archives("collector.phase1", 1, &pubkey, Some(parsed), None);
    assert!(
        report.ok(),
        "the committed archive must verify under its published key: {:?}",
        report.findings
    );

    let edges = derive_lineage_edges(&verified);
    assert!(
        !edges.is_empty(),
        "the real agent run produced observable delegation edges"
    );
    // Every derived edge is start-verified lineage from the scheduler
    // tracepoint (derive_lineage_edges keeps only start-verified execs).
    assert!(
        edges
            .iter()
            .all(|e| e.mechanism == SourceMechanism::SchedTracepoint),
        "every edge is scheduler-tracepoint lineage"
    );
    // A genuine multi-level chain: some child instance is itself the parent of
    // another edge (parent graph -> child -> grandchild, observed from the
    // kernel, not asserted by any agent).
    let has_multi_level = edges.iter().any(|c| {
        edges
            .iter()
            .any(|p| p.child.process == c.parent.process && p.child.process != c.child.process)
    });
    assert!(
        has_multi_level,
        "the real archive contains a multi-level delegation chain (a child that \
         is itself a parent)"
    );
}

fn hex_decode_32(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex key must be even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
