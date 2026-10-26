//! Structural attribution (ADR-019) over real collector-signed chains:
//! events are attributed to a decision by the kernel's cgroup id inside an
//! observed, supervisor-created placement — never by pid, never by binary.

use aip_observe::*;
use aip_reconcile::{
    attribute_event, derive_placement, EventAttribution as A, PlacementGap as G, PlacementPolicy,
};
use aip_types::placement::decision_cgroup_name;
use aip_types::ProcessInstance;

const PROBE: &str = "probe-placement";
const OBSERVER: &str = "collector.placement";
const V2: u32 = 0;
const SUPERVISOR_EXE: [u8; 32] = [0x5a; 32];
const DECISION: [u8; 16] = [0xd1; 16];
const PLACEMENT_ID: u64 = 9001;

fn policy() -> PlacementPolicy {
    PlacementPolicy {
        supervisor_exe_sha256: SUPERVISOR_EXE,
        hierarchy: V2,
    }
}

fn instance(pid: u32, exe: [u8; 32]) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: 1_000 + pid as u64,
            boot_id: [0xb0; 16],
        },
        exe_content_sha256: exe,
        exe_path: "/usr/libexec/aip-placement".into(),
        container: None,
    }
}

fn path_for(d: &[u8; 16]) -> String {
    format!("/aip-placement/{}", decision_cgroup_name(d))
}

fn ev(t: u64, mechanism: SourceMechanism, kind: KernelLifecycleKind) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: PROBE.into(),
        mechanism,
        kind,
        cpu: 0,
        kernel_timestamp_ns: t,
        probe_seq: 0,
        bound: None,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
        cgroup: CgroupSample::NotSampled,
    }
}

/// A placement created by `creator` (None: unanchored) at time `t`.
fn created(
    t: u64,
    d: &[u8; 16],
    id: u64,
    creator: Option<ObservedProcess>,
) -> KernelLifecycleEvent {
    let mut e = ev(
        t,
        SourceMechanism::CgroupTracepoint,
        KernelLifecycleKind::CgroupCreated {
            hierarchy: V2,
            level: 2,
            cgroup_id: id,
            path: path_for(d),
            creator_pid: creator.as_ref().map_or(1, |c| c.process.pid),
        },
    );
    e.bound = creator;
    e
}

fn supervisor() -> Option<ObservedProcess> {
    Some(instance(77, SUPERVISOR_EXE))
}

fn exec(t: u64, pid: u32, cgroup: Option<u64>) -> KernelLifecycleEvent {
    let mut e = ev(
        t,
        SourceMechanism::SchedTracepoint,
        KernelLifecycleKind::ProcessExec {
            pid,
            old_pid: pid,
            filename: "/bin/true".into(),
        },
    );
    e.cgroup = cgroup.map_or(CgroupSample::NotSampled, |cgroup_id| {
        CgroupSample::Sampled { cgroup_id }
    });
    e
}

fn attach(t: u64, dst: u64, pid: u32) -> KernelLifecycleEvent {
    ev(
        t,
        SourceMechanism::CgroupTracepoint,
        KernelLifecycleKind::CgroupAttach {
            hierarchy: V2,
            dst_level: 2,
            dst_cgroup_id: dst,
            dst_path: "/x".into(),
            pid,
            comm: "sh".into(),
            writer_pid: 4242,
        },
    )
}

/// A collector and a probe that declares both sources live with a counted
/// loss counter.
struct Chain {
    signer: CollectorSigner,
    probe: ProcfsProbe,
    batches: Vec<AttestedBatch>,
}

fn chain() -> Chain {
    let kp = aip_crypto::generate_ed25519_keypair();
    let mut probe = ProcfsProbe::new(PROBE);
    probe.declare_source(SourceMechanism::SchedTracepoint);
    probe.declare_source(SourceMechanism::CgroupTracepoint);
    probe.enable_loss_counter();
    Chain {
        signer: CollectorSigner::new(OBSERVER, 1, &kp.private_key, &kp.public_key).unwrap(),
        probe,
        batches: Vec::new(),
    }
}

impl Chain {
    /// Attest one batch carrying `events`.
    fn push(&mut self, events: Vec<KernelLifecycleEvent>) -> &mut Self {
        let n = self.batches.len() as u64;
        let mut b = self
            .probe
            .batch([n as u8 + 1; 16], 100 * n, 100 * n + 99, vec![]);
        b.probe_seq_first = 1_000 * (n + 1);
        for (i, mut e) in events.into_iter().enumerate() {
            e.probe_seq = b.probe_seq_first + i as u64;
            b.kernel_events.push(e);
        }
        b.probe_seq_last = b.probe_seq_first + b.kernel_events.len().saturating_sub(1) as u64;
        self.batches.push(self.signer.attest(b).unwrap());
        self
    }

    fn refs(&self) -> Vec<&AttestedBatch> {
        self.batches.iter().collect()
    }

    fn placement(&self) -> Result<aip_reconcile::Placement, G> {
        derive_placement(&DECISION, &self.refs(), &policy())
    }

    fn event(&self, batch: usize, index: usize) -> &KernelLifecycleEvent {
        &self.batches[batch].batch.kernel_events[index]
    }
}

// ═══ The M2 gate tests ═══

/// A child that exits within a millisecond is attributed: its exec carries
/// the cgroup id the kernel wrote at the event, whatever happened after.
#[test]
fn a_child_that_exits_at_once_is_still_attributed() {
    let mut c = chain();
    c.push(vec![
        created(1_000, &DECISION, PLACEMENT_ID, supervisor()),
        exec(1_000_000, 5001, Some(PLACEMENT_ID)),
    ]);
    let p = c.placement().unwrap();
    assert_eq!(p.cgroup_id, PLACEMENT_ID);
    assert_eq!(p.creator.exe_content_sha256, SUPERVISOR_EXE);
    assert_eq!(attribute_event(&p, c.event(0, 1)), A::Attributed);
}

/// PID reuse never transfers a decision: the same pid outside the placement
/// is not attributed, and a pid seen outside first is attributed once it
/// runs inside. Attribution never reads a pid.
#[test]
fn pid_reuse_never_transfers_identity() {
    let mut c = chain();
    c.push(vec![
        created(1_000, &DECISION, PLACEMENT_ID, supervisor()),
        exec(2_000, 5001, Some(PLACEMENT_ID)),
        exec(3_000, 5001, Some(1234)),
        exec(4_000, 6000, Some(1234)),
        exec(5_000, 6000, Some(PLACEMENT_ID)),
    ]);
    let p = c.placement().unwrap();
    assert_eq!(attribute_event(&p, c.event(0, 1)), A::Attributed);
    assert_eq!(
        attribute_event(&p, c.event(0, 2)),
        A::NotInPlacement,
        "same pid, other cgroup"
    );
    assert_eq!(attribute_event(&p, c.event(0, 3)), A::NotInPlacement);
    assert_eq!(
        attribute_event(&p, c.event(0, 4)),
        A::Attributed,
        "a pid's past is irrelevant"
    );
}

/// The same binary running elsewhere is a decoy, not the decision's work.
#[test]
fn a_decoy_with_the_same_binary_is_not_attributed() {
    let mut c = chain();
    c.push(vec![
        created(1_000, &DECISION, PLACEMENT_ID, supervisor()),
        exec(2_000, 5001, Some(PLACEMENT_ID)),
        exec(2_000, 5002, Some(4444)),
    ]);
    let p = c.placement().unwrap();
    assert_eq!(attribute_event(&p, c.event(0, 2)), A::NotInPlacement);
}

// ═══ Forged and ambiguous placements ═══

/// A process that is not the supervisor creates a cgroup named for a real
/// decision: not a placement.
#[test]
fn a_placement_created_by_anything_but_the_supervisor_is_not_one() {
    let mut c = chain();
    c.push(vec![created(
        1_000,
        &DECISION,
        PLACEMENT_ID,
        Some(instance(66, [0xee; 32])),
    )]);
    assert_eq!(c.placement().unwrap_err(), G::CreatorNotSupervisor);

    let mut d = chain();
    d.push(vec![created(1_000, &DECISION, PLACEMENT_ID, None)]);
    assert_eq!(d.placement().unwrap_err(), G::CreatorNotAnchored);
}

#[test]
fn two_creations_naming_one_decision_are_ambiguous() {
    let mut c = chain();
    c.push(vec![
        created(1_000, &DECISION, PLACEMENT_ID, supervisor()),
        created(2_000, &DECISION, PLACEMENT_ID + 1, supervisor()),
    ]);
    assert_eq!(c.placement().unwrap_err(), G::Ambiguous { creations: 2 });
}

#[test]
fn another_decisions_or_another_hierarchys_cgroup_is_not_this_placement() {
    let mut c = chain();
    let mut v1 = created(1_000, &DECISION, PLACEMENT_ID, supervisor());
    if let KernelLifecycleKind::CgroupCreated { hierarchy, .. } = &mut v1.kind {
        *hierarchy = 3;
    }
    c.push(vec![created(1_000, &[0xd2; 16], 1, supervisor()), v1]);
    assert_eq!(c.placement().unwrap_err(), G::NotObserved);
}

/// A name with the decision id as a *prefix* is not the decision's name.
#[test]
fn a_lookalike_name_is_not_the_decision() {
    let mut c = chain();
    let mut e = created(1_000, &DECISION, PLACEMENT_ID, supervisor());
    if let KernelLifecycleKind::CgroupCreated { path, .. } = &mut e.kind {
        path.push('0');
    }
    c.push(vec![e]);
    assert_eq!(c.placement().unwrap_err(), G::NotObserved);
}

// ═══ Descendants and migration ═══

#[test]
fn a_descendant_created_after_the_placement_is_attributed_and_a_sibling_is_not() {
    let mut c = chain();
    let base = path_for(&DECISION);
    let child = |t, id, path: String| {
        let mut e = created(t, &DECISION, id, supervisor());
        if let KernelLifecycleKind::CgroupCreated { path: p, .. } = &mut e.kind {
            *p = path;
        }
        e
    };
    c.push(vec![
        created(1_000, &DECISION, PLACEMENT_ID, supervisor()),
        child(2_000, 9100, format!("{base}/worker")),
        child(2_000, 9200, format!("{base}x/worker")),
        exec(3_000, 5001, Some(9100)),
        exec(3_000, 5002, Some(9200)),
    ]);
    let p = c.placement().unwrap();
    assert!(p.members.contains(&9100) && !p.members.contains(&9200));
    assert_eq!(attribute_event(&p, c.event(0, 3)), A::Attributed);
    assert_eq!(attribute_event(&p, c.event(0, 4)), A::NotInPlacement);
}

/// A task migrated into the placement could pass its children off as the
/// decision's: from the first migration in, nothing more is attributed.
#[test]
fn nothing_is_attributed_from_a_migration_into_the_placement_onwards() {
    let mut c = chain();
    c.push(vec![
        created(1_000, &DECISION, PLACEMENT_ID, supervisor()),
        exec(2_000, 5001, Some(PLACEMENT_ID)),
        attach(3_000, PLACEMENT_ID, 6666),
        exec(3_000, 5001, Some(PLACEMENT_ID)),
        exec(4_000, 6667, Some(PLACEMENT_ID)),
    ]);
    let p = c.placement().unwrap();
    assert_eq!(p.first_migration_in_ns, Some(3_000));
    assert_eq!(attribute_event(&p, c.event(0, 1)), A::Attributed);
    assert_eq!(attribute_event(&p, c.event(0, 3)), A::AfterMigrationIn);
    assert_eq!(attribute_event(&p, c.event(0, 4)), A::AfterMigrationIn);
}

/// A migration *out of* the placement does not close attribution — that is
/// the M3 divergence question, not this one.
#[test]
fn a_migration_elsewhere_does_not_close_attribution() {
    let mut c = chain();
    c.push(vec![
        created(1_000, &DECISION, PLACEMENT_ID, supervisor()),
        attach(2_000, 4444, 5001),
        exec(3_000, 5002, Some(PLACEMENT_ID)),
    ]);
    let p = c.placement().unwrap();
    assert_eq!(p.first_migration_in_ns, None);
    assert_eq!(attribute_event(&p, c.event(0, 2)), A::Attributed);
}

#[test]
fn an_unsampled_event_is_not_attributed() {
    let mut c = chain();
    c.push(vec![
        created(1_000, &DECISION, PLACEMENT_ID, supervisor()),
        exec(2_000, 5001, None),
    ]);
    let p = c.placement().unwrap();
    assert_eq!(attribute_event(&p, c.event(0, 1)), A::NotSampled);
}

#[test]
fn an_event_before_the_placement_existed_is_not_attributed() {
    let mut c = chain();
    c.push(vec![
        exec(500, 5001, Some(PLACEMENT_ID)),
        created(1_000, &DECISION, PLACEMENT_ID, supervisor()),
    ]);
    let p = c.placement().unwrap();
    assert_eq!(attribute_event(&p, c.event(0, 0)), A::BeforePlacement);
}

// ═══ Coverage and chain ═══

/// Across batches, the chain must be whole and the placement source live.
#[test]
fn placement_spans_a_contiguous_chain() {
    let mut c = chain();
    c.push(vec![created(1_000, &DECISION, PLACEMENT_ID, supervisor())]);
    c.push(vec![exec(2_000, 5001, Some(PLACEMENT_ID))]);
    let p = c.placement().unwrap();
    assert_eq!(attribute_event(&p, c.event(1, 0)), A::Attributed);
    // Order of the supplied batches does not matter.
    let mut rev = c.refs();
    rev.reverse();
    assert!(derive_placement(&DECISION, &rev, &policy()).is_ok());
}

/// A missing link means a migration could have gone unseen.
#[test]
fn a_gap_in_the_chain_is_not_covered() {
    let mut c = chain();
    c.push(vec![created(1_000, &DECISION, PLACEMENT_ID, supervisor())]);
    c.push(vec![]);
    c.push(vec![exec(3_000, 5001, Some(PLACEMENT_ID))]);
    let with_gap = vec![&c.batches[0], &c.batches[2]];
    assert_eq!(
        derive_placement(&DECISION, &with_gap, &policy()).unwrap_err(),
        G::ChainBroken {
            after_sequence: c.batches[0].sequence
        }
    );
    assert_eq!(
        derive_placement(&DECISION, &[], &policy()).unwrap_err(),
        G::NoEvidence
    );
}

#[test]
fn a_batch_without_the_placement_source_or_with_loss_is_not_covered() {
    let mut c = chain();
    c.push(vec![created(1_000, &DECISION, PLACEMENT_ID, supervisor())]);
    // Same chain, the next batch declares no placement source.
    let mut b = c.probe.batch([9; 16], 200, 299, vec![]);
    b.active_mechanisms
        .retain(|m| *m != SourceMechanism::CgroupTracepoint);
    c.batches.push(c.signer.attest(b).unwrap());
    let seq = c.batches[1].sequence;
    assert_eq!(
        c.placement().unwrap_err(),
        G::CoverageNotEstablished {
            batch_sequence: seq
        }
    );

    let mut d = chain();
    d.push(vec![created(1_000, &DECISION, PLACEMENT_ID, supervisor())]);
    let mut b = d.probe.batch([9; 16], 200, 299, vec![]);
    b.dropped_events = Some(3);
    d.batches.push(d.signer.attest(b).unwrap());
    let seq = d.batches[1].sequence;
    assert_eq!(
        d.placement().unwrap_err(),
        G::CoverageNotEstablished {
            batch_sequence: seq
        }
    );
}

#[test]
fn a_probe_restart_inside_the_chain_is_not_covered() {
    let mut c = chain();
    c.push(vec![created(1_000, &DECISION, PLACEMENT_ID, supervisor())]);
    let mut b = c.probe.batch([9; 16], 200, 299, vec![]);
    b.probe_run_id = [0x42; 16];
    c.batches.push(c.signer.attest(b).unwrap());
    let seq = c.batches[1].sequence;
    assert_eq!(
        c.placement().unwrap_err(),
        G::ProbeRestarted { at_sequence: seq }
    );
}

/// A batch from another chain with the right sequence number is not a link:
/// the chain is joined by head, not by counter.
#[test]
fn a_spliced_batch_with_the_right_sequence_is_not_a_link() {
    let mut c = chain();
    c.push(vec![created(1_000, &DECISION, PLACEMENT_ID, supervisor())]);
    let mut other = chain();
    other.push(vec![]);
    other.push(vec![exec(2_000, 5001, Some(PLACEMENT_ID))]);
    let spliced = vec![&c.batches[0], &other.batches[1]];
    assert_eq!(spliced[1].sequence, spliced[0].sequence + 1);
    assert_eq!(
        derive_placement(&DECISION, &spliced, &policy()).unwrap_err(),
        G::ChainBroken {
            after_sequence: c.batches[0].sequence
        }
    );
}
