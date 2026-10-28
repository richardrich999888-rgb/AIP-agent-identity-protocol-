//! Structural attribution (ADR-019): which kernel events belong to a
//! decision, by the cgroup the decision was placed in — never by pid.
//!
//! Pure and offline, like the other `derive_*` functions: it reads attested
//! batches the caller has already verified, and decides nothing about
//! whether what ran was permitted. It answers one narrower question first —
//! *was this decision placed, observably, by the supervisor?* — and only
//! then, per event, *did this event happen inside that placement?*
//!
//! # When a placement is established
//!
//! All of these, or a named [`PlacementGap`]:
//!
//! 1. the batches are **one contiguous attested chain** from **one probe
//!    run** — a restart (and so any reboot) or a missing link means a
//!    migration could have gone unseen;
//! 2. every batch declares `CgroupTracepoint` live and counts **zero loss**;
//! 3. **exactly one** cgroup creation in the verifier's hierarchy is named
//!    for the decision — none is not placed, two is ambiguous;
//! 4. its creator was **anchored as a process instance** running the
//!    supervisor binary the **verifier** names. A process that creates a
//!    cgroup named for someone else's decision is not the supervisor.
//!
//! # Which events it attributes
//!
//! An event is attributed iff the kernel sampled its cgroup id, that id is
//! the placement or a descendant whose creation was observed after the
//! placement's, and no migration into that set has occurred by the event's
//! kernel time. After the first migration *into* the set nothing more is
//! attributed: a cgroup id cannot tell a migrated task's children from the
//! placement's own, and borrowing a decision's authority is the
//! false-attribution direction (ADR-019 §6).
//!
//! What is **not** done here: migration *out* of the set, which needs the
//! moved task's identity, and the verdict either direction produces — both
//! M3.

use crate::action::EventPosition;
use aip_observe::{
    AttestedBatch, CgroupSample, KernelLifecycleEvent, KernelLifecycleKind, ObservedProcess,
    SourceMechanism,
};
use aip_types::placement::parse_decision_cgroup_name;
use std::collections::BTreeSet;

/// The verifier's terms for accepting a placement. Never read from evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementPolicy {
    /// SHA-256 of the supervisor binary the verifier trusts to place work.
    pub supervisor_exe_sha256: [u8; 32],
    /// The cgroup v2 hierarchy id placements live in, as the kernel reports
    /// it in the tracepoint's `root` field.
    pub hierarchy: u32,
}

/// Why a placement could not be established. Every case is `CANNOT_PROVE`
/// for attribution; none is an accusation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlacementGap {
    /// No batches were supplied.
    NoEvidence,
    /// Batches do not form one contiguous chain: a link is missing after
    /// `after_sequence`.
    ChainBroken { after_sequence: u64 },
    /// The probe restarted inside the chain; a reboot looks the same.
    ProbeRestarted { at_sequence: u64 },
    /// This batch did not declare cgroup placement events live, or counted
    /// (or could not count) loss.
    CoverageNotEstablished { batch_sequence: u64 },
    /// No creation in the policy's hierarchy names this decision.
    NotObserved,
    /// More than one creation names this decision.
    Ambiguous { creations: usize },
    /// The creation's acting task was not anchored as an instance.
    CreatorNotAnchored,
    /// The creator's measured binary is not the supervisor's.
    CreatorNotSupervisor,
}

/// A decision placement established from attested kernel events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    pub decision_id: [u8; 16],
    pub cgroup_id: u64,
    pub path: String,
    /// The supervisor instance that created it.
    pub creator: ObservedProcess,
    pub created_at: EventPosition,
    /// The placement and every descendant whose creation was observed
    /// after it.
    pub members: BTreeSet<u64>,
    /// The kernel time of the first migration into `members`, if any:
    /// nothing at or after it is attributed.
    pub first_migration_in_ns: Option<u64>,
}

/// Whether one kernel event belongs to the placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAttribution {
    /// Inside the placement, before any migration into it.
    Attributed,
    /// The kernel placed this event's task in some other cgroup.
    NotInPlacement,
    /// The source did not sample a cgroup id: attribution not established.
    NotSampled,
    /// At or after a migration into the placement: attribution not
    /// established.
    AfterMigrationIn,
    /// Earlier in kernel time than the placement's creation: no event can
    /// be inside a cgroup that did not exist yet, so the record is not
    /// trusted to say it was.
    BeforePlacement,
}

/// Establish the placement of `decision_id` from `batches` (verified by the
/// caller, any order) under `policy`.
pub fn derive_placement(
    decision_id: &[u8; 16],
    batches: &[&AttestedBatch],
    policy: &PlacementPolicy,
) -> Result<Placement, PlacementGap> {
    let chain = contiguous_chain(batches)?;
    let mut creation: Option<(EventPosition, String, u64, ObservedProcess)> = None;
    let mut creations = 0usize;
    let mut creator_problem: Option<PlacementGap> = None;
    for b in &chain {
        for (i, e) in placement_events(b) {
            let KernelLifecycleKind::CgroupCreated {
                hierarchy,
                cgroup_id,
                path,
                ..
            } = &e.kind
            else {
                continue;
            };
            if *hierarchy != policy.hierarchy || !names_decision(path, decision_id) {
                continue;
            }
            creations += 1;
            match &e.bound {
                None => creator_problem = Some(PlacementGap::CreatorNotAnchored),
                Some(p) if p.exe_content_sha256 != policy.supervisor_exe_sha256 => {
                    creator_problem = Some(PlacementGap::CreatorNotSupervisor)
                }
                Some(p) => {
                    creation = Some((position(b, i, e), path.clone(), *cgroup_id, p.clone()));
                }
            }
        }
    }
    match creations {
        0 => return Err(PlacementGap::NotObserved),
        1 => {}
        n => return Err(PlacementGap::Ambiguous { creations: n }),
    }
    if let Some(gap) = creator_problem {
        return Err(gap);
    }
    let (created_at, path, cgroup_id, creator) =
        creation.expect("exactly one creation, and its creator passed");

    let mut members = BTreeSet::from([cgroup_id]);
    let mut first_migration_in_ns: Option<u64> = None;
    let descendant_prefix = format!("{path}/");
    for b in &chain {
        for (i, e) in placement_events(b) {
            let at = position(b, i, e);
            if (at.batch_sequence, at.index) <= (created_at.batch_sequence, created_at.index) {
                continue;
            }
            match &e.kind {
                KernelLifecycleKind::CgroupCreated {
                    hierarchy,
                    cgroup_id,
                    path,
                    ..
                } if *hierarchy == policy.hierarchy && path.starts_with(&descendant_prefix) => {
                    members.insert(*cgroup_id);
                }
                KernelLifecycleKind::CgroupAttach {
                    hierarchy,
                    dst_cgroup_id,
                    ..
                } if *hierarchy == policy.hierarchy && members.contains(dst_cgroup_id) => {
                    first_migration_in_ns.get_or_insert(e.kernel_timestamp_ns);
                }
                _ => {}
            }
        }
    }
    Ok(Placement {
        decision_id: *decision_id,
        cgroup_id,
        path,
        creator,
        created_at,
        members,
        first_migration_in_ns,
    })
}

/// Whether `e` belongs to `placement`. By the kernel's cgroup id only — a
/// pid never enters the decision.
pub fn attribute_event(placement: &Placement, e: &KernelLifecycleEvent) -> EventAttribution {
    let CgroupSample::Sampled { cgroup_id } = e.cgroup else {
        return EventAttribution::NotSampled;
    };
    if !placement.members.contains(&cgroup_id) {
        return EventAttribution::NotInPlacement;
    }
    if e.kernel_timestamp_ns < placement.created_at.kernel_timestamp_ns {
        return EventAttribution::BeforePlacement;
    }
    if placement
        .first_migration_in_ns
        .is_some_and(|t| e.kernel_timestamp_ns >= t)
    {
        return EventAttribution::AfterMigrationIn;
    }
    EventAttribution::Attributed
}

/// The last path component names exactly this decision.
fn names_decision(path: &str, decision_id: &[u8; 16]) -> bool {
    path.rsplit('/')
        .next()
        .and_then(parse_decision_cgroup_name)
        .is_some_and(|d| &d == decision_id)
}

fn placement_events(b: &AttestedBatch) -> impl Iterator<Item = (usize, &KernelLifecycleEvent)> {
    b.batch
        .kernel_events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.mechanism == SourceMechanism::CgroupTracepoint)
}

fn position(b: &AttestedBatch, i: usize, e: &KernelLifecycleEvent) -> EventPosition {
    EventPosition {
        batch_sequence: b.sequence,
        index: i as u32,
        kernel_timestamp_ns: e.kernel_timestamp_ns,
    }
}

/// Sort by sequence and require one unbroken chain from one probe run, with
/// placement coverage and counted zero loss in every batch.
fn contiguous_chain<'a>(
    batches: &[&'a AttestedBatch],
) -> Result<Vec<&'a AttestedBatch>, PlacementGap> {
    let mut chain: Vec<&AttestedBatch> = batches.to_vec();
    chain.sort_by_key(|b| b.sequence);
    let first = chain.first().ok_or(PlacementGap::NoEvidence)?;
    let run = first.batch.probe_run_id;
    for w in chain.windows(2) {
        let (prev, next) = (w[0], w[1]);
        if next.sequence != prev.sequence + 1 || next.prev_head != prev.head() {
            return Err(PlacementGap::ChainBroken {
                after_sequence: prev.sequence,
            });
        }
    }
    for b in &chain {
        if b.batch.probe_run_id != run {
            return Err(PlacementGap::ProbeRestarted {
                at_sequence: b.sequence,
            });
        }
        let live = b
            .batch
            .active_mechanisms
            .contains(&SourceMechanism::CgroupTracepoint);
        if !live || b.batch.dropped_events != Some(0) {
            return Err(PlacementGap::CoverageNotEstablished {
                batch_sequence: b.sequence,
            });
        }
    }
    Ok(chain)
}
