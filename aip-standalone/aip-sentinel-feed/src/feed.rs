//! Mapping attested kernel evidence onto out-of-band effect observations.
//!
//! # What this module is, and what it refuses to be
//!
//! It is a **pure mapping**. Every fact it emits was already derived by
//! `aip-reconcile` from signed evidence: bound spawns, established
//! connections, accepted sends. Nothing here re-derives lineage, re-parses a
//! kernel event or re-checks a signature, because a second implementation of
//! any of those is a second place for them to disagree.
//!
//! It is not a verifier. [`feed`] takes batches a caller has already verified
//! under the observer's anchor, and the binary that drives it will not call it
//! otherwise. The gate is at the edge, where the bytes come in.
//!
//! # Fail closed, and count what was dropped
//!
//! Every event that cannot be rendered **honestly** is dropped and counted in
//! [`ScopeReport`], never approximated. The four that matter:
//!
//! * **A fork with no bound execution.** The kernel showed a process being
//!   created; the derived evidence carries no image for it. Two causes reach
//!   this state and the feed cannot tell them apart — the child never executed
//!   an image, or its exec was observed but could not be bound — so the
//!   counter is named for what is known rather than for the likelier guess.
//!   Either way there is no command to name, so there is no record: the same
//!   `CANNOT_PROVE` discipline that stops the lineage engine inventing a
//!   parent.
//! * **An exec whose child start could not be verified against the clock
//!   anchor.** The pairing of fork to exec is then unanchored, and an
//!   unanchored pairing can name the wrong image after a pid reuse.
//! * **A `connect()` with no completion.** AIP records it as an attempt. The
//!   consumer would judge it against an egress allow-list at *critical*
//!   severity, so emitting a refused connection as egress would manufacture a
//!   critical finding out of a connection that moved nothing. This is the same
//!   defect class as counting failed `execve` attempts as observation gaps:
//!   the harness would be wrong, not the system under test.
//! * **A batch with no clock anchor.** Without one there is no conversion from
//!   kernel monotonic time to wall time, and the consumer's schema is wall
//!   time. A guessed timestamp is worse than a missing record, because it
//!   reconciles against the wrong window silently.
//!
//! A dropped record is a **coverage limit that is reported**, which is what
//! lets the consumer's completeness claim stay sound: silence may be read as
//! absence only within what a sensor says it sees.
//!
//! # Unbound events are counted by a direct scan, and that is not re-derivation
//!
//! An event the probe could not bind to a process instance never reaches the
//! derivation layer at all — `aip-reconcile` discards it, correctly, because
//! an unbound event is not evidence of an instance. The consequence is that a
//! report built only from derived values is silently incomplete: on Phase 1's
//! real archive, eight `connect()` initiations were unbound and appeared
//! nowhere in this report's first version, which claimed zero unaccounted
//! attempts while nine had been observed.
//!
//! [`coverage`] therefore scans the raw events once, to **count** them. That
//! is a measurement of what the observer saw, not a second derivation of what
//! it means: nothing from the scan is attributed, rendered, or paired with
//! anything. The distinction matters, because a second derivation is a second
//! place for the two to disagree, and a count cannot disagree with anything.
//!
//! # Byte counts are attributed within a socket's lifetime, not by key alone
//!
//! `sk` is a kernel socket address and the kernel reuses it. Summing every
//! send that shares an `sk` onto one connection would credit a later
//! connection's traffic to an earlier one. Each send is therefore attributed
//! to the **most recent connection on that `sk` that had already started** when
//! the send was observed. A send preceding every connection on its `sk` is
//! attributed to none.

use std::collections::BTreeMap;

use aip_corroborate::clock::monotonic_ns_to_wall_ms;
use aip_observe::{AttestedBatch, BootClockAnchor};
use aip_reconcile::{derive_executions, derive_sends, derive_transitions, EventPosition};
use aip_siem::rfc3339_ms;

use crate::endpoint;
use crate::record::{EffectDetail, EffectKind, EffectRecord};

/// What the feed saw and what it declined to render, so a reader can tell the
/// difference between "nothing happened" and "nothing could be said".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeReport {
    /// Spawn records emitted.
    pub spawns_emitted: usize,
    /// Egress records emitted.
    pub egress_emitted: usize,
    /// Of those, how many carry a measured byte count.
    pub egress_with_measured_bytes: usize,
    /// Forks for which the derived evidence carries no executed image —
    /// either the child never executed one, or its exec could not be bound.
    pub fork_without_bound_execution: usize,
    /// Execs whose child start could not be checked against the clock anchor.
    pub exec_start_unverified: usize,
    /// `connect()` calls the kernel never reported completing.
    pub connect_attempt_not_established: usize,
    /// `sched_process_fork` events the probe could not bind to an instance.
    /// Counted from the raw events, because derivation discards them.
    pub spawn_unbound: usize,
    /// `sched_process_exec` events the probe could not bind to an instance.
    pub exec_unbound: usize,
    /// `connect()` initiations the probe could not bind to an instance.
    pub connect_initiation_unbound: usize,
    /// Events in a batch that carried no clock anchor.
    pub dropped_no_clock_anchor: usize,
    /// Events whose converted wall time fell before the Unix epoch, which
    /// means the anchor and the event disagree about which boot they belong
    /// to. Refused rather than clamped.
    pub dropped_timestamp_before_epoch: usize,
}

impl ScopeReport {
    /// Total records emitted.
    pub fn emitted(&self) -> usize {
        self.spawns_emitted + self.egress_emitted
    }

    /// Total events seen but not rendered, derivation and scan together.
    ///
    /// The two sets do not overlap: an unbound event never reaches derivation,
    /// so it can be counted by the scan without also being counted as a
    /// derived-but-refused one.
    pub fn dropped(&self) -> usize {
        self.fork_without_bound_execution
            + self.exec_start_unverified
            + self.connect_attempt_not_established
            + self.dropped_no_clock_anchor
            + self.dropped_timestamp_before_epoch
            + self.spawn_unbound
            + self.exec_unbound
            + self.connect_initiation_unbound
    }
}

/// The effect log derived from a set of verified batches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Feed {
    /// Records in evidence order.
    pub records: Vec<EffectRecord>,
    /// What was seen, and what was refused.
    pub scope: ScopeReport,
}

impl Feed {
    /// The whole feed as JSONL, one record per line, newline-terminated.
    pub fn to_jsonl(&self, observer_id: &str) -> String {
        let mut out = String::new();
        for r in &self.records {
            out.push_str(&r.to_line(observer_id));
            out.push('\n');
        }
        out
    }
}

/// Position ordering: evidence order, independent of timestamps.
fn before_or_equal(a: &EventPosition, b: &EventPosition) -> bool {
    (a.batch_sequence, a.index) <= (b.batch_sequence, b.index)
}

/// Clock anchors by batch sequence, for converting kernel time to wall time.
fn anchors(batches: &[AttestedBatch]) -> BTreeMap<u64, BootClockAnchor> {
    batches
        .iter()
        .filter_map(|b| b.batch.clock_anchor.map(|a| (b.sequence, a)))
        .collect()
}

/// Wall-clock RFC 3339 for an event, or the reason it has none.
fn timestamp(
    anchors: &BTreeMap<u64, BootClockAnchor>,
    position: &EventPosition,
    kernel_timestamp_ns: u64,
    scope: &mut ScopeReport,
) -> Option<String> {
    let Some(anchor) = anchors.get(&position.batch_sequence) else {
        scope.dropped_no_clock_anchor += 1;
        return None;
    };
    let ms = monotonic_ns_to_wall_ms(anchor, kernel_timestamp_ns);
    // Signed throughout: an event inside a batch routinely precedes the
    // anchor, so the difference is negative and must stay so until here.
    if ms < 0 {
        scope.dropped_timestamp_before_epoch += 1;
        return None;
    }
    Some(rfc3339_ms(ms as u64))
}

/// Derive the effect log from **already-verified** batches.
///
/// The caller is responsible for having verified them; see this module's note
/// and [`crate`] for where that gate lives. Ordering of the result is a total
/// order over evidence position and kind, so the same input is always the same
/// bytes.
pub fn feed(batches: &[AttestedBatch]) -> Feed {
    let mut scope = coverage(batches);
    let mut records = Vec::new();
    let anchors = anchors(batches);

    // ── spawns ────────────────────────────────────────────────────────────
    for execution in derive_executions(batches.iter()) {
        let Some(image) = &execution.execution else {
            scope.fork_without_bound_execution += 1;
            continue;
        };
        if !image.child_start_verified {
            scope.exec_start_unverified += 1;
            continue;
        }
        let Some(observed_at_utc) = timestamp(
            &anchors,
            &image.at,
            image.at.kernel_timestamp_ns,
            &mut scope,
        ) else {
            continue;
        };
        records.push(EffectRecord::new(
            EffectKind::Spawn,
            image.at,
            observed_at_utc,
            execution.attribution.claimed_agent_id().map(str::to_string),
            EffectDetail::Spawn {
                path: image.filename.clone(),
                exe_sha256: hex::encode(image.child.exe_content_sha256),
            },
        ));
        scope.spawns_emitted += 1;
    }

    // ── egress ────────────────────────────────────────────────────────────
    let transitions = derive_transitions(batches.iter());
    let bytes_by_initiation = attribute_sends(&transitions, batches);

    for transition in &transitions {
        let Some(completion) = &transition.completion else {
            scope.connect_attempt_not_established += 1;
            continue;
        };
        // Timestamped at establishment (that is what the record asserts
        // happened), identified by the initiation (where the probe anchored
        // the process instance, and unique per connection).
        let Some(observed_at_utc) = timestamp(
            &anchors,
            &transition.initiation,
            completion.kernel_timestamp_ns,
            &mut scope,
        ) else {
            continue;
        };
        let bytes = bytes_by_initiation
            .get(&key(&transition.initiation))
            .copied();
        if bytes.is_some() {
            scope.egress_with_measured_bytes += 1;
        }
        records.push(EffectRecord::new(
            EffectKind::Egress,
            transition.initiation,
            observed_at_utc,
            transition
                .attribution
                .claimed_agent_id()
                .map(str::to_string),
            EffectDetail::Egress {
                destination: endpoint::render(&transition.remote),
                bytes,
            },
        ));
        scope.egress_emitted += 1;
    }

    records.sort_by_key(EffectRecord::sort_key);
    Feed { records, scope }
}

/// A position as a comparable, hashable key.
fn key(position: &EventPosition) -> (u64, u32) {
    (position.batch_sequence, position.index)
}

/// Sum each connection's observed sends, scoped to that connection's lifetime
/// on its socket rather than to the socket key alone.
///
/// Returns bytes by initiating position; a connection with no observed send is
/// absent, which the record renders as *not measured* rather than as zero.
fn attribute_sends(
    transitions: &[aip_reconcile::SocketTransition],
    batches: &[AttestedBatch],
) -> BTreeMap<(u64, u32), u64> {
    // Connections per socket key, in evidence order.
    let mut by_sk: BTreeMap<u64, Vec<&aip_reconcile::SocketTransition>> = BTreeMap::new();
    for t in transitions {
        by_sk.entry(t.sk).or_default().push(t);
    }
    for list in by_sk.values_mut() {
        list.sort_by_key(|t| key(&t.initiation));
    }

    let mut totals: BTreeMap<(u64, u32), u64> = BTreeMap::new();
    for send in derive_sends(batches.iter()) {
        let Some(candidates) = by_sk.get(&send.sk) else {
            continue;
        };
        // The most recent connection on this socket that had already started.
        // `sk` is reused by the kernel, so an earlier connection must not be
        // credited with a later one's traffic.
        let owner = candidates
            .iter()
            .rev()
            .find(|t| before_or_equal(&t.initiation, &send.at));
        if let Some(owner) = owner {
            *totals.entry(key(&owner.initiation)).or_insert(0) += u64::from(send.bytes);
        }
    }
    totals
}

/// Count the events derivation never sees, by one pass over the raw evidence.
///
/// Pure counting. Nothing here is attributed to a process, paired with another
/// event, or rendered — see this module's note on why that distinction is what
/// keeps the scan from becoming a second derivation.
fn coverage(batches: &[AttestedBatch]) -> ScopeReport {
    let mut scope = ScopeReport::default();
    for batch in batches {
        for event in &batch.batch.kernel_events {
            if event.bound.is_some() {
                continue;
            }
            match (&event.mechanism, &event.kind) {
                (
                    aip_observe::SourceMechanism::SchedTracepoint,
                    aip_observe::KernelLifecycleKind::ProcessSpawn { .. },
                ) => scope.spawn_unbound += 1,
                (
                    aip_observe::SourceMechanism::SchedTracepoint,
                    aip_observe::KernelLifecycleKind::ProcessExec { .. },
                ) => scope.exec_unbound += 1,
                (aip_observe::SourceMechanism::SockStateTracepoint, kind)
                    if kind.is_connect_initiation() =>
                {
                    scope.connect_initiation_unbound += 1
                }
                _ => {}
            }
        }
    }
    scope
}
