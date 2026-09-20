//! Corroborate AIP's attested observations against an **independently built**
//! runtime observer, and state where the two agree, where they do not, and
//! what each of them missed.
//!
//! # The objection this answers
//!
//! Every sensor that has so far agreed with this system is a sensor we wrote.
//! The cross-sensor divergence check in `aip-observe::divergence` is real, but
//! it compares two of *our* sensors. An assessor is entitled to ask whether a
//! runtime observer built by someone else, watching the same kernel over the
//! same window, records what we say it records. This crate answers that, and
//! is the evidence behind subsection 10a of the RBI technical brief.
//!
//! # The rule that governs the output
//!
//! **A disagreement is reported, never suppressed.** In particular
//! [`Corroboration::external_only`] — executions the third-party observer
//! recorded and AIP did not — is the finding that costs us something, and it
//! is computed and printed with the same prominence as agreement. A tool that
//! only counted the flattering direction would be worthless as assurance.
//!
//! # Independence has two different strengths, and they are not equal
//!
//! * **bpftrace** is an independent *implementation* attached to the same
//!   `sched:sched_process_exec` tracepoint AIP's perf sensor uses. It
//!   corroborates that AIP faithfully reported what that tracepoint emitted.
//!   It does **not** corroborate the tracepoint itself: a foreign eBPF gate on
//!   that tracepoint blinds both observers identically.
//! * **auditd** reaches the kernel through the audit subsystem, a wholly
//!   different mechanism. A tracepoint gate does not blind it. It is therefore
//!   the stronger of the two for the blinding question, and the weaker for
//!   timing precision, since its stamps are millisecond wall-clock.
//!
//! [`IndependenceClass`] carries that distinction into the report so a reader
//! cannot mistake the first kind of agreement for the second.
//!
//! # Fail closed
//!
//! Comparison needs a [`aip_observe::BootClockAnchor`] to put both observers in
//! one time domain. A batch without an anchor is **refused**, not guessed at:
//! see [`CorroborateError::NoClockAnchor`].

use aip_observe::{AttestedBatch, KernelLifecycleKind};

pub mod clock;
pub mod parse;

pub use parse::{parse_auditd, parse_bpftrace, Parsed};

/// Default tolerance when pairing two observers' records of one execution.
///
/// Generous on purpose. AIP's `kernel_timestamp_ns` is the probe's own
/// dequeue stamp rather than the instant the kernel emitted the event, and
/// auditd's stamps are millisecond wall-clock written by a userspace daemon.
/// A tight window would turn ordinary scheduling and buffering skew into
/// fabricated disagreement, which is the failure mode this tool must not have.
/// It is reported in the output so a reader can judge it.
pub const DEFAULT_MATCH_WINDOW_MS: i64 = 250;

/// Which third-party observer produced an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ExternalSource {
    Bpftrace,
    Auditd,
    /// Reserved for a Falco JSON adapter. Falco's distribution repository is
    /// not reachable from the environment this was built in; the comparison
    /// core is source-agnostic so the adapter is the only missing piece.
    Falco,
}

impl ExternalSource {
    /// How independent this observer actually is of AIP's own sensing path.
    pub fn independence(&self) -> IndependenceClass {
        match self {
            // Same tracepoint, different implementation.
            ExternalSource::Bpftrace => IndependenceClass::SameMechanism,
            // Different kernel subsystem entirely.
            ExternalSource::Auditd => IndependenceClass::DifferentMechanism,
            // Falco's modern probe reads the same tracepoints/syscall path.
            ExternalSource::Falco => IndependenceClass::SameMechanism,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ExternalSource::Bpftrace => "bpftrace",
            ExternalSource::Auditd => "auditd",
            ExternalSource::Falco => "falco",
        }
    }
}

/// The strength of an agreement, which is not the same for every observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum IndependenceClass {
    /// Independently built, but reading the same kernel mechanism AIP reads.
    /// Corroborates reporting fidelity; does not survive a gate on that
    /// mechanism, which would blind both observers identically.
    SameMechanism,
    /// Reaches the kernel by a different subsystem. Survives a gate on AIP's
    /// mechanism and is therefore the stronger corroboration.
    DifferentMechanism,
}

/// Whether the execution the observer recorded actually took place.
///
/// This distinction is load-bearing and was found empirically. `auditd` audits
/// the **execve syscall**, and records every *attempt*, including the failures
/// a `$PATH` search produces: `/usr/bin/env true` generates a dozen `ENOENT`
/// records before the one that succeeds. AIP's `sched:sched_process_exec`
/// tracepoint fires only when an exec **succeeds**, which is correct — a
/// failed execve is not an execution and nothing ran.
///
/// Comparing the two classes without this field reports every failed attempt
/// as an AIP blind spot. That is a defect in the comparison, not in AIP, and
/// filtering on it is a like-for-like correction rather than a weakening: the
/// alternative is demanding that AIP record executions that never happened.
/// The attempts are still counted and reported, as a scope difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ExecOutcome {
    /// The exec succeeded; a new program image is running.
    Succeeded,
    /// The execve syscall failed (e.g. ENOENT during a `$PATH` search).
    Failed,
    /// The observer does not report an outcome. bpftrace on
    /// `sched:sched_process_exec` is in this case: the tracepoint only fires
    /// on success, so every event it emits is already a real execution.
    NotReported,
}

/// One execution as a third-party observer recorded it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ExternalExec {
    pub source: ExternalSource,
    pub pid: u32,
    /// Kernel monotonic stamp, when the observer reports in that domain.
    pub monotonic_ns: Option<u64>,
    /// Wall-clock milliseconds, when the observer reports in that domain.
    pub wall_ms: Option<i64>,
    /// The image the observer named. Context for a reader; never the join key,
    /// because two observers legitimately name the same binary differently.
    pub image: String,
    /// Whether the exec actually happened. See [`ExecOutcome`].
    pub outcome: ExecOutcome,
}

impl ExternalExec {
    /// Whether this record describes a program that actually started running.
    pub fn is_execution(&self) -> bool {
        !matches!(self.outcome, ExecOutcome::Failed)
    }
}

/// One execution as AIP's attested evidence recorded it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AipExec {
    pub pid: u32,
    pub wall_ms: i64,
    pub image: String,
    /// The collector sequence of the batch that carried it, so a reader can
    /// find the record in the signed archive.
    pub batch_sequence: u64,
}

/// A paired observation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Agreement {
    pub aip: AipExec,
    pub external_wall_ms: i64,
    pub external_image: String,
    /// Signed skew, external minus AIP, in milliseconds.
    pub skew_ms: i64,
}

/// The whole result. Every field is reported; none is hidden by a threshold.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Corroboration {
    pub source: ExternalSource,
    pub independence: IndependenceClass,
    /// The wall-clock window actually compared: the intersection of AIP's
    /// claimed coverage and the third-party observer's run.
    pub window_from_ms: i64,
    pub window_to_ms: i64,
    pub match_window_ms: i64,
    /// Both observers recorded it.
    pub agreed: Vec<Agreement>,
    /// AIP recorded it inside the window; the third-party observer did not.
    pub aip_only: Vec<AipExec>,
    /// **The finding that costs us something.** The third-party observer
    /// recorded it inside a window AIP claims to have covered, and AIP did not.
    pub external_only: Vec<ExternalExec>,
    /// Lines of the observer's output that did not parse. Non-zero means this
    /// report is incomplete and says so.
    pub external_unparsed: usize,
    /// Failed execve **attempts** the observer recorded inside the window.
    /// Excluded from the comparison because nothing executed, and reported
    /// because it is a real difference in what the two observers can see:
    /// auditd sees attempts, the scheduler tracepoint sees executions.
    pub external_failed_attempts: usize,
}

impl Corroboration {
    /// Agreement as a fraction of everything either observer saw in the
    /// window. Reported, never used as a pass/fail threshold — this crate
    /// states results and does not grade them.
    pub fn agreement_ratio(&self) -> f64 {
        let total = self.agreed.len() + self.aip_only.len() + self.external_only.len();
        if total == 0 {
            return 1.0;
        }
        self.agreed.len() as f64 / total as f64
    }

    /// True when nothing the third-party observer saw was missing from AIP's
    /// evidence. The honest headline; `aip_only` alone is not a defect, since
    /// AIP legitimately observes more than a single-rule external tracer.
    pub fn no_aip_blind_spot(&self) -> bool {
        self.external_only.is_empty()
    }
}

/// Why a comparison could not be made. Each case refuses rather than guesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorroborateError {
    /// A batch overlapping the window carries no clock anchor, so its events
    /// cannot be placed in wall time. Guessing would invent disagreement.
    NoClockAnchor { batch_sequence: u64 },
    /// The two runs do not overlap in time; there is nothing to compare and a
    /// report over an empty window would read as total agreement.
    NoOverlap,
    /// The third-party observer produced no usable event at all.
    NoExternalEvents,
}

impl std::fmt::Display for CorroborateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorroborateError::NoClockAnchor { batch_sequence } => write!(
                f,
                "batch {batch_sequence} has no clock anchor; refusing to guess a time domain"
            ),
            CorroborateError::NoOverlap => {
                write!(f, "the two observation windows do not overlap")
            }
            CorroborateError::NoExternalEvents => {
                write!(f, "the third-party observer produced no usable events")
            }
        }
    }
}

impl std::error::Error for CorroborateError {}

/// Every execution AIP's attested batches recorded, in wall-clock ms.
///
/// Only `ProcessExec` events are taken, because that is the event class both
/// third-party observers report. Comparing AIP's richer event set against a
/// tracer configured for exec alone would manufacture `aip_only` entries that
/// mean nothing.
pub fn aip_executions(batches: &[AttestedBatch]) -> Result<Vec<AipExec>, CorroborateError> {
    let mut out = Vec::new();
    for b in batches {
        let mut anchor = None;
        for e in &b.batch.kernel_events {
            let KernelLifecycleKind::ProcessExec { pid, filename, .. } = &e.kind else {
                continue;
            };
            let a = match anchor {
                Some(a) => a,
                None => {
                    let Some(a) = b.batch.clock_anchor else {
                        return Err(CorroborateError::NoClockAnchor {
                            batch_sequence: b.sequence,
                        });
                    };
                    anchor = Some(a);
                    a
                }
            };
            out.push(AipExec {
                pid: *pid,
                wall_ms: clock::monotonic_ns_to_wall_ms(&a, e.kernel_timestamp_ns),
                image: filename.clone(),
                batch_sequence: b.sequence,
            });
        }
    }
    Ok(out)
}

/// The wall-clock coverage AIP's batches claim.
pub fn aip_claimed_window(batches: &[AttestedBatch]) -> Option<(i64, i64)> {
    let from = batches.iter().map(|b| b.batch.claimed_from_ms).min()?;
    let to = batches.iter().map(|b| b.batch.claimed_to_ms).max()?;
    Some((from as i64, to as i64))
}

/// Place a third-party event in wall-clock ms, converting from the monotonic
/// domain when that is what the observer reports.
fn external_wall_ms(e: &ExternalExec, anchor: &aip_observe::BootClockAnchor) -> Option<i64> {
    match (e.wall_ms, e.monotonic_ns) {
        (Some(w), _) => Some(w),
        (None, Some(ns)) => Some(clock::monotonic_ns_to_wall_ms(anchor, ns)),
        (None, None) => None,
    }
}

/// Compare AIP's attested evidence against a third-party observer's events.
///
/// `external_window` is the observer's own run window in wall-clock ms, when
/// the caller knows it. Supplying it matters: without it the window is taken
/// from the first and last event the observer emitted, which silently excuses
/// AIP for anything the observer missed at the edges of its run.
///
/// The comparison is restricted to the intersection of that window with AIP's
/// **claimed coverage**. That restriction is the whole basis on which an
/// `external_only` entry is a real finding: AIP asserted it was watching.
///
/// Matching is deterministic: events are ordered by `(wall_ms, pid)`, and each
/// external event takes the nearest unclaimed AIP event with the same pid
/// inside `match_window_ms`, ties broken by position.
pub fn corroborate(
    batches: &[AttestedBatch],
    external: &[ExternalExec],
    external_window: Option<(i64, i64)>,
    match_window_ms: i64,
    external_unparsed: usize,
) -> Result<Corroboration, CorroborateError> {
    if external.is_empty() {
        return Err(CorroborateError::NoExternalEvents);
    }
    let source = external[0].source;

    // An anchor is needed to place monotonic-domain external events. Any batch
    // carrying one will do; they are captured from the same host clock.
    let anchor = batches.iter().find_map(|b| b.batch.clock_anchor);

    let mut ext: Vec<(i64, &ExternalExec)> = Vec::new();
    let mut failed_attempts = 0usize;
    for e in external {
        // A failed execve is not an execution; see `ExecOutcome`.
        if !e.is_execution() {
            failed_attempts += 1;
            continue;
        }
        let w = match external_wall_ms(
            e,
            anchor.as_ref().ok_or(CorroborateError::NoClockAnchor {
                batch_sequence: batches.first().map(|b| b.sequence).unwrap_or(0),
            })?,
        ) {
            Some(w) => w,
            None => continue,
        };
        ext.push((w, e));
    }
    if ext.is_empty() {
        return Err(CorroborateError::NoExternalEvents);
    }

    let aip_all = aip_executions(batches)?;
    let (aip_from, aip_to) = aip_claimed_window(batches).ok_or(CorroborateError::NoOverlap)?;
    let (ext_from, ext_to) = external_window.unwrap_or_else(|| {
        let lo = ext.iter().map(|(w, _)| *w).min().unwrap_or(aip_from);
        let hi = ext.iter().map(|(w, _)| *w).max().unwrap_or(aip_to);
        (lo, hi)
    });

    let from = aip_from.max(ext_from);
    let to = aip_to.min(ext_to);
    if from > to {
        return Err(CorroborateError::NoOverlap);
    }

    let in_window = |w: i64| w >= from && w <= to;
    let mut aip: Vec<AipExec> = aip_all
        .into_iter()
        .filter(|a| in_window(a.wall_ms))
        .collect();
    let mut ext: Vec<(i64, &ExternalExec)> =
        ext.into_iter().filter(|(w, _)| in_window(*w)).collect();

    // Deterministic order, so the same inputs always yield the same pairing.
    aip.sort_by_key(|a| (a.wall_ms, a.pid));
    ext.sort_by_key(|(w, e)| (*w, e.pid));

    let mut claimed = vec![false; aip.len()];
    let mut agreed = Vec::new();
    let mut external_only = Vec::new();

    for (ew, e) in &ext {
        let mut best: Option<(i64, usize)> = None;
        for (i, a) in aip.iter().enumerate() {
            if claimed[i] || a.pid != e.pid {
                continue;
            }
            let skew = ew - a.wall_ms;
            if skew.abs() > match_window_ms {
                continue;
            }
            // Nearest wins; earlier index breaks a tie, which keeps the
            // pairing stable rather than dependent on iteration luck.
            if best.is_none_or(|(b, _)| skew.abs() < b.abs()) {
                best = Some((skew, i));
            }
        }
        match best {
            Some((skew, i)) => {
                claimed[i] = true;
                agreed.push(Agreement {
                    aip: aip[i].clone(),
                    external_wall_ms: *ew,
                    external_image: e.image.clone(),
                    skew_ms: skew,
                });
            }
            None => external_only.push((*e).clone()),
        }
    }

    let aip_only: Vec<AipExec> = aip
        .into_iter()
        .zip(claimed)
        .filter_map(|(a, c)| (!c).then_some(a))
        .collect();

    Ok(Corroboration {
        source,
        independence: source.independence(),
        window_from_ms: from,
        window_to_ms: to,
        match_window_ms,
        agreed,
        aip_only,
        external_only,
        external_unparsed,
        external_failed_attempts: failed_attempts,
    })
}
