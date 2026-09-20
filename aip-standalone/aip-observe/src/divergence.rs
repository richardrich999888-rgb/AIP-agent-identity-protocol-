//! Cross-sensor divergence: the one blinding signal that survives a
//! submission-path hook.
//!
//! # The problem this exists for
//!
//! Every per-sensor loss signal this crate already reads can be zeroed by an
//! attacker who hooks *above* the accounting. The kernel increments the perf
//! loss counter (`PERF_RECORD_LOST`) in exactly one place — the `fail:` label
//! of `__perf_output_begin()`, reached only when the ring is genuinely full.
//! A rootkit that hooks `perf_event_output` or `perf_trace_run_bpf_submit`
//! and returns early produces no sample *and* no loss record: an invisible
//! drop. The netlink connector's `ENOBUFS` is the same story from the other
//! side — it fires on backpressure, not on a hook that drops the message
//! before the socket sees it. So a sensor's own books, consulted alone,
//! cannot be trusted to notice that the sensor has been blinded.
//!
//! What a single hook *cannot* do is suppress two independent delivery paths
//! at once and keep them consistent with each other. The netlink process
//! connector and the `sched:sched_process_exec` perf tracepoint both report
//! process execs, by different kernel facilities. When the connector delivers
//! an exec that the perf tracepoint — declared live in the same batch — never
//! delivered, that gap is affirmative evidence the perf path was suppressed,
//! whatever the perf sensor's own loss counter says. That is the signal here.
//!
//! # What this is not
//!
//! It is not a claim to defeat a kernel attacker. An attacker who hooks
//! *both* paths, or who hooks the connector alone, defeats this too; that is
//! the standing kernel-compromise limit and is not narrowed here. It is the
//! mechanism that turns the *common* case — a hook on one delivery path,
//! which is what every public PoC (TripleCross, ebpfkit, the 0xMatheuZ perf
//! rootkit) actually does — from an invisible drop into a signed
//! `IntegrityUnknown`.
//!
//! It is also distinct from, and complementary to, the structural rule in
//! [`crate::SignedSensorHealth::covered_by_kernel_pushed_source`]: that rule
//! *withholds* a non-occurrence claim unless a gate-independent mechanism
//! covered the window. This detector is the *positive* half — it takes an
//! observed disagreement and raises a finding, rather than merely declining
//! to make one.
//!
//! # How the finding is expressed
//!
//! As a [`MechanismIntegrityReport`] of
//! [`MechanismIntegrity::Unverifiable`] against the blinded mechanism —
//! **not** `ForeignTracepointGate`. The distinction is deliberate and honest:
//! `ForeignTracepointGate` asserts the probe *found* a foreign program on the
//! tracepoint's gate, a positive fact. Here the probe found nothing (its own
//! detection query may itself be hooked); the collector merely observes that
//! one sensor delivered what another did not, and so cannot establish that
//! the silent sensor was capable. `Unverifiable` says exactly that, and it
//! already drives [`crate::ObserverState::IntegrityUnknown`] through the
//! existing signer pathway, so nothing downstream needs a new verdict.

use crate::health::MechanismIntegrity;
use crate::observed::{
    KernelLifecycleKind, MechanismIntegrityReport, ObservationBatch, SourceMechanism,
};

/// Default matching window, in kernel-clock nanoseconds.
///
/// The connector and the perf tracepoint timestamp the *same* exec on
/// `CLOCK_MONOTONIC`, but not at the same instant: one reads the event as the
/// kernel pushes it, the other as the ring is drained. 50 ms is far wider than
/// that skew and far narrower than the interval between two unrelated execs of
/// one pid, so it never fails to pair a genuine match and never pairs two
/// different events. It is generous on purpose: a false "unmatched" is a
/// false blinding accusation, which is the expensive direction.
pub const DEFAULT_MATCH_WINDOW_NS: u64 = 50_000_000;

/// A connector-reported exec that the perf tracepoint did not corroborate.
///
/// Kept as data rather than collapsed straight into a finding so a caller —
/// and a test — can see exactly which exec went unmatched, not merely that
/// one did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// The mechanism that delivered the exec (the gate-independent anchor).
    pub reported_by: SourceMechanism,
    /// The mechanism that was declared live and should have corroborated it
    /// but did not — the one implicated as blinded.
    pub missing_from: SourceMechanism,
    /// The pid the connector reported the exec for. Kernel pid, not identity;
    /// used only as the join key within one boot and one window.
    pub pid: u32,
    pub tgid: u32,
    /// The connector's kernel timestamp for the exec.
    pub kernel_timestamp_ns: u64,
}

/// The result of reconciling one batch's two exec-reporting sensors.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrossSensorReport {
    /// Every connector exec the perf tracepoint failed to corroborate.
    pub divergences: Vec<Divergence>,
}

impl CrossSensorReport {
    /// The integrity findings this divergence implies, one per blinded
    /// mechanism, ready for [`crate::CollectorSigner::note_mechanism_integrity`].
    ///
    /// Deduplicated: many unmatched execs on one sensor are one capability
    /// failure, not many. Empty when nothing diverged.
    pub fn integrity_reports(&self) -> Vec<MechanismIntegrityReport> {
        let mut blinded: Vec<SourceMechanism> =
            self.divergences.iter().map(|d| d.missing_from).collect();
        blinded.sort_by_key(SourceMechanism::code);
        blinded.dedup();
        blinded
            .into_iter()
            .map(|m| MechanismIntegrityReport {
                mechanism: m,
                integrity: MechanismIntegrity::Unverifiable,
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.divergences.is_empty()
    }
}

/// One exec, reduced to the fields the join needs.
struct ExecEvent {
    pid: u32,
    tgid: u32,
    ts_ns: u64,
}

/// Every exec reported by `mechanism` in this batch.
///
/// Only [`KernelLifecycleKind::Exec`] is used as the comparable unit: it is
/// the one lifecycle fact both the connector and `sched:sched_process_exec`
/// emit for the same act, so it is the only kind on which a missing
/// corroboration is meaningful. Fork and Exit are deliberately excluded — the
/// perf sched sensor does not mirror the connector's fork/exit stream, and
/// treating their absence as divergence would be a false positive by
/// construction.
fn execs_of(batch: &ObservationBatch, mechanism: SourceMechanism) -> Vec<ExecEvent> {
    batch
        .kernel_events
        .iter()
        .filter(|e| e.mechanism == mechanism)
        .filter_map(|e| match e.kind {
            KernelLifecycleKind::Exec { pid, tgid } => Some(ExecEvent {
                pid,
                tgid,
                ts_ns: e.kernel_timestamp_ns,
            }),
            _ => None,
        })
        .collect()
}

/// Detect execs the gate-independent connector delivered that the perf
/// tracepoint did not, within `window_ns`.
///
/// # Direction, and why it is one-way
///
/// The check runs connector → perf and not the reverse. The connector is the
/// gate-independent anchor the whole design leans on: it does not pass through
/// the per-tracepoint eBPF submission gate, so it is the reference a perf
/// sensor is measured against. The reverse case — perf delivered an exec the
/// connector missed — implicates the connector, whose loss has its own
/// first-class signal (`ENOBUFS` → counted loss → degraded epoch), so folding
/// it in here would double-count one loss and risk accusing the sturdier
/// sensor on ordinary backpressure. This detector answers exactly one
/// question: *did the sensor most likely to be hooked go silent while the
/// sensor hardest to hook kept talking?*
///
/// # Fail-closed preconditions (no false positives)
///
/// Returns an empty report unless **both** mechanisms are declared live in
/// `active_mechanisms`. If the perf tracepoint was never opened this cycle,
/// its silence is expected and is not divergence; if the connector was not
/// opened, there is no anchor to measure against. An idle window with no
/// connector execs likewise diverges from nothing.
pub fn detect(batch: &ObservationBatch, window_ns: u64) -> CrossSensorReport {
    let anchor = SourceMechanism::ProcConnector;
    let measured = SourceMechanism::SchedTracepoint;

    let both_live =
        batch.active_mechanisms.contains(&anchor) && batch.active_mechanisms.contains(&measured);
    if !both_live {
        return CrossSensorReport::default();
    }

    let anchor_execs = execs_of(batch, anchor);
    let measured_execs = execs_of(batch, measured);

    let divergences = anchor_execs
        .into_iter()
        .filter(|a| {
            // Corroborated iff the measured sensor delivered an exec for the
            // same (pid, tgid) within the window on either side.
            !measured_execs.iter().any(|m| {
                m.pid == a.pid && m.tgid == a.tgid && a.ts_ns.abs_diff(m.ts_ns) <= window_ns
            })
        })
        .map(|a| Divergence {
            reported_by: anchor,
            missing_from: measured,
            pid: a.pid,
            tgid: a.tgid,
            kernel_timestamp_ns: a.ts_ns,
        })
        .collect();

    CrossSensorReport { divergences }
}

/// [`detect`] with [`DEFAULT_MATCH_WINDOW_NS`].
pub fn detect_default(batch: &ObservationBatch) -> CrossSensorReport {
    detect(batch, DEFAULT_MATCH_WINDOW_NS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observed::{
        AgentAttribution, KernelLifecycleEvent, ObservationBatch, OBSERVE_PROTOCOL_VERSION,
    };

    fn exec_event(mechanism: SourceMechanism, pid: u32, ts_ns: u64) -> KernelLifecycleEvent {
        KernelLifecycleEvent {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe-1".into(),
            mechanism,
            kind: KernelLifecycleKind::Exec { pid, tgid: pid },
            cpu: 0,
            kernel_timestamp_ns: ts_ns,
            probe_seq: 1,
            bound: None,
            attribution: AgentAttribution::NotEstablished,
            claimed_decision_id: None,
        }
    }

    fn fork_event(mechanism: SourceMechanism, child: u32, ts_ns: u64) -> KernelLifecycleEvent {
        KernelLifecycleEvent {
            kind: KernelLifecycleKind::Fork {
                parent_pid: 1,
                parent_tgid: 1,
                child_pid: child,
                child_tgid: child,
            },
            ..exec_event(mechanism, child, ts_ns)
        }
    }

    fn batch(active: &[SourceMechanism], events: Vec<KernelLifecycleEvent>) -> ObservationBatch {
        ObservationBatch {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe-1".into(),
            batch_id: [1u8; 16],
            probe_run_id: [2u8; 16],
            probe_seq_first: 1,
            probe_seq_last: 10,
            dropped_events: Some(0),
            active_mechanisms: SourceMechanism::canonical_set(active.to_vec()),
            mechanism_integrity: Vec::new(),
            claimed_from_ms: 1_000,
            claimed_to_ms: 2_000,
            observations: vec![],
            kernel_events: events,
            clock_anchor: None,
        }
    }

    const BOTH: [SourceMechanism; 2] = [
        SourceMechanism::ProcConnector,
        SourceMechanism::SchedTracepoint,
    ];

    // ── The honest path: agreement is not divergence ─────────────────────

    #[test]
    fn a_connector_exec_the_perf_tracepoint_also_delivered_is_not_divergence() {
        let b = batch(
            &BOTH,
            vec![
                exec_event(SourceMechanism::ProcConnector, 4242, 1_000_000),
                // The perf tracepoint delivered the same exec 2 ms later.
                exec_event(SourceMechanism::SchedTracepoint, 4242, 1_002_000),
            ],
        );
        let r = detect_default(&b);
        assert!(r.is_empty(), "corroborated exec must not diverge: {r:?}");
        assert!(r.integrity_reports().is_empty());
    }

    // ── The decisive case: perf blinded while the connector still talks ──

    #[test]
    fn a_connector_exec_the_perf_tracepoint_missed_is_divergence() {
        let b = batch(
            &BOTH,
            vec![exec_event(SourceMechanism::ProcConnector, 4242, 1_000_000)],
        );
        let r = detect_default(&b);
        assert_eq!(r.divergences.len(), 1);
        assert_eq!(
            r.divergences[0].missing_from,
            SourceMechanism::SchedTracepoint
        );
        assert_eq!(r.divergences[0].pid, 4242);

        // And it maps to the finding that already drives IntegrityUnknown.
        let reports = r.integrity_reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].mechanism, SourceMechanism::SchedTracepoint);
        assert_eq!(reports[0].integrity, MechanismIntegrity::Unverifiable);
    }

    // ── Fail-closed: silence is only divergence when the sensor was live ─

    #[test]
    fn perf_silence_is_not_divergence_when_perf_was_not_declared_active() {
        // The perf tracepoint was never opened this cycle, so its not
        // reporting the connector's exec is expected, not suppression.
        let b = batch(
            &[SourceMechanism::ProcConnector],
            vec![exec_event(SourceMechanism::ProcConnector, 4242, 1_000_000)],
        );
        assert!(detect_default(&b).is_empty());
    }

    #[test]
    fn nothing_diverges_without_the_connector_anchor() {
        // Perf active, connector not: there is no gate-independent anchor to
        // measure against, so no finding can be raised here (the structural
        // coverage rule handles a perf-only window elsewhere).
        let b = batch(
            &[SourceMechanism::SchedTracepoint],
            vec![exec_event(
                SourceMechanism::SchedTracepoint,
                4242,
                1_000_000,
            )],
        );
        assert!(detect_default(&b).is_empty());
    }

    #[test]
    fn an_idle_window_diverges_from_nothing() {
        let b = batch(&BOTH, vec![]);
        assert!(detect_default(&b).is_empty());
    }

    // ── The window boundary ──────────────────────────────────────────────

    #[test]
    fn a_perf_exec_just_inside_the_window_corroborates() {
        let b = batch(
            &BOTH,
            vec![
                exec_event(SourceMechanism::ProcConnector, 7, 1_000_000_000),
                exec_event(
                    SourceMechanism::SchedTracepoint,
                    7,
                    1_000_000_000 + DEFAULT_MATCH_WINDOW_NS,
                ),
            ],
        );
        assert!(detect_default(&b).is_empty(), "exactly-at-window must pair");
    }

    #[test]
    fn a_perf_exec_just_outside_the_window_does_not_corroborate() {
        let b = batch(
            &BOTH,
            vec![
                exec_event(SourceMechanism::ProcConnector, 7, 1_000_000_000),
                exec_event(
                    SourceMechanism::SchedTracepoint,
                    7,
                    1_000_000_000 + DEFAULT_MATCH_WINDOW_NS + 1,
                ),
            ],
        );
        assert_eq!(detect_default(&b).divergences.len(), 1);
    }

    // ── Identity of the join key ─────────────────────────────────────────

    #[test]
    fn a_perf_exec_for_a_different_pid_does_not_corroborate() {
        let b = batch(
            &BOTH,
            vec![
                exec_event(SourceMechanism::ProcConnector, 100, 1_000_000),
                exec_event(SourceMechanism::SchedTracepoint, 101, 1_000_000),
            ],
        );
        let r = detect_default(&b);
        assert_eq!(r.divergences.len(), 1);
        assert_eq!(r.divergences[0].pid, 100);
    }

    // ── Aggregation: many gaps on one sensor are one finding ──────────────

    #[test]
    fn several_unmatched_execs_yield_one_integrity_report() {
        let b = batch(
            &BOTH,
            vec![
                exec_event(SourceMechanism::ProcConnector, 1, 1_000_000),
                exec_event(SourceMechanism::ProcConnector, 2, 2_000_000),
                exec_event(SourceMechanism::ProcConnector, 3, 3_000_000),
            ],
        );
        let r = detect_default(&b);
        assert_eq!(r.divergences.len(), 3, "each gap is recorded");
        assert_eq!(
            r.integrity_reports().len(),
            1,
            "but they are one capability failure of one sensor"
        );
    }

    // ── Only execs are comparable ────────────────────────────────────────

    #[test]
    fn a_connector_fork_without_a_perf_fork_is_not_divergence() {
        // The perf sched sensor does not mirror the connector's fork stream,
        // so a missing fork corroboration is not a blinding signal and must
        // not be treated as one.
        let b = batch(
            &BOTH,
            vec![fork_event(SourceMechanism::ProcConnector, 4242, 1_000_000)],
        );
        assert!(detect_default(&b).is_empty());
    }
}
