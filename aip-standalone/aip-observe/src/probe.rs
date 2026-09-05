//! The host-side probe: measures processes, ingests kernel events, holds no key.
//!
//! This type runs on the observed host, inside the attacker's reach under the
//! threat model. It therefore has **no signing key, no signing method, and no
//! access to the collector's chain state**. The strongest thing a compromised
//! host can do to this component is feed it lies or stop it; neither produces
//! an attestation, and stopping it produces a visible discontinuity at the
//! collector rather than silence that looks like coverage.
//!
//! # Sources (Stage 6.5)
//!
//! - [`ProcfsProbe::measure`] — polled `/proc` read (`ProcfsPoll`), the
//!   Stage 3 baseline.
//! - [`ProcfsProbe::measure_anchored`] — the same read bracketed by a kernel
//!   `pidfd` (`PidFdAnchored`): the facts provably belong to one instance
//!   that was alive when the read completed.
//! - [`ProcfsProbe::ingest_kernel_event`] — a fork/exec/exit the kernel
//!   pushed over the process-event connector (`ProcConnector`), bound to an
//!   instance if the probe could anchor one before it exited.
//! - [`ProcfsProbe::observe_sockets`] — kernel socket-table rows joined to
//!   the instance's open descriptors (`ProcNetTable`), socket-level only.
//!
//! Every observation carries its mechanism inside the signed bytes, and the
//! collector's probe registry decides which mechanisms this probe may claim.
//!
//! # Run epochs, sequence and loss
//!
//! Each probe start draws a random `run_id`; every observation and kernel
//! event gets the next per-run sequence number; each batch reports the range
//! it contains and the number of events the source reported lost since the
//! previous batch. The collector uses these to *see* restarts, gaps and
//! drops. They never widen coverage.

use std::collections::HashMap;

use aip_core::capability::random_jti;
use aip_core::execution_binding::BindingError;
use aip_types::ProcessInstance;

use crate::linux::ProcEvent;
use crate::observed::{
    AgentAttribution, BootClockAnchor, KernelLifecycleEvent, KernelLifecycleKind, ObservationBatch,
    ObservedEffect, ObservedExecution, ObservedProcess, SourceMechanism, OBSERVE_PROTOCOL_VERSION,
};

/// Why a measurement could not be taken. Never silently substituted with a
/// weaker identifier, and never turned into a statement about the workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    UnsupportedPlatform(&'static str),
    /// The process was not there (exited, never existed, or invisible in this
    /// PID namespace). This is a fact about the measurement, not about
    /// whether anything executed.
    ProcessNotVisible {
        pid: u32,
    },
    /// The instance bound by a pidfd exited before the measurement finished;
    /// whatever was read may belong to nothing, so nothing is returned.
    InstanceEnded {
        pid: u32,
    },
    Unavailable {
        field: &'static str,
        reason: String,
    },
}

impl From<BindingError> for ProbeError {
    fn from(e: BindingError) -> Self {
        match e {
            BindingError::UnsupportedPlatform(p) => ProbeError::UnsupportedPlatform(p),
            BindingError::Unavailable { field, reason } => {
                ProbeError::Unavailable { field, reason }
            }
        }
    }
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProbeError {}

/// An identity claim handed to the probe by some host-side party. The probe
/// records it verbatim as a claim; it never checks it and never upgrades it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentClaim {
    pub agent_id: String,
    pub claim_source: String,
    pub decision_id: Option<[u8; 16]>,
}

/// A measurement whose reads were bracketed by a live `pidfd`.
#[cfg(target_os = "linux")]
pub struct AnchoredMeasurement {
    pub process: ObservedProcess,
    pidfd: crate::linux::PidFd,
}

#[cfg(target_os = "linux")]
impl AnchoredMeasurement {
    /// Block up to `timeout_ms` for the bound instance to exit. `Ok(true)`
    /// once it has; this is a kernel fact about *this* instance, immune to
    /// PID reuse.
    pub fn wait_exit(&self, timeout_ms: i32) -> Result<bool, ProbeError> {
        self.pidfd.wait_exit(timeout_ms)
    }

    pub fn is_alive(&self) -> Result<bool, ProbeError> {
        self.pidfd.is_alive()
    }
}

/// Reads process facts from procfs, ingests kernel events, assembles unsigned
/// batches. Deliberately holds no key material: see the module docs.
#[derive(Debug, Clone)]
pub struct ProcfsProbe {
    probe_id: String,
    run_id: [u8; 16],
    seq: u64,
    /// `None` until a loss-capable source is attached; `Some(n)` counts
    /// events the source reported lost since the last batch.
    dropped_since_last_batch: Option<u64>,
    /// pid → claim registered by a host-side party. Attached to observations
    /// and kernel events of that pid as a *claim*.
    claims: HashMap<u32, AgentClaim>,
    /// pid → instance bound at exec time, so a later kernel exit event for
    /// the same pid can be attributed to that instance. Cleared whenever the
    /// source reports loss: after a gap the pid may have been recycled.
    bound_by_exec: HashMap<u32, ObservedProcess>,
    pending_kernel_events: Vec<KernelLifecycleEvent>,
    /// Sources the operator has wired to this probe and declares live. Added
    /// to every batch's `active_mechanisms` together with the mechanisms
    /// actually used in that batch.
    declared_sources: Vec<SourceMechanism>,
    /// Host realtime ↔ boot clock sample, included in every batch so kernel
    /// timestamps can be placed on the wall clock. A probe claim.
    clock_anchor: Option<BootClockAnchor>,
}

impl ProcfsProbe {
    pub fn new(probe_id: impl Into<String>) -> Self {
        Self {
            probe_id: probe_id.into(),
            run_id: random_jti(),
            seq: 0,
            dropped_since_last_batch: None,
            claims: HashMap::new(),
            bound_by_exec: HashMap::new(),
            pending_kernel_events: Vec::new(),
            declared_sources: Vec::new(),
            clock_anchor: None,
        }
    }

    /// Record the host's realtime/boot clock relation for the batches that
    /// follow. The anchor is signed into each batch as a probe claim; without
    /// one, kernel timestamps cannot be placed on the wall clock at all.
    pub fn declare_clock_anchor(&mut self, anchor: BootClockAnchor) {
        self.clock_anchor = Some(anchor);
    }

    /// Declare that a source is wired and live from now on. Coverage by a
    /// mechanism that produced no events in a window can only be claimed if
    /// it was declared; declaring is a probe claim that the collector bounds
    /// by its registry.
    pub fn declare_source(&mut self, mechanism: SourceMechanism) {
        if !self.declared_sources.contains(&mechanism) {
            self.declared_sources.push(mechanism);
        }
    }

    pub fn declared_sources(&self) -> &[SourceMechanism] {
        &self.declared_sources
    }

    pub fn probe_id(&self) -> &str {
        &self.probe_id
    }

    /// Random per probe start. A collector that sees it change knows the
    /// probe restarted, whatever the probe says.
    pub fn run_id(&self) -> [u8; 16] {
        self.run_id
    }

    /// Current per-run sequence position.
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Declare that a loss-capable source is attached: from now on the batch
    /// reports a counted loss (`Some`), starting at zero.
    pub fn enable_loss_counter(&mut self) {
        self.dropped_since_last_batch.get_or_insert(0);
    }

    /// The source reported `n` lost events. Also forgets every exec-time
    /// binding: after a gap, a pid may belong to a different instance.
    pub fn record_lost_events(&mut self, n: u64) {
        *self.dropped_since_last_batch.get_or_insert(0) += n;
        self.bound_by_exec.clear();
    }

    /// Register a host-side identity claim for `pid`. It stays a claim.
    pub fn register_claim(&mut self, pid: u32, claim: AgentClaim) {
        self.claims.insert(pid, claim);
    }

    fn attribution_for(&self, pid: u32) -> (AgentAttribution, Option<[u8; 16]>) {
        match self.claims.get(&pid) {
            None => (AgentAttribution::NotEstablished, None),
            Some(c) => (
                AgentAttribution::Claimed {
                    agent_id: c.agent_id.clone(),
                    claim_source: c.claim_source.clone(),
                },
                c.decision_id,
            ),
        }
    }

    // ─── Measurement ───

    fn read_process(pid: u32) -> Result<ObservedProcess, ProbeError> {
        use aip_core::execution_binding::{
            hash_file_contents, parse_boot_id, parse_proc_stat_start_time,
        };
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| ProbeError::ProcessNotVisible { pid })?;
        let pid_start_time_ticks = parse_proc_stat_start_time(&stat)?;
        let boot_text =
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e| {
                ProbeError::Unavailable {
                    field: "boot_id",
                    reason: e.to_string(),
                }
            })?;
        let boot_id = parse_boot_id(&boot_text)?;
        let exe_link = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
        let exe_path = std::fs::read_link(&exe_link)
            .map_err(|_| ProbeError::ProcessNotVisible { pid })?
            .to_string_lossy()
            .into_owned();
        let exe_content_sha256 = hash_file_contents(&exe_link)?;
        Ok(ObservedProcess {
            process: ProcessInstance {
                pid,
                pid_start_time_ticks,
                boot_id,
            },
            exe_content_sha256,
            exe_path,
        })
    }

    /// Polled measurement (`ProcfsPoll`). No liveness anchor: the reads may
    /// straddle an exit and PID reuse without this function knowing.
    #[cfg(target_os = "linux")]
    pub fn measure(&self, pid: u32) -> Result<ObservedProcess, ProbeError> {
        Self::read_process(pid)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn measure(&self, _pid: u32) -> Result<ObservedProcess, ProbeError> {
        Err(ProbeError::UnsupportedPlatform(std::env::consts::OS))
    }

    /// Anchored measurement (`PidFdAnchored`): open a pidfd first, read the
    /// facts, then confirm the *same* instance is still alive. If it exited
    /// in between, the reads may describe a recycled pid and are discarded
    /// with `InstanceEnded`.
    #[cfg(target_os = "linux")]
    pub fn measure_anchored(&self, pid: u32) -> Result<AnchoredMeasurement, ProbeError> {
        let pidfd = crate::linux::PidFd::open(pid)?;
        if !pidfd.is_alive()? {
            return Err(ProbeError::InstanceEnded { pid });
        }
        let process = Self::read_process(pid)?;
        if !pidfd.is_alive()? {
            return Err(ProbeError::InstanceEnded { pid });
        }
        Ok(AnchoredMeasurement { process, pidfd })
    }

    /// Socket-level effects of the instance (`ProcNetTable`): rows of the
    /// kernel socket tables whose inode is open in `/proc/<pid>/fd`, taken
    /// under a pidfd anchor. Returns the anchored process and its socket
    /// effects; `malformed_rows` counts table lines this crate could not
    /// parse (skipped, never guessed).
    #[cfg(target_os = "linux")]
    pub fn observe_sockets(
        &self,
        pid: u32,
    ) -> Result<(ObservedProcess, Vec<ObservedEffect>, usize), ProbeError> {
        let anchored = self.measure_anchored(pid)?;
        let inodes = crate::linux::socket_inodes_of(pid)?;
        let (table, malformed) = crate::linux::snapshot_socket_tables()?;
        if !anchored.is_alive()? {
            return Err(ProbeError::InstanceEnded { pid });
        }
        let effects = table
            .into_iter()
            .filter(|r| inodes.contains(&r.inode))
            .map(|r| ObservedEffect::SocketObserved {
                protocol: r.protocol,
                local: r.local,
                remote: r.remote,
                state: r.state,
                inode: r.inode,
            })
            .collect();
        Ok((anchored.process, effects, malformed))
    }

    // ─── Assembly ───

    /// Build one polled observation from an already-taken measurement
    /// (`ProcfsPoll`). Kept for the Stage 3 call shape.
    pub fn observation(
        &mut self,
        observed: ObservedProcess,
        effect: ObservedEffect,
        claim: Option<&AgentClaim>,
        host_wall_clock_ms: u64,
    ) -> ObservedExecution {
        self.observation_with(
            observed,
            effect,
            SourceMechanism::ProcfsPoll,
            claim,
            host_wall_clock_ms,
        )
    }

    /// Build one observation, stating how it was obtained.
    pub fn observation_with(
        &mut self,
        observed: ObservedProcess,
        effect: ObservedEffect,
        mechanism: SourceMechanism,
        claim: Option<&AgentClaim>,
        host_wall_clock_ms: u64,
    ) -> ObservedExecution {
        let seq = self.next_seq();
        ObservedExecution {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: self.probe_id.clone(),
            observed,
            attribution: match claim {
                None => AgentAttribution::NotEstablished,
                Some(c) => AgentAttribution::Claimed {
                    agent_id: c.agent_id.clone(),
                    claim_source: c.claim_source.clone(),
                },
            },
            effect,
            mechanism,
            claimed_decision_id: claim.and_then(|c| c.decision_id),
            host_wall_clock_ms,
            probe_monotonic_ns: seq,
        }
    }

    /// Ingest a kernel-pushed process event (`ProcConnector`). For an exec,
    /// the probe tries an anchored measurement of the subject *now*; if it
    /// succeeds the event is bound to that instance and the binding is
    /// remembered so the matching exit can be attributed. If the subject
    /// already exited, the event is recorded unbound — kernel-attested
    /// existence, identity `CANNOT_PROVE`.
    pub fn ingest_kernel_event(&mut self, ev: ProcEvent) -> &KernelLifecycleEvent {
        self.ingest_event(ev, SourceMechanism::ProcConnector)
    }

    /// Ingest a kernel-pushed socket state transition
    /// (`SockStateTracepoint`). Only the `connect()` call itself —
    /// `CLOSE → SYN_SENT` — runs in the acting task's context, so only that
    /// transition is anchored: the probe opens a pidfd on `current_pid`,
    /// measures the instance, and binds the event to it **only if the
    /// instance's start time (boot clock, tick resolution) is not later than
    /// the event's kernel timestamp** — otherwise the pid was recycled after
    /// the event and the measurement describes a different process. Every
    /// other transition is recorded unbound; the reconciler links it to the
    /// initiating transition through the kernel socket identity `sk`.
    pub fn ingest_socket_event(&mut self, ev: ProcEvent) -> &KernelLifecycleEvent {
        self.ingest_event(ev, SourceMechanism::SockStateTracepoint)
    }

    fn ingest_event(&mut self, ev: ProcEvent, mechanism: SourceMechanism) -> &KernelLifecycleEvent {
        let seq = self.next_seq();
        let subject = ev.kind.subject_pid();
        let bound = match (&ev.kind, subject) {
            (KernelLifecycleKind::Exec { .. }, Some(pid))
            | (KernelLifecycleKind::Fork { .. }, Some(pid)) => {
                let b = self.try_anchor(pid);
                if let Some(p) = &b {
                    self.bound_by_exec.insert(pid, p.clone());
                }
                b
            }
            (KernelLifecycleKind::Exit { .. }, Some(pid)) => self.bound_by_exec.remove(&pid),
            (KernelLifecycleKind::SocketState { .. }, Some(pid)) => self
                .try_anchor(pid)
                .filter(|p| instance_started_no_later_than(p, ev.timestamp_ns)),
            _ => None,
        };
        let (attribution, claimed_decision_id) = subject
            .map(|pid| self.attribution_for(pid))
            .unwrap_or((AgentAttribution::NotEstablished, None));
        self.pending_kernel_events.push(KernelLifecycleEvent {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: self.probe_id.clone(),
            mechanism,
            kind: ev.kind,
            cpu: ev.cpu,
            kernel_timestamp_ns: ev.timestamp_ns,
            probe_seq: seq,
            bound,
            attribution,
            claimed_decision_id,
        });
        self.pending_kernel_events.last().unwrap()
    }

    #[cfg(target_os = "linux")]
    fn try_anchor(&self, pid: u32) -> Option<ObservedProcess> {
        self.measure_anchored(pid).ok().map(|a| a.process)
    }

    #[cfg(not(target_os = "linux"))]
    fn try_anchor(&self, _pid: u32) -> Option<ObservedProcess> {
        None
    }

    /// Kernel events ingested since the last batch.
    pub fn pending_kernel_events(&self) -> &[KernelLifecycleEvent] {
        &self.pending_kernel_events
    }

    /// Assemble an unsigned batch containing `observations` and every kernel
    /// event ingested since the previous batch. The probe cannot sign it,
    /// cannot assign it a chain position, and cannot decide what coverage
    /// will be attested.
    pub fn batch(
        &mut self,
        batch_id: [u8; 16],
        claimed_from_ms: u64,
        claimed_to_ms: u64,
        observations: Vec<ObservedExecution>,
    ) -> ObservationBatch {
        let kernel_events = std::mem::take(&mut self.pending_kernel_events);
        let seqs = observations
            .iter()
            .map(|o| o.probe_monotonic_ns)
            .chain(kernel_events.iter().map(|e| e.probe_seq));
        let (first, last) = seqs.fold((u64::MAX, 0u64), |(lo, hi), s| (lo.min(s), hi.max(s)));
        let (probe_seq_first, probe_seq_last) = if first == u64::MAX {
            // Empty batch: a point at the current position, not a range.
            (self.seq, self.seq)
        } else {
            (first, last)
        };
        let dropped_events = self.dropped_since_last_batch;
        if self.dropped_since_last_batch.is_some() {
            self.dropped_since_last_batch = Some(0);
        }
        // Active over the window = declared live ∪ actually used.
        let active_mechanisms = SourceMechanism::canonical_set(
            self.declared_sources
                .iter()
                .copied()
                .chain(observations.iter().map(|o| o.mechanism))
                .chain(kernel_events.iter().map(|e| e.mechanism))
                .collect(),
        );
        ObservationBatch {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: self.probe_id.clone(),
            batch_id,
            probe_run_id: self.run_id,
            probe_seq_first,
            probe_seq_last,
            dropped_events,
            active_mechanisms,
            claimed_from_ms,
            claimed_to_ms,
            observations,
            kernel_events,
            clock_anchor: self.clock_anchor,
        }
    }
}

/// `pid_start_time_ticks` (clock ticks since boot, `/proc/<pid>/stat`) is
/// not later than `event_boottime_ns`. Both are the kernel's boot clock, so
/// the comparison is inside one clock domain; the tick (`CLK_TCK`, usually
/// 10 ms) is the resolution, and the start is taken at the *beginning* of
/// its tick so a start inside the event's tick still passes — pid reuse
/// within one tick is not excluded by time alone (documented).
pub fn instance_started_no_later_than(p: &ObservedProcess, event_boottime_ns: u64) -> bool {
    let start_ns = p
        .process
        .pid_start_time_ticks
        .saturating_mul(1_000_000_000 / clk_tck());
    start_ns <= event_boottime_ns
}

#[cfg(target_os = "linux")]
fn clk_tck() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 {
        v as u64
    } else {
        100
    }
}

#[cfg(not(target_os = "linux"))]
fn clk_tck() -> u64 {
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_process(pid: u32) -> ObservedProcess {
        ObservedProcess {
            process: ProcessInstance {
                pid,
                pid_start_time_ticks: 1,
                boot_id: [1u8; 16],
            },
            exe_content_sha256: [2u8; 32],
            exe_path: "/x".into(),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_measures_a_real_process_and_matches_stage_one_binding() {
        let probe = ProcfsProbe::new("probe-self");
        let pid = std::process::id();
        let measured = probe.measure(pid).unwrap();
        assert_eq!(measured.process.pid, pid);
        assert!(measured.process.pid_start_time_ticks > 0);
        assert_ne!(measured.process.boot_id, [0u8; 16]);
        assert_ne!(measured.exe_content_sha256, [0u8; 32]);

        let self_reported =
            aip_core::execution_binding::collect_self_binding("aip1claimed").unwrap();
        assert!(measured.matches_process_of(&self_reported));

        // Anchored measurement of a live process agrees and is alive.
        let anchored = probe.measure_anchored(pid).unwrap();
        assert_eq!(anchored.process, measured);
        assert!(anchored.is_alive().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probing_an_impossible_pid_is_an_explicit_measurement_failure() {
        let probe = ProcfsProbe::new("probe-self");
        assert_eq!(
            probe.measure(u32::MAX),
            Err(ProbeError::ProcessNotVisible { pid: u32::MAX })
        );
        assert!(matches!(
            probe.measure_anchored(u32::MAX),
            Err(ProbeError::ProcessNotVisible { pid: u32::MAX })
        ));
    }

    #[test]
    fn a_claim_is_recorded_as_a_claim() {
        let mut probe = ProcfsProbe::new("probe-1");
        let observed = fake_process(1);
        let claim = AgentClaim {
            agent_id: "aip1agent".into(),
            claim_source: "orchestrator".into(),
            decision_id: Some([9u8; 16]),
        };
        let o = probe.observation(
            observed.clone(),
            ObservedEffect::ProcessPresent,
            Some(&claim),
            5,
        );
        assert!(matches!(o.attribution, AgentAttribution::Claimed { .. }));
        assert_eq!(o.attribution.claimed_agent_id(), Some("aip1agent"));
        assert_eq!(o.mechanism, SourceMechanism::ProcfsPoll);

        let o2 = probe.observation(observed, ObservedEffect::ProcessPresent, None, 6);
        assert_eq!(o2.attribution, AgentAttribution::NotEstablished);
        assert_eq!(o2.claimed_decision_id, None);
        assert!(o2.probe_monotonic_ns > o.probe_monotonic_ns);
    }

    #[test]
    fn batch_reports_run_id_sequence_range_and_loss() {
        let mut probe = ProcfsProbe::new("probe-1");
        let run = probe.run_id();
        assert_ne!(run, [0u8; 16]);

        // No loss-capable source: loss is unknown, not zero.
        let b0 = probe.batch([0u8; 16], 0, 1, vec![]);
        assert_eq!(b0.dropped_events, None);
        assert_eq!(b0.probe_run_id, run);
        assert_eq!((b0.probe_seq_first, b0.probe_seq_last), (0, 0));

        probe.enable_loss_counter();
        let o1 = probe.observation(fake_process(1), ObservedEffect::ProcessPresent, None, 1);
        let o2 = probe.observation(fake_process(2), ObservedEffect::ProcessPresent, None, 2);
        probe.record_lost_events(3);
        let b1 = probe.batch([1u8; 16], 1, 2, vec![o1, o2]);
        assert_eq!(b1.dropped_events, Some(3));
        assert_eq!((b1.probe_seq_first, b1.probe_seq_last), (1, 2));

        // Loss counter resets per batch; run id does not.
        let b2 = probe.batch([2u8; 16], 2, 3, vec![]);
        assert_eq!(b2.dropped_events, Some(0));
        assert_eq!(b2.probe_run_id, run);

        // A new probe is a new run.
        let other = ProcfsProbe::new("probe-1");
        assert_ne!(other.run_id(), run);
    }

    #[test]
    fn kernel_exit_after_loss_is_not_attributed_to_an_earlier_exec() {
        let mut probe = ProcfsProbe::new("probe-1");
        // Simulate an exec that was bound (inject the binding directly, as a
        // live anchor would have).
        probe.bound_by_exec.insert(77, fake_process(77));
        probe.record_lost_events(1);
        let ev = probe.ingest_kernel_event(ProcEvent {
            kind: KernelLifecycleKind::Exit {
                pid: 77,
                tgid: 77,
                exit_code: 0,
                exit_signal: 0,
            },
            cpu: 0,
            timestamp_ns: 5,
        });
        assert_eq!(ev.bound, None, "after loss the pid may have been recycled");
        assert_eq!(ev.subject_identity_digest(), None);
    }

    #[test]
    fn kernel_exit_without_loss_is_attributed_to_the_bound_exec_instance() {
        let mut probe = ProcfsProbe::new("probe-1");
        probe.bound_by_exec.insert(77, fake_process(77));
        let ev = probe.ingest_kernel_event(ProcEvent {
            kind: KernelLifecycleKind::Exit {
                pid: 77,
                tgid: 77,
                exit_code: 0,
                exit_signal: 0,
            },
            cpu: 0,
            timestamp_ns: 5,
        });
        assert_eq!(ev.bound, Some(fake_process(77)));
        assert_eq!(ev.mechanism, SourceMechanism::ProcConnector);
        // Consumed: a second exit for the same pid is a different instance.
        let ev2 = probe.ingest_kernel_event(ProcEvent {
            kind: KernelLifecycleKind::Exit {
                pid: 77,
                tgid: 77,
                exit_code: 0,
                exit_signal: 0,
            },
            cpu: 0,
            timestamp_ns: 6,
        });
        assert_eq!(ev2.bound, None);
    }
}
