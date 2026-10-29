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
#[cfg(any(target_os = "linux", test))]
use aip_types::ProcessInstance;

use crate::health::MechanismIntegrity;
use crate::linux::ProcEvent;
use crate::observed::MechanismIntegrityReport;
use crate::observed::{
    AgentAttribution, BootClockAnchor, KernelLifecycleEvent, KernelLifecycleKind, ObservationBatch,
    ObservedEffect, ObservedExecution, ObservedProcess, SourceMechanism, OBSERVE_PROTOCOL_VERSION,
};

/// Bounds for the live daemon's deferred records. Leave room for one kernel
/// record before reading another source; capacity exhaustion is uncertainty,
/// never permission to discard an already ingested record.
pub const MAX_LIVE_PENDING_EVENTS: usize = 4096;
pub const MAX_LIVE_PENDING_BYTES: usize = 512 * 1024;
const LIVE_EVENT_RESERVE_BYTES: usize = 64 * 1024;

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
    pending_kernel_bytes: usize,
    live_published_seq: u64,
    live_finalized_ns: Option<u64>,
    live_faults: Vec<SourceMechanism>,
    /// Sources the operator has wired to this probe and declares live. Added
    /// to every batch's `active_mechanisms` together with the mechanisms
    /// actually used in that batch.
    declared_sources: Vec<SourceMechanism>,
    /// The latest integrity finding per mechanism, as the sensor that owns
    /// it reported this cycle. Carried in every batch so the off-host
    /// collector learns of a gated tracepoint (see
    /// [`MechanismIntegrityReport`]). Re-declared each cycle by the sensor
    /// set; a mechanism that is not re-declared keeps its last finding.
    mechanism_integrity: Vec<MechanismIntegrityReport>,
    /// Host realtime ↔ boot clock sample, included in every batch so kernel
    /// timestamps can be placed on the wall clock. A probe claim.
    clock_anchor: Option<BootClockAnchor>,
    /// pid → the last image hash taken for that pid, with what it was taken
    /// of. Host-wide sources (socket sends, Gate 3) fire for every process
    /// on the host, and hashing a large executable for each event never
    /// catches up; the cache makes the cost one hash per (instance, image).
    /// A hit requires the same start tick (the same instance) **and** the
    /// same inode, size and modification time of the file `/proc/<pid>/exe`
    /// resolves to (the same image); any change re-hashes. The pidfd anchor
    /// around every measurement is unchanged.
    #[cfg(target_os = "linux")]
    image_cache: std::cell::RefCell<HashMap<u32, CachedImage>>,
}

/// What an image hash in the probe's cache was taken of.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
struct CachedImage {
    pid_start_time_ticks: u64,
    exe_ino: u64,
    exe_size: u64,
    exe_mtime: (i64, i64),
    exe_path: String,
    exe_content_sha256: [u8; 32],
}

#[cfg(any(target_os = "linux", test))]
impl CachedImage {
    /// Does a cached hash still describe what `/proc/<pid>/exe` now resolves
    /// to, for the same instance? Every field must agree: a recycled pid
    /// (other start tick), an exec of another file (other inode), a rewrite
    /// of the file (other size or mtime) or another path all miss.
    fn still_describes(
        &self,
        pid_start_time_ticks: u64,
        exe_ino: u64,
        exe_size: u64,
        exe_mtime: (i64, i64),
        exe_path: &str,
    ) -> bool {
        self.pid_start_time_ticks == pid_start_time_ticks
            && self.exe_ino == exe_ino
            && self.exe_size == exe_size
            && self.exe_mtime == exe_mtime
            && self.exe_path == exe_path
    }
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
            pending_kernel_bytes: 0,
            live_published_seq: 0,
            live_finalized_ns: None,
            live_faults: Vec::new(),
            declared_sources: Vec::new(),
            mechanism_integrity: Vec::new(),
            clock_anchor: None,
            #[cfg(target_os = "linux")]
            image_cache: std::cell::RefCell::new(HashMap::new()),
        }
    }

    /// Record the sensor's integrity finding for `mechanism` for the batches
    /// that follow (one slot per mechanism; the latest declaration wins). The
    /// probe does not interpret the finding — it is shipped to the collector,
    /// which decides what the signed state becomes.
    pub fn declare_mechanism_integrity(
        &mut self,
        mechanism: SourceMechanism,
        integrity: MechanismIntegrity,
    ) {
        self.mechanism_integrity
            .retain(|r| r.mechanism != mechanism);
        self.mechanism_integrity.push(MechanismIntegrityReport {
            mechanism,
            integrity,
        });
    }

    /// The findings the next batch will carry, in canonical order.
    pub fn mechanism_integrity_reports(&self) -> Vec<MechanismIntegrityReport> {
        MechanismIntegrityReport::canonical_set(self.mechanism_integrity.clone())
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

    #[cfg(target_os = "linux")]
    fn read_process(&self, pid: u32) -> Result<ObservedProcess, ProbeError> {
        use aip_core::execution_binding::{
            hash_file_contents, parse_boot_id, parse_proc_stat_start_time,
        };
        use std::os::unix::fs::MetadataExt;
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
        // `metadata` follows the link: the image file's own inode, size and
        // modification time, read from the kernel, not from the path.
        let meta =
            std::fs::metadata(&exe_link).map_err(|_| ProbeError::ProcessNotVisible { pid })?;
        let (exe_ino, exe_size, exe_mtime) =
            (meta.ino(), meta.len(), (meta.mtime(), meta.mtime_nsec()));
        let cached = self.image_cache.borrow().get(&pid).cloned();
        let exe_content_sha256 = match cached {
            Some(c)
                if c.still_describes(
                    pid_start_time_ticks,
                    exe_ino,
                    exe_size,
                    exe_mtime,
                    &exe_path,
                ) =>
            {
                c.exe_content_sha256
            }
            _ => {
                let sha = hash_file_contents(&exe_link)?;
                self.image_cache.borrow_mut().insert(
                    pid,
                    CachedImage {
                        pid_start_time_ticks,
                        exe_ino,
                        exe_size,
                        exe_mtime,
                        exe_path: exe_path.clone(),
                        exe_content_sha256: sha,
                    },
                );
                sha
            }
        };
        Ok(ObservedProcess {
            process: ProcessInstance {
                pid,
                pid_start_time_ticks,
                boot_id,
            },
            exe_content_sha256,
            exe_path,
            // B3: the observer reads the kernel's placement itself rather
            // than taking the authorizing side's word for it. `None` when it
            // cannot — no permission, a kernel that withholds the files, or
            // the process exited between the anchor and this read — and the
            // namespaces are all-or-nothing, so a partial read records
            // nothing rather than a placement that would compare unequal
            // against a complete one for the same container.
            container: aip_core::execution_binding::collect_container_identity(pid),
        })
    }

    /// Polled measurement (`ProcfsPoll`). No liveness anchor: the reads may
    /// straddle an exit and PID reuse without this function knowing.
    #[cfg(target_os = "linux")]
    pub fn measure(&self, pid: u32) -> Result<ObservedProcess, ProbeError> {
        self.read_process(pid)
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
        let process = self.read_process(pid)?;
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

    /// Ingest a kernel-pushed process spawn or exec (`SchedTracepoint`).
    /// A spawn is anchored to the **parent** (the acting task; fork runs in
    /// its context) and an exec to the **new image's task**; both bindings
    /// require the instance's start tick to be no later than the event's
    /// kernel time. The reconciler pairs a spawn with the child's exec.
    pub fn ingest_sched_event(&mut self, ev: ProcEvent) -> &KernelLifecycleEvent {
        self.ingest_event(ev, SourceMechanism::SchedTracepoint)
    }

    /// Ingest a kernel-pushed cgroup placement event (`CgroupTracepoint`,
    /// ADR-019). The acting task — creator, remover, or the task migrated —
    /// is anchored under the start-tick rule, so the reconciler can later
    /// ask *which instance* created a decision placement, never just which
    /// pid number.
    pub fn ingest_cgroup_event(&mut self, ev: ProcEvent) -> &KernelLifecycleEvent {
        self.ingest_event(ev, SourceMechanism::CgroupTracepoint)
    }

    /// Ingest a TCP segment copied from a network device
    /// (`WireTapAfPacket`). The device layer has no task context, so the
    /// event is recorded **unbound** with no attribution and no claim,
    /// whatever claims are registered: the wire names no process.
    pub fn ingest_wire_event(&mut self, ev: ProcEvent) -> &KernelLifecycleEvent {
        self.ingest_event(ev, SourceMechanism::WireTapAfPacket)
    }

    /// Ingest a kernel-pushed socket send (`SockSendTracepoint`). The event
    /// fires in the sending task's context, so the probe anchors
    /// `current_pid` exactly as it anchors a `connect()` initiation: pidfd,
    /// measurement, and the instance's start tick no later than the event's
    /// kernel time — otherwise the pid was recycled and the event is
    /// recorded unbound.
    pub fn ingest_send_event(&mut self, ev: ProcEvent) -> &KernelLifecycleEvent {
        self.ingest_event(ev, SourceMechanism::SockSendTracepoint)
    }

    /// Ingest a fanotify file event (`Fanotify`). The kernel handed the
    /// probe a pidfd it created for the acting process itself; the probe
    /// measures the instance **through that pidfd** (alive before and after
    /// the read) instead of opening one by number, and still applies the
    /// start-tick rule against the read stamp. Without a pidfd (the process
    /// had gone) the event is recorded unbound: existence, no identity.
    #[cfg(target_os = "linux")]
    pub fn ingest_file_event(
        &mut self,
        obs: crate::fanotify::FileObservation,
    ) -> &KernelLifecycleEvent {
        let seq = self.next_seq();
        let ev = obs.event;
        let subject = ev.kind.subject_pid();
        let anchor = self.clock_anchor;
        let bound = obs
            .pidfd
            .and_then(|pidfd| self.measure_through(&pidfd).ok())
            .filter(|p| instance_started_no_later_than(p, ev.timestamp_ns, anchor.as_ref()));
        let (attribution, claimed_decision_id) = subject
            .map(|pid| self.attribution_for(pid))
            .unwrap_or((AgentAttribution::NotEstablished, None));
        self.queue_kernel_event(KernelLifecycleEvent {
            cgroup: crate::observed::CgroupSample::NotSampled,
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: self.probe_id.clone(),
            mechanism: SourceMechanism::Fanotify,
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

    /// Measure the instance a kernel-created pidfd refers to: alive before
    /// the procfs reads and still alive after them, or nothing.
    #[cfg(target_os = "linux")]
    fn measure_through(&self, pidfd: &crate::linux::PidFd) -> Result<ObservedProcess, ProbeError> {
        let pid = pidfd.pid();
        if !pidfd.is_alive()? {
            return Err(ProbeError::InstanceEnded { pid });
        }
        let process = self.read_process(pid)?;
        if !pidfd.is_alive()? {
            return Err(ProbeError::InstanceEnded { pid });
        }
        Ok(process)
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
            (KernelLifecycleKind::SocketState { .. }, Some(pid))
            | (KernelLifecycleKind::SocketSend { .. }, Some(pid))
            | (KernelLifecycleKind::ProcessSpawn { .. }, Some(pid))
            | (KernelLifecycleKind::ProcessExec { .. }, Some(pid))
            | (KernelLifecycleKind::CgroupCreated { .. }, Some(pid))
            | (KernelLifecycleKind::CgroupRemoved { .. }, Some(pid))
            | (KernelLifecycleKind::CgroupAttach { .. }, Some(pid)) => {
                let anchor = self.clock_anchor;
                self.try_anchor(pid)
                    .filter(|p| instance_started_no_later_than(p, ev.timestamp_ns, anchor.as_ref()))
            }
            _ => None,
        };
        let (attribution, claimed_decision_id) = subject
            .map(|pid| self.attribution_for(pid))
            .unwrap_or((AgentAttribution::NotEstablished, None));
        self.queue_kernel_event(KernelLifecycleEvent {
            // The kernel's own sample, copied, never derived.
            cgroup: ev.cgroup,
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

    fn queue_kernel_event(&mut self, event: KernelLifecycleEvent) {
        self.pending_kernel_bytes = self
            .pending_kernel_bytes
            .saturating_add(Self::event_bytes(&event));
        self.pending_kernel_events.push(event);
    }

    fn event_bytes(event: &KernelLifecycleEvent) -> usize {
        serde_json::to_vec(event).map_or(usize::MAX, |bytes| bytes.len())
    }

    /// The live driver checks this BEFORE polling a source. Unread records
    /// remain in their kernel queue, whose own loss accounting still applies.
    pub fn live_event_capacity_available(&self) -> bool {
        self.pending_kernel_events.len() < MAX_LIVE_PENDING_EVENTS
            && self.pending_kernel_bytes
                <= MAX_LIVE_PENDING_BYTES.saturating_sub(LIVE_EVENT_RESERVE_BYTES)
    }

    /// A source could not be completely drained for the candidate window.
    /// Applied to the outgoing live batch after normal integrity readings, so
    /// a successful gate query cannot erase a queue/read failure.
    pub fn record_source_fault(&mut self, mechanism: SourceMechanism) {
        if !self.live_faults.contains(&mechanism) {
            self.live_faults.push(mechanism);
        }
        self.bound_by_exec.clear();
    }

    /// Finalize the live sensor stream through ONE common monotonic cutoff.
    /// Capture and clock-anchor that cutoff before draining any source. The
    /// driver leaves a matching-window holdback so ordinary asynchronous
    /// delivery can settle; a late record behind a finalized cutoff still
    /// withdraws coverage rather than repairing already published history.
    ///
    /// Matched connector/scheduler execs straddling the cutoff are retained
    /// together, and the coverage frontier retreats before their first event.
    /// Bindings were captured at ingestion and are moved verbatim. Published
    /// sequence numbers are assigned only now, avoiding gaps from deferred
    /// records. This live-only API must not be mixed with legacy `batch()` on
    /// one probe run; that API's fixture semantics are unchanged.
    pub fn batch_through(
        &mut self,
        batch_id: [u8; 16],
        claimed_from_ms: u64,
        claimed_to_ms: u64,
        cutoff_ns: Option<u64>,
    ) -> ObservationBatch {
        let mut batch = self.batch(batch_id, claimed_from_ms, claimed_to_ms, vec![]);
        let mut faults = std::mem::take(&mut self.live_faults);
        if let (Some(mut frontier), Some(anchor)) = (cutoff_ns, self.clock_anchor) {
            if frontier >= anchor.monotonic_ns {
                faults.extend(batch.active_mechanisms.iter().copied());
                frontier = anchor.monotonic_ns.saturating_sub(1_000_000);
            }
            let both = batch
                .active_mechanisms
                .contains(&SourceMechanism::ProcConnector)
                && batch
                    .active_mechanisms
                    .contains(&SourceMechanism::SchedTracepoint);
            if both {
                // Each connector exec chooses its nearest scheduler mate under
                // the existing exact (pid,tgid,50 ms) comparison. Neither the
                // match window nor the collector's strict check is changed.
                let mut sched: HashMap<(u32, u32), Vec<u64>> = HashMap::new();
                for event in &batch.kernel_events {
                    if event.mechanism == SourceMechanism::SchedTracepoint {
                        if let Some(key) = exec_key(&event.kind) {
                            sched
                                .entry(key)
                                .or_default()
                                .push(event.kernel_timestamp_ns);
                        }
                    }
                }
                for times in sched.values_mut() {
                    times.sort_unstable();
                }
                let mut pairs = Vec::new();
                for event in &batch.kernel_events {
                    if event.mechanism != SourceMechanism::ProcConnector {
                        continue;
                    }
                    let Some(times) = exec_key(&event.kind).and_then(|key| sched.get(&key)) else {
                        continue;
                    };
                    let stamp = event.kernel_timestamp_ns;
                    let position = times.partition_point(|time| *time < stamp);
                    let mate = times
                        .get(position)
                        .into_iter()
                        .chain(position.checked_sub(1).and_then(|p| times.get(p)))
                        .min_by_key(|time| time.abs_diff(stamp));
                    if let Some(mate) = mate.filter(|time| {
                        time.abs_diff(stamp) <= crate::divergence::DEFAULT_MATCH_WINDOW_NS
                    }) {
                        pairs.push((stamp.min(*mate), stamp.max(*mate)));
                    }
                }
                loop {
                    let previous = frontier;
                    for (first, last) in &pairs {
                        if *first <= frontier && *last > frontier {
                            // Signed coverage has millisecond resolution.
                            // Retreat a whole millisecond so a retained event
                            // cannot still round into the claimed interval.
                            frontier = frontier.min(first.saturating_sub(1_000_000));
                        }
                    }
                    frontier = align_cutoff_before_anchor(frontier, anchor.monotonic_ns);
                    if previous == frontier {
                        break;
                    }
                }
            }
            frontier = align_cutoff_before_anchor(frontier, anchor.monotonic_ns);
            let late = self.live_finalized_ns.is_some_and(|last| {
                frontier < last
                    || batch
                        .kernel_events
                        .iter()
                        .any(|e| e.kernel_timestamp_ns <= last)
            });
            let close = anchor.wall_ms(frontier).min(claimed_to_ms);
            if late || close < claimed_from_ms {
                faults.extend(batch.active_mechanisms.iter().copied());
            }
            batch.claimed_to_ms = close.max(claimed_from_ms);
            let (ready, pending): (Vec<_>, Vec<_>) = std::mem::take(&mut batch.kernel_events)
                .into_iter()
                .partition(|event| event.kernel_timestamp_ns <= frontier);
            batch.kernel_events = ready;
            self.pending_kernel_bytes = pending
                .iter()
                .map(Self::event_bytes)
                .fold(0usize, usize::saturating_add);
            self.pending_kernel_events = pending;
            if self
                .pending_kernel_events
                .iter()
                .any(|event| anchor.wall_ms(event.kernel_timestamp_ns) <= batch.claimed_to_ms)
            {
                // Includes boot-origin saturation and unrepresentable clock
                // edges: retained evidence may not sit inside Active coverage.
                faults.extend(batch.active_mechanisms.iter().copied());
            }
            self.live_finalized_ns = Some(
                self.live_finalized_ns
                    .map_or(frontier, |last| last.max(frontier)),
            );
        } else {
            // No usable common clock/cutoff: preserve every captured record,
            // but make no positive coverage claim on that batch.
            faults.extend(batch.active_mechanisms.iter().copied());
        }
        if self.pending_kernel_bytes > MAX_LIVE_PENDING_BYTES
            || self.pending_kernel_events.len() > MAX_LIVE_PENDING_EVENTS
        {
            faults.extend(batch.active_mechanisms.iter().copied());
        }
        for mechanism in SourceMechanism::canonical_set(faults) {
            match batch
                .mechanism_integrity
                .iter_mut()
                .find(|r| r.mechanism == mechanism)
            {
                Some(report) => report.integrity = MechanismIntegrity::Unverifiable,
                None => batch.mechanism_integrity.push(MechanismIntegrityReport {
                    mechanism,
                    integrity: MechanismIntegrity::Unverifiable,
                }),
            }
        }
        let first = self.live_published_seq + 1;
        for event in &mut batch.kernel_events {
            self.live_published_seq += 1;
            event.probe_seq = self.live_published_seq;
        }
        (batch.probe_seq_first, batch.probe_seq_last) = if batch.kernel_events.is_empty() {
            (self.live_published_seq, self.live_published_seq)
        } else {
            (first, self.live_published_seq)
        };
        batch
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
        self.pending_kernel_bytes = 0;
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
            mechanism_integrity: self.mechanism_integrity_reports(),
            claimed_from_ms,
            claimed_to_ms,
            observations,
            kernel_events,
            clock_anchor: self.clock_anchor,
        }
    }
}

fn exec_key(kind: &KernelLifecycleKind) -> Option<(u32, u32)> {
    match kind {
        KernelLifecycleKind::Exec { pid, tgid } => Some((*pid, *tgid)),
        KernelLifecycleKind::ProcessExec { pid, .. } => Some((*pid, *pid)),
        _ => None,
    }
}

fn align_cutoff_before_anchor(frontier: u64, anchor_ns: u64) -> u64 {
    // wall_ms() rounds older stamps toward the anchor. A cutoff between its
    // millisecond boundaries would leave retained records inside the inclusive
    // signed coverage. Round DOWN on the monotonic axis, never widen coverage.
    let remainder = anchor_ns.saturating_sub(frontier) % 1_000_000;
    if remainder == 0 {
        frontier
    } else {
        frontier.saturating_sub(1_000_000 - remainder)
    }
}

/// `pid_start_time_ticks` (boot-clock ticks, `/proc/<pid>/stat`) is not
/// later than the event's kernel stamp (`CLOCK_MONOTONIC`). With an anchor
/// the start is converted into the event clock through the anchor's
/// boot−monotonic offset; without one the two clocks are assumed to
/// coincide (true unless the host has suspended since boot). The tick
/// (`CLK_TCK`, usually 10 ms) is the resolution, and the start is taken at
/// the *beginning* of its tick so a start inside the event's tick still
/// passes — pid reuse within one tick is not excluded by time alone.
pub fn instance_started_no_later_than(
    p: &ObservedProcess,
    event_ns: u64,
    anchor: Option<&BootClockAnchor>,
) -> bool {
    let start_ns = match anchor {
        Some(a) => a.start_ticks_to_ns(p.process.pid_start_time_ticks),
        None => p
            .process
            .pid_start_time_ticks
            .saturating_mul(1_000_000_000 / clk_tck()),
    };
    start_ns <= event_ns
}

/// Clock ticks per second on this host (`sysconf(_SC_CLK_TCK)`).
#[cfg(target_os = "linux")]
pub fn clk_tck() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 {
        v as u64
    } else {
        100
    }
}

#[cfg(not(target_os = "linux"))]
pub fn clk_tck() -> u64 {
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

            container: None,
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
    fn an_image_hash_is_reused_only_for_the_same_instance_and_the_same_file() {
        let c = CachedImage {
            pid_start_time_ticks: 900_000,
            exe_ino: 4242,
            exe_size: 1_000,
            exe_mtime: (1_700_000_000, 5),
            exe_path: "/opt/agent".into(),
            exe_content_sha256: [7u8; 32],
        };
        assert!(c.still_describes(900_000, 4242, 1_000, (1_700_000_000, 5), "/opt/agent"));
        // Recycled pid: another instance.
        assert!(!c.still_describes(900_001, 4242, 1_000, (1_700_000_000, 5), "/opt/agent"));
        // Exec of another file at the same path.
        assert!(!c.still_describes(900_000, 4243, 1_000, (1_700_000_000, 5), "/opt/agent"));
        // The file was rewritten (size, or only mtime).
        assert!(!c.still_describes(900_000, 4242, 1_001, (1_700_000_000, 5), "/opt/agent"));
        assert!(!c.still_describes(900_000, 4242, 1_000, (1_700_000_000, 6), "/opt/agent"));
        // Another path (bind mount, rename) is not assumed to be the same.
        assert!(!c.still_describes(900_000, 4242, 1_000, (1_700_000_000, 5), "/opt/other"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repeated_measurements_of_one_instance_agree_and_do_not_rehash_a_stable_image() {
        let probe = ProcfsProbe::new("probe-self");
        let pid = std::process::id();
        let a = probe.measure(pid).unwrap();
        assert_eq!(probe.image_cache.borrow().len(), 1);
        let cached = probe.image_cache.borrow().get(&pid).cloned().unwrap();
        let b = probe.measure(pid).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            probe.image_cache.borrow().get(&pid).cloned().unwrap(),
            cached
        );
        // A poisoned cache entry for a different inode is not used.
        probe
            .image_cache
            .borrow_mut()
            .get_mut(&pid)
            .unwrap()
            .exe_ino += 1;
        probe
            .image_cache
            .borrow_mut()
            .get_mut(&pid)
            .unwrap()
            .exe_content_sha256 = [0xee; 32];
        let c = probe.measure(pid).unwrap();
        assert_eq!(
            c.exe_content_sha256, a.exe_content_sha256,
            "re-hashed, not trusted"
        );
    }

    #[test]
    fn kernel_exit_after_loss_is_not_attributed_to_an_earlier_exec() {
        let mut probe = ProcfsProbe::new("probe-1");
        // Simulate an exec that was bound (inject the binding directly, as a
        // live anchor would have).
        probe.bound_by_exec.insert(77, fake_process(77));
        probe.record_lost_events(1);
        let ev = probe.ingest_kernel_event(ProcEvent {
            cgroup: crate::observed::CgroupSample::NotSampled,
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
            cgroup: crate::observed::CgroupSample::NotSampled,
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
            cgroup: crate::observed::CgroupSample::NotSampled,
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
