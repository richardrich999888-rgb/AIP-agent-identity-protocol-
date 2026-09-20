//! What the observer saw — `ObservedExecution`, kernel lifecycle events, and
//! the unsigned `ObservationBatch` a host-side probe hands to the collector.
//!
//! Nothing in this module can be signed. Signing lives in [`crate::attest`]
//! and belongs to the collector, which is off-host by construction.
//!
//! # Protocol version 2 (Stage 6.5)
//!
//! Version 1 (Stage 3) carried procfs-polled observations with no statement
//! of *how* they were obtained. Version 2 adds, inside the signed encoding:
//! the [`SourceMechanism`] of every observation; kernel-pushed lifecycle
//! events ([`KernelLifecycleEvent`]) with their kernel CPU and timestamp;
//! socket-level effects; and per-probe run/sequence/loss fields on the batch
//! so restarts and dropped events are visible to the collector. Version 1
//! records are refused by every verifier and by the collector.

use aip_crypto::sha256;
use aip_types::canonical::*;
use aip_types::{ContainerIdentity, ExecutionBinding, ExecutionMatch, ProcessInstance};
use serde::{Deserialize, Serialize};

use crate::health::MechanismIntegrity;

/// Domain tag leading the canonical encoding of an [`ObservedExecution`].
pub const OBSERVED_EXECUTION_DOMAIN: &str = "SYNTRIASS/GHOST/OBSERVED_EXECUTION/v1";
/// Domain tag leading the canonical encoding of an [`ObservationBatch`].
pub const OBSERVATION_BATCH_DOMAIN: &str = "SYNTRIASS/GHOST/OBSERVATION_BATCH/v1";
/// Domain tag leading the canonical encoding of the observer-measured process
/// facts only (excludes every claimed field).
pub const OBSERVED_PROCESS_DOMAIN: &str = "SYNTRIASS/GHOST/OBSERVED_PROCESS/v1";
/// Domain tag leading the canonical encoding of a [`KernelLifecycleEvent`].
pub const KERNEL_EVENT_DOMAIN: &str = "SYNTRIASS/GHOST/KERNEL_EVENT/v1";
/// Protocol version of every structure in this crate.
///
/// - `1` Stage 3: polled observations, no provenance.
/// - `2` Stage 6.5: `SourceMechanism` per observation, kernel lifecycle
///   events, socket effects, probe run/sequence/loss fields.
/// - `3` PR3 A-3: `ObservationBatch.active_mechanisms` (which sources the
///   probe declares live over the batch window) and
///   `SensorHealth.covered_by` (the intersection over the coverage epoch),
///   so a verifier can read per-mechanism coverage from signed bytes
///   instead of inferring it from whether events happened to occur.
/// - `4` Stage 7b: `KernelLifecycleKind::SocketState`, batch `clock_anchor`,
///   `AttestedBatch.attested_at_ms`.
/// - `5` Stage 7c: `ProcessSpawn` / `ProcessExec`, anchor `monotonic_ns` and
///   `clk_tck`.
/// - `6` Gate 2: `SourceMechanism::WireTapAfPacket`, `WireSegment` with
///   `WireDirection` and the kernel realtime capture stamp.
/// - `7` Gate 3: `SourceMechanism::SockSendTracepoint`, `SocketSend`.
/// - `8` Gate 4: `SourceMechanism::Fanotify`, `FileEvent`.
/// - `10` Observation integrity for the two-host deployment:
///   `ObservationBatch.mechanism_integrity` — the probe's per-mechanism
///   integrity finding (`MechanismIntegrityReport`) inside the attested
///   bytes, so the off-host collector can sign `IntegrityUnknown`.
/// - `11` Independent container identity (matrix row B3):
///   `ObservedProcess.container` — the kernel's namespace placement as the
///   *observer* read it, inside the attested bytes. `ExecutionBinding` has
///   carried this since v2, but only the authorizing side filled it in, so
///   a "different container" claim rested on one party's word. It is in the
///   full encoding and deliberately **not** in
///   `ObservedProcess::identity_bytes`, because an observer that cannot
///   read the namespaces would otherwise produce a different identity
///   digest for the same process and manufacture a divergence out of a read
///   failure; `ObservedProcess::compare_container` answers
///   `ContainerNotComparable` instead.
/// - `12` Attested clock discipline (matrix row E4):
///   `SensorHealth.clock` — the kernel's `ntp_adjtime` view of whether the
///   collector's wall clock was being steered when it signed, and the
///   kernel's bound on its error. The collector stamps every attested batch
///   and every health record, so an undisciplined clock does not produce one
///   wrong timestamp: it produces an archive that is wrong *together* and
///   self-consistent, which nothing in the sealed bytes afterwards reveals.
///   The reading existed before this version as a startup gate and a log
///   line, and a log is not evidence a verifier holds. `None` means **not
///   read**, never "fine".
///
/// Earlier versions never left this branch; all are refused.
pub const OBSERVE_PROTOCOL_VERSION: u16 = 12;

/// Kernel TCP state bytes (`include/net/tcp_states.h`), as they appear in
/// `/proc/net/tcp` and in the `sock:inet_sock_set_state` tracepoint.
pub mod tcp_state {
    pub const ESTABLISHED: u8 = 1;
    pub const SYN_SENT: u8 = 2;
    pub const SYN_RECV: u8 = 3;
    pub const FIN_WAIT1: u8 = 4;
    pub const FIN_WAIT2: u8 = 5;
    pub const TIME_WAIT: u8 = 6;
    pub const CLOSE: u8 = 7;
    pub const CLOSE_WAIT: u8 = 8;
    pub const LAST_ACK: u8 = 9;
    pub const LISTEN: u8 = 10;
    pub const CLOSING: u8 = 11;
    pub const NEW_SYN_RECV: u8 = 12;
}

// ─── Provenance ───

/// How an observation was obtained. Inside the signed bytes, so it cannot be
/// rewritten after attestation — and gated at the collector by the probe
/// registry, so a host-side party cannot label its own report as kernel
/// provenance (see `attest::CollectorSigner::register_probe`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceMechanism {
    /// The probe read `/proc/<pid>/{stat,exe}` for a pid it was told about.
    /// Host-reported: no liveness anchor, no event, root-forgeable.
    ProcfsPoll,
    /// As `ProcfsPoll`, but bracketed by a `pidfd` the kernel bound to the
    /// process *instance*: the reads are proven to refer to one instance
    /// that was still alive when they completed. Content is still procfs.
    PidFdAnchored,
    /// A fork/exec/exit event **pushed by the kernel** over the netlink
    /// process-event connector, carrying the kernel's own CPU and timestamp.
    /// Existence and order of the event are kernel-generated; the identity
    /// of the process behind it is established only if a `PidFdAnchored`
    /// measurement could be taken before it exited.
    ProcConnector,
    /// A socket-to-process association read from the kernel socket tables
    /// (`/proc/net/{tcp,tcp6,udp,udp6}`) joined to `/proc/<pid>/fd`.
    /// **Socket-level only** — not packet-level, not wire-level.
    ProcNetTable,
    /// A TCP socket **state transition pushed by the kernel** through the
    /// `sock:inet_sock_set_state` tracepoint, sampled with `perf_event_open`
    /// (no eBPF). Carries the kernel's own timestamp (`CLOCK_BOOTTIME`), CPU,
    /// the task current at the transition, old/new state, family, protocol
    /// and endpoints. Existence, order and time of the transition are
    /// kernel-generated; the process *instance* behind it is established
    /// only for syscall-driven transitions (`CLOSE → SYN_SENT`) and only if a
    /// `PidFdAnchored` measurement of that task succeeded and pre-dated the
    /// event in kernel time. Loss is signalled by the perf ring
    /// (`PERF_RECORD_LOST`). Not packet-level; nothing about payload.
    SockStateTracepoint,
    /// Process creation and image execution **pushed by the kernel** through
    /// the `sched:sched_process_fork` and `sched:sched_process_exec`
    /// tracepoints, sampled with `perf_event_open` (no eBPF). Fork fires in
    /// the parent's task context (the actor is attributable); exec fires in
    /// the new image's context with the kernel's own `filename`. The
    /// executed *content* is not in the event: the probe hashes
    /// `/proc/<pid>/exe` under a pidfd anchor. Loss via `PERF_RECORD_LOST`.
    SchedTracepoint,
    /// A copy of a frame the kernel handed to a network device or took from
    /// one, delivered through an `AF_PACKET` socket (`packet_rcv` on
    /// receive, `dev_queue_xmit_nit` on transmit), stamped by the kernel
    /// (`SO_TIMESTAMPNS`, realtime clock) and counted for loss
    /// (`PACKET_STATISTICS`). **Headers only**: IP addresses, TCP ports,
    /// flags, sequence numbers and the payload *length*; no payload byte is
    /// copied, hashed or kept (I23). The device layer knows no process: a
    /// wire segment carries no pid and is never bound to an instance. The
    /// same code produces the same evidence on a mirror-port or TAP host
    /// outside the observed host's root; on the observed host it is as
    /// root-forgeable as every other source here. No eBPF, no XDP.
    WireTapAfPacket,
    /// A send of application bytes on a socket **pushed by the kernel**
    /// through the `sock:sock_send_length` tracepoint, sampled with
    /// `perf_event_open` (no eBPF). Fires in `sock_sendmsg` in the
    /// **sending task's** context with the socket's kernel identity `sk`,
    /// family, protocol, the byte count the kernel accepted and the flags.
    /// The count, never the bytes and never a hash of them (I23). The
    /// instance behind it is established only if a `PidFdAnchored`
    /// measurement of the task succeeded under the start-tick rule. Loss
    /// via `PERF_RECORD_LOST`.
    SockSendTracepoint,
    /// A file event **queued by the kernel** through `fanotify`
    /// (`FAN_CLOSE_WRITE`, `FAN_MODIFY`) on a marked mount, with a pidfd the
    /// kernel created from the event's own process reference
    /// (`FAN_REPORT_PIDFD`): the acting instance is bound by the kernel,
    /// not by a pid number. The probe resolves the object descriptor to
    /// the kernel's current path and inode and reads nothing from the
    /// file. Events carry no kernel timestamp; the probe stamps them at
    /// read time. Loss via `FAN_Q_OVERFLOW`. No eBPF, no syscall tracing.
    Fanotify,
}

impl SourceMechanism {
    pub fn code(&self) -> u8 {
        match self {
            SourceMechanism::ProcfsPoll => 0x01,
            SourceMechanism::PidFdAnchored => 0x02,
            SourceMechanism::ProcConnector => 0x03,
            SourceMechanism::ProcNetTable => 0x04,
            SourceMechanism::SockStateTracepoint => 0x05,
            SourceMechanism::SchedTracepoint => 0x06,
            SourceMechanism::WireTapAfPacket => 0x07,
            SourceMechanism::SockSendTracepoint => 0x08,
            SourceMechanism::Fanotify => 0x09,
        }
    }

    /// The kernel generated and delivered this event itself (as opposed to
    /// the probe reading a kernel table at a moment of its choosing).
    pub fn is_kernel_pushed(&self) -> bool {
        matches!(
            self,
            SourceMechanism::ProcConnector
                | SourceMechanism::SockStateTracepoint
                | SourceMechanism::SchedTracepoint
                | SourceMechanism::WireTapAfPacket
                | SourceMechanism::SockSendTracepoint
                | SourceMechanism::Fanotify
        )
    }

    /// Kernel-pushed coverage of **process lifecycle** (fork/exec/exit).
    /// Only this can support a statement that a process instance never
    /// appeared. The socket-state stream says nothing about processes; the
    /// sched fork/exec stream carries no exit and is deliberately not
    /// accepted here yet — lifecycle coverage means the connector.
    pub fn covers_process_lifecycle(&self) -> bool {
        matches!(self, SourceMechanism::ProcConnector)
    }

    /// Does this mechanism's delivery pass through the kernel's per-tracepoint
    /// eBPF submission gate — `perf_trace_run_bpf_submit()`, keyed on the
    /// `trace_event_call`?
    ///
    /// These are the mechanisms sampled with `perf_event_open` on a
    /// tracepoint. Any eBPF program attached to the same tracepoint by any
    /// process runs before the sample is submitted, and a program returning
    /// zero suppresses the sample for **every** perf consumer of that
    /// tracepoint host-wide, with no dropped-record accounting. That is the
    /// observation-integrity finding (`docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`):
    /// a `CAP_BPF` process, or a co-resident eBPF observer, can blind these
    /// mechanisms silently.
    ///
    /// It is therefore false for the kernel-pushed mechanisms that reach the
    /// observer by a different facility — the netlink process connector, the
    /// `fanotify` queue, and the `AF_PACKET` device tap — none of which is
    /// gated by a tracepoint's eBPF program array. Two mechanisms that both
    /// return true here are **not** independent observers of one another: a
    /// single gate closes both. See `docs/OBSERVATION_MECHANISM_INDEPENDENCE.md`.
    pub fn shares_perf_tracepoint_gate(&self) -> bool {
        matches!(
            self,
            SourceMechanism::SchedTracepoint
                | SourceMechanism::SockStateTracepoint
                | SourceMechanism::SockSendTracepoint
        )
    }

    /// Kernel-pushed **and** not exposed to the per-tracepoint eBPF submission
    /// gate: the observer's evidence that an event was delivered by the kernel
    /// through a facility a co-resident eBPF program cannot silently suppress.
    /// This is the independence property the reconciler requires before it
    /// will treat kernel-pushed coverage as trustworthy for a statement about
    /// what did *not* happen.
    pub fn is_gate_independent_kernel_pushed(&self) -> bool {
        self.is_kernel_pushed() && !self.shares_perf_tracepoint_gate()
    }

    /// The measurement is proven to refer to one process instance.
    pub fn is_instance_anchored(&self) -> bool {
        matches!(self, SourceMechanism::PidFdAnchored)
    }

    pub const ALL: [SourceMechanism; 9] = [
        SourceMechanism::ProcfsPoll,
        SourceMechanism::PidFdAnchored,
        SourceMechanism::ProcConnector,
        SourceMechanism::ProcNetTable,
        SourceMechanism::SockStateTracepoint,
        SourceMechanism::SchedTracepoint,
        SourceMechanism::WireTapAfPacket,
        SourceMechanism::SockSendTracepoint,
        SourceMechanism::Fanotify,
    ];

    /// Canonical ordering of a mechanism set: by code, deduplicated. Used
    /// wherever a set of mechanisms enters signed bytes, so two equal sets
    /// always encode identically.
    pub fn canonical_set(mut v: Vec<SourceMechanism>) -> Vec<SourceMechanism> {
        v.sort_by_key(|m| m.code());
        v.dedup();
        v
    }
}

// ─── Agent attribution ───

/// Whether the observer could tie the process it measured to an AIP identity.
///
/// The observer reads the kernel's view of a process. It can measure the
/// process instance and the executable's contents. It **cannot** determine an
/// AIP-ID: that requires proof of key possession, which is an authority
/// question, not an observation. There is deliberately no `Verified` variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentAttribution {
    /// No AIP identity was associated with the observed process.
    NotEstablished,
    /// An AIP-ID was *claimed* to the observer by the named source. The
    /// observer attests that the claim was made, never that it is true.
    Claimed {
        agent_id: String,
        /// Where the claim came from, e.g. "agent-registration",
        /// "orchestrator". Free text; part of the signed bytes so it cannot
        /// be rewritten later, but it confers no trust.
        claim_source: String,
    },
}

impl AgentAttribution {
    pub fn claimed_agent_id(&self) -> Option<&str> {
        match self {
            AgentAttribution::NotEstablished => None,
            AgentAttribution::Claimed { agent_id, .. } => Some(agent_id),
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            AgentAttribution::NotEstablished => put_u8(buf, 0x00),
            AgentAttribution::Claimed {
                agent_id,
                claim_source,
            } => {
                put_u8(buf, 0x01);
                put_str(buf, agent_id);
                put_str(buf, claim_source);
            }
        }
    }
}

// ─── Sockets ───

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketProtocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl SocketProtocol {
    fn code(&self) -> u8 {
        match self {
            SocketProtocol::Tcp => 0x01,
            SocketProtocol::Tcp6 => 0x02,
            SocketProtocol::Udp => 0x03,
            SocketProtocol::Udp6 => 0x04,
        }
    }
}

/// One end of a socket as the kernel table reports it. IPv4 addresses occupy
/// the first four bytes with `is_v6 == false`; the flag is encoded so a v4
/// address zero-padded to 16 bytes can never collide with a v6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SocketEndpoint {
    pub addr: [u8; 16],
    pub is_v6: bool,
    pub port: u16,
}

impl SocketEndpoint {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, u8::from(self.is_v6));
        buf.extend_from_slice(&self.addr);
        put_u16(buf, self.port);
    }
}

/// Which way a captured frame was travelling, from the `AF_PACKET`
/// `sll_pkttype`: `PACKET_OUTGOING` is a frame the host is transmitting,
/// `PACKET_HOST` one addressed to it; everything else (broadcast, multicast,
/// other-host in promiscuous mode) is `Other`. Recorded, never inferred from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireDirection {
    Outgoing,
    Incoming,
    Other,
}

impl WireDirection {
    fn code(&self) -> u8 {
        match self {
            WireDirection::Outgoing => 0x01,
            WireDirection::Incoming => 0x02,
            WireDirection::Other => 0x03,
        }
    }
}

// ─── Observed effect ───

/// The kind of effect the observer actually recorded.
///
/// Every variant has an implemented observation path behind it. There is no
/// packet-level, wire-level, filesystem or syscall variant, because no such
/// sensor exists in this crate; a variant with no sensor would be a claim.
/// Per I23, `SocketObserved` is **metadata** (addresses, ports, kernel socket
/// state) and never application payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservedEffect {
    /// The observer measured a live process at this instant.
    ProcessPresent,
    /// The observer previously measured this instance and now finds it gone.
    /// Absence of the instance is a fact about the observer's own sampling;
    /// it says nothing about what the process did while it existed.
    ProcessNoLongerPresent,
    /// A socket owned by the measured process instance, as the kernel socket
    /// table reported it at measurement time. Socket-level only.
    SocketObserved {
        protocol: SocketProtocol,
        local: SocketEndpoint,
        remote: SocketEndpoint,
        /// Kernel TCP/UDP state byte from the table (e.g. `0x0A` = LISTEN).
        state: u8,
        /// Kernel socket inode — the join key between `/proc/net/*` and
        /// `/proc/<pid>/fd`.
        inode: u64,
    },
}

impl ObservedEffect {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            ObservedEffect::ProcessPresent => put_u8(buf, 0x01),
            ObservedEffect::ProcessNoLongerPresent => put_u8(buf, 0x02),
            ObservedEffect::SocketObserved {
                protocol,
                local,
                remote,
                state,
                inode,
            } => {
                put_u8(buf, 0x03);
                put_u8(buf, protocol.code());
                local.encode(buf);
                remote.encode(buf);
                put_u8(buf, *state);
                put_u64(buf, *inode);
            }
        }
    }
}

// ─── Observed process identity ───

/// Exactly the process facts the observer measured itself.
///
/// This is the subset of [`ExecutionBinding`] the observer can establish
/// without trusting anyone: the process instance (pid, start ticks, boot id)
/// and the SHA-256 of the executable's contents. `exe_path` is context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedProcess {
    pub process: ProcessInstance,
    pub exe_content_sha256: [u8; 32],
    pub exe_path: String,
    /// The kernel's container placement of this process, when the observer
    /// could read it (B3, protocol 11).
    ///
    /// `None` means **not observed**, never "not in a container". An
    /// observer that cannot read `/proc/<pid>/ns/*` — no permission, a
    /// kernel that withholds them, a process that exited first — records
    /// `None` and says so, because the alternative is a blind observer
    /// asserting a placement it never saw.
    ///
    /// Why this exists on the *observed* side: `ExecutionBinding` has
    /// carried container identity since v2, but only the party that
    /// authorized the execution filled it in. Until now the observer could
    /// not assert the placement independently, so a claim that two
    /// workloads were in different containers rested on one side's word.
    /// With this field both sides record what the kernel told them, and
    /// [`ObservedProcess::compare_container`] says plainly when they cannot
    /// be compared.
    #[serde(default)]
    pub container: Option<ContainerIdentity>,
}

impl ObservedProcess {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.process.pid);
        put_u64(buf, self.process.pid_start_time_ticks);
        buf.extend_from_slice(&self.process.boot_id);
        buf.extend_from_slice(&self.exe_content_sha256);
        put_str(buf, &self.exe_path);
        // Full encoding: namespaces and the cgroup id. This is the attested
        // form, so what the observer saw of the placement is signed and
        // non-repudiable — including the fact that it saw nothing (a `0`
        // discriminant), which is itself evidence about the observer.
        aip_types::put_container(buf, &self.container, true);
    }

    /// Domain-tagged encoding of the measured facts only. `exe_path` is
    /// excluded so two spellings of one binary compare equal, matching the
    /// Stage 1 identity rule.
    ///
    /// # Why `container` is *not* here
    ///
    /// An observer that can read `/proc/<pid>/ns/*` and one that cannot
    /// would otherwise produce different identity digests for the very same
    /// process, manufacturing a difference out of a read failure — the
    /// exact error `ExecutionMatch::ContainerNotComparable` exists to
    /// prevent, and which `aip-core` already refuses to make on the
    /// authorized side. Container placement is therefore compared
    /// explicitly, through [`ObservedProcess::compare_container`], where
    /// "one side did not record one" is a distinct answer rather than a
    /// silent inequality. The placement is still attested: it is in
    /// [`Self::encode`], which is what gets signed.
    pub fn identity_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, OBSERVED_PROCESS_DOMAIN);
        put_u16(&mut buf, OBSERVE_PROTOCOL_VERSION);
        put_u32(&mut buf, self.process.pid);
        put_u64(&mut buf, self.process.pid_start_time_ticks);
        buf.extend_from_slice(&self.process.boot_id);
        buf.extend_from_slice(&self.exe_content_sha256);
        buf
    }

    /// Compare the container placement two observations recorded.
    ///
    /// Three outcomes, and the third is the point:
    ///
    /// * both recorded a placement and the namespaces agree → `Same`
    /// * both recorded a placement and they differ → `DifferentContainer`,
    ///   a **positive finding**: these are two workloads
    /// * exactly one side recorded a placement → `ContainerNotComparable`
    ///
    /// The third case is never a divergence. An observer that could not
    /// read the namespaces has told us about its own blindness, not about
    /// the process, and treating that as a difference would let a degraded
    /// observer manufacture an accusation. This mirrors
    /// `ExecutionBinding::compare_execution` on the authorized side, so the
    /// two halves of a reconciliation answer the same question the same
    /// way.
    ///
    /// Only the namespaces are compared. The cgroup id is context: a
    /// cgroup-v1-only host exposes none, and moving a process between
    /// cgroups is not a change of workload.
    pub fn compare_container(&self, other: &ObservedProcess) -> ExecutionMatch {
        match (&self.container, &other.container) {
            (Some(a), Some(b)) if !a.same_namespaces(b) => ExecutionMatch::DifferentContainer,
            (Some(_), None) | (None, Some(_)) => ExecutionMatch::ContainerNotComparable,
            _ => ExecutionMatch::Same,
        }
    }

    pub fn identity_digest(&self) -> [u8; 32] {
        sha256(&self.identity_bytes())
    }

    /// Do the observer's measurements match the process identity inside an
    /// expected/claimed [`ExecutionBinding`]?
    ///
    /// Compares process instance and executable contents only. The binding's
    /// `agent_id` is **not** compared here: the observer never measured it.
    /// Equal PIDs alone can never satisfy this — all three tuple fields and
    /// the executable digest must match.
    pub fn matches_process_of(&self, binding: &ExecutionBinding) -> bool {
        self.process == binding.process && self.exe_content_sha256 == binding.exe_content_sha256
    }
}

// ─── ObservedExecution ───

/// One observation: what the observer measured, how, when, and which claims
/// (if any) were attached to it.
///
/// There is no `permitted`, `authorized`, `allowed`, `safe` or `malicious`
/// field, and there never may be (I19). Authorization is the decision
/// point's authority; interpretation is the reconciler's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedExecution {
    pub version: u16,
    /// Identifier of the host-side probe that took the measurement. Not a
    /// trust anchor — the probe cannot sign anything.
    pub probe_id: String,
    /// The facts the observer measured.
    pub observed: ObservedProcess,
    /// Whether an AIP identity was claimed for this process, and by whom.
    pub attribution: AgentAttribution,
    pub effect: ObservedEffect,
    /// How the measurement was obtained.
    pub mechanism: SourceMechanism,
    /// Correlation hint copied from a claim, when one was supplied. Present
    /// only so the reconciler can join; it carries no authorization meaning
    /// and the observer never reads an `ExpectedExecution`.
    pub claimed_decision_id: Option<[u8; 16]>,
    /// Host wall clock at measurement, Unix ms. **Contextual only** — the
    /// host clock is attacker-controllable under the threat model. Ordering
    /// comes from the collector's sequence, never from this field.
    pub host_wall_clock_ms: u64,
    /// Per-run probe sequence number of this observation (the field name is
    /// historical). Resets on probe restart, which the batch's `probe_run_id`
    /// makes visible; it is not a continuity source on its own.
    pub probe_monotonic_ns: u64,
}

impl ObservedExecution {
    /// Canonical, domain-tagged, injective encoding of the whole observation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, OBSERVED_EXECUTION_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.probe_id);
        self.observed.encode(&mut buf);
        self.attribution.encode(&mut buf);
        self.effect.encode(&mut buf);
        put_u8(&mut buf, self.mechanism.code());
        match &self.claimed_decision_id {
            Some(d) => {
                put_u8(&mut buf, 1);
                buf.extend_from_slice(d);
            }
            None => put_u8(&mut buf, 0),
        }
        put_u64(&mut buf, self.host_wall_clock_ms);
        put_u64(&mut buf, self.probe_monotonic_ns);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

// ─── Kernel lifecycle events ───

/// A process-lifecycle fact as the kernel reported it. The numeric pids are
/// the kernel's; on their own they are **not identity** (I2, I4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelLifecycleKind {
    Fork {
        parent_pid: u32,
        parent_tgid: u32,
        child_pid: u32,
        child_tgid: u32,
    },
    Exec {
        pid: u32,
        tgid: u32,
    },
    Exit {
        pid: u32,
        tgid: u32,
        exit_code: u32,
        exit_signal: u32,
    },
    /// A connector event type this crate does not interpret (uid/gid/sid/
    /// comm/ptrace/coredump). Recorded, never inferred from.
    Other {
        what: u32,
    },
    /// A TCP socket changed state (`sock:inet_sock_set_state`). `sk` is the
    /// kernel's socket identity for the socket's lifetime — the only field
    /// that links the transitions of one socket (the `CLOSE → SYN_SENT`
    /// transition of an outbound connect has no local port yet).
    /// `current_pid` is the task current on the CPU: it names the acting
    /// process **only** for syscall-driven transitions; handshake completions
    /// run in softirq context under whatever task happens to be current.
    SocketState {
        protocol: SocketProtocol,
        local: SocketEndpoint,
        remote: SocketEndpoint,
        old_state: u8,
        new_state: u8,
        sk: u64,
        current_pid: u32,
    },
    /// `sched:sched_process_fork`: `parent_pid` created `child_pid`. Fires in
    /// the parent's context, so the parent is the acting task. `comm`s are
    /// kernel-authored context (16 bytes, lossy UTF-8), never identity.
    ProcessSpawn {
        parent_pid: u32,
        child_pid: u32,
        parent_comm: String,
        child_comm: String,
    },
    /// `sched:sched_process_exec`: task `pid` (formerly `old_pid`) replaced
    /// its image with the kernel-resolved `filename`. Fires in the new
    /// image's context. The path is context; the image's identity is the
    /// content hash the probe takes under a pidfd anchor (`bound`).
    ProcessExec {
        pid: u32,
        old_pid: u32,
        filename: String,
    },
    /// One TCP segment as it crossed a network device (`WireTapAfPacket`):
    /// the headers the kernel copied, and nothing of the payload but its
    /// length. `kernel_realtime_ns` is the kernel's capture stamp on the
    /// **realtime** clock (`SO_TIMESTAMPNS`); the event's
    /// `kernel_timestamp_ns` is the probe's own monotonic dequeue stamp, an
    /// upper bound. A verifier relates the two through the batch's
    /// `clock_anchor`. No task context exists at the device layer: this
    /// kind never names a pid and is never bound.
    WireSegment {
        ifindex: u32,
        direction: WireDirection,
        protocol: SocketProtocol,
        src: SocketEndpoint,
        dst: SocketEndpoint,
        /// TCP flags byte (FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10 …).
        flags: u8,
        seq: u32,
        ack: u32,
        /// Bytes after the TCP header, by the IP length field. Never the
        /// bytes themselves.
        payload_len: u32,
        /// Bytes the kernel delivered for the frame (link header excluded).
        frame_len: u32,
        kernel_realtime_ns: u64,
    },
    /// `sock:sock_send_length`: the task `current_pid` handed `bytes` to the
    /// kernel for send on socket `sk` (`SockSendTracepoint`). Fires in the
    /// caller's context, so `current_pid` is the sender. The endpoint is not
    /// in the event: a verifier resolves it from the state transitions of
    /// the same `sk`. Never the bytes, never a digest of them.
    SocketSend {
        protocol: SocketProtocol,
        sk: u64,
        bytes: u32,
        flags: u32,
        current_pid: u32,
    },
    /// A fanotify event (`Fanotify`): process `pid` acted on the object the
    /// kernel resolved to `path` (`deleted` when the kernel reported the
    /// name as unlinked), with device `dev` and inode `ino`. `mask` is the
    /// kernel's event mask (`FAN_CLOSE_WRITE` = a completed write). The
    /// acting instance is bound through the kernel's own pidfd. Nothing of
    /// the file's content is here or anywhere.
    FileEvent {
        mask: u64,
        pid: u32,
        path: String,
        deleted: bool,
        dev: u64,
        ino: u64,
    },
}

/// TCP flag bits as they appear in `WireSegment::flags`.
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

impl KernelLifecycleKind {
    /// A wire segment that is a SYN without ACK: a connection being opened.
    pub fn is_wire_syn(&self) -> bool {
        matches!(self, KernelLifecycleKind::WireSegment { flags, .. }
            if flags & (tcp_flags::SYN | tcp_flags::ACK) == tcp_flags::SYN)
    }

    /// A wire segment that is a SYN-ACK: the peer accepting.
    pub fn is_wire_syn_ack(&self) -> bool {
        matches!(self, KernelLifecycleKind::WireSegment { flags, .. }
            if flags & (tcp_flags::SYN | tcp_flags::ACK) == tcp_flags::SYN | tcp_flags::ACK)
    }

    /// A file event that is a **completed** write: the object was closed
    /// after being opened for writing (`FAN_CLOSE_WRITE`). A `FAN_MODIFY`
    /// alone is a write in progress.
    pub fn is_file_write(&self) -> bool {
        matches!(self, KernelLifecycleKind::FileEvent { mask, .. }
            if mask & crate::fanotify::FAN_CLOSE_WRITE != 0)
    }

    /// The pid the event is *about* (the child for a fork). For a socket
    /// transition, only `CLOSE → SYN_SENT` — the `connect()` call itself —
    /// runs in the acting task's context; every other transition's current
    /// task is not the socket's owner in general and yields `None`.
    pub fn subject_pid(&self) -> Option<u32> {
        match self {
            KernelLifecycleKind::Fork { child_pid, .. } => Some(*child_pid),
            KernelLifecycleKind::Exec { pid, .. } | KernelLifecycleKind::Exit { pid, .. } => {
                Some(*pid)
            }
            KernelLifecycleKind::Other { .. } => None,
            KernelLifecycleKind::SocketState {
                old_state,
                new_state,
                current_pid,
                ..
            } => {
                if *old_state == tcp_state::CLOSE && *new_state == tcp_state::SYN_SENT {
                    Some(*current_pid)
                } else {
                    None
                }
            }
            // The spawning task is the actor; the child is the *subject of
            // the spawn* (see `spawned_child_pid`), not the actor.
            KernelLifecycleKind::ProcessSpawn { parent_pid, .. } => Some(*parent_pid),
            KernelLifecycleKind::ProcessExec { pid, .. } => Some(*pid),
            // The device layer has no task context.
            KernelLifecycleKind::WireSegment { .. } => None,
            // sendmsg runs in the caller.
            KernelLifecycleKind::SocketSend { current_pid, .. } => Some(*current_pid),
            // The kernel names the acting process on the event.
            KernelLifecycleKind::FileEvent { pid, .. } => Some(*pid),
        }
    }

    /// For a spawn, the child the actor created.
    pub fn spawned_child_pid(&self) -> Option<u32> {
        match self {
            KernelLifecycleKind::ProcessSpawn { child_pid, .. } => Some(*child_pid),
            KernelLifecycleKind::Fork { child_pid, .. } => Some(*child_pid),
            _ => None,
        }
    }

    /// Is this the `connect()` call: `CLOSE → SYN_SENT`?
    pub fn is_connect_initiation(&self) -> bool {
        matches!(self, KernelLifecycleKind::SocketState { old_state, new_state, .. }
            if *old_state == tcp_state::CLOSE && *new_state == tcp_state::SYN_SENT)
    }

    /// Is this the client-side handshake completion: `SYN_SENT → ESTABLISHED`?
    pub fn is_connect_established(&self) -> bool {
        matches!(self, KernelLifecycleKind::SocketState { old_state, new_state, .. }
            if *old_state == tcp_state::SYN_SENT && *new_state == tcp_state::ESTABLISHED)
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            KernelLifecycleKind::Fork {
                parent_pid,
                parent_tgid,
                child_pid,
                child_tgid,
            } => {
                put_u8(buf, 0x01);
                put_u32(buf, *parent_pid);
                put_u32(buf, *parent_tgid);
                put_u32(buf, *child_pid);
                put_u32(buf, *child_tgid);
            }
            KernelLifecycleKind::Exec { pid, tgid } => {
                put_u8(buf, 0x02);
                put_u32(buf, *pid);
                put_u32(buf, *tgid);
            }
            KernelLifecycleKind::Exit {
                pid,
                tgid,
                exit_code,
                exit_signal,
            } => {
                put_u8(buf, 0x03);
                put_u32(buf, *pid);
                put_u32(buf, *tgid);
                put_u32(buf, *exit_code);
                put_u32(buf, *exit_signal);
            }
            KernelLifecycleKind::Other { what } => {
                put_u8(buf, 0x7f);
                put_u32(buf, *what);
            }
            KernelLifecycleKind::SocketState {
                protocol,
                local,
                remote,
                old_state,
                new_state,
                sk,
                current_pid,
            } => {
                put_u8(buf, 0x04);
                put_u8(buf, protocol.code());
                local.encode(buf);
                remote.encode(buf);
                put_u8(buf, *old_state);
                put_u8(buf, *new_state);
                put_u64(buf, *sk);
                put_u32(buf, *current_pid);
            }
            KernelLifecycleKind::ProcessSpawn {
                parent_pid,
                child_pid,
                parent_comm,
                child_comm,
            } => {
                put_u8(buf, 0x05);
                put_u32(buf, *parent_pid);
                put_u32(buf, *child_pid);
                put_str(buf, parent_comm);
                put_str(buf, child_comm);
            }
            KernelLifecycleKind::ProcessExec {
                pid,
                old_pid,
                filename,
            } => {
                put_u8(buf, 0x06);
                put_u32(buf, *pid);
                put_u32(buf, *old_pid);
                put_str(buf, filename);
            }
            KernelLifecycleKind::WireSegment {
                ifindex,
                direction,
                protocol,
                src,
                dst,
                flags,
                seq,
                ack,
                payload_len,
                frame_len,
                kernel_realtime_ns,
            } => {
                put_u8(buf, 0x07);
                put_u32(buf, *ifindex);
                put_u8(buf, direction.code());
                put_u8(buf, protocol.code());
                src.encode(buf);
                dst.encode(buf);
                put_u8(buf, *flags);
                put_u32(buf, *seq);
                put_u32(buf, *ack);
                put_u32(buf, *payload_len);
                put_u32(buf, *frame_len);
                put_u64(buf, *kernel_realtime_ns);
            }
            KernelLifecycleKind::SocketSend {
                protocol,
                sk,
                bytes,
                flags,
                current_pid,
            } => {
                put_u8(buf, 0x08);
                put_u8(buf, protocol.code());
                put_u64(buf, *sk);
                put_u32(buf, *bytes);
                put_u32(buf, *flags);
                put_u32(buf, *current_pid);
            }
            KernelLifecycleKind::FileEvent {
                mask,
                pid,
                path,
                deleted,
                dev,
                ino,
            } => {
                put_u8(buf, 0x09);
                put_u64(buf, *mask);
                put_u32(buf, *pid);
                put_str(buf, path);
                put_u8(buf, u8::from(*deleted));
                put_u64(buf, *dev);
                put_u64(buf, *ino);
            }
        }
    }
}

/// A kernel-pushed lifecycle event, optionally bound to a measured instance.
///
/// `bound` is `Some` only when the probe managed a `PidFdAnchored`
/// measurement of the subject while it was still alive. When it is `None`
/// the event proves *that the kernel reported a pid doing something at a
/// kernel time*, and nothing about which process instance or binary that
/// was — identity is `CANNOT_PROVE` and no method here will pretend
/// otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelLifecycleEvent {
    pub version: u16,
    pub probe_id: String,
    pub mechanism: SourceMechanism,
    pub kind: KernelLifecycleKind,
    /// CPU the kernel reported the event on.
    pub cpu: u32,
    /// Kernel timestamp from the event itself — not the host wall clock, and
    /// not settable by user space. `CLOCK_MONOTONIC` for perf tracepoint
    /// sources and for the connector; comparable only within one boot, and
    /// placed on the wall clock only through a batch's `clock_anchor`.
    pub kernel_timestamp_ns: u64,
    /// Per-run probe sequence number, shared with observations.
    pub probe_seq: u64,
    /// Instance measurement taken while the subject was alive, if any.
    pub bound: Option<ObservedProcess>,
    pub attribution: AgentAttribution,
    pub claimed_decision_id: Option<[u8; 16]>,
}

impl KernelLifecycleEvent {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, KERNEL_EVENT_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.probe_id);
        put_u8(&mut buf, self.mechanism.code());
        self.kind.encode(&mut buf);
        put_u32(&mut buf, self.cpu);
        put_u64(&mut buf, self.kernel_timestamp_ns);
        put_u64(&mut buf, self.probe_seq);
        match &self.bound {
            Some(p) => {
                put_u8(&mut buf, 1);
                p.encode(&mut buf);
            }
            None => put_u8(&mut buf, 0),
        }
        self.attribution.encode(&mut buf);
        match &self.claimed_decision_id {
            Some(d) => {
                put_u8(&mut buf, 1);
                buf.extend_from_slice(d);
            }
            None => put_u8(&mut buf, 0),
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// Identity of the subject, if — and only if — an instance was bound.
    /// A bare pid never yields an identity.
    pub fn subject_identity_digest(&self) -> Option<[u8; 32]> {
        self.bound.as_ref().map(|p| p.identity_digest())
    }

    /// Does the bound instance (if any) match a Stage 1 binding? An unbound
    /// event matches nothing, whatever its pid says.
    pub fn matches_process_of(&self, binding: &ExecutionBinding) -> bool {
        self.bound
            .as_ref()
            .is_some_and(|p| p.matches_process_of(binding))
    }
}

// ─── ObservationBatch ───

/// The probe's integrity finding for one mechanism, carried in the batch.
///
/// Produced on the observed host by the sensor that owns the mechanism (on
/// Linux, `PERF_EVENT_IOC_QUERY_BPF` over the tracepoint's perf rings) and
/// shipped to the off-host collector as a probe claim. It exists so the
/// two-host deployment — where the sensor and the signing key are on
/// different machines — can sign [`crate::ObserverState::IntegrityUnknown`]
/// at all: without it the collector never learns a sampled tracepoint was
/// gated, and a false `Active` follows. The collector treats it as it treats
/// every batch field: it can lower the signed state, never raise it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MechanismIntegrityReport {
    pub mechanism: SourceMechanism,
    pub integrity: MechanismIntegrity,
}

impl MechanismIntegrityReport {
    /// Canonical order: by mechanism code, one report per mechanism (the
    /// first in code order is kept after sorting, so callers that upsert per
    /// mechanism never present a duplicate). Deterministic bytes for the
    /// same findings however the probe collected them.
    pub fn canonical_set(mut reports: Vec<Self>) -> Vec<Self> {
        reports.sort_by_key(|r| r.mechanism.code());
        reports.dedup_by_key(|r| r.mechanism.code());
        reports
    }
}

/// A batch of observations as produced on the observed host.
///
/// **Unsigned by construction.** It carries no observer identity, no key
/// version, no collector sequence number and no chain head: those are
/// collector state that lives off-host, so a compromised host cannot
/// fabricate a position in the attested history. It is the collector that
/// assigns them, in [`crate::attest`].
///
/// What it does carry about the probe — `probe_run_id`, the per-run sequence
/// range, and the loss counter — lets the collector *see* probe restarts,
/// intra-run gaps and dropped events. Those fields are claims the collector
/// checks for consistency; they never widen coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationBatch {
    pub version: u16,
    pub probe_id: String,
    pub batch_id: [u8; 16],
    /// Random per probe start. A change means the probe restarted.
    pub probe_run_id: [u8; 16],
    /// Lowest and highest per-run sequence number in this batch.
    pub probe_seq_first: u64,
    pub probe_seq_last: u64,
    /// Events the probe's source reported as lost since the previous batch.
    /// `None` means the mechanism exposes no loss counter (polling), so "no
    /// loss" is `CANNOT_PROVE`; `Some(0)` is a counted zero.
    pub dropped_events: Option<u64>,
    /// The sources the probe declares were live over this batch's window,
    /// whether or not they produced anything. Canonically ordered. A *claim*,
    /// bounded by the collector's registry; the collector intersects it over
    /// the coverage epoch into signed health so a verifier can tell a
    /// connector-covered window from a poll-only one without inferring it
    /// from event presence.
    pub active_mechanisms: Vec<SourceMechanism>,
    /// The probe's integrity finding per mechanism it checked this cycle
    /// (see [`MechanismIntegrityReport`]). Canonically ordered. A *claim* the
    /// collector absorbs fail-closed: any non-capable finding lowers the
    /// signed state to `IntegrityUnknown`; a `Verified` finding counts only
    /// for a mechanism this batch also declares active. Empty from probes
    /// that check nothing, which then say nothing.
    #[serde(default)]
    pub mechanism_integrity: Vec<MechanismIntegrityReport>,
    /// The interval the probe claims to have been sampling. A *claim*: the
    /// collector decides what coverage it will attest, and a claimed window
    /// never widens attested coverage.
    pub claimed_from_ms: u64,
    pub claimed_to_ms: u64,
    pub observations: Vec<ObservedExecution>,
    pub kernel_events: Vec<KernelLifecycleEvent>,
    /// The probe's sample of the host's realtime, boot and monotonic clocks,
    /// taken back-to-back, so a verifier can place kernel event stamps
    /// (`CLOCK_MONOTONIC`) on the wall clock the decision point uses and
    /// convert process start ticks (boot clock) into the event clock. A **probe claim** about the
    /// host clock: kernel-authored (`clock_gettime`) but the host clock is
    /// attacker-controllable under the threat model, so any placement
    /// derived from it is `Attested` at most. `None` when the probe has no
    /// kernel-timestamped source; kernel time is then unanchored.
    pub clock_anchor: Option<BootClockAnchor>,
}

/// Three clocks read as close together as user space can. Kernel event stamps
/// from the perf tracepoints are `CLOCK_MONOTONIC`; process start ticks are
/// on the boot clock (which additionally counts time in suspend); the
/// decision point speaks in realtime. `wall_ms(event) = realtime_ms +
/// (event_ns − monotonic_ns) / 1e6`. A suspend between the anchor and an
/// event shifts the boot↔monotonic relation; probes re-anchor per batch to
/// bound that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootClockAnchor {
    pub realtime_ms: u64,
    pub boottime_ns: u64,
    pub monotonic_ns: u64,
    /// Clock ticks per second (`CLK_TCK`) on the host, so a verifier can
    /// convert `pid_start_time_ticks` into the same boot-clock nanoseconds
    /// the kernel events carry. Part of the host clock description.
    pub clk_tck: u32,
}

impl BootClockAnchor {
    /// `pid_start_time_ticks` as boot-clock nanoseconds (start of its tick).
    pub fn start_ticks_to_ns(&self, ticks: u64) -> u64 {
        let tck = if self.clk_tck == 0 {
            100
        } else {
            self.clk_tck as u64
        };
        ticks.saturating_mul(1_000_000_000 / tck)
    }

    /// One tick in nanoseconds — the resolution of process start times.
    pub fn tick_ns(&self) -> u64 {
        let tck = if self.clk_tck == 0 {
            100
        } else {
            self.clk_tck as u64
        };
        1_000_000_000 / tck
    }

    /// Place a kernel **realtime** capture stamp (nanoseconds since the Unix
    /// epoch, as `SO_TIMESTAMPNS` reports it) on the `CLOCK_MONOTONIC` axis
    /// the tracepoint events are stamped on. The anchor's realtime is known
    /// to the millisecond, so the placement is exact to that resolution.
    /// Saturates rather than wrapping.
    pub fn realtime_ns_to_monotonic(&self, realtime_ns: u64) -> u64 {
        let anchor_rt_ns = self.realtime_ms.saturating_mul(1_000_000);
        if realtime_ns >= anchor_rt_ns {
            self.monotonic_ns.saturating_add(realtime_ns - anchor_rt_ns)
        } else {
            self.monotonic_ns.saturating_sub(anchor_rt_ns - realtime_ns)
        }
    }

    /// Place a `CLOCK_MONOTONIC` event stamp on the wall clock. Saturates
    /// rather than wrapping; a stamp earlier than the anchor is subtracted.
    pub fn wall_ms(&self, event_ns: u64) -> u64 {
        if event_ns >= self.monotonic_ns {
            self.realtime_ms
                .saturating_add((event_ns - self.monotonic_ns) / 1_000_000)
        } else {
            self.realtime_ms
                .saturating_sub((self.monotonic_ns - event_ns) / 1_000_000)
        }
    }
}

impl ObservationBatch {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, OBSERVATION_BATCH_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.probe_id);
        buf.extend_from_slice(&self.batch_id);
        buf.extend_from_slice(&self.probe_run_id);
        put_u64(&mut buf, self.probe_seq_first);
        put_u64(&mut buf, self.probe_seq_last);
        put_opt_u64(&mut buf, &self.dropped_events);
        put_u32(&mut buf, self.active_mechanisms.len() as u32);
        for m in &self.active_mechanisms {
            put_u8(&mut buf, m.code());
        }
        // Version 10: the probe's per-mechanism integrity reports, inside the
        // attested bytes so a finding cannot be edited or dropped after
        // signing. Count, then (mechanism, finding code, diagnostic count).
        put_u32(&mut buf, self.mechanism_integrity.len() as u32);
        for r in &self.mechanism_integrity {
            put_u8(&mut buf, r.mechanism.code());
            put_u8(&mut buf, r.integrity.code());
            put_u32(&mut buf, r.integrity.foreign_program_count());
        }
        put_u64(&mut buf, self.claimed_from_ms);
        put_u64(&mut buf, self.claimed_to_ms);
        put_u32(&mut buf, self.observations.len() as u32);
        for o in &self.observations {
            put_bytes(&mut buf, &o.canonical_bytes());
        }
        put_u32(&mut buf, self.kernel_events.len() as u32);
        for e in &self.kernel_events {
            put_bytes(&mut buf, &e.canonical_bytes());
        }
        match &self.clock_anchor {
            Some(a) => {
                put_u8(&mut buf, 1);
                put_u64(&mut buf, a.realtime_ms);
                put_u64(&mut buf, a.boottime_ns);
                put_u64(&mut buf, a.monotonic_ns);
                put_u32(&mut buf, a.clk_tck);
            }
            None => put_u8(&mut buf, 0),
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// Every mechanism claimed anywhere in the batch: declared active, used
    /// by an observation, or used by a kernel event.
    pub fn mechanisms(&self) -> impl Iterator<Item = SourceMechanism> + '_ {
        self.active_mechanisms
            .iter()
            .copied()
            .chain(self.observations.iter().map(|o| o.mechanism))
            .chain(self.kernel_events.iter().map(|e| e.mechanism))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc_at(pid: u32, start: u64, boot: u8, exe: u8) -> ObservedProcess {
        ObservedProcess {
            process: ProcessInstance {
                pid,
                pid_start_time_ticks: start,
                boot_id: [boot; 16],
            },
            exe_content_sha256: [exe; 32],
            exe_path: "/opt/agent".into(),

            container: None,
        }
    }

    fn obs(p: ObservedProcess) -> ObservedExecution {
        ObservedExecution {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe-1".into(),
            observed: p,
            attribution: AgentAttribution::NotEstablished,
            effect: ObservedEffect::ProcessPresent,
            mechanism: SourceMechanism::ProcfsPoll,
            claimed_decision_id: None,
            host_wall_clock_ms: 0,
            probe_monotonic_ns: 0,
        }
    }

    fn empty_batch() -> ObservationBatch {
        ObservationBatch {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe-1".into(),
            batch_id: [7u8; 16],
            probe_run_id: [8u8; 16],
            probe_seq_first: 0,
            probe_seq_last: 0,
            dropped_events: None,
            active_mechanisms: vec![],
            mechanism_integrity: Vec::new(),
            claimed_from_ms: 1,
            claimed_to_ms: 2,
            observations: vec![],
            kernel_events: vec![],
            clock_anchor: None,
        }
    }

    #[test]
    fn active_mechanisms_are_canonically_ordered_and_signed() {
        let a = SourceMechanism::canonical_set(vec![
            SourceMechanism::ProcConnector,
            SourceMechanism::ProcfsPoll,
            SourceMechanism::ProcfsPoll,
        ]);
        let b = SourceMechanism::canonical_set(vec![
            SourceMechanism::ProcfsPoll,
            SourceMechanism::ProcConnector,
        ]);
        assert_eq!(a, b);
        let mut with = empty_batch();
        with.active_mechanisms = a;
        assert_ne!(with.digest(), empty_batch().digest());
        assert!(with
            .mechanisms()
            .any(|m| m == SourceMechanism::ProcConnector));
    }

    #[test]
    fn process_identity_excludes_path_and_survives_pid_reuse() {
        let a = proc_at(42, 1000, 0xb0, 0xe0);
        let mut respelled = a.clone();
        respelled.exe_path = "/opt/./agent".into();
        assert_eq!(a.identity_digest(), respelled.identity_digest());

        let reused = proc_at(42, 2000, 0xb0, 0xe0);
        assert_eq!(a.process.pid, reused.process.pid);
        assert_ne!(a.identity_digest(), reused.identity_digest());

        let rebooted = proc_at(42, 1000, 0xb1, 0xe0);
        assert_ne!(a.identity_digest(), rebooted.identity_digest());

        let replaced_binary = proc_at(42, 1000, 0xb0, 0xe1);
        assert_ne!(a.identity_digest(), replaced_binary.identity_digest());
    }

    #[test]
    fn attribution_encoding_is_injective_and_has_no_verified_variant() {
        let mut none = Vec::new();
        AgentAttribution::NotEstablished.encode(&mut none);
        let mut ab_c = Vec::new();
        AgentAttribution::Claimed {
            agent_id: "ab".into(),
            claim_source: "c".into(),
        }
        .encode(&mut ab_c);
        let mut a_bc = Vec::new();
        AgentAttribution::Claimed {
            agent_id: "a".into(),
            claim_source: "bc".into(),
        }
        .encode(&mut a_bc);
        assert_ne!(none, ab_c);
        assert_ne!(ab_c, a_bc);

        let json = serde_json::to_string(&AgentAttribution::Claimed {
            agent_id: "aip1x".into(),
            claim_source: "s".into(),
        })
        .unwrap();
        assert!(json.contains("Claimed"));
        assert!(!json.to_lowercase().contains("verified"));
    }

    #[test]
    fn batch_encoding_is_domain_tagged_and_count_prefixed() {
        let b = empty_batch();
        let bytes = b.canonical_bytes();
        let tag = OBSERVATION_BATCH_DOMAIN.as_bytes();
        assert_eq!(&bytes[4..4 + tag.len()], tag);

        let mut b2 = b.clone();
        b2.observations.push(obs(proc_at(1, 1, 1, 1)));
        assert_ne!(b.digest(), b2.digest());

        let mut b3 = b.clone();
        b3.dropped_events = Some(0);
        assert_ne!(b.digest(), b3.digest(), "None and Some(0) loss differ");
    }

    #[test]
    fn mechanism_codes_are_distinct_and_change_the_encoding() {
        let mut codes: Vec<u8> = SourceMechanism::ALL.iter().map(|m| m.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), SourceMechanism::ALL.len());

        let a = obs(proc_at(1, 1, 1, 1));
        let mut b = a.clone();
        b.mechanism = SourceMechanism::ProcConnector;
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        assert!(!SourceMechanism::ProcfsPoll.is_kernel_pushed());
        assert!(SourceMechanism::ProcConnector.is_kernel_pushed());
        assert!(SourceMechanism::PidFdAnchored.is_instance_anchored());
    }

    #[test]
    fn perf_tracepoint_mechanisms_are_the_gate_able_ones() {
        // Exactly the three sampled with perf_event_open on a tracepoint pass
        // through perf_trace_run_bpf_submit and can be blinded by a single
        // eBPF program on that tracepoint (the observation-integrity finding).
        for m in [
            SourceMechanism::SchedTracepoint,
            SourceMechanism::SockStateTracepoint,
            SourceMechanism::SockSendTracepoint,
        ] {
            assert!(m.shares_perf_tracepoint_gate(), "{m:?} is gate-able");
            assert!(
                !m.is_gate_independent_kernel_pushed(),
                "{m:?} is not gate-independent"
            );
        }
        // The kernel-pushed mechanisms that reach the observer by another
        // facility are gate-independent: a tracepoint program cannot suppress
        // them.
        for m in [
            SourceMechanism::ProcConnector,
            SourceMechanism::WireTapAfPacket,
            SourceMechanism::Fanotify,
        ] {
            assert!(!m.shares_perf_tracepoint_gate(), "{m:?} is not gate-able");
            assert!(
                m.is_gate_independent_kernel_pushed(),
                "{m:?} is gate-independent kernel-pushed"
            );
        }
        // Polled mechanisms are neither kernel-pushed nor gate-independent.
        assert!(!SourceMechanism::ProcfsPoll.is_gate_independent_kernel_pushed());
    }

    #[test]
    fn kernel_event_kinds_with_equal_numbers_do_not_collide() {
        let base = KernelLifecycleEvent {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "p".into(),
            mechanism: SourceMechanism::ProcConnector,
            kind: KernelLifecycleKind::Exec { pid: 5, tgid: 5 },
            cpu: 0,
            kernel_timestamp_ns: 1,
            probe_seq: 1,
            bound: None,
            attribution: AgentAttribution::NotEstablished,
            claimed_decision_id: None,
        };
        let mut exit = base.clone();
        exit.kind = KernelLifecycleKind::Exit {
            pid: 5,
            tgid: 5,
            exit_code: 0,
            exit_signal: 0,
        };
        let mut fork = base.clone();
        fork.kind = KernelLifecycleKind::Fork {
            parent_pid: 5,
            parent_tgid: 5,
            child_pid: 0,
            child_tgid: 0,
        };
        assert_ne!(base.digest(), exit.digest());
        assert_ne!(base.digest(), fork.digest());
        assert_ne!(exit.digest(), fork.digest());

        // An unbound event has no identity and matches nothing.
        assert_eq!(base.subject_identity_digest(), None);
        let binding = ExecutionBinding {
            version: aip_types::EXECUTION_BINDING_VERSION,
            agent_id: "aip1x".into(),
            process: ProcessInstance {
                pid: 5,
                pid_start_time_ticks: 1,
                boot_id: [1; 16],
            },
            exe_content_sha256: [1; 32],
            exe_path: "/x".into(),
            bound_at_ms: 0,
            container: None,
        };
        assert!(
            !base.matches_process_of(&binding),
            "pid equality is not identity"
        );
    }

    #[test]
    fn socket_endpoint_v4_and_v6_with_same_bytes_differ() {
        let v4 = SocketEndpoint {
            addr: [0u8; 16],
            is_v6: false,
            port: 80,
        };
        let v6 = SocketEndpoint {
            addr: [0u8; 16],
            is_v6: true,
            port: 80,
        };
        let mut a = Vec::new();
        v4.encode(&mut a);
        let mut b = Vec::new();
        v6.encode(&mut b);
        assert_ne!(a, b);
    }
}
