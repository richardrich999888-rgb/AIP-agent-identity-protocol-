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
use aip_types::{ExecutionBinding, ProcessInstance};
use serde::{Deserialize, Serialize};

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
///
/// Earlier versions never left this branch; all are refused.
pub const OBSERVE_PROTOCOL_VERSION: u16 = 5;

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

    /// The measurement is proven to refer to one process instance.
    pub fn is_instance_anchored(&self) -> bool {
        matches!(self, SourceMechanism::PidFdAnchored)
    }

    pub const ALL: [SourceMechanism; 6] = [
        SourceMechanism::ProcfsPoll,
        SourceMechanism::PidFdAnchored,
        SourceMechanism::ProcConnector,
        SourceMechanism::ProcNetTable,
        SourceMechanism::SockStateTracepoint,
        SourceMechanism::SchedTracepoint,
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
}

impl ObservedProcess {
    fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.process.pid);
        put_u64(buf, self.process.pid_start_time_ticks);
        buf.extend_from_slice(&self.process.boot_id);
        buf.extend_from_slice(&self.exe_content_sha256);
        put_str(buf, &self.exe_path);
    }

    /// Domain-tagged encoding of the measured facts only. `exe_path` is
    /// excluded so two spellings of one binary compare equal, matching the
    /// Stage 1 identity rule.
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
}

impl KernelLifecycleKind {
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
