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
pub const OBSERVE_PROTOCOL_VERSION: u16 = 2;

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
}

impl SourceMechanism {
    pub fn code(&self) -> u8 {
        match self {
            SourceMechanism::ProcfsPoll => 0x01,
            SourceMechanism::PidFdAnchored => 0x02,
            SourceMechanism::ProcConnector => 0x03,
            SourceMechanism::ProcNetTable => 0x04,
        }
    }

    /// The kernel generated and delivered this event itself (as opposed to
    /// the probe reading a kernel table at a moment of its choosing).
    pub fn is_kernel_pushed(&self) -> bool {
        matches!(self, SourceMechanism::ProcConnector)
    }

    /// The measurement is proven to refer to one process instance.
    pub fn is_instance_anchored(&self) -> bool {
        matches!(self, SourceMechanism::PidFdAnchored)
    }

    pub const ALL: [SourceMechanism; 4] = [
        SourceMechanism::ProcfsPoll,
        SourceMechanism::PidFdAnchored,
        SourceMechanism::ProcConnector,
        SourceMechanism::ProcNetTable,
    ];
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
}

impl KernelLifecycleKind {
    /// The pid the event is *about* (the child for a fork).
    pub fn subject_pid(&self) -> Option<u32> {
        match self {
            KernelLifecycleKind::Fork { child_pid, .. } => Some(*child_pid),
            KernelLifecycleKind::Exec { pid, .. } | KernelLifecycleKind::Exit { pid, .. } => {
                Some(*pid)
            }
            KernelLifecycleKind::Other { .. } => None,
        }
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
    /// Kernel monotonic timestamp (ns since boot) from the event itself —
    /// not the host wall clock, and not settable by user space. Comparable
    /// only within one boot.
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
    /// The interval the probe claims to have been sampling. A *claim*: the
    /// collector decides what coverage it will attest, and a claimed window
    /// never widens attested coverage.
    pub claimed_from_ms: u64,
    pub claimed_to_ms: u64,
    pub observations: Vec<ObservedExecution>,
    pub kernel_events: Vec<KernelLifecycleEvent>,
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
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// Every mechanism claimed anywhere in the batch.
    pub fn mechanisms(&self) -> impl Iterator<Item = SourceMechanism> + '_ {
        self.observations
            .iter()
            .map(|o| o.mechanism)
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
            claimed_from_ms: 1,
            claimed_to_ms: 2,
            observations: vec![],
            kernel_events: vec![],
        }
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
