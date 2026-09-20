//! Interpreting an observation as evidence of one action class.
//!
//! The observer signs what it saw — a row of the kernel socket table joined
//! to a process instance — and never what that means for authorization
//! (I19). Meaning is assigned here, deterministically, by one documented
//! mapping per action class, and the result is compared with the decision
//! point's `action_kind` / `parameter_digest` through the same canonical
//! `ActionParameters` encoding the decision point used. Nothing is inferred:
//! if the observation is not, exactly, an instance of a known class, it is
//! not action evidence.
//!
//! One class exists: [`aip_authorize::NET_CONNECT_ACTION`], an established
//! TCP connection to a remote endpoint, read from `/proc/net/{tcp,tcp6}` under
//! a pidfd anchor (`SourceMechanism::ProcNetTable`). This is **socket-level
//! metadata obtained by polling procfs** — kernel-authored, host-readable,
//! root-forgeable. It is not a kernel-pushed event, it says nothing about
//! payload, and it shows that a connection *existed* at the sample, not when
//! it was created. Every strength derived from it is capped at `Attested`.

use aip_authorize::{
    fs_write_action, fs_write_parameters, net_connect_action, net_connect_parameters,
    net_send_action, net_send_parameters, process_exec_action, process_exec_parameters,
    NetProtocol,
};
use aip_observe::{
    AgentAttribution, AttestedBatch, BootClockAnchor, KernelLifecycleKind, ObservedEffect,
    ObservedExecution, ObservedProcess, SocketEndpoint, SocketProtocol, SourceMechanism,
};
use aip_types::ScopeAction;
use serde::Serialize;

/// Kernel TCP state byte for ESTABLISHED (`include/net/tcp_states.h`).
pub const TCP_ESTABLISHED: u8 = 0x01;

/// What an observation means as an action, when it means anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedAction {
    pub kind: ScopeAction,
    /// `ActionParameters::digest()` of the observed tuple under the same
    /// vocabulary the decision point uses.
    pub parameter_digest: [u8; 32],
    /// How the observation was obtained. Recorded in the result so a reader
    /// sees that this was polled table metadata, not a kernel event.
    pub mechanism: SourceMechanism,
}

/// Map one observation to the action it evidences, or `None`.
///
/// `None` is the answer for everything that is not, exactly, an established
/// TCP connection read from the socket table: process presence, UDP rows,
/// LISTEN/SYN_SENT/TIME_WAIT sockets, a socket row whose address family does
/// not match its protocol, port 0, or a socket effect labelled with a
/// mechanism other than `ProcNetTable`. `None` never means "did not
/// happen"; it means "not evidence of this class".
pub fn derive_action(o: &ObservedExecution) -> Option<DerivedAction> {
    let ObservedEffect::SocketObserved {
        protocol,
        remote,
        state,
        ..
    } = &o.effect
    else {
        return None;
    };
    if o.mechanism != SourceMechanism::ProcNetTable || *state != TCP_ESTABLISHED {
        return None;
    }
    let (net, addr): (NetProtocol, &[u8]) = match protocol {
        SocketProtocol::Tcp if !remote.is_v6 => (NetProtocol::Tcp, &remote.addr[..4]),
        SocketProtocol::Tcp6 if remote.is_v6 => (NetProtocol::Tcp6, &remote.addr[..]),
        _ => return None,
    };
    let params = net_connect_parameters(net, addr, remote.port).ok()?;
    Some(DerivedAction {
        kind: net_connect_action(),
        parameter_digest: params.digest(),
        mechanism: o.mechanism,
    })
}

// ─── Transition evidence (kernel-pushed) ───

/// Where an event sits in the attested chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EventPosition {
    pub batch_sequence: u64,
    pub index: u32,
    pub kernel_timestamp_ns: u64,
}

/// A connection the kernel reported being **made**: the `connect()`
/// initiation (`CLOSE → SYN_SENT`), anchored to a process instance by the
/// probe, paired with the completion (`SYN_SENT → ESTABLISHED`) of the same
/// kernel socket. Derived from `SockStateTracepoint` events only.
///
/// The pairing key is `sk`, the kernel's socket identity; the initiation has
/// no local port yet, so the 4-tuple cannot pair them. A completion is
/// accepted only if it names the same protocol and remote endpoint and is
/// not earlier than the initiation in kernel time. `completion == None` is
/// an attempt, not a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketTransition {
    /// The instance the probe anchored at the initiation.
    pub bound: ObservedProcess,
    pub kind: ScopeAction,
    pub parameter_digest: [u8; 32],
    pub protocol: SocketProtocol,
    pub remote: SocketEndpoint,
    /// Local endpoint, known once the completion is seen.
    pub local: Option<SocketEndpoint>,
    pub sk: u64,
    pub initiation: EventPosition,
    pub completion: Option<EventPosition>,
    /// Claim attached to the initiating event by the probe (a claim, not a
    /// fact).
    pub attribution: AgentAttribution,
    pub claimed_decision_id: Option<[u8; 16]>,
    pub mechanism: SourceMechanism,
}

fn connect_digest(protocol: SocketProtocol, remote: &SocketEndpoint) -> Option<[u8; 32]> {
    let (net, addr): (NetProtocol, &[u8]) = match protocol {
        SocketProtocol::Tcp if !remote.is_v6 => (NetProtocol::Tcp, &remote.addr[..4]),
        SocketProtocol::Tcp6 if remote.is_v6 => (NetProtocol::Tcp6, &remote.addr[..]),
        _ => return None,
    };
    net_connect_parameters(net, addr, remote.port)
        .ok()
        .map(|p| p.digest())
}

/// Derive every bound connection transition from the kernel events of the
/// supplied (verified, chain-ordered) batches. Unbound initiations are not
/// transitions — the instance is `CANNOT_PROVE` — and events from any
/// mechanism other than `SockStateTracepoint` are ignored.
pub fn derive_transitions<'a>(
    batches: impl IntoIterator<Item = &'a AttestedBatch>,
) -> Vec<SocketTransition> {
    struct Completion {
        sk: u64,
        protocol: SocketProtocol,
        local: SocketEndpoint,
        remote: SocketEndpoint,
        at: EventPosition,
    }
    let mut initiations: Vec<SocketTransition> = Vec::new();
    let mut completions: Vec<Completion> = Vec::new();
    for b in batches {
        for (i, e) in b.batch.kernel_events.iter().enumerate() {
            if e.mechanism != SourceMechanism::SockStateTracepoint {
                continue;
            }
            let KernelLifecycleKind::SocketState {
                protocol,
                local,
                remote,
                sk,
                ..
            } = &e.kind
            else {
                continue;
            };
            let at = EventPosition {
                batch_sequence: b.sequence,
                index: i as u32,
                kernel_timestamp_ns: e.kernel_timestamp_ns,
            };
            if e.kind.is_connect_initiation() {
                let Some(bound) = &e.bound else { continue };
                let Some(digest) = connect_digest(*protocol, remote) else {
                    continue;
                };
                initiations.push(SocketTransition {
                    bound: bound.clone(),
                    kind: net_connect_action(),
                    parameter_digest: digest,
                    protocol: *protocol,
                    remote: *remote,
                    local: None,
                    sk: *sk,
                    initiation: at,
                    completion: None,
                    attribution: e.attribution.clone(),
                    claimed_decision_id: e.claimed_decision_id,
                    mechanism: e.mechanism,
                });
            } else if e.kind.is_connect_established() {
                completions.push(Completion {
                    sk: *sk,
                    protocol: *protocol,
                    local: *local,
                    remote: *remote,
                    at,
                });
            }
        }
    }
    for t in &mut initiations {
        let best = completions
            .iter()
            .filter(|c| {
                c.sk == t.sk
                    && c.protocol == t.protocol
                    && c.remote == t.remote
                    && c.at.kernel_timestamp_ns >= t.initiation.kernel_timestamp_ns
            })
            .min_by_key(|c| c.at.kernel_timestamp_ns);
        if let Some(c) = best {
            t.local = Some(c.local);
            t.completion = Some(c.at);
        }
    }
    initiations
}

// ─── Process execution evidence (kernel-pushed) ───

/// A process the kernel reported being **spawned and executed**: the
/// `sched_process_fork` of a child by an anchored actor, paired with the
/// child's `sched_process_exec`, at which the probe anchored the child and
/// hashed its image. Derived from `SchedTracepoint` events only.
///
/// Pairing key: the fork's `child_pid` equals the exec's `pid`, the exec is
/// not earlier than the fork in kernel time, and the anchored child's start
/// tick lies within `[fork − one tick, exec]` so a recycled pid cannot pose
/// as the forked child. A spawn with no paired exec is a child that never
/// executed an image (or exited before it could be anchored): an attempt,
/// not an execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessExecution {
    /// The instance that forked (anchored at the fork, in its own context).
    pub actor: ObservedProcess,
    pub child_pid: u32,
    pub kind: ScopeAction,
    /// `process_exec_parameters(child.exe_content_sha256).digest()`, once
    /// the child's image is known.
    pub parameter_digest: Option<[u8; 32]>,
    pub fork: EventPosition,
    /// The child as anchored at exec, the kernel's filename, the position.
    pub execution: Option<ExecutedImage>,
    pub attribution: AgentAttribution,
    pub claimed_decision_id: Option<[u8; 16]>,
    pub mechanism: SourceMechanism,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedImage {
    pub child: ObservedProcess,
    /// Kernel-resolved path: context, never identity.
    pub filename: String,
    pub at: EventPosition,
    /// The anchored child's start tick was checked against the fork and
    /// exec kernel times through the batch's clock anchor. Without an
    /// anchor the check cannot be made and the pairing is unanchored.
    pub child_start_verified: bool,
}

/// Derive every anchored spawn (and its execution, when paired) from the
/// kernel events of the supplied batches.
pub fn derive_executions<'a>(
    batches: impl IntoIterator<Item = &'a AttestedBatch>,
) -> Vec<ProcessExecution> {
    struct Exec {
        pid: u32,
        child: ObservedProcess,
        filename: String,
        at: EventPosition,
        anchor: Option<BootClockAnchor>,
    }
    let mut spawns: Vec<ProcessExecution> = Vec::new();
    let mut execs: Vec<Exec> = Vec::new();
    for b in batches {
        for (i, e) in b.batch.kernel_events.iter().enumerate() {
            if e.mechanism != SourceMechanism::SchedTracepoint {
                continue;
            }
            let at = EventPosition {
                batch_sequence: b.sequence,
                index: i as u32,
                kernel_timestamp_ns: e.kernel_timestamp_ns,
            };
            match &e.kind {
                KernelLifecycleKind::ProcessSpawn { child_pid, .. } => {
                    let Some(actor) = &e.bound else { continue };
                    spawns.push(ProcessExecution {
                        actor: actor.clone(),
                        child_pid: *child_pid,
                        kind: process_exec_action(),
                        parameter_digest: None,
                        fork: at,
                        execution: None,
                        attribution: e.attribution.clone(),
                        claimed_decision_id: e.claimed_decision_id,
                        mechanism: e.mechanism,
                    });
                }
                KernelLifecycleKind::ProcessExec { pid, filename, .. } => {
                    let Some(child) = &e.bound else { continue };
                    execs.push(Exec {
                        pid: *pid,
                        child: child.clone(),
                        filename: filename.clone(),
                        at,
                        anchor: b.batch.clock_anchor,
                    });
                }
                _ => {}
            }
        }
    }
    // The anchored child must be the forked child: with an anchor, its start
    // tick must lie within [fork − tick, exec]; an exec whose child fails
    // that is a recycled pid and does not pair. Without an anchor the check
    // cannot be made; the pairing is recorded as unverified.
    let start_ok = |a: &BootClockAnchor, s: &ProcessExecution, x: &Exec| {
        let start = a.start_ticks_to_ns(x.child.process.pid_start_time_ticks);
        start.saturating_add(a.tick_ns()) >= s.fork.kernel_timestamp_ns
            && start <= x.at.kernel_timestamp_ns
    };
    for s in &mut spawns {
        let best = execs
            .iter()
            .filter(|x| {
                x.pid == s.child_pid
                    && x.at.kernel_timestamp_ns >= s.fork.kernel_timestamp_ns
                    && x.anchor.is_none_or(|a| start_ok(&a, s, x))
            })
            .min_by_key(|x| x.at.kernel_timestamp_ns);
        if let Some(x) = best {
            s.parameter_digest = Some(process_exec_parameters(x.child.exe_content_sha256).digest());
            s.execution = Some(ExecutedImage {
                child: x.child.clone(),
                filename: x.filename.clone(),
                at: x.at,
                child_start_verified: x.anchor.is_some(),
            });
        }
    }
    spawns
}

// ─── Socket send evidence (kernel-pushed, Gate 3) ───

/// A send the kernel reported: `sock:sock_send_length` in the sender's own
/// context, anchored to an instance by the probe, with the socket's endpoint
/// resolved from the attested state transitions of the same kernel socket.
/// Derived from `SockSendTracepoint` and `SockStateTracepoint` events only.
///
/// The endpoint is named by the **latest** attested transition of `sk` that
/// is not later than the send in kernel time and is not itself a close —
/// unless a transition of `sk` to `CLOSE` lies between that transition and
/// the send, in which case the kernel may have reused the socket's address
/// and the send is left **unresolved** (`remote == None`). The digest, when
/// resolved, is `net_send_parameters(protocol, remote).digest()`: the
/// endpoint only. `bytes` is the count the kernel accepted, signed as
/// context; it never enters the digest and no payload digest exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSend {
    /// The instance the probe anchored at the send.
    pub bound: ObservedProcess,
    pub kind: ScopeAction,
    pub parameter_digest: Option<[u8; 32]>,
    pub protocol: SocketProtocol,
    pub sk: u64,
    pub bytes: u32,
    pub remote: Option<SocketEndpoint>,
    pub local: Option<SocketEndpoint>,
    pub at: EventPosition,
    pub attribution: AgentAttribution,
    pub claimed_decision_id: Option<[u8; 16]>,
    pub mechanism: SourceMechanism,
}

fn send_digest(protocol: SocketProtocol, remote: &SocketEndpoint) -> Option<[u8; 32]> {
    let (net, addr): (NetProtocol, &[u8]) = match protocol {
        SocketProtocol::Tcp if !remote.is_v6 => (NetProtocol::Tcp, &remote.addr[..4]),
        SocketProtocol::Tcp6 if remote.is_v6 => (NetProtocol::Tcp6, &remote.addr[..]),
        _ => return None,
    };
    net_send_parameters(net, addr, remote.port)
        .ok()
        .map(|p| p.digest())
}

/// Derive every bound send from the kernel events of the supplied batches,
/// resolving each socket's endpoint from the transitions of the same `sk`.
/// Unbound sends are not evidence of an instance (`CANNOT_PROVE`); sends of
/// zero bytes are not sends.
pub fn derive_sends<'a>(batches: impl IntoIterator<Item = &'a AttestedBatch>) -> Vec<SocketSend> {
    struct State {
        sk: u64,
        protocol: SocketProtocol,
        local: SocketEndpoint,
        remote: SocketEndpoint,
        closed: bool,
        ts: u64,
    }
    let mut states: Vec<State> = Vec::new();
    let mut sends: Vec<SocketSend> = Vec::new();
    for b in batches {
        for (i, e) in b.batch.kernel_events.iter().enumerate() {
            match (&e.mechanism, &e.kind) {
                (
                    SourceMechanism::SockStateTracepoint,
                    KernelLifecycleKind::SocketState {
                        protocol,
                        local,
                        remote,
                        new_state,
                        sk,
                        ..
                    },
                ) => states.push(State {
                    sk: *sk,
                    protocol: *protocol,
                    local: *local,
                    remote: *remote,
                    closed: *new_state == aip_observe::tcp_state::CLOSE,
                    ts: e.kernel_timestamp_ns,
                }),
                (
                    SourceMechanism::SockSendTracepoint,
                    KernelLifecycleKind::SocketSend {
                        protocol,
                        sk,
                        bytes,
                        ..
                    },
                ) => {
                    let Some(bound) = &e.bound else { continue };
                    if *bytes == 0 {
                        continue;
                    }
                    sends.push(SocketSend {
                        bound: bound.clone(),
                        kind: net_send_action(),
                        parameter_digest: None,
                        protocol: *protocol,
                        sk: *sk,
                        bytes: *bytes,
                        remote: None,
                        local: None,
                        at: EventPosition {
                            batch_sequence: b.sequence,
                            index: i as u32,
                            kernel_timestamp_ns: e.kernel_timestamp_ns,
                        },
                        attribution: e.attribution.clone(),
                        claimed_decision_id: e.claimed_decision_id,
                        mechanism: e.mechanism,
                    });
                }
                _ => {}
            }
        }
    }
    for s in &mut sends {
        let at = s.at.kernel_timestamp_ns;
        let Some(named) = states
            .iter()
            .filter(|st| {
                st.sk == s.sk
                    && st.protocol == s.protocol
                    && !st.closed
                    && st.remote.port != 0
                    && st.ts <= at
            })
            .max_by_key(|st| st.ts)
        else {
            continue;
        };
        let reused = states
            .iter()
            .any(|st| st.sk == s.sk && st.closed && st.ts > named.ts && st.ts <= at);
        if reused {
            continue;
        }
        s.remote = Some(named.remote);
        s.local = Some(named.local);
        s.parameter_digest = send_digest(s.protocol, &named.remote);
    }
    sends
}

// ─── File write evidence (kernel-queued, Gate 4) ───

/// A completed write the kernel reported through fanotify
/// (`FAN_CLOSE_WRITE`), bound to the acting instance through the kernel's
/// own pidfd, on the object the kernel resolved to `path`. Derived from
/// `Fanotify` events only. The digest, when the name is one an
/// authorization can carry (absolute, not reported deleted), is
/// `fs_write_parameters(path).digest()`: the path bytes only. `(dev, ino)`
/// is signed context; nothing about content exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWrite {
    pub bound: ObservedProcess,
    pub kind: ScopeAction,
    pub parameter_digest: Option<[u8; 32]>,
    pub path: String,
    pub deleted: bool,
    pub dev: u64,
    pub ino: u64,
    pub at: EventPosition,
    pub attribution: AgentAttribution,
    pub claimed_decision_id: Option<[u8; 16]>,
    pub mechanism: SourceMechanism,
}

/// Derive every bound completed write from the kernel events of the
/// supplied batches. Unbound events (the writer had gone before the event
/// was read) are not evidence of an instance; a `FAN_MODIFY` without
/// `FAN_CLOSE_WRITE` is a write in progress, not a completed write.
pub fn derive_file_writes<'a>(
    batches: impl IntoIterator<Item = &'a AttestedBatch>,
) -> Vec<FileWrite> {
    let mut out = Vec::new();
    for b in batches {
        for (i, e) in b.batch.kernel_events.iter().enumerate() {
            if e.mechanism != SourceMechanism::Fanotify || !e.kind.is_file_write() {
                continue;
            }
            let KernelLifecycleKind::FileEvent {
                path,
                deleted,
                dev,
                ino,
                ..
            } = &e.kind
            else {
                continue;
            };
            let Some(bound) = &e.bound else { continue };
            let parameter_digest = if *deleted {
                None
            } else {
                fs_write_parameters(path).ok().map(|p| p.digest())
            };
            out.push(FileWrite {
                bound: bound.clone(),
                kind: fs_write_action(),
                parameter_digest,
                path: path.clone(),
                deleted: *deleted,
                dev: *dev,
                ino: *ino,
                at: EventPosition {
                    batch_sequence: b.sequence,
                    index: i as u32,
                    kernel_timestamp_ns: e.kernel_timestamp_ns,
                },
                attribution: e.attribution.clone(),
                claimed_decision_id: e.claimed_decision_id,
                mechanism: e.mechanism,
            });
        }
    }
    out
}

// ─── One view over every transition class ───

/// Kernel-reported action evidence of any class, seen uniformly by the
/// reconciler: an anchored actor, an initiating event, an optional
/// completing event, a claim, and — once complete — an action kind and
/// parameter digest to compare with the expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionEvidence {
    Socket(SocketTransition),
    Exec(ProcessExecution),
    /// A send is one kernel event: it initiates and completes at once (the
    /// kernel accepted the bytes), so `completion() == Some(initiation())`.
    Send(SocketSend),
    /// A completed file write is one kernel event likewise.
    File(FileWrite),
}

impl TransitionEvidence {
    pub fn kind(&self) -> &ScopeAction {
        match self {
            TransitionEvidence::Socket(t) => &t.kind,
            TransitionEvidence::Exec(t) => &t.kind,
            TransitionEvidence::Send(t) => &t.kind,
            TransitionEvidence::File(t) => &t.kind,
        }
    }

    /// `None` while the transition is incomplete and its parameters are not
    /// yet knowable (a spawn whose child has not executed an image; a send
    /// whose socket endpoint could not be resolved).
    pub fn parameter_digest(&self) -> Option<[u8; 32]> {
        match self {
            TransitionEvidence::Socket(t) => Some(t.parameter_digest),
            TransitionEvidence::Exec(t) => t.parameter_digest,
            TransitionEvidence::Send(t) => t.parameter_digest,
            TransitionEvidence::File(t) => t.parameter_digest,
        }
    }

    /// The instance that acted, anchored at the initiating event.
    pub fn actor(&self) -> &ObservedProcess {
        match self {
            TransitionEvidence::Socket(t) => &t.bound,
            TransitionEvidence::Exec(t) => &t.actor,
            TransitionEvidence::Send(t) => &t.bound,
            TransitionEvidence::File(t) => &t.bound,
        }
    }

    pub fn attribution(&self) -> &AgentAttribution {
        match self {
            TransitionEvidence::Socket(t) => &t.attribution,
            TransitionEvidence::Exec(t) => &t.attribution,
            TransitionEvidence::Send(t) => &t.attribution,
            TransitionEvidence::File(t) => &t.attribution,
        }
    }

    pub fn claimed_decision_id(&self) -> Option<[u8; 16]> {
        match self {
            TransitionEvidence::Socket(t) => t.claimed_decision_id,
            TransitionEvidence::Exec(t) => t.claimed_decision_id,
            TransitionEvidence::Send(t) => t.claimed_decision_id,
            TransitionEvidence::File(t) => t.claimed_decision_id,
        }
    }

    pub fn initiation(&self) -> EventPosition {
        match self {
            TransitionEvidence::Socket(t) => t.initiation,
            TransitionEvidence::Exec(t) => t.fork,
            TransitionEvidence::Send(t) => t.at,
            TransitionEvidence::File(t) => t.at,
        }
    }

    pub fn completion(&self) -> Option<EventPosition> {
        match self {
            TransitionEvidence::Socket(t) => t.completion,
            TransitionEvidence::Exec(t) => t.execution.as_ref().map(|x| x.at),
            TransitionEvidence::Send(t) => Some(t.at),
            TransitionEvidence::File(t) => Some(t.at),
        }
    }

    pub fn mechanism(&self) -> SourceMechanism {
        match self {
            TransitionEvidence::Socket(t) => t.mechanism,
            TransitionEvidence::Exec(t) => t.mechanism,
            TransitionEvidence::Send(t) => t.mechanism,
            TransitionEvidence::File(t) => t.mechanism,
        }
    }

    /// For socket transitions: the connection tuple, used to recognise the
    /// same connection in polled presence evidence.
    pub fn socket_tuple(&self) -> Option<(SocketProtocol, SocketEndpoint, Option<SocketEndpoint>)> {
        match self {
            TransitionEvidence::Socket(t) => Some((t.protocol, t.remote, t.local)),
            TransitionEvidence::Exec(_)
            | TransitionEvidence::Send(_)
            | TransitionEvidence::File(_) => None,
        }
    }
}

/// Every transition of every class in the supplied batches.
pub fn derive_transition_evidence<'a>(
    batches: impl IntoIterator<Item = &'a AttestedBatch> + Clone,
) -> Vec<TransitionEvidence> {
    derive_transitions(batches.clone())
        .into_iter()
        .map(TransitionEvidence::Socket)
        .chain(
            derive_executions(batches.clone())
                .into_iter()
                .map(TransitionEvidence::Exec),
        )
        .chain(
            derive_sends(batches.clone())
                .into_iter()
                .map(TransitionEvidence::Send),
        )
        .chain(
            derive_file_writes(batches)
                .into_iter()
                .map(TransitionEvidence::File),
        )
        .collect()
}

// ─── Process lineage edges (Sniffer Dog 2.0, Phase C) ───

/// "Bound instance `parent` forked bound instance `child`, which executed
/// `image_sha256`" — derived from collector-signed kernel events and nothing
/// else. An edge exists only when both ends were pidfd-anchored by the probe
/// and the child's start tick was verified against the batch's clock anchor
/// (`ExecutedImage::child_start_verified`); a fork without an exec, an
/// unbound end, an unanchored pairing or a recycled child pid derives no
/// edge. It carries no agent identity and no decision: which *agent* either
/// instance is remains a separate question answered elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineageEdge {
    pub parent: ObservedProcess,
    pub child: ObservedProcess,
    pub fork: EventPosition,
    pub exec: EventPosition,
    /// The executed image's content hash (`child.exe_content_sha256`).
    pub image_sha256: [u8; 32],
    /// The kernel's `filename` at exec — context, never identity.
    pub filename: String,
    pub mechanism: SourceMechanism,
    /// The collector sequence of the batch carrying the fork.
    pub batch_sequence: u64,
}

/// Derive every process lineage edge the batches support. Reuses the
/// fork/exec pairing of [`derive_executions`] and keeps only completed,
/// start-verified executions.
pub fn derive_lineage_edges<'a>(
    batches: impl IntoIterator<Item = &'a AttestedBatch>,
) -> Vec<LineageEdge> {
    derive_executions(batches)
        .into_iter()
        .filter_map(|x| {
            let img = x.execution?;
            if !img.child_start_verified {
                return None;
            }
            Some(LineageEdge {
                image_sha256: img.child.exe_content_sha256,
                parent: x.actor,
                child: img.child,
                fork: x.fork,
                exec: img.at,
                filename: img.filename,
                mechanism: x.mechanism,
                batch_sequence: x.fork.batch_sequence,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observe::{
        AgentAttribution, ObservedProcess, SocketEndpoint, OBSERVE_PROTOCOL_VERSION,
    };
    use aip_types::ProcessInstance;

    fn obs(effect: ObservedEffect, mechanism: SourceMechanism) -> ObservedExecution {
        ObservedExecution {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "p".into(),
            observed: ObservedProcess {
                process: ProcessInstance {
                    pid: 1,
                    pid_start_time_ticks: 1,
                    boot_id: [1; 16],
                },
                exe_content_sha256: [2; 32],
                exe_path: "/x".into(),
                container: None,
            },
            attribution: AgentAttribution::NotEstablished,
            effect,
            mechanism,
            claimed_decision_id: None,
            host_wall_clock_ms: 0,
            probe_monotonic_ns: 1,
        }
    }

    fn ep(addr: &[u8], v6: bool, port: u16) -> SocketEndpoint {
        let mut a = [0u8; 16];
        a[..addr.len()].copy_from_slice(addr);
        SocketEndpoint {
            addr: a,
            is_v6: v6,
            port,
        }
    }

    fn sock(protocol: SocketProtocol, remote: SocketEndpoint, state: u8) -> ObservedEffect {
        ObservedEffect::SocketObserved {
            protocol,
            local: ep(&[127, 0, 0, 1], false, 40_000),
            remote,
            state,
            inode: 7,
        }
    }

    #[test]
    fn established_tcp_from_the_table_is_net_connect_with_the_dp_digest() {
        let o = obs(
            sock(
                SocketProtocol::Tcp,
                ep(&[10, 0, 0, 5], false, 443),
                TCP_ESTABLISHED,
            ),
            SourceMechanism::ProcNetTable,
        );
        let d = derive_action(&o).unwrap();
        assert_eq!(d.kind, net_connect_action());
        assert_eq!(
            d.parameter_digest,
            net_connect_parameters(NetProtocol::Tcp, &[10, 0, 0, 5], 443)
                .unwrap()
                .digest()
        );
        assert_eq!(d.mechanism, SourceMechanism::ProcNetTable);

        let o6 = obs(
            sock(
                SocketProtocol::Tcp6,
                ep(&[0xfd; 16], true, 8443),
                TCP_ESTABLISHED,
            ),
            SourceMechanism::ProcNetTable,
        );
        assert_eq!(
            derive_action(&o6).unwrap().parameter_digest,
            net_connect_parameters(NetProtocol::Tcp6, &[0xfd; 16], 8443)
                .unwrap()
                .digest()
        );
    }

    #[test]
    fn everything_else_is_not_action_evidence() {
        let est = ep(&[10, 0, 0, 5], false, 443);
        for (label, o) in [
            (
                "process presence",
                obs(
                    ObservedEffect::ProcessPresent,
                    SourceMechanism::PidFdAnchored,
                ),
            ),
            (
                "udp",
                obs(
                    sock(SocketProtocol::Udp, est, TCP_ESTABLISHED),
                    SourceMechanism::ProcNetTable,
                ),
            ),
            (
                "listen",
                obs(
                    sock(SocketProtocol::Tcp, ep(&[0, 0, 0, 0], false, 0), 0x0a),
                    SourceMechanism::ProcNetTable,
                ),
            ),
            (
                "syn_sent",
                obs(
                    sock(SocketProtocol::Tcp, est, 0x02),
                    SourceMechanism::ProcNetTable,
                ),
            ),
            (
                "family mismatch",
                obs(
                    sock(
                        SocketProtocol::Tcp,
                        ep(&[0xfd; 16], true, 443),
                        TCP_ESTABLISHED,
                    ),
                    SourceMechanism::ProcNetTable,
                ),
            ),
            (
                "port zero",
                obs(
                    sock(
                        SocketProtocol::Tcp,
                        ep(&[10, 0, 0, 5], false, 0),
                        TCP_ESTABLISHED,
                    ),
                    SourceMechanism::ProcNetTable,
                ),
            ),
            (
                "socket row labelled as a poll",
                obs(
                    sock(SocketProtocol::Tcp, est, TCP_ESTABLISHED),
                    SourceMechanism::ProcfsPoll,
                ),
            ),
        ] {
            assert!(derive_action(&o).is_none(), "{label}");
        }
    }
}
