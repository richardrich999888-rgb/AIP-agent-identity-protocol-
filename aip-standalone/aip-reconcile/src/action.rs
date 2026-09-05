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

use aip_authorize::{net_connect_action, net_connect_parameters, NetProtocol};
use aip_observe::{
    AgentAttribution, AttestedBatch, KernelLifecycleKind, ObservedEffect, ObservedExecution,
    ObservedProcess, SocketEndpoint, SocketProtocol, SourceMechanism,
};
use aip_types::ScopeAction;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
