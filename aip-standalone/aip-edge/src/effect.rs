//! Reading a stance from live kernel evidence, and where the reading stops.
//!
//! # Who decides what an observation *means*
//!
//! `aip-effect` is domain-neutral on purpose: an `ObservationRecord` says that
//! a mechanism observed a class for an execution, and whether a particular
//! socket row **supports** "hold a connection to 127.0.0.1:41053" is a domain
//! question. `EffectObservation::new` therefore takes the stance from the
//! caller, and the caller is a verifier.
//!
//! This module is that verifier's reading, for this reference's one action
//! class. It is deliberately small and deliberately literal:
//!
//! | observation content | stance | why |
//! |---|---|---|
//! | a TCP socket owned by the instance, `ESTABLISHED`, remote == requested | `Supports` | the requested state exists and the kernel says so |
//! | anything else — `ProcessPresent`, another endpoint, another state | `Neither` | it is about this execution and says nothing about *this* effect |
//!
//! # `Opposes` is not derived here, and that is a limitation, not a design win
//!
//! There is no rule below that returns `Opposes`, because this reference has
//! no observation that contradicts "a connection to X was held". A socket to Y
//! does not contradict it — a process may hold both. The absence of a socket
//! to X in one sample does not contradict it either; that is a statement about
//! the observer's sampling, and reading it as contradiction is precisely the
//! absence-as-evidence error the whole model refuses.
//!
//! Consequently the live reference reaches `Corroborated` and `Inconclusive`
//! and cannot reach `Contradicted` or `Conflicting`. Those two are exercised
//! in `tests/effect_boundary.rs` over **real** attested records with the
//! opposing stance supplied explicitly — which is legitimate, because supplying
//! the stance is the caller's documented job, and the *record* is still one an
//! anchored observer signed. The report states this rather than implying the
//! reference demonstrated a contradiction it did not.

use aip_effect::{
    EffectAssessment, EffectCorrelation, EffectObservation, EffectWindow, ObservedStance,
};
use aip_execution::RequestedEffect;
use aip_observation::{
    Completeness, EvidenceCeiling, ObservationClass, ObservationProfile, ObservationRecord,
};
use aip_observe::{ObservedEffect, ObservedExecution, SocketProtocol};
use serde::{Deserialize, Serialize};

use crate::correlate::ObservationSubject;
use crate::error::EdgeError;

/// TCP `ESTABLISHED`, from the kernel socket table.
const TCP_ESTABLISHED: u8 = aip_observe::tcp_state::ESTABLISHED;

/// The action class the reference authorizes and observes.
///
/// Equal to `aip_authorize::net_connect_action()`'s string. Named here so the
/// `RequestedEffect` this module builds can be compared with an
/// `ExpectedExecution.action_kind` without either side importing the other's
/// vocabulary.
pub const ACTION_KIND: &str = "ghost.net.connect.v1";

/// The requested effect, in Skill 18's vocabulary.
///
/// `parameter_commitment` is built by the **same** function the workload used
/// (`aip_edge_contract::connect_parameter_bytes` under AIRI's parameter
/// domain), so a mismatch means the two parties disagreed about the action and
/// never that they spelled the same action differently.
///
/// This is a `SelfReported` layer-1 statement and nothing here promotes it.
pub fn requested_effect(ip: [u8; 4], port: u16) -> RequestedEffect {
    RequestedEffect {
        action_kind: ACTION_KIND.to_owned(),
        parameter_commitment: aip_airi::parameter_commitment(
            &aip_edge_contract::connect_parameter_bytes(ip, port),
        ),
        target: Some(format!("{}.{}.{}.{}:{port}", ip[0], ip[1], ip[2], ip[3])),
    }
}

/// The verifier's reading of one observation, for this action class.
///
/// Takes the raw `ObservedExecution` rather than the `ObservationRecord`,
/// because the record deliberately carries no content — it carries which class
/// was observed, by whom, when. The content lives in the batch the record was
/// derived from, and reading it is exactly what a domain verifier does.
pub fn stance_of(observed: &ObservedExecution, ip: [u8; 4], port: u16) -> ObservedStance {
    match &observed.effect {
        ObservedEffect::SocketObserved {
            protocol: SocketProtocol::Tcp | SocketProtocol::Tcp6,
            remote,
            state,
            ..
        } if *state == TCP_ESTABLISHED
            && !remote.is_v6
            && remote.addr[..4] == ip
            && remote.port == port =>
        {
            ObservedStance::Supports
        }
        // Everything else is about this execution and silent about this
        // effect. Never `Opposes`: see the module documentation.
        _ => ObservedStance::Neither,
    }
}

/// Everything the Skill 21 boundary needs, assembled from verified material.
pub struct EffectInputs<'a> {
    pub requested: &'a RequestedEffect,
    pub subject: &'a ObservationSubject,
    pub window: EffectWindow,
    pub profile: &'a ObservationProfile,
    /// How many effects the whole execution requested. Drives
    /// `EffectBinding`: one means an admitted observation can only be about
    /// this effect; more means it binds at execution granularity and the
    /// assessment must say so (ADR-004).
    pub requested_effects_in_execution: u32,
}

impl EffectInputs<'_> {
    /// The subject an effect assessment is about, in `aip-effect`'s type.
    ///
    /// Four of its five fields are the observation correlation's, deliberately:
    /// an observation and an effect must agree on the *same* identifiers or a
    /// match means nothing. The fifth is the effect's own commitment.
    pub fn correlation(&self) -> EffectCorrelation {
        EffectCorrelation {
            system_id: self.subject.system_id.clone(),
            execution_id: self.subject.execution_id,
            boot_id: self.subject.boot_id,
            decision_id: self.subject.decision_id,
            parameter_commitment: self.requested.parameter_commitment,
        }
    }
}

/// Which of `items` to count: one per distinct kernel socket, per instance.
///
/// `aip-effect` is domain-neutral and counts **records**: every record it is
/// handed with a `Supports` stance is one more corroboration. That is right
/// for distinct observations and wrong for one socket described twice, and
/// two routes produce the second (issue #18):
///
/// - a single read of `/proc/net/tcp` repeats a row when the socket table
///   changes during the read, so one table snapshot can contain one socket
///   twice (the observer now drops those, but a verifier must not depend on
///   every observer doing so);
/// - an observer that polls more than once describes a socket that is still
///   open in every batch, at a different time each time.
///
/// Neither is a second corroboration. A connection held once is one fact, and
/// counting it once per sighting is evidence inflation by the verifier's own
/// loop — the exact error `t10_and_t11` exists to catch.
///
/// Two items are the same socket when they describe the **same observed
/// process instance** and an equal `SocketObserved` effect (protocol, local
/// and remote endpoint, state, inode). Different instances are never merged,
/// whatever their sockets look like: that would let one execution's evidence
/// stand in for another's.
///
/// The representative of a group is its first member **inside the window**,
/// else its first member. `aip-effect` filters by window after this, so
/// keeping an out-of-window duplicate while dropping an in-window one would
/// turn a real corroboration into `OutsideWindow`. Items that are not socket
/// observations are never collapsed. Returns the indices to keep, in their
/// original order, and how many were collapsed.
pub fn distinct_socket_observations(
    items: &[(u64, &ObservedExecution)],
    window: EffectWindow,
) -> (Vec<usize>, usize) {
    let mut groups: Vec<(usize, Vec<usize>)> = Vec::new();
    let mut keep: Vec<usize> = Vec::with_capacity(items.len());
    for (i, (_, observed)) in items.iter().enumerate() {
        if !matches!(observed.effect, ObservedEffect::SocketObserved { .. }) {
            keep.push(i);
            continue;
        }
        let existing = groups.iter_mut().find(|(first, _)| {
            let other = items[*first].1;
            other.observed == observed.observed && other.effect == observed.effect
        });
        match existing {
            Some((_, members)) => members.push(i),
            None => groups.push((i, vec![i])),
        }
    }
    for (_, members) in &groups {
        let representative = members
            .iter()
            .copied()
            .find(|&i| window.contains(items[i].0))
            .unwrap_or(members[0]);
        keep.push(representative);
    }
    keep.sort_unstable();
    let collapsed = items.len() - keep.len();
    (keep, collapsed)
}

/// Pair verified records with the stances read from their content, and assess.
///
/// `records` are `(record, observed)` pairs: the record as
/// `ObservationRecord::from_attested` produced it, and the observation it was
/// derived from, for the content. They must correspond — [`assess_effect`] is
/// called by `reference::run`, which builds them together from one index.
///
/// Every refusal is propagated. In particular a record whose `Completeness` is
/// not `Observed` cannot be given a stance other than `Neither`, and
/// `EffectObservation::new` enforces that rather than this module remembering
/// to.
pub fn assess_effect(
    inputs: &EffectInputs<'_>,
    records: &[(ObservationRecord, ObservedExecution)],
    ip: [u8; 4],
    port: u16,
) -> Result<EffectAssessment, EdgeError> {
    // Validate every input before collapsing duplicates. A duplicate must
    // never hide a refusal that the uncollapsed assessment would propagate.
    let validated = records
        .iter()
        .map(|(record, observed)| {
            EffectObservation::new(record.clone(), stance_of(observed, ip, port))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // One socket is one fact, however many records describe it. See
    // `distinct_socket_observations` for why this happens before the count,
    // and why it is a verifier's job rather than only the observer's.
    let index: Vec<(u64, &ObservedExecution)> = records
        .iter()
        .map(|(record, observed)| (record.attested_at_ms(), observed))
        .collect();
    let (keep, _collapsed) = distinct_socket_observations(&index, inputs.window);
    let observations: Vec<_> = keep.iter().map(|&i| validated[i].clone()).collect();
    Ok(EffectAssessment::assess(
        inputs.requested,
        &inputs.correlation(),
        inputs.window,
        &observations,
        inputs.profile,
        inputs.requested_effects_in_execution,
    )?)
}

/// What the reference can say about physical effect. Nothing, and precisely
/// why nothing.
///
/// Every field is **derived** from the real class table and the real profile;
/// none is asserted by this module. That matters because the temptation at
/// this exact point is to write a sentence instead of a computation, and a
/// sentence does not fail when someone later implements a sensor and forgets
/// to update it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalEffectStatus {
    /// `ObservationClass::PhysicalEffect::is_implemented()`. `false` in this
    /// build and must stay so until an ADR revising ADR-003 says otherwise.
    pub class_implemented: bool,
    /// Whether the deployment's profile declares the class observable.
    /// `false` here because no mechanism projects into it.
    pub observable_in_profile: bool,
    /// How the profile records the class in the absence of evidence.
    /// `NotObservable` — *this deployment cannot look* — as distinct from
    /// `NotObserved`, which would mean it looked and saw nothing.
    pub completeness: Completeness,
    /// The class's declared ceiling. Reported so a reader can see that even a
    /// future sensor would be capped at `Attested`, because a sensor reading
    /// is content measured on the observed host and host root forges it
    /// (ADR-003 §2).
    pub ceiling_if_ever_implemented: EvidenceCeiling,
}

impl PhysicalEffectStatus {
    /// Whether anything in this build could establish a physical effect.
    ///
    /// Always `false`. It is a method rather than a constant so that a future
    /// change that implements the class has to make this function return
    /// something else, and fail its test, rather than quietly leaving a stale
    /// comment behind.
    pub fn establishes_physical_effect(&self) -> bool {
        self.class_implemented && self.observable_in_profile
    }
}

/// Derive the physical-effect status from the class table and a real profile.
///
/// The reconciler's equivalent of this state is `CANNOT_PROVE`. This function
/// does not construct that value — assigning a result class is
/// `aip-reconcile`'s and nothing else's — it reports the structural facts a
/// verifier would reach it from.
pub fn physical_effect_finding(profile: &ObservationProfile) -> PhysicalEffectStatus {
    let class = ObservationClass::PhysicalEffect;
    PhysicalEffectStatus {
        class_implemented: class.is_implemented(),
        observable_in_profile: profile.capability(class).is_observable(),
        completeness: profile.completeness_without_evidence(class),
        ceiling_if_ever_implemented: class.ceiling(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observe::SocketEndpoint;

    fn endpoint(ip: [u8; 4], port: u16) -> SocketEndpoint {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&ip);
        SocketEndpoint {
            addr,
            is_v6: false,
            port,
        }
    }

    fn socket(ip: [u8; 4], port: u16, state: u8) -> ObservedEffect {
        ObservedEffect::SocketObserved {
            protocol: SocketProtocol::Tcp,
            local: endpoint([127, 0, 0, 1], 1),
            remote: endpoint(ip, port),
            state,
            inode: 42,
        }
    }

    fn with_effect(effect: ObservedEffect) -> ObservedExecution {
        ObservedExecution {
            version: aip_observe::OBSERVE_PROTOCOL_VERSION,
            probe_id: "p".into(),
            observed: aip_observe::ObservedProcess {
                process: aip_types::ProcessInstance {
                    pid: 1,
                    pid_start_time_ticks: 1,
                    boot_id: [7u8; 16],
                },
                exe_content_sha256: [9u8; 32],
                exe_path: "/x".into(),
                container: None,
            },
            attribution: aip_observe::AgentAttribution::NotEstablished,
            effect,
            mechanism: aip_observe::SourceMechanism::ProcNetTable,
            claimed_decision_id: None,
            host_wall_clock_ms: 0,
            probe_monotonic_ns: 0,
        }
    }

    // ─── One socket is one fact (issue #18) ───

    const IP: [u8; 4] = [127, 0, 0, 1];
    const PORT: u16 = 41879;
    const ALL_TIME: EffectWindow = EffectWindow {
        from_ms: 0,
        to_ms: u64::MAX,
    };

    fn sock(inode: u64, local_port: u16) -> ObservedEffect {
        ObservedEffect::SocketObserved {
            protocol: SocketProtocol::Tcp,
            local: endpoint(IP, local_port),
            remote: endpoint(IP, PORT),
            state: TCP_ESTABLISHED,
            inode,
        }
    }

    fn on_instance(effect: ObservedEffect, pid: u32) -> ObservedExecution {
        let mut o = with_effect(effect);
        o.observed.process.pid = pid;
        o
    }

    fn supporting(items: &[(u64, &ObservedExecution)], window: EffectWindow) -> usize {
        let (keep, _) = distinct_socket_observations(items, window);
        keep.iter()
            .filter(|&&i| stance_of(items[i].1, IP, PORT) == ObservedStance::Supports)
            .count()
    }

    #[test]
    fn a_socket_repeated_within_one_snapshot_counts_once() {
        // Path 1: the shape captured in issue #18 — one table read, one
        // socket, two identical rows, two records at the same instant.
        let a = with_effect(sock(68001, 51406));
        let b = a.clone();
        let items = [(1000, &a), (1000, &b)];
        assert_eq!(supporting(&items, ALL_TIME), 1);
        assert_eq!(distinct_socket_observations(&items, ALL_TIME).1, 1);
    }

    #[test]
    fn a_socket_seen_in_two_batches_counts_once() {
        // Path 2: an observer that polls twice describes the same open socket
        // twice, at two times. Still one connection.
        let a = with_effect(sock(68001, 51406));
        let b = a.clone();
        let items = [(1000, &a), (2000, &b)];
        assert_eq!(supporting(&items, ALL_TIME), 1);
    }

    #[test]
    fn four_repeats_of_one_socket_still_count_once() {
        let a = with_effect(sock(68001, 51406));
        let items: Vec<(u64, &ObservedExecution)> = (0..4).map(|t| (1000 + t, &a)).collect();
        assert_eq!(supporting(&items, ALL_TIME), 1);
        assert_eq!(distinct_socket_observations(&items, ALL_TIME).1, 3);
    }

    #[test]
    fn the_in_window_sighting_is_kept_when_the_first_is_outside_it() {
        // Collapsing must not turn a real corroboration into OutsideWindow:
        // the out-of-window sighting comes first, and must not be the one kept.
        let a = with_effect(sock(68001, 51406));
        let b = a.clone();
        let items = [(10, &a), (5000, &b)];
        let window = EffectWindow {
            from_ms: 1000,
            to_ms: 9000,
        };
        let (keep, collapsed) = distinct_socket_observations(&items, window);
        assert_eq!(keep, vec![1]);
        assert_eq!(collapsed, 1);
    }

    #[test]
    fn two_distinct_sockets_still_count_twice() {
        // Not over-collapsing: two connections are two kernel facts.
        let a = with_effect(sock(68001, 51406));
        let b = with_effect(sock(68002, 51407));
        let items = [(1000, &a), (1000, &b)];
        assert_eq!(supporting(&items, ALL_TIME), 2);
        assert_eq!(distinct_socket_observations(&items, ALL_TIME).1, 0);
    }

    #[test]
    fn identical_sockets_on_different_instances_are_never_merged() {
        // One execution's evidence must never stand in for another's.
        let a = on_instance(sock(68001, 51406), 100);
        let b = on_instance(sock(68001, 51406), 200);
        let items = [(1000, &a), (1000, &b)];
        assert_eq!(
            distinct_socket_observations(&items, ALL_TIME),
            (vec![0, 1], 0)
        );
    }

    #[test]
    fn pid_reuse_or_another_boot_is_not_the_same_socket_observation() {
        let a = on_instance(sock(68001, 51406), 100);
        let mut reused = a.clone();
        reused.observed.process.pid_start_time_ticks += 1;
        let mut another_boot = a.clone();
        another_boot.observed.process.boot_id[0] ^= 1;
        let items = [(1000, &a), (1000, &reused), (1000, &another_boot)];
        assert_eq!(
            distinct_socket_observations(&items, ALL_TIME),
            (vec![0, 1, 2], 0)
        );
    }

    #[test]
    fn a_state_change_is_preserved_but_does_not_add_support() {
        let a = with_effect(sock(68001, 51406));
        let mut closed = a.clone();
        if let ObservedEffect::SocketObserved { state, .. } = &mut closed.effect {
            *state = 8;
        }
        let items = [(1000, &a), (1001, &closed), (1002, &a)];
        assert_eq!(
            distinct_socket_observations(&items, ALL_TIME),
            (vec![0, 1], 1)
        );
        assert_eq!(supporting(&items, ALL_TIME), 1);
    }

    #[test]
    fn non_socket_observations_are_never_collapsed() {
        let a = with_effect(ObservedEffect::ProcessPresent);
        let b = a.clone();
        let items = [(1000, &a), (1000, &b)];
        assert_eq!(
            distinct_socket_observations(&items, ALL_TIME),
            (vec![0, 1], 0)
        );
    }

    #[test]
    fn the_kept_indices_preserve_input_order() {
        let a = with_effect(sock(1, 1));
        let b = with_effect(sock(2, 2));
        let items = [(1, &a), (1, &b), (2, &a), (2, &b)];
        assert_eq!(distinct_socket_observations(&items, ALL_TIME).0, vec![0, 1]);
    }

    #[test]
    fn an_established_socket_to_the_requested_endpoint_supports() {
        let o = with_effect(socket([127, 0, 0, 1], 9000, TCP_ESTABLISHED));
        assert_eq!(
            stance_of(&o, [127, 0, 0, 1], 9000),
            ObservedStance::Supports
        );
    }

    #[test]
    fn a_socket_to_another_endpoint_says_nothing_rather_than_opposing() {
        let o = with_effect(socket([127, 0, 0, 1], 9001, TCP_ESTABLISHED));
        assert_eq!(stance_of(&o, [127, 0, 0, 1], 9000), ObservedStance::Neither);
    }

    #[test]
    fn a_non_established_socket_to_the_endpoint_does_not_support() {
        // LISTEN, not ESTABLISHED. The requested state is "held", so a socket
        // in another state is not the requested effect.
        let o = with_effect(socket([127, 0, 0, 1], 9000, aip_observe::tcp_state::LISTEN));
        assert_eq!(stance_of(&o, [127, 0, 0, 1], 9000), ObservedStance::Neither);
    }

    #[test]
    fn a_process_presence_measurement_says_nothing_about_the_effect() {
        let o = with_effect(ObservedEffect::ProcessPresent);
        assert_eq!(stance_of(&o, [127, 0, 0, 1], 9000), ObservedStance::Neither);
    }

    #[test]
    fn absence_of_the_instance_is_never_read_as_opposition() {
        let o = with_effect(ObservedEffect::ProcessNoLongerPresent);
        assert_eq!(
            stance_of(&o, [127, 0, 0, 1], 9000),
            ObservedStance::Neither,
            "a vanished instance is a fact about sampling, not a contradiction"
        );
    }

    #[test]
    fn no_input_reaches_opposes_in_this_reference() {
        // Sweep every effect shape the observer can produce for this action
        // class and assert none of them is read as opposition. If a future
        // change adds a genuine contradiction rule it must change this test
        // deliberately.
        let states = [
            TCP_ESTABLISHED,
            aip_observe::tcp_state::LISTEN,
            aip_observe::tcp_state::SYN_SENT,
            aip_observe::tcp_state::CLOSE,
            aip_observe::tcp_state::TIME_WAIT,
        ];
        let mut cases: Vec<ObservedExecution> = vec![
            with_effect(ObservedEffect::ProcessPresent),
            with_effect(ObservedEffect::ProcessNoLongerPresent),
        ];
        for s in states {
            cases.push(with_effect(socket([127, 0, 0, 1], 9000, s)));
            cases.push(with_effect(socket([10, 0, 0, 1], 9000, s)));
            cases.push(with_effect(socket([127, 0, 0, 1], 9999, s)));
        }
        for c in &cases {
            assert_ne!(
                stance_of(c, [127, 0, 0, 1], 9000),
                ObservedStance::Opposes,
                "this reference derives no contradiction: {:?}",
                c.effect
            );
        }
    }

    #[test]
    fn physical_effect_is_unreachable_under_a_real_profile() {
        let profile = crate::profile::profile_from_mechanisms(
            "obs",
            &[
                aip_observe::SourceMechanism::PidFdAnchored,
                aip_observe::SourceMechanism::ProcNetTable,
            ],
        )
        .unwrap();
        let status = physical_effect_finding(&profile);
        assert!(!status.class_implemented);
        assert!(!status.observable_in_profile);
        assert!(!status.establishes_physical_effect());
        assert_eq!(status.completeness, Completeness::NotObservable);
        assert_eq!(
            status.ceiling_if_ever_implemented,
            EvidenceCeiling::Attested
        );
    }

    #[test]
    fn physical_effect_stays_unreachable_even_if_every_mechanism_is_declared() {
        // The strongest profile this build can produce still cannot see it,
        // because no mechanism maps to the class at all (ADR-003 decision 2).
        let profile =
            crate::profile::profile_from_mechanisms("obs", &aip_observe::SourceMechanism::ALL)
                .unwrap();
        let status = physical_effect_finding(&profile);
        assert!(!status.establishes_physical_effect());
        assert_eq!(status.completeness, Completeness::NotObservable);
    }

    #[test]
    fn the_requested_effect_commitment_matches_the_workloads_construction() {
        // Both sides must agree byte for byte, or the reference would report a
        // parameter mismatch for two spellings of one action.
        let r = requested_effect([127, 0, 0, 1], 8080);
        let expected = aip_airi::parameter_commitment(&aip_edge_contract::connect_parameter_bytes(
            [127, 0, 0, 1],
            8080,
        ));
        assert_eq!(r.parameter_commitment, expected);
        assert_eq!(r.action_kind, ACTION_KIND);
    }
}
