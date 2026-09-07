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
        target: Some(format!(
            "{}.{}.{}.{}:{port}",
            ip[0], ip[1], ip[2], ip[3]
        )),
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
    let observations = records
        .iter()
        .map(|(record, observed)| {
            EffectObservation::new(record.clone(), stance_of(observed, ip, port))
        })
        .collect::<Result<Vec<_>, _>>()?;
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
            },
            attribution: aip_observe::AgentAttribution::NotEstablished,
            effect,
            mechanism: aip_observe::SourceMechanism::ProcNetTable,
            claimed_decision_id: None,
            host_wall_clock_ms: 0,
            probe_monotonic_ns: 0,
        }
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
        assert_eq!(status.ceiling_if_ever_implemented, EvidenceCeiling::Attested);
    }

    #[test]
    fn physical_effect_stays_unreachable_even_if_every_mechanism_is_declared() {
        // The strongest profile this build can produce still cannot see it,
        // because no mechanism maps to the class at all (ADR-003 decision 2).
        let profile = crate::profile::profile_from_mechanisms(
            "obs",
            &aip_observe::SourceMechanism::ALL,
        )
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
        let expected = aip_airi::parameter_commitment(
            &aip_edge_contract::connect_parameter_bytes([127, 0, 0, 1], 8080),
        );
        assert_eq!(r.parameter_commitment, expected);
        assert_eq!(r.action_kind, ACTION_KIND);
    }
}
