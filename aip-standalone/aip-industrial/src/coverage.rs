//! Observation coverage, in the three domains the spec names.
//!
//! # Compute, network, process state
//!
//! An industrial deployment wants one sentence per domain, and the three
//! sentences are very different:
//!
//! | domain | what a deployment can have | ceiling |
//! |---|---|---|
//! | compute | process identity, lifecycle, config writes, host-boot | `Attested` |
//! | network | sockets, byte counts, frame headers | `Attested` |
//! | process state | nothing | unreachable |
//!
//! The third row is the deliverable. A deployment that projects its instrument
//! list into an observation profile and finds `NotObservable` for the physical
//! effect class has been told, mechanically, that its plant is unobserved —
//! rather than discovering it during an incident review.
//!
//! # Two classes belong to no domain
//!
//! `ObservationClass::ObserverIntegrity` is evidence about the *observer*, not
//! about the deployment's view of the plant. Folding it into a domain would let
//! an observer's own signature arithmetic count as coverage of something, which
//! is the one direction this architecture must never allow.
//!
//! `class_domain` returns `None` for it, and the match is exhaustive, so a
//! class added later cannot silently join a domain.
//!
//! # Non-occurrence is the hard question
//!
//! Saying "the command was issued" needs evidence. Saying "no command was
//! issued" needs evidence **and** a guarantee that the observer could not have
//! been blinded — which is the observation-integrity finding
//! (`docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`).
//!
//! [`ObservationCoverage::non_occurrence_admissible`] therefore requires three
//! things at once: a domain where the question is meaningful at all, a declared
//! mechanism that does not pass through the per-tracepoint eBPF submission
//! gate, and an observer whose *signed* health actually vouches for the window.
//! The third is delegated to `SignedSensorHealth::covered_by_kernel_pushed_source`
//! rather than re-derived here: an observer in `IntegrityUnknown` fails that
//! predicate, and a profile that re-implemented the rule would be a second
//! place to get it wrong.

use aip_observation::{EvidenceCeiling, ObservationClass, ObservationProfile};
use aip_observe::{SignedSensorHealth, SourceMechanism};
use serde::{Deserialize, Serialize};

use crate::sensing::ProcessSensingSource;

/// One of the three evidence domains an industrial deployment reasons about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CoverageDomain {
    /// What ran on the edge node, and where.
    Compute,
    /// What the edge node said to the network.
    Network,
    /// What the plant did.
    ProcessState,
}

impl CoverageDomain {
    pub const ALL: [CoverageDomain; 3] = [Self::Compute, Self::Network, Self::ProcessState];

    pub fn code(self) -> u8 {
        match self {
            Self::Compute => 0x01,
            Self::Network => 0x02,
            Self::ProcessState => 0x03,
        }
    }

    /// The classes that belong to this domain.
    pub fn classes(self) -> &'static [ObservationClass] {
        match self {
            Self::Compute => &[
                ObservationClass::ProcessLifecycle,
                ObservationClass::ProcessIdentity,
                ObservationClass::FilesystemEffect,
                ObservationClass::PlatformBinding,
            ],
            Self::Network => &[
                ObservationClass::NetworkSocket,
                ObservationClass::NetworkWire,
                ObservationClass::DataTransfer,
            ],
            Self::ProcessState => &[ObservationClass::PhysicalEffect],
        }
    }

    /// Whether a statement of *non-occurrence* is meaningful in this domain at
    /// all.
    ///
    /// False for `ProcessState`: with no mechanism, absence of evidence is the
    /// only possible state, and treating it as evidence of absence is precisely
    /// the error this architecture exists to prevent. A deployment cannot say
    /// "the valve did not move" here, and no amount of observer health changes
    /// that.
    pub fn can_support_non_occurrence(self) -> bool {
        self.classes().iter().any(|c| c.is_implemented())
    }
}

/// The domain a class belongs to, or `None` when it belongs to none.
///
/// Total over `ObservationClass::ALL` — a class added later cannot silently
/// lack a domain, because this match is exhaustive and the compiler enforces it.
pub fn class_domain(class: ObservationClass) -> Option<CoverageDomain> {
    match class {
        ObservationClass::ProcessLifecycle
        | ObservationClass::ProcessIdentity
        | ObservationClass::FilesystemEffect
        | ObservationClass::PlatformBinding => Some(CoverageDomain::Compute),
        ObservationClass::NetworkSocket
        | ObservationClass::NetworkWire
        | ObservationClass::DataTransfer => Some(CoverageDomain::Network),
        ObservationClass::PhysicalEffect => Some(CoverageDomain::ProcessState),
        // Evidence about the observer, not about the plant. Deliberately
        // outside every domain.
        ObservationClass::ObserverIntegrity => None,
    }
}

/// What a deployment can observe in one domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainCoverage {
    pub domain: CoverageDomain,
    /// Whether any declared source can produce a record in this domain.
    pub observable: bool,
    /// The strongest evidence this domain could contribute.
    pub ceiling: EvidenceCeiling,
    /// The mechanisms this deployment declared for the domain.
    pub mechanisms: Vec<SourceMechanism>,
    /// Whether any of them survives an on-host adversary gating a tracepoint.
    pub gate_independent: bool,
}

impl DomainCoverage {
    /// A domain nothing covers. The honest default.
    fn empty(domain: CoverageDomain) -> Self {
        Self {
            domain,
            observable: false,
            ceiling: EvidenceCeiling::Corroborative,
            mechanisms: Vec::new(),
            gate_independent: false,
        }
    }
}

/// A deployment's coverage across all three domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationCoverage {
    domains: Vec<DomainCoverage>,
}

impl ObservationCoverage {
    /// Compute coverage from a deployment's declared sources.
    ///
    /// Only sources with an implemented mechanism contribute. A source without
    /// one is dropped rather than downgraded, which is what lets the resulting
    /// answer be "this deployment cannot look" rather than "it looked and saw
    /// nothing".
    pub fn from_sources(sources: &[ProcessSensingSource]) -> Self {
        let domains = CoverageDomain::ALL
            .iter()
            .map(|domain| {
                let mut cov = DomainCoverage::empty(*domain);
                for s in sources.iter().copied() {
                    let (Some(mechanism), Some(class)) = (s.mechanism(), s.observation_class())
                    else {
                        continue;
                    };
                    if class_domain(class) != Some(*domain) {
                        continue;
                    }
                    cov.observable = true;
                    cov.ceiling = cov.ceiling.max(class.ceiling());
                    if !cov.mechanisms.contains(&mechanism) {
                        cov.mechanisms.push(mechanism);
                    }
                    cov.gate_independent |= mechanism.is_gate_independent_kernel_pushed();
                }
                cov.mechanisms.sort_unstable_by_key(|m| m.code());
                cov
            })
            .collect();
        Self { domains }
    }

    /// Coverage for one domain. A domain nothing covers reads as unobservable
    /// at the lowest ceiling — never an optimistic default.
    pub fn domain(&self, domain: CoverageDomain) -> &DomainCoverage {
        self.domains
            .iter()
            .find(|d| d.domain == domain)
            .expect("every domain is constructed")
    }

    pub fn all(&self) -> &[DomainCoverage] {
        &self.domains
    }

    /// Whether a statement that something did **not** happen may be made in
    /// this domain, for this observer, over the window its health covers.
    ///
    /// Three conjuncts, each of which can only take the answer from `true` to
    /// `false`:
    ///
    /// 1. the domain has any implemented class at all;
    /// 2. the deployment declared a gate-independent kernel-pushed mechanism
    ///    for it;
    /// 3. the observer's signed health vouches for the window, which
    ///    `covered_by_kernel_pushed_source` refuses for a non-`Active` state —
    ///    including `IntegrityUnknown`, the observation-integrity finding.
    ///
    /// A `false` here is never a claim that the thing happened. It is the
    /// refusal to claim that it did not.
    pub fn non_occurrence_admissible(
        &self,
        domain: CoverageDomain,
        health: &SignedSensorHealth,
    ) -> bool {
        domain.can_support_non_occurrence()
            && self.domain(domain).gate_independent
            && health.covered_by_kernel_pushed_source()
    }

    /// Project into the generic observation profile.
    ///
    /// `with_mechanism` derives the class from the mechanism and takes the
    /// class's own ceiling, so the projection cannot inflate.
    pub fn observation_profile(
        &self,
        observer_id: &str,
    ) -> Result<ObservationProfile, crate::error::IndustrialError> {
        let mut profile = ObservationProfile::new(observer_id)?;
        for d in &self.domains {
            for m in &d.mechanisms {
                profile = profile.with_mechanism(*m);
            }
        }
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observe::{ContinuityStatus, CoverageWindow, ObserverState, ProbePolicy, SensorHealth};
    use aip_types::Signature;

    /// The strongest realistic critical-edge deployment: every instrument the
    /// plant has, plus a fully provisioned anchored observer on the edge node.
    const FULL: [ProcessSensingSource; 8] = [
        ProcessSensingSource::ProcessTransmitter,
        ProcessSensingSource::ActuatorPositionFeedback,
        ProcessSensingSource::EdgeProcessObservation,
        ProcessSensingSource::EdgeLifecycleObservation,
        ProcessSensingSource::EdgeNetworkObservation,
        ProcessSensingSource::EdgeDataTransferObservation,
        ProcessSensingSource::ProtocolWireObservation,
        ProcessSensingSource::EdgeConfigWriteObservation,
    ];

    fn health(state: ObserverState, covered_by: Vec<SourceMechanism>) -> SignedSensorHealth {
        SignedSensorHealth {
            health: SensorHealth {
                version: 9,
                observer_id: "edge-collector".into(),
                key_version: 1,
                state,
                continuity: ContinuityStatus::Verified,
                probe_policy: ProbePolicy::RegisteredOnly,
                sequence: 1,
                head: [0u8; 32],
                last_batch_id: None,
                attested_coverage: Some(CoverageWindow {
                    from_ms: 0,
                    to_ms: 10_000,
                }),
                covered_by,
                emitted_at_ms: 10_000,
            },
            // The predicates under test never inspect the signature; a
            // placeholder keeps the test to the logic it is pinning.
            attestation: Signature {
                algorithm: aip_types::AlgorithmId::Ed25519,
                signer_id: "edge-collector".into(),
                timestamp: 10_000,
                nonce: [0u8; 16],
                payload_hash: [0u8; 32],
                signature_bytes: vec![0u8; 64],
            },
        }
    }

    #[test]
    fn process_state_is_never_observable_however_the_plant_is_instrumented() {
        let c = ObservationCoverage::from_sources(&ProcessSensingSource::ALL);
        let ps = c.domain(CoverageDomain::ProcessState);
        assert!(!ps.observable);
        assert!(ps.mechanisms.is_empty());
        assert_eq!(ps.ceiling, EvidenceCeiling::Corroborative);
        assert!(!ps.gate_independent);
        assert!(!CoverageDomain::ProcessState.can_support_non_occurrence());
    }

    #[test]
    fn compute_and_network_are_observable_with_an_edge_observer() {
        let c = ObservationCoverage::from_sources(&FULL);
        for d in [CoverageDomain::Compute, CoverageDomain::Network] {
            assert!(c.domain(d).observable, "{d:?}");
            assert_eq!(c.domain(d).ceiling, EvidenceCeiling::Attested, "{d:?}");
            assert!(c.domain(d).gate_independent, "{d:?}");
            assert!(d.can_support_non_occurrence(), "{d:?}");
        }
    }

    #[test]
    fn plant_instruments_alone_cover_nothing() {
        let c = ObservationCoverage::from_sources(&[
            ProcessSensingSource::ProcessTransmitter,
            ProcessSensingSource::ActuatorPositionFeedback,
            ProcessSensingSource::SafetySystemStatus,
            ProcessSensingSource::HistorianArchive,
            ProcessSensingSource::IndependentPlantSensor,
        ]);
        for d in CoverageDomain::ALL {
            assert!(!c.domain(d).observable, "{d:?}");
        }
    }

    #[test]
    fn a_gate_able_mechanism_alone_does_not_make_a_domain_gate_independent() {
        // Data transfer is the sock-send tracepoint, which a single foreign
        // eBPF program blinds host-wide with no loss accounting.
        let c =
            ObservationCoverage::from_sources(&[ProcessSensingSource::EdgeDataTransferObservation]);
        let net = c.domain(CoverageDomain::Network);
        assert!(net.observable);
        assert!(
            !net.gate_independent,
            "a lone perf tracepoint must not license a non-occurrence claim"
        );
    }

    #[test]
    fn an_observer_with_unknown_integrity_cannot_support_a_non_occurrence_claim() {
        // The Skill 24-era production fix, carried into the profile: the
        // deployment is fully provisioned and the observer is live and
        // continuous, but its mechanism integrity is unknown.
        let c = ObservationCoverage::from_sources(&FULL);
        let blinded = health(
            ObserverState::IntegrityUnknown,
            vec![
                SourceMechanism::ProcConnector,
                SourceMechanism::WireTapAfPacket,
            ],
        );
        for d in CoverageDomain::ALL {
            assert!(
                !c.non_occurrence_admissible(d, &blinded),
                "{d:?}: an observer that may have been blind must not license an absence claim"
            );
        }
        // And the same deployment with a healthy observer can, in the two
        // domains where the question is meaningful — so the test above is
        // sensitive to the state and not to the fixture.
        let healthy = health(
            ObserverState::Active,
            vec![
                SourceMechanism::ProcConnector,
                SourceMechanism::WireTapAfPacket,
            ],
        );
        assert!(c.non_occurrence_admissible(CoverageDomain::Compute, &healthy));
        assert!(c.non_occurrence_admissible(CoverageDomain::Network, &healthy));
        assert!(!c.non_occurrence_admissible(CoverageDomain::ProcessState, &healthy));
    }

    #[test]
    fn every_non_active_observer_state_refuses_a_non_occurrence_claim() {
        let c = ObservationCoverage::from_sources(&FULL);
        for state in [
            ObserverState::Degraded,
            ObserverState::Recovering,
            ObserverState::ContinuityUnverified,
            ObserverState::Quarantined,
            ObserverState::IntegrityUnknown,
        ] {
            let h = health(state, vec![SourceMechanism::ProcConnector]);
            assert!(
                !c.non_occurrence_admissible(CoverageDomain::Compute, &h),
                "{state:?}"
            );
        }
    }

    #[test]
    fn every_class_has_at_most_one_domain_and_only_observer_integrity_has_none() {
        let mut without: Vec<ObservationClass> = Vec::new();
        for class in ObservationClass::ALL {
            match class_domain(class) {
                Some(d) => assert!(
                    d.classes().contains(&class),
                    "{class:?} maps to {d:?} which does not list it"
                ),
                None => without.push(class),
            }
        }
        assert_eq!(without, vec![ObservationClass::ObserverIntegrity]);
        // And every class a domain lists maps back to it.
        for d in CoverageDomain::ALL {
            for class in d.classes() {
                assert_eq!(class_domain(*class), Some(d), "{class:?}");
            }
        }
    }

    #[test]
    fn the_projection_says_not_observable_rather_than_not_observed() {
        let c = ObservationCoverage::from_sources(&FULL);
        let p = c.observation_profile("edge-collector").unwrap();
        assert_eq!(
            p.completeness_without_evidence(ObservationClass::PhysicalEffect),
            aip_observation::Completeness::NotObservable
        );
        assert_eq!(
            p.completeness_without_evidence(ObservationClass::ProcessIdentity),
            aip_observation::Completeness::NotObserved
        );
    }

    #[test]
    fn the_projection_cannot_raise_a_ceiling() {
        let c = ObservationCoverage::from_sources(&ProcessSensingSource::ALL);
        let p = c.observation_profile("edge-collector").unwrap();
        for class in ObservationClass::ALL {
            assert!(
                p.capability(class).ceiling() <= class.ceiling(),
                "{class:?}"
            );
        }
    }

    #[test]
    fn an_empty_deployment_covers_nothing_and_is_still_well_formed() {
        let c = ObservationCoverage::from_sources(&[]);
        for d in CoverageDomain::ALL {
            assert!(!c.domain(d).observable, "{d:?}");
            assert!(!c.domain(d).gate_independent, "{d:?}");
        }
        assert_eq!(c.all().len(), 3);
        assert!(c.observation_profile("o").is_ok());
        assert!(c.observation_profile("").is_err());
    }
}
