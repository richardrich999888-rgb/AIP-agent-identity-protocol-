//! The industrial profile document and its projections.
//!
//! Fills `ProfileKind::Environment`, the slot Skill 17 reserved for verticals —
//! the same slot `aip-uas` and `aip-robotics` occupy, under a third id. A
//! `ProfileRef` is a `(kind, id, digest)` commitment: the core names which
//! profile applied and pins its bytes without knowing what is in it.
//!
//! # Projections narrow, never widen
//!
//! [`IndustrialProfile::observation_profile`] projects **only** the sources
//! backed by an implemented mechanism. A pressure transmitter is dropped, not
//! downgraded — which is what lets the resulting `ObservationProfile` say
//! `NotObservable` ("this deployment cannot look") rather than `NotObserved`
//! ("it looked and saw nothing").

use aip_crypto::sha256;
use aip_observation::{ObservationClass, ObservationProfile};
use aip_system::{ProfileKind, ProfileRef};
use aip_types::canonical::{put_domain, put_str, put_u16, put_u32, put_u8};
use serde::{Deserialize, Serialize};

use crate::controlloop::{ControlLoopChain, ControlRung};
use crate::coverage::ObservationCoverage;
use crate::error::IndustrialError;
use crate::process::{PhysicalProcessEffect, ProcessClaim, ProcessVariable};
use crate::protocol::IndustrialProtocol;
use crate::safety::{SafetyEvidence, SafetyFunction};
use crate::sensing::ProcessSensingSource;
use crate::{INDUSTRIAL_PROFILE_DOMAIN, INDUSTRIAL_PROFILE_VERSION};

/// The profile id this crate commits under.
///
/// A constant rather than a caller-supplied string: two deployments running
/// this build are running the same profile, and letting each name it
/// differently would make the `ProfileRef` id useless as a join key.
pub const INDUSTRIAL_PROFILE_ID: &str = "vanian.industrial.v1";

/// What an industrial or critical-edge deployment declares about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndustrialProfile {
    pub version: u16,
    observer_id: String,
    /// The sources the deployment has. Sorted and deduplicated.
    sources: Vec<ProcessSensingSource>,
    /// The protocols it speaks. Sorted and deduplicated.
    protocols: Vec<IndustrialProtocol>,
    /// Whether controller and transmitter reports are cryptographically
    /// authenticated.
    ///
    /// Named `authenticated` and not `trusted`, because that is what it is: it
    /// establishes who spoke, and reaches no conclusion about what happened.
    pub telemetry_authenticated: bool,
}

impl IndustrialProfile {
    pub fn new(
        observer_id: &str,
        sources: &[ProcessSensingSource],
        protocols: &[IndustrialProtocol],
    ) -> Result<Self, IndustrialError> {
        if observer_id.is_empty() || observer_id.len() > 128 {
            return Err(IndustrialError::Malformed {
                reason: "observer id must be 1-128 bytes",
            });
        }
        let mut sources = sources.to_vec();
        sources.sort_unstable();
        sources.dedup();
        let mut protocols = protocols.to_vec();
        protocols.sort_unstable();
        protocols.dedup();
        Ok(Self {
            version: INDUSTRIAL_PROFILE_VERSION,
            observer_id: observer_id.to_owned(),
            sources,
            protocols,
            telemetry_authenticated: false,
        })
    }

    pub fn with_authenticated_telemetry(mut self) -> Self {
        self.telemetry_authenticated = true;
        self
    }

    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }
    pub fn sources(&self) -> &[ProcessSensingSource] {
        &self.sources
    }
    pub fn protocols(&self) -> &[IndustrialProtocol] {
        &self.protocols
    }

    /// The sources that can actually produce an observation record.
    pub fn mechanised_sources(&self) -> Vec<ProcessSensingSource> {
        self.sources
            .iter()
            .copied()
            .filter(|s| s.can_produce_observation_record())
            .collect()
    }

    /// Coverage across the three domains.
    pub fn coverage(&self) -> ObservationCoverage {
        ObservationCoverage::from_sources(&self.sources)
    }

    /// Project into the generic observation profile.
    pub fn observation_profile(&self) -> Result<ObservationProfile, IndustrialError> {
        self.coverage().observation_profile(&self.observer_id)
    }

    /// What this deployment could establish about one claimed process effect.
    pub fn process_effect(
        &self,
        variable: ProcessVariable,
        claim: ProcessClaim,
    ) -> PhysicalProcessEffect {
        PhysicalProcessEffect::from_sources(variable, claim, &self.sources)
    }

    /// The full table, for a report that has to state every claim's status.
    pub fn process_effect_table(&self) -> Vec<PhysicalProcessEffect> {
        ProcessClaim::ALL
            .iter()
            .map(|c| self.process_effect(ProcessVariable::Flow, *c))
            .collect()
    }

    /// What this deployment could establish about one protective function.
    pub fn safety_evidence(&self, function: SafetyFunction) -> SafetyEvidence {
        SafetyEvidence::derive(function, self.has_edge_observer())
    }

    /// Whether the deployment has an anchored observer on the edge node.
    pub fn has_edge_observer(&self) -> bool {
        !self.mechanised_sources().is_empty()
    }

    /// The control chain, and how far this deployment reaches along it.
    pub fn control_chain(&self) -> ControlLoopChain {
        ControlLoopChain::current()
    }

    /// The highest rung this deployment establishes.
    ///
    /// `None` when it has no anchored edge observer: without one, not even the
    /// supervisory software's execution is established.
    pub fn highest_established_rung(&self) -> Option<ControlRung> {
        if !self.has_edge_observer() {
            return None;
        }
        self.control_chain().highest_observable()
    }

    /// Whether this deployment can establish any physical process effect.
    pub fn establishes_process_effect(&self) -> bool {
        ObservationClass::PhysicalEffect.is_implemented()
            && self
                .sources
                .iter()
                .any(|s| s.observation_class() == Some(ObservationClass::PhysicalEffect))
    }

    /// The acceptance-gate question, answered as a pair.
    ///
    /// The Skill 25 gate says the verifier must distinguish command execution
    /// from physical process confirmation. This returns exactly that
    /// distinction: `(command_execution_establishable,
    /// process_confirmation_establishable)`. The two must never be equal in
    /// this build for a deployment with an observer, and the second must never
    /// be `true` for any deployment at all.
    pub fn execution_versus_confirmation(&self) -> (bool, bool) {
        (
            self.highest_established_rung() == Some(ControlRung::CommandIssued),
            self.establishes_process_effect(),
        )
    }

    pub fn check_version(&self) -> Result<(), IndustrialError> {
        if self.version != INDUSTRIAL_PROFILE_VERSION {
            return Err(IndustrialError::UnsupportedVersion {
                found: self.version,
                supported: INDUSTRIAL_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, INDUSTRIAL_PROFILE_DOMAIN);
        // Structure discriminant inside the shared domain: 0x01 is a control
        // loop execution, 0x02 is this, 0x03 is a safety boundary.
        put_u8(&mut buf, 0x02);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.observer_id);
        put_u8(&mut buf, u8::from(self.telemetry_authenticated));
        put_u32(&mut buf, self.sources.len() as u32);
        for s in &self.sources {
            put_u8(&mut buf, s.code());
        }
        put_u32(&mut buf, self.protocols.len() as u32);
        for p in &self.protocols {
            put_u8(&mut buf, p.code());
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// The commitment the core carries.
    pub fn profile_ref(&self) -> Result<ProfileRef, IndustrialError> {
        ProfileRef::new(
            ProfileKind::Environment,
            INDUSTRIAL_PROFILE_ID,
            self.digest(),
        )
        .map_err(|_| IndustrialError::Malformed {
            reason: "the industrial profile id is not a valid profile reference id",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::CoverageDomain;

    /// A fully instrumented plant with no independent observer of anything.
    const PLANT: [ProcessSensingSource; 8] = [
        ProcessSensingSource::SupervisoryRuntimeReport,
        ProcessSensingSource::ControllerStatusReport,
        ProcessSensingSource::ProcessTransmitter,
        ProcessSensingSource::ActuatorPositionFeedback,
        ProcessSensingSource::HistorianArchive,
        ProcessSensingSource::HmiOperatorLog,
        ProcessSensingSource::SafetySystemStatus,
        ProcessSensingSource::MeteringDevice,
    ];

    /// The same plant with an anchored observer on its edge node.
    const WITH_OBSERVER: [ProcessSensingSource; 12] = [
        ProcessSensingSource::SupervisoryRuntimeReport,
        ProcessSensingSource::ControllerStatusReport,
        ProcessSensingSource::ProcessTransmitter,
        ProcessSensingSource::ActuatorPositionFeedback,
        ProcessSensingSource::HistorianArchive,
        ProcessSensingSource::HmiOperatorLog,
        ProcessSensingSource::SafetySystemStatus,
        ProcessSensingSource::MeteringDevice,
        ProcessSensingSource::EdgeProcessObservation,
        ProcessSensingSource::EdgeLifecycleObservation,
        ProcessSensingSource::EdgeNetworkObservation,
        ProcessSensingSource::EdgeDataTransferObservation,
    ];

    const PROTOCOLS: [IndustrialProtocol; 2] =
        [IndustrialProtocol::ModbusTcp, IndustrialProtocol::OpcUa];

    #[test]
    fn a_full_instrument_suite_projects_to_a_profile_that_observes_nothing() {
        let p = IndustrialProfile::new("edge", &PLANT, &PROTOCOLS)
            .unwrap()
            .with_authenticated_telemetry();
        assert!(p.mechanised_sources().is_empty());
        assert!(!p.has_edge_observer());
        let op = p.observation_profile().unwrap();
        for class in ObservationClass::ALL {
            assert!(!op.capability(class).is_observable(), "{class:?}");
        }
        assert_eq!(
            p.highest_established_rung(),
            None,
            "without an edge observer, not even the software is established"
        );
    }

    #[test]
    fn undeclared_classes_are_not_observable_rather_than_not_observed() {
        let p = IndustrialProfile::new("edge", &PLANT, &PROTOCOLS).unwrap();
        let op = p.observation_profile().unwrap();
        for class in [
            ObservationClass::PhysicalEffect,
            ObservationClass::ProcessIdentity,
        ] {
            assert_eq!(
                op.completeness_without_evidence(class),
                aip_observation::Completeness::NotObservable,
                "{class:?}"
            );
        }
    }

    #[test]
    fn adding_an_edge_observer_makes_exactly_four_classes_observable() {
        let p = IndustrialProfile::new("edge", &WITH_OBSERVER, &PROTOCOLS).unwrap();
        let op = p.observation_profile().unwrap();
        let observable: Vec<ObservationClass> = ObservationClass::ALL
            .iter()
            .copied()
            .filter(|c| op.capability(*c).is_observable())
            .collect();
        assert_eq!(
            observable,
            vec![
                ObservationClass::ProcessLifecycle,
                ObservationClass::ProcessIdentity,
                ObservationClass::NetworkSocket,
                ObservationClass::DataTransfer,
            ]
        );
        assert_eq!(
            p.highest_established_rung(),
            Some(ControlRung::CommandIssued)
        );
    }

    #[test]
    fn the_acceptance_gate_distinction_holds_for_every_deployment() {
        for sources in [
            &PLANT[..],
            &WITH_OBSERVER[..],
            &ProcessSensingSource::ALL[..],
        ] {
            let p = IndustrialProfile::new("edge", sources, &PROTOCOLS).unwrap();
            let (execution, confirmation) = p.execution_versus_confirmation();
            assert!(
                !confirmation,
                "no deployment may establish physical process confirmation"
            );
            assert_eq!(
                execution,
                p.has_edge_observer(),
                "command execution is establishable exactly when an edge observer exists"
            );
            if p.has_edge_observer() {
                assert!(
                    execution && !confirmation,
                    "an observed deployment must establish command execution and not process \
                     confirmation; that difference is the acceptance gate"
                );
            } else {
                // Without an observer nothing is established either way. That
                // is not the two being conflated — it is both being absent,
                // and the profile says so rather than defaulting either to
                // true.
                assert!(!execution && !confirmation);
            }
        }
    }

    #[test]
    fn no_declared_source_set_makes_the_process_state_domain_observable() {
        for sources in [
            &PLANT[..],
            &WITH_OBSERVER[..],
            &ProcessSensingSource::ALL[..],
        ] {
            let p = IndustrialProfile::new("edge", sources, &PROTOCOLS).unwrap();
            assert!(!p.establishes_process_effect());
            assert!(!p.coverage().domain(CoverageDomain::ProcessState).observable);
            let op = p.observation_profile().unwrap();
            assert!(!op
                .capability(ObservationClass::PhysicalEffect)
                .is_observable());
        }
    }

    #[test]
    fn no_process_claim_is_established_even_with_every_source_declared() {
        let p =
            IndustrialProfile::new("edge", &ProcessSensingSource::ALL, &IndustrialProtocol::ALL)
                .unwrap();
        for e in p.process_effect_table() {
            assert!(!e.establishes(), "{:?}", e.claim);
        }
        for f in SafetyFunction::ALL {
            assert!(!p.safety_evidence(f).establishes_action(), "{f:?}");
        }
    }

    #[test]
    fn the_profile_ref_occupies_the_environment_slot() {
        let p = IndustrialProfile::new("edge", &PLANT, &PROTOCOLS).unwrap();
        let r = p.profile_ref().unwrap();
        assert_eq!(r.kind, ProfileKind::Environment);
        assert_eq!(r.id(), INDUSTRIAL_PROFILE_ID);
        assert_eq!(r.digest, p.digest());
    }

    #[test]
    fn the_digest_is_order_independent_and_content_sensitive() {
        let a = IndustrialProfile::new(
            "edge",
            &[
                ProcessSensingSource::ProcessTransmitter,
                ProcessSensingSource::HistorianArchive,
            ],
            &[IndustrialProtocol::OpcUa, IndustrialProtocol::ModbusTcp],
        )
        .unwrap();
        let b = IndustrialProfile::new(
            "edge",
            &[
                ProcessSensingSource::HistorianArchive,
                ProcessSensingSource::ProcessTransmitter,
            ],
            &[IndustrialProtocol::ModbusTcp, IndustrialProtocol::OpcUa],
        )
        .unwrap();
        assert_eq!(a.digest(), b.digest());
        assert_ne!(
            a.digest(),
            IndustrialProfile::new(
                "edge",
                &[ProcessSensingSource::ProcessTransmitter],
                &[IndustrialProtocol::ModbusTcp, IndustrialProtocol::OpcUa],
            )
            .unwrap()
            .digest()
        );
        assert_ne!(
            a.digest(),
            IndustrialProfile::new(
                "edge",
                &[
                    ProcessSensingSource::ProcessTransmitter,
                    ProcessSensingSource::HistorianArchive,
                ],
                &[IndustrialProtocol::ModbusTcp],
            )
            .unwrap()
            .digest(),
            "the protocol set is part of the document"
        );
    }

    #[test]
    fn the_industrial_profile_id_differs_from_the_other_two() {
        // All three occupy ProfileKind::Environment; the id is what tells a
        // verifier which vertical a commitment is about.
        assert_ne!(INDUSTRIAL_PROFILE_ID, "vanian.uas.v1");
        assert_ne!(INDUSTRIAL_PROFILE_ID, "vanian.robotics.v1");
    }

    #[test]
    fn authentication_changes_the_document_but_not_what_is_established() {
        let plain = IndustrialProfile::new("edge", &WITH_OBSERVER, &PROTOCOLS).unwrap();
        let signed = plain.clone().with_authenticated_telemetry();
        assert_ne!(plain.digest(), signed.digest());
        for c in ProcessClaim::ALL {
            assert_eq!(
                plain
                    .process_effect(ProcessVariable::Pressure, c)
                    .establishes(),
                signed
                    .process_effect(ProcessVariable::Pressure, c)
                    .establishes(),
                "{c:?}"
            );
        }
        assert_eq!(
            plain.execution_versus_confirmation(),
            signed.execution_versus_confirmation()
        );
    }

    #[test]
    fn an_empty_observer_id_is_refused_and_an_empty_deployment_is_allowed() {
        assert!(IndustrialProfile::new("", &PLANT, &PROTOCOLS).is_err());
        assert!(IndustrialProfile::new(&"x".repeat(129), &PLANT, &PROTOCOLS).is_err());
        let empty = IndustrialProfile::new("edge", &[], &[]).unwrap();
        assert!(empty.mechanised_sources().is_empty());
        assert!(empty.observation_profile().is_ok());
        assert!(empty.check_version().is_ok());
    }
}
