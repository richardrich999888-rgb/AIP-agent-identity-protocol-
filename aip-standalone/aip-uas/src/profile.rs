//! The UAS profile document, and its two projections.
//!
//! # Where this sits
//!
//! Skill 17 left a slot: `ProfileKind::Environment` is documented as *"the
//! slot vertical profiles will occupy; deliberately empty of meaning in Skill
//! 17"*. This crate fills it, and fills it the way the core intended — a
//! `ProfileRef` is a `(kind, id, digest)` commitment, so the core names which
//! profile applied and pins its bytes without knowing what is in it. Adding
//! UGV, robotics, industrial or space later requires no change to any core
//! type, which is the property that makes this compositional rather than a
//! fork.
//!
//! # Two projections, both narrowing
//!
//! [`UasProfile::observation_profile`] projects the declared telemetry sources
//! into the generic `ObservationProfile`, and it projects **only the sources
//! backed by an implemented mechanism**. A GNSS receiver is dropped, not
//! downgraded. That is the difference between a profile that says "this
//! deployment cannot observe position" and one that says "this deployment
//! observed no position this time" — `NotObservable` versus `NotObserved`, and
//! the whole observation model exists to keep them apart.
//!
//! [`UasProfile::navigation_evidence`] projects the same declaration into the
//! per-quantity evidence table.
//!
//! Neither projection can inflate. `ObservationProfile::with_mechanism`
//! derives the class from the mechanism and takes the class's own ceiling; a
//! caller does not get to choose either.

use aip_crypto::sha256;
use aip_observation::{ObservationClass, ObservationProfile};
use aip_system::{ProfileKind, ProfileRef};
use aip_types::canonical::{put_domain, put_str, put_u16, put_u32, put_u8};
use serde::{Deserialize, Serialize};

use crate::error::UasError;
use crate::navigation::{NavigationEvidence, NavigationQuantity};
use crate::telemetry::TelemetrySource;
use crate::{UAS_PROFILE_DOMAIN, UAS_PROFILE_VERSION};

/// The profile id this crate commits under.
///
/// A constant rather than a caller-supplied string: two deployments running
/// this build are running the same profile, and letting each name it
/// differently would make the `ProfileRef` id useless as a join key.
pub const UAS_PROFILE_ID: &str = "vanian.uas.v1";

/// What a UAS deployment declares about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UasProfile {
    pub version: u16,
    /// The observer this profile's observation projection describes. A
    /// reference the existing anchor model resolves; naming an observer here
    /// grants it nothing.
    observer_id: String,
    /// The telemetry sources the deployment has.
    ///
    /// Sorted and deduplicated, so two deployments with the same sources
    /// commit to the same digest whatever order they listed them in.
    sources: Vec<TelemetrySource>,
    /// Whether the subject signs its own reports.
    ///
    /// Carried because an operator wants to know, and used for exactly one
    /// field of [`NavigationEvidence`]. It reaches no conclusion: see that
    /// type's documentation for why authentication is not on the occurrence
    /// path.
    pub telemetry_authenticated: bool,
}

impl UasProfile {
    /// Declare a deployment's sources.
    ///
    /// An empty source list is allowed and is meaningful: it is a deployment
    /// that observes nothing, which is a fact worth recording rather than an
    /// error to raise.
    pub fn new(observer_id: &str, sources: &[TelemetrySource]) -> Result<Self, UasError> {
        if observer_id.is_empty() || observer_id.len() > 128 {
            return Err(UasError::Malformed {
                reason: "observer id must be 1-128 bytes",
            });
        }
        let mut sources = sources.to_vec();
        sources.sort_unstable();
        sources.dedup();
        Ok(Self {
            version: UAS_PROFILE_VERSION,
            observer_id: observer_id.to_owned(),
            sources,
            telemetry_authenticated: false,
        })
    }

    /// Declare that the subject signs its telemetry.
    ///
    /// Named `authenticated` and not `trusted`, because that is what it is.
    pub fn with_authenticated_telemetry(mut self) -> Self {
        self.telemetry_authenticated = true;
        self
    }

    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }
    pub fn sources(&self) -> &[TelemetrySource] {
        &self.sources
    }

    /// The sources that can actually produce an observation record.
    ///
    /// In this build: at most the companion computer's process and socket
    /// observation. Everything else is declared and unimplementable.
    pub fn mechanised_sources(&self) -> Vec<TelemetrySource> {
        self.sources
            .iter()
            .copied()
            .filter(|s| s.can_produce_observation_record())
            .collect()
    }

    /// Project into the generic observation profile.
    ///
    /// Only mechanised sources are projected. A declared GNSS receiver
    /// contributes nothing here, so `ObservationProfile` reports every
    /// navigation-bearing class as `NotObservable` — *this deployment cannot
    /// look* — rather than `NotObserved`, which would mean it looked and saw
    /// nothing.
    pub fn observation_profile(&self) -> Result<ObservationProfile, UasError> {
        let mut profile = ObservationProfile::new(&self.observer_id)?;
        for s in self.mechanised_sources() {
            if let Some(m) = s.mechanism() {
                profile = profile.with_mechanism(m);
            }
        }
        Ok(profile)
    }

    /// What is known about one navigation quantity in this deployment.
    pub fn navigation_evidence(&self, quantity: NavigationQuantity) -> NavigationEvidence {
        NavigationEvidence::from_sources(quantity, &self.sources, self.telemetry_authenticated)
    }

    /// The full navigation table, for a report.
    pub fn navigation_table(&self) -> Vec<NavigationEvidence> {
        NavigationQuantity::ALL
            .iter()
            .map(|q| self.navigation_evidence(*q))
            .collect()
    }

    /// Whether this deployment can establish any physical effect.
    ///
    /// Computed from the class table and the declared sources, so a future
    /// build that implements a physical mechanism changes this answer without
    /// anyone editing a sentence.
    pub fn establishes_physical_effect(&self) -> bool {
        ObservationClass::PhysicalEffect.is_implemented()
            && self
                .sources
                .iter()
                .any(|s| s.observation_class() == Some(ObservationClass::PhysicalEffect))
    }

    pub fn check_version(&self) -> Result<(), UasError> {
        if self.version != UAS_PROFILE_VERSION {
            return Err(UasError::UnsupportedVersion {
                found: self.version,
                supported: UAS_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, UAS_PROFILE_DOMAIN);
        // Structure discriminant inside the shared domain: `0x01` is a mission
        // plan, `0x02` is this.
        put_u8(&mut buf, 0x02);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.observer_id);
        put_u8(&mut buf, u8::from(self.telemetry_authenticated));
        put_u32(&mut buf, self.sources.len() as u32);
        for s in &self.sources {
            put_u8(&mut buf, s.code());
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// The commitment the core carries.
    ///
    /// `ProfileKind::Environment` is the slot Skill 17 reserved. The core will
    /// name this profile and pin its bytes; it will not know what is in it,
    /// and nothing in `aip-system` resolves the digest.
    pub fn profile_ref(&self) -> Result<ProfileRef, UasError> {
        ProfileRef::new(ProfileKind::Environment, UAS_PROFILE_ID, self.digest()).map_err(|_| {
            UasError::Malformed {
                reason: "the UAS profile id is not a valid profile reference id",
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic airframe: full avionics, no independent observer.
    const AIRFRAME: [TelemetrySource; 6] = [
        TelemetrySource::FlightControllerTelemetry,
        TelemetrySource::CompanionAutonomyReport,
        TelemetrySource::GnssReceiverOnboard,
        TelemetrySource::ImuOnboard,
        TelemetrySource::BarometerOnboard,
        TelemetrySource::AirspeedProbeOnboard,
    ];

    /// The same airframe with an anchored companion-computer observer.
    const WITH_OBSERVER: [TelemetrySource; 8] = [
        TelemetrySource::FlightControllerTelemetry,
        TelemetrySource::CompanionAutonomyReport,
        TelemetrySource::GnssReceiverOnboard,
        TelemetrySource::ImuOnboard,
        TelemetrySource::BarometerOnboard,
        TelemetrySource::AirspeedProbeOnboard,
        TelemetrySource::CompanionProcessObservation,
        TelemetrySource::CompanionNetworkObservation,
    ];

    #[test]
    fn a_full_avionics_suite_projects_to_a_profile_that_observes_nothing() {
        let p = UasProfile::new("obs", &AIRFRAME)
            .unwrap()
            .with_authenticated_telemetry();
        assert!(p.mechanised_sources().is_empty());
        let op = p.observation_profile().unwrap();
        for class in ObservationClass::ALL {
            assert!(
                !op.capability(class).is_observable(),
                "{class:?} became observable from onboard avionics alone"
            );
        }
    }

    #[test]
    fn every_class_a_full_airframe_cannot_see_is_not_observable_rather_than_not_observed() {
        let p = UasProfile::new("obs", &AIRFRAME).unwrap();
        let op = p.observation_profile().unwrap();
        assert_eq!(
            op.completeness_without_evidence(ObservationClass::PhysicalEffect),
            aip_observation::Completeness::NotObservable
        );
        assert_eq!(
            op.completeness_without_evidence(ObservationClass::ProcessIdentity),
            aip_observation::Completeness::NotObservable,
            "with no companion observer, even process identity is unobservable here"
        );
    }

    #[test]
    fn adding_a_companion_observer_makes_exactly_two_classes_observable() {
        let p = UasProfile::new("obs", &WITH_OBSERVER).unwrap();
        let op = p.observation_profile().unwrap();
        let observable: Vec<ObservationClass> = ObservationClass::ALL
            .iter()
            .copied()
            .filter(|c| op.capability(*c).is_observable())
            .collect();
        assert_eq!(
            observable,
            vec![
                ObservationClass::ProcessIdentity,
                ObservationClass::NetworkSocket
            ],
            "the companion computer is what a UAS deployment can actually watch"
        );
    }

    #[test]
    fn no_declared_source_set_makes_physical_effect_reachable() {
        for sources in [&AIRFRAME[..], &WITH_OBSERVER[..], &TelemetrySource::ALL[..]] {
            let p = UasProfile::new("obs", sources).unwrap();
            assert!(
                !p.establishes_physical_effect(),
                "a declaration made physical effect reachable"
            );
            let op = p.observation_profile().unwrap();
            assert!(!op
                .capability(ObservationClass::PhysicalEffect)
                .is_observable());
        }
    }

    #[test]
    fn a_profile_cannot_declare_a_class_it_has_no_mechanism_for() {
        // The declaration is a list of sources, and the projection reads the
        // mechanism. There is no path from "I have a GNSS receiver" to a
        // declared NetworkSocket capability.
        let p = UasProfile::new("obs", &[TelemetrySource::GnssReceiverOnboard]).unwrap();
        let op = p.observation_profile().unwrap();
        for class in ObservationClass::ALL {
            assert!(!op.capability(class).is_observable(), "{class:?}");
        }
    }

    #[test]
    fn the_profile_ref_occupies_the_environment_slot() {
        let p = UasProfile::new("obs", &AIRFRAME).unwrap();
        let r = p.profile_ref().unwrap();
        assert_eq!(r.kind, ProfileKind::Environment);
        assert_eq!(r.id(), UAS_PROFILE_ID);
        assert_eq!(r.digest, p.digest());
    }

    #[test]
    fn the_digest_is_order_independent_and_content_sensitive() {
        let a = UasProfile::new(
            "obs",
            &[
                TelemetrySource::ImuOnboard,
                TelemetrySource::GnssReceiverOnboard,
            ],
        )
        .unwrap();
        let b = UasProfile::new(
            "obs",
            &[
                TelemetrySource::GnssReceiverOnboard,
                TelemetrySource::ImuOnboard,
            ],
        )
        .unwrap();
        assert_eq!(a.digest(), b.digest());
        let c = UasProfile::new("obs", &[TelemetrySource::ImuOnboard]).unwrap();
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn authentication_changes_the_document_but_not_what_is_established() {
        let plain = UasProfile::new("obs", &AIRFRAME).unwrap();
        let signed = plain.clone().with_authenticated_telemetry();
        assert_ne!(
            plain.digest(),
            signed.digest(),
            "whether the subject signs is part of the declared deployment"
        );
        for q in NavigationQuantity::ALL {
            assert_eq!(
                plain.navigation_evidence(q).establishes(),
                signed.navigation_evidence(q).establishes(),
                "{q:?}: signing moved an occurrence answer"
            );
        }
    }

    #[test]
    fn an_empty_deployment_is_allowed_and_observes_nothing() {
        let p = UasProfile::new("obs", &[]).unwrap();
        assert!(p.mechanised_sources().is_empty());
        assert!(p.observation_profile().is_ok());
        for e in p.navigation_table() {
            assert!(!e.establishes());
        }
    }

    #[test]
    fn an_empty_observer_id_is_refused() {
        assert!(UasProfile::new("", &AIRFRAME).is_err());
        assert!(UasProfile::new(&"x".repeat(129), &AIRFRAME).is_err());
    }

    #[test]
    fn the_navigation_table_covers_every_quantity() {
        let p = UasProfile::new("obs", &WITH_OBSERVER).unwrap();
        let table = p.navigation_table();
        assert_eq!(table.len(), NavigationQuantity::ALL.len());
        // Only link state is established, and only because the companion
        // socket observer is a real mechanism.
        let established: Vec<NavigationQuantity> = table
            .iter()
            .filter(|e| e.establishes())
            .map(|e| e.quantity)
            .collect();
        assert_eq!(established, vec![NavigationQuantity::LinkState]);
    }
}
