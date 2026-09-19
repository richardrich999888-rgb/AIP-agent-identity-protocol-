//! The enterprise profile document and its projections.
//!
//! Fills `ProfileKind::Environment` under a fifth id, beside `aip-uas`,
//! `aip-robotics`, `aip-industrial` and `aip-space`. **Enterprise is one
//! deployment class, not the definition of Vanian**, and occupying the same
//! slot under an ordinary id is what that means structurally.

use aip_crypto::sha256;
use aip_observation::ObservationProfile;
use aip_system::{ProfileKind, ProfileRef};
use aip_types::canonical::{put_domain, put_str, put_u16, put_u32, put_u8};
use serde::{Deserialize, Serialize};

use crate::effect::EnterpriseEffect;
use crate::error::EnterpriseError;
use crate::resource::EnterpriseResource;
use crate::source::EnterpriseSource;
use crate::{ENTERPRISE_PROFILE_DOMAIN, ENTERPRISE_PROFILE_VERSION};

/// The profile id this crate commits under.
pub const ENTERPRISE_PROFILE_ID: &str = "vanian.enterprise.v1";

/// What an enterprise deployment declares about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseProfile {
    pub version: u16,
    observer_id: String,
    /// The evidence sources the deployment has. Sorted and deduplicated.
    sources: Vec<EnterpriseSource>,
    /// The resources its agents act on. Sorted and deduplicated.
    resources: Vec<EnterpriseResource>,
    /// Whether agent and framework reports are cryptographically signed.
    ///
    /// Named `authenticated` and not `trusted`.
    pub telemetry_authenticated: bool,
}

impl EnterpriseProfile {
    pub fn new(
        observer_id: &str,
        sources: &[EnterpriseSource],
        resources: &[EnterpriseResource],
    ) -> Result<Self, EnterpriseError> {
        if observer_id.is_empty() || observer_id.len() > 128 {
            return Err(EnterpriseError::Malformed {
                reason: "observer id must be 1-128 bytes",
            });
        }
        let mut sources = sources.to_vec();
        sources.sort_unstable();
        sources.dedup();
        let mut resources = resources.to_vec();
        resources.sort_unstable();
        resources.dedup();
        Ok(Self {
            version: ENTERPRISE_PROFILE_VERSION,
            observer_id: observer_id.to_owned(),
            sources,
            resources,
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
    pub fn sources(&self) -> &[EnterpriseSource] {
        &self.sources
    }
    pub fn resources(&self) -> &[EnterpriseResource] {
        &self.resources
    }

    pub fn mechanised_sources(&self) -> Vec<EnterpriseSource> {
        self.sources
            .iter()
            .copied()
            .filter(|s| s.can_produce_observation_record())
            .collect()
    }

    pub fn has_host_observer(&self) -> bool {
        !self.mechanised_sources().is_empty()
    }

    /// Project into the generic observation profile.
    pub fn observation_profile(&self) -> Result<ObservationProfile, EnterpriseError> {
        let mut profile = ObservationProfile::new(&self.observer_id)?;
        for s in self.mechanised_sources() {
            if let Some(m) = s.mechanism() {
                profile = profile.with_mechanism(m);
            }
        }
        Ok(profile)
    }

    /// What this deployment could establish about one resource's effect.
    pub fn effect(&self, resource: EnterpriseResource) -> EnterpriseEffect {
        EnterpriseEffect::from_sources(resource, &self.sources)
    }

    /// The full table, for a report that must state every resource's standing.
    pub fn effect_table(&self) -> Vec<EnterpriseEffect> {
        EnterpriseResource::ALL
            .iter()
            .map(|r| self.effect(*r))
            .collect()
    }

    /// The resources whose effect this deployment can actually establish.
    ///
    /// Non-empty for a deployment with filesystem observation, which is the
    /// property that distinguishes this vertical from the four embodied ones.
    pub fn establishable_effects(&self) -> Vec<EnterpriseResource> {
        EnterpriseResource::ALL
            .iter()
            .copied()
            .filter(|r| self.effect(*r).establishes_occurrence())
            .collect()
    }

    /// Whether any remote effect is establishable. `false`, always.
    pub fn establishes_remote_effect(&self) -> bool {
        self.effect_table()
            .iter()
            .any(|e| e.establishes_remote_outcome())
    }

    pub fn check_version(&self) -> Result<(), EnterpriseError> {
        if self.version != ENTERPRISE_PROFILE_VERSION {
            return Err(EnterpriseError::UnsupportedVersion {
                found: self.version,
                supported: ENTERPRISE_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, ENTERPRISE_PROFILE_DOMAIN);
        // Structure discriminant: 0x01 is the profile document.
        put_u8(&mut buf, 0x01);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.observer_id);
        put_u8(&mut buf, u8::from(self.telemetry_authenticated));
        put_u32(&mut buf, self.sources.len() as u32);
        for s in &self.sources {
            put_u8(&mut buf, s.code());
        }
        put_u32(&mut buf, self.resources.len() as u32);
        for r in &self.resources {
            put_u8(&mut buf, r.code());
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    pub fn profile_ref(&self) -> Result<ProfileRef, EnterpriseError> {
        ProfileRef::new(
            ProfileKind::Environment,
            ENTERPRISE_PROFILE_ID,
            self.digest(),
        )
        .map_err(|_| EnterpriseError::Malformed {
            reason: "the enterprise profile id is not a valid profile reference id",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observation::ObservationClass;

    const IN_PROCESS_ONLY: [EnterpriseSource; 4] = [
        EnterpriseSource::AgentSelfReport,
        EnterpriseSource::FrameworkTrace,
        EnterpriseSource::ApmTelemetry,
        EnterpriseSource::ApplicationLog,
    ];

    const WITH_HOST_OBSERVER: [EnterpriseSource; 8] = [
        EnterpriseSource::AgentSelfReport,
        EnterpriseSource::FrameworkTrace,
        EnterpriseSource::ApmTelemetry,
        EnterpriseSource::ApplicationLog,
        EnterpriseSource::HostProcessObservation,
        EnterpriseSource::HostLifecycleObservation,
        EnterpriseSource::HostSocketObservation,
        EnterpriseSource::HostFilesystemObservation,
    ];

    fn profile(sources: &[EnterpriseSource]) -> EnterpriseProfile {
        EnterpriseProfile::new("host-collector", sources, &EnterpriseResource::ALL).unwrap()
    }

    #[test]
    fn a_fully_instrumented_process_with_no_observer_establishes_nothing() {
        let p = profile(&IN_PROCESS_ONLY).with_authenticated_telemetry();
        assert!(!p.has_host_observer());
        assert!(p.establishable_effects().is_empty());
        let op = p.observation_profile().unwrap();
        for class in ObservationClass::ALL {
            assert!(!op.capability(class).is_observable(), "{class:?}");
        }
    }

    #[test]
    fn a_host_observer_makes_four_classes_observable_and_one_effect_establishable() {
        let p = profile(&WITH_HOST_OBSERVER);
        assert!(p.has_host_observer());
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
                ObservationClass::FilesystemEffect,
            ]
        );
        // The enterprise difference: a real, positive, establishable effect.
        assert_eq!(
            p.establishable_effects(),
            vec![
                EnterpriseResource::Filesystem,
                EnterpriseResource::Container
            ]
        );
    }

    #[test]
    fn no_deployment_establishes_a_remote_effect() {
        for sources in [
            &IN_PROCESS_ONLY[..],
            &WITH_HOST_OBSERVER[..],
            &EnterpriseSource::ALL[..],
        ] {
            let p = profile(sources);
            assert!(!p.establishes_remote_effect());
            for e in p.effect_table() {
                assert!(!e.establishes_remote_outcome(), "{:?}", e.resource);
            }
        }
    }

    #[test]
    fn the_profile_ref_occupies_the_environment_slot_under_a_fifth_id() {
        let r = profile(&IN_PROCESS_ONLY).profile_ref().unwrap();
        assert_eq!(r.kind, ProfileKind::Environment);
        assert_eq!(r.id(), ENTERPRISE_PROFILE_ID);
        for other in [
            "vanian.uas.v1",
            "vanian.robotics.v1",
            "vanian.industrial.v1",
            "vanian.space.v1",
        ] {
            assert_ne!(ENTERPRISE_PROFILE_ID, other);
        }
    }

    #[test]
    fn the_digest_is_order_independent_and_content_sensitive() {
        let a = EnterpriseProfile::new(
            "obs",
            &[
                EnterpriseSource::AgentSelfReport,
                EnterpriseSource::CloudAuditLog,
            ],
            &[EnterpriseResource::Tool, EnterpriseResource::Api],
        )
        .unwrap();
        let b = EnterpriseProfile::new(
            "obs",
            &[
                EnterpriseSource::CloudAuditLog,
                EnterpriseSource::AgentSelfReport,
            ],
            &[EnterpriseResource::Api, EnterpriseResource::Tool],
        )
        .unwrap();
        assert_eq!(a.digest(), b.digest());
        let c = EnterpriseProfile::new(
            "obs",
            &[EnterpriseSource::AgentSelfReport],
            &[EnterpriseResource::Tool, EnterpriseResource::Api],
        )
        .unwrap();
        assert_ne!(a.digest(), c.digest());
        let d = EnterpriseProfile::new(
            "obs",
            &[
                EnterpriseSource::AgentSelfReport,
                EnterpriseSource::CloudAuditLog,
            ],
            &[EnterpriseResource::Tool],
        )
        .unwrap();
        assert_ne!(a.digest(), d.digest());
    }

    #[test]
    fn authentication_changes_the_document_and_not_what_is_established() {
        let plain = profile(&WITH_HOST_OBSERVER);
        let signed = plain.clone().with_authenticated_telemetry();
        assert_ne!(plain.digest(), signed.digest());
        assert_eq!(
            plain.establishable_effects(),
            signed.establishable_effects()
        );
        assert_eq!(
            plain.establishes_remote_effect(),
            signed.establishes_remote_effect()
        );
    }

    #[test]
    fn bounds_and_versions_are_checked() {
        assert!(EnterpriseProfile::new("", &IN_PROCESS_ONLY, &[]).is_err());
        assert!(EnterpriseProfile::new(&"x".repeat(129), &IN_PROCESS_ONLY, &[]).is_err());
        let empty = EnterpriseProfile::new("obs", &[], &[]).unwrap();
        assert!(empty.observation_profile().is_ok());
        assert!(empty.check_version().is_ok());
        assert!(empty.establishable_effects().is_empty());
    }
}
