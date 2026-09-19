//! Effects, split by where they land.
//!
//! The enterprise profile's one genuinely different claim: **some effects here
//! are observable.** A marked path written on the observed host is
//! `SourceMechanism::Fanotify`, an implemented mechanism producing an
//! `ObservationClass::FilesystemEffect` record.
//!
//! What stays out of reach is the far end. A socket to a database is not a row.
//! A call to an API is not a consequence at the other side. A cloud
//! control-plane request is not a resource that changed.
//!
//! [`EnterpriseEffect::establishes_occurrence`] returns `true` exactly for the
//! local case, computed from the resource table, and `false` everywhere else.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::resource::{EffectLocality, EnterpriseResource};
use crate::source::EnterpriseSource;

/// What is known about one claimed effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseEffect {
    pub resource: EnterpriseResource,
    /// Sources inside the workload that report on it.
    pub self_reported_by: Vec<EnterpriseSource>,
    /// Sources outside the workload that report on it.
    pub externally_reported_by: Vec<EnterpriseSource>,
    /// Whether an anchored source with an implemented mechanism observed it.
    /// Computed once, in `from_sources`, and assigned nowhere else.
    anchored_observation: bool,
}

impl EnterpriseEffect {
    /// Derive from a deployment's declared sources.
    pub fn from_sources(resource: EnterpriseResource, sources: &[EnterpriseSource]) -> Self {
        let self_reported_by: Vec<EnterpriseSource> = sources
            .iter()
            .copied()
            .filter(|s| s.workload_controls_source())
            .collect();
        let externally_reported_by: Vec<EnterpriseSource> = sources
            .iter()
            .copied()
            .filter(|s| s.is_independent())
            .collect();
        let anchored_observation = externally_reported_by
            .iter()
            .any(|s| s.can_produce_observation_record());
        Self {
            resource,
            self_reported_by,
            externally_reported_by,
            anchored_observation,
        }
    }

    pub fn has_anchored_observation(&self) -> bool {
        self.anchored_observation
    }

    pub fn locality(&self) -> EffectLocality {
        self.resource.locality()
    }

    /// Whether the effect may be asserted to have occurred.
    ///
    /// Requires an anchored observation **and** a resource whose effect lands
    /// where a mechanism can reach. Both, written out rather than
    /// short-circuited, so a change to either has to be deliberate.
    pub fn establishes_occurrence(&self) -> bool {
        self.anchored_observation && self.resource.outcome_establishable()
    }

    /// Whether the effect at the **far end** may be asserted.
    ///
    /// `false` for every resource and every source set.
    pub fn establishes_remote_outcome(&self) -> bool {
        false
    }

    /// The strongest evidence this effect could carry.
    pub fn ceiling(&self) -> EvidenceCeiling {
        self.self_reported_by
            .iter()
            .chain(self.externally_reported_by.iter())
            .map(|s| s.ceiling())
            .max()
            .unwrap_or(EvidenceCeiling::Corroborative)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULLY_OBSERVED: [EnterpriseSource; 6] = [
        EnterpriseSource::AgentSelfReport,
        EnterpriseSource::FrameworkTrace,
        EnterpriseSource::CloudAuditLog,
        EnterpriseSource::HostProcessObservation,
        EnterpriseSource::HostSocketObservation,
        EnterpriseSource::HostFilesystemObservation,
    ];

    #[test]
    fn a_local_filesystem_effect_is_establishable() {
        // The enterprise difference. This is a real positive result and it is
        // the only kind there is.
        let e = EnterpriseEffect::from_sources(EnterpriseResource::Filesystem, &FULLY_OBSERVED);
        assert!(e.has_anchored_observation());
        assert_eq!(e.locality(), EffectLocality::LocalHost);
        assert!(e.establishes_occurrence());
        assert!(!e.establishes_remote_outcome());
        assert_eq!(e.ceiling(), EvidenceCeiling::Attested);
    }

    #[test]
    fn no_remote_effect_is_establishable_however_well_observed_the_host_is() {
        for r in [
            EnterpriseResource::Model,
            EnterpriseResource::Tool,
            EnterpriseResource::Api,
            EnterpriseResource::Database,
            EnterpriseResource::CloudExecution,
        ] {
            let e = EnterpriseEffect::from_sources(r, &FULLY_OBSERVED);
            assert!(e.has_anchored_observation(), "{r:?}");
            assert!(
                !e.establishes_occurrence(),
                "{r:?}: a socket is not a consequence at the far end"
            );
            assert!(!e.establishes_remote_outcome(), "{r:?}");
        }
    }

    #[test]
    fn a_cloud_audit_log_alone_does_not_anchor_anything() {
        let e = EnterpriseEffect::from_sources(
            EnterpriseResource::CloudExecution,
            &[
                EnterpriseSource::AgentSelfReport,
                EnterpriseSource::CloudAuditLog,
            ],
        );
        assert_eq!(
            e.externally_reported_by,
            vec![EnterpriseSource::CloudAuditLog]
        );
        assert!(
            !e.has_anchored_observation(),
            "independence without an implemented mechanism is nobody observing"
        );
        assert!(!e.establishes_occurrence());
    }

    #[test]
    fn self_reports_alone_establish_nothing_for_any_resource() {
        for r in EnterpriseResource::ALL {
            let e = EnterpriseEffect::from_sources(
                r,
                &[
                    EnterpriseSource::AgentSelfReport,
                    EnterpriseSource::FrameworkTrace,
                    EnterpriseSource::ApmTelemetry,
                    EnterpriseSource::ApplicationLog,
                ],
            );
            assert!(!e.has_anchored_observation(), "{r:?}");
            assert!(!e.establishes_occurrence(), "{r:?}");
            assert_eq!(e.ceiling(), EvidenceCeiling::Corroborative, "{r:?}");
        }
    }
}
