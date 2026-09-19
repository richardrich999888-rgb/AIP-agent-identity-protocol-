//! Where an enterprise deployment's evidence comes from.
//!
//! The same question as every other vertical. The enterprise answer has one
//! entry worth arguing about: a **cloud audit log** is genuinely outside the
//! workload — a different service, a different account, written by the provider
//! — and it still has no mechanism here. It is the cleanest instance in the
//! whole system of *independence without an implemented mechanism establishes
//! nothing*, because nobody is tempted to call a wheel encoder independent and
//! everybody is tempted to call CloudTrail independent.

use aip_observation::{EvidenceCeiling, ObservationClass};
use aip_observe::SourceMechanism;
use serde::{Deserialize, Serialize};

/// A source of evidence about an enterprise workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EnterpriseSource {
    /// The agent's own account of its decisions, tool calls and outcomes.
    AgentSelfReport,
    /// The framework's own trace: spans, callbacks, graph transitions.
    FrameworkTrace,
    /// An APM or observability agent running in or beside the workload.
    ApmTelemetry,
    /// The application's structured logs.
    ApplicationLog,
    /// A cloud provider's audit log. Outside the workload, written by the
    /// provider — and unmechanised here.
    CloudAuditLog,
    /// A service mesh or gateway's record of a call.
    ServiceMeshRecord,
    /// An anchored observer measuring the host's process identity.
    HostProcessObservation,
    /// An anchored observer measuring the host's process lifecycle.
    HostLifecycleObservation,
    /// An anchored observer measuring the host's sockets.
    HostSocketObservation,
    /// An anchored observer measuring writes to marked paths.
    HostFilesystemObservation,
}

impl EnterpriseSource {
    pub const ALL: [EnterpriseSource; 10] = [
        Self::AgentSelfReport,
        Self::FrameworkTrace,
        Self::ApmTelemetry,
        Self::ApplicationLog,
        Self::CloudAuditLog,
        Self::ServiceMeshRecord,
        Self::HostProcessObservation,
        Self::HostLifecycleObservation,
        Self::HostSocketObservation,
        Self::HostFilesystemObservation,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::AgentSelfReport => 0x01,
            Self::FrameworkTrace => 0x02,
            Self::ApmTelemetry => 0x03,
            Self::ApplicationLog => 0x04,
            Self::CloudAuditLog => 0x05,
            Self::ServiceMeshRecord => 0x06,
            Self::HostProcessObservation => 0x07,
            Self::HostLifecycleObservation => 0x08,
            Self::HostSocketObservation => 0x09,
            Self::HostFilesystemObservation => 0x0A,
        }
    }

    /// Whether the workload under scrutiny can alter what this source says.
    ///
    /// Four of ten. An APM agent is included: it runs in the workload's own
    /// process or as its sidecar, instrumented by the workload's own build.
    pub fn workload_controls_source(self) -> bool {
        matches!(
            self,
            Self::AgentSelfReport
                | Self::FrameworkTrace
                | Self::ApmTelemetry
                | Self::ApplicationLog
        )
    }

    pub fn is_independent(self) -> bool {
        !self.workload_controls_source()
    }

    pub fn mechanism(self) -> Option<SourceMechanism> {
        match self {
            Self::HostProcessObservation => Some(SourceMechanism::PidFdAnchored),
            Self::HostLifecycleObservation => Some(SourceMechanism::ProcConnector),
            Self::HostSocketObservation => Some(SourceMechanism::ProcNetTable),
            Self::HostFilesystemObservation => Some(SourceMechanism::Fanotify),
            _ => None,
        }
    }

    pub fn can_produce_observation_record(self) -> bool {
        self.mechanism().is_some()
    }

    pub fn observation_class(self) -> Option<ObservationClass> {
        self.mechanism().map(aip_observation::class_of)
    }

    pub fn is_gate_independent(self) -> bool {
        self.mechanism()
            .is_some_and(|m| m.is_gate_independent_kernel_pushed())
    }

    /// The strongest evidence this source could ever contribute. Computed.
    pub fn ceiling(self) -> EvidenceCeiling {
        match self.observation_class() {
            Some(class) => class.ceiling(),
            None => EvidenceCeiling::Corroborative,
        }
    }

    pub fn does_not_establish(self) -> &'static str {
        match self {
            Self::AgentSelfReport => "that anything it describes occurred",
            Self::FrameworkTrace => {
                "more than the agent's own account: the framework runs inside the workload and \
                 traces what the workload told it"
            }
            Self::ApmTelemetry => {
                "an independent view: an agent in the process is the process reporting on itself"
            }
            Self::ApplicationLog => "that the logged events happened",
            Self::CloudAuditLog => {
                "anything, absent an anchor: it is written by a party the verifier has not \
                 anchored, and no mechanism here ingests it — independence without an \
                 implemented mechanism is nobody observing"
            }
            Self::ServiceMeshRecord => {
                "what the request was or what the far end did; and the mesh is deployed by the \
                 same platform team as the workload"
            }
            Self::HostProcessObservation => "what the process did, or any effect off the host",
            Self::HostLifecycleObservation => "what ran between the events",
            Self::HostSocketObservation => {
                "what the bytes were, that they arrived, or what the far end did"
            }
            Self::HostFilesystemObservation => "the file's contents, or that the write was correct",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_four_sources_can_produce_an_observation_record() {
        let backed: Vec<EnterpriseSource> = EnterpriseSource::ALL
            .iter()
            .copied()
            .filter(|s| s.can_produce_observation_record())
            .collect();
        assert_eq!(
            backed,
            vec![
                EnterpriseSource::HostProcessObservation,
                EnterpriseSource::HostLifecycleObservation,
                EnterpriseSource::HostSocketObservation,
                EnterpriseSource::HostFilesystemObservation,
            ]
        );
    }

    #[test]
    fn a_cloud_audit_log_is_independent_and_still_establishes_nothing() {
        // The cleanest instance of the rule in the whole system.
        let s = EnterpriseSource::CloudAuditLog;
        assert!(s.is_independent());
        assert!(s.mechanism().is_none());
        assert!(!s.can_produce_observation_record());
        assert_eq!(s.ceiling(), EvidenceCeiling::Corroborative);
        assert!(s.does_not_establish().contains("nobody observing"));
    }

    #[test]
    fn a_framework_trace_and_an_apm_agent_are_inside_the_workload() {
        for s in [
            EnterpriseSource::FrameworkTrace,
            EnterpriseSource::ApmTelemetry,
        ] {
            assert!(s.workload_controls_source(), "{s:?}");
            assert!(!s.is_independent(), "{s:?}");
            assert_eq!(s.ceiling(), EvidenceCeiling::Corroborative, "{s:?}");
        }
    }

    #[test]
    fn the_four_host_observers_reach_attested_and_none_reaches_proven() {
        for s in EnterpriseSource::ALL {
            assert_ne!(s.ceiling(), EvidenceCeiling::Proven, "{s:?}");
            assert!(!s.does_not_establish().is_empty(), "{s:?}");
        }
        for s in [
            EnterpriseSource::HostProcessObservation,
            EnterpriseSource::HostLifecycleObservation,
            EnterpriseSource::HostSocketObservation,
            EnterpriseSource::HostFilesystemObservation,
        ] {
            assert_eq!(s.ceiling(), EvidenceCeiling::Attested, "{s:?}");
        }
    }

    #[test]
    fn exactly_two_mechanised_sources_are_gate_independent() {
        let independent: Vec<EnterpriseSource> = EnterpriseSource::ALL
            .iter()
            .copied()
            .filter(|s| s.is_gate_independent())
            .collect();
        assert_eq!(
            independent,
            vec![
                EnterpriseSource::HostLifecycleObservation,
                EnterpriseSource::HostFilesystemObservation,
            ]
        );
    }

    #[test]
    fn no_source_claims_the_physical_effect_class_and_codes_are_unique() {
        for s in EnterpriseSource::ALL {
            assert_ne!(
                s.observation_class(),
                Some(ObservationClass::PhysicalEffect),
                "{s:?}"
            );
        }
        let mut codes: Vec<u8> = EnterpriseSource::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), EnterpriseSource::ALL.len());
    }
}
