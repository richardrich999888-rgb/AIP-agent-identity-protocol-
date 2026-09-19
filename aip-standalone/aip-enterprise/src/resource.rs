//! The eight enterprise resources, and what each one's effect is worth.
//!
//! # The finding that makes this vertical different
//!
//! UAS, robotics and industrial all bottom out at a physical effect no
//! mechanism implements. Enterprise does not. A file write **is**
//! `SourceMechanism::Fanotify`. A socket **is** `ProcNetTable`. Bytes accepted
//! for it **are** `SockSendTracepoint`. Those are implemented mechanisms
//! observing real effects, and this is the first vertical where the effect tier
//! is partially reachable.
//!
//! What stays out of reach is the **remote** effect: that a row changed in a
//! database on another host, that an API call had its intended consequence at
//! the far end, that a cloud control-plane action took hold. Those are outside
//! every mechanism, exactly as a valve is.
//!
//! So the honest split is not "physical versus not". It is [`EffectLocality`]:
//! what happened on the host we can watch, and what happened somewhere else.

use aip_observation::EvidenceCeiling;
use aip_observe::SourceMechanism;
use serde::{Deserialize, Serialize};

/// Where a resource's effect lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EffectLocality {
    /// On the observed host. A mechanism may reach it.
    LocalHost,
    /// On another host. No mechanism here reaches it, and the fact that the
    /// call left this host is not the fact that it landed.
    Remote,
    /// Inside the agent's own process. Observable as *that the process ran*
    /// and never as *what it decided*.
    InProcess,
}

impl EffectLocality {
    pub fn code(self) -> u8 {
        match self {
            Self::LocalHost => 0x01,
            Self::Remote => 0x02,
            Self::InProcess => 0x03,
        }
    }

    /// Whether an effect at this locality could be established by some
    /// mechanism in this build.
    pub fn establishable(self) -> bool {
        matches!(self, Self::LocalHost)
    }
}

/// A thing an enterprise agent acts on or through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EnterpriseResource {
    /// The agent itself: a process running a graph, a chain, a loop.
    Agent,
    /// A model invocation — local or hosted.
    Model,
    /// A tool the agent calls.
    Tool,
    /// An HTTP or RPC endpoint on another host.
    Api,
    /// A database, reached over a socket.
    Database,
    /// A path on the observed host.
    Filesystem,
    /// A container the agent or its children run in.
    Container,
    /// A cloud control-plane action: start an instance, write a bucket, assume
    /// a role.
    CloudExecution,
}

impl EnterpriseResource {
    pub const ALL: [EnterpriseResource; 8] = [
        Self::Agent,
        Self::Model,
        Self::Tool,
        Self::Api,
        Self::Database,
        Self::Filesystem,
        Self::Container,
        Self::CloudExecution,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Agent => 0x01,
            Self::Model => 0x02,
            Self::Tool => 0x03,
            Self::Api => 0x04,
            Self::Database => 0x05,
            Self::Filesystem => 0x06,
            Self::Container => 0x07,
            Self::CloudExecution => 0x08,
        }
    }

    pub fn locality(self) -> EffectLocality {
        match self {
            Self::Agent => EffectLocality::InProcess,
            // A model call is a socket to somewhere else, whatever the vendor.
            // A locally hosted model is a subprocess, and a deployment that has
            // one declares `Tool` for it rather than being given a discount
            // here for the word "local".
            Self::Model | Self::Api | Self::Database | Self::CloudExecution => {
                EffectLocality::Remote
            }
            Self::Filesystem => EffectLocality::LocalHost,
            // A tool may be either; the conservative reading is remote, because
            // a tool that shells out locally is observed as a subprocess and a
            // tool that calls out is not observed at all.
            Self::Tool => EffectLocality::Remote,
            // A container is a process in namespaces. What is observable is the
            // process; the container as an identity is not measured.
            Self::Container => EffectLocality::LocalHost,
        }
    }

    /// The mechanisms that observe something about this resource.
    ///
    /// "Something" is doing work: a socket to a database endpoint is observed;
    /// the query is not, and the row is not.
    pub fn mechanisms(self) -> &'static [SourceMechanism] {
        match self {
            Self::Agent | Self::Container => &[
                SourceMechanism::PidFdAnchored,
                SourceMechanism::ProcConnector,
            ],
            Self::Model | Self::Api | Self::Database | Self::CloudExecution => &[
                SourceMechanism::ProcNetTable,
                SourceMechanism::SockSendTracepoint,
            ],
            Self::Filesystem => &[SourceMechanism::Fanotify],
            // A tool is whatever the tool is. A shell-out is a process; a call
            // out is a socket. Both are listed because the adapter says which.
            Self::Tool => &[
                SourceMechanism::SchedTracepoint,
                SourceMechanism::ProcNetTable,
            ],
        }
    }

    /// The strongest evidence any mechanism could contribute about this
    /// resource. Computed from the class table, never tabulated.
    pub fn ceiling(self) -> EvidenceCeiling {
        self.mechanisms()
            .iter()
            .map(|m| aip_observation::class_of(*m).ceiling())
            .max()
            .unwrap_or(EvidenceCeiling::Corroborative)
    }

    /// Whether *that the resource was reached* can be established.
    ///
    /// True for all eight: every one of them has at least a socket or a process
    /// behind it. This is the enterprise vertical's genuine strength and it is
    /// worth stating precisely, because it is one sentence away from the claim
    /// that must never be made.
    pub fn access_establishable(self) -> bool {
        !self.mechanisms().is_empty()
    }

    /// Whether *what the resource did* can be established.
    ///
    /// The sentence one away. False for six of eight: a socket to a database
    /// is not a row, a socket to an API is not a side effect at the far end,
    /// and a model call is not a model's answer. True only where the effect
    /// lands on the observed host.
    pub fn outcome_establishable(self) -> bool {
        self.locality().establishable()
    }

    /// What is observed, stated narrowly.
    pub fn observes(self) -> &'static str {
        match self {
            Self::Agent => "that a process instance ran measured executable content on a boot",
            Self::Model => "that a socket to an endpoint existed, and a count of bytes",
            Self::Tool => "that a subprocess ran, or that a socket existed",
            Self::Api => "that a socket to an endpoint existed, and a count of bytes",
            Self::Database => "that a socket to a database endpoint existed",
            Self::Filesystem => "that a marked path was modified or closed for write",
            Self::Container => "the process; a container is a process in namespaces",
            Self::CloudExecution => "that a socket to a control-plane endpoint existed",
        }
    }

    /// What must not be concluded.
    pub fn does_not_establish(self) -> &'static str {
        match self {
            Self::Agent => "what the agent decided, or why",
            Self::Model => {
                "the prompt, the completion, or that the model returned what the agent says it did"
            }
            Self::Tool => "what the tool did, or whether it succeeded",
            Self::Api => "the request, the response, or any effect at the far end",
            Self::Database => "the query, the rows, or that anything was written",
            Self::Filesystem => "the file's contents, or that the write was correct",
            Self::Container => {
                "the container as an identity: no mechanism measures a namespace set or a cgroup, \
                 and a namespace inode is reused after it is freed"
            }
            Self::CloudExecution => {
                "that the control-plane action took hold, or what it did to anything"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observation::ObservationClass;

    #[test]
    fn access_is_establishable_for_every_resource() {
        for r in EnterpriseResource::ALL {
            assert!(r.access_establishable(), "{r:?}");
            assert!(!r.observes().is_empty(), "{r:?}");
            assert!(!r.does_not_establish().is_empty(), "{r:?}");
        }
    }

    #[test]
    fn the_outcome_is_establishable_for_exactly_the_local_resources() {
        let local: Vec<EnterpriseResource> = EnterpriseResource::ALL
            .iter()
            .copied()
            .filter(|r| r.outcome_establishable())
            .collect();
        assert_eq!(
            local,
            vec![
                EnterpriseResource::Filesystem,
                EnterpriseResource::Container
            ]
        );
    }

    #[test]
    fn no_remote_resource_has_an_establishable_outcome() {
        for r in [
            EnterpriseResource::Model,
            EnterpriseResource::Tool,
            EnterpriseResource::Api,
            EnterpriseResource::Database,
            EnterpriseResource::CloudExecution,
        ] {
            assert_eq!(r.locality(), EffectLocality::Remote, "{r:?}");
            assert!(!r.outcome_establishable(), "{r:?}");
        }
        assert!(!EffectLocality::Remote.establishable());
        assert!(!EffectLocality::InProcess.establishable());
        assert!(EffectLocality::LocalHost.establishable());
    }

    #[test]
    fn a_socket_to_a_database_is_not_a_row() {
        let r = EnterpriseResource::Database;
        assert!(r.access_establishable());
        assert!(!r.outcome_establishable());
        assert!(r.does_not_establish().contains("rows"));
    }

    #[test]
    fn a_container_is_a_process_and_not_an_identity() {
        let r = EnterpriseResource::Container;
        assert_eq!(r.locality(), EffectLocality::LocalHost);
        assert!(r.does_not_establish().contains("namespace inode is reused"));
    }

    #[test]
    fn every_resource_is_capped_at_attested_and_none_reaches_proven() {
        for r in EnterpriseResource::ALL {
            assert_ne!(r.ceiling(), EvidenceCeiling::Proven, "{r:?}");
        }
        // The wire-tap class is the only Corroborative one and no resource
        // maps to it alone, so every resource reaches Attested.
        for r in EnterpriseResource::ALL {
            assert_eq!(r.ceiling(), EvidenceCeiling::Attested, "{r:?}");
        }
    }

    #[test]
    fn no_resource_claims_the_physical_effect_class() {
        for r in EnterpriseResource::ALL {
            for m in r.mechanisms() {
                assert_ne!(
                    aip_observation::class_of(*m),
                    ObservationClass::PhysicalEffect,
                    "{r:?}"
                );
            }
        }
    }

    #[test]
    fn codes_are_unique() {
        let mut codes: Vec<u8> = EnterpriseResource::ALL.iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), EnterpriseResource::ALL.len());
    }
}
