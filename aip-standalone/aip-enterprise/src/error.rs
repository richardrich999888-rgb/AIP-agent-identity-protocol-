//! Refusals. Every variant is a path the profile declined to take.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterpriseError {
    UnsupportedVersion {
        found: u16,
        supported: u16,
    },
    Malformed {
        reason: &'static str,
    },
    CeilingRaised {
        class: aip_observation::ObservationClass,
    },
    /// A workload binding was offered for an execution it does not cover.
    ///
    /// The central refusal of this profile. A tenant token, a workload name and
    /// a framework label are all strings; the binding commits to the execution
    /// identity as well, so copying the strings without the process instance
    /// and executable content produces a different digest.
    BindingDoesNotCoverExecution {
        expected: [u8; 32],
        offered: [u8; 32],
    },
    /// A context hop did not link to the one before it.
    ContextChainBroken {
        at_hop: u32,
    },
    /// A context was offered outside the window it is valid for.
    ContextStale {
        at_ms: u64,
        from_ms: u64,
        until_ms: u64,
    },
    /// A resource commitment was offered for a different resource.
    ResourceMismatch,
}

impl fmt::Display for EnterpriseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found, supported } => write!(
                f,
                "enterprise profile version {found} is not implemented by this build \
                 (supported: {supported}); refusing rather than guessing what the fields mean"
            ),
            Self::Malformed { reason } => write!(f, "{reason}"),
            Self::CeilingRaised { class } => write!(
                f,
                "the enterprise profile tried to raise the ceiling of {class:?}; a profile may \
                 lower a ceiling and may never raise one"
            ),
            Self::BindingDoesNotCoverExecution { .. } => write!(
                f,
                "the workload binding does not cover this execution; a tenant token, a workload \
                 name and a framework label are strings, and copying them does not copy the \
                 process instance or the executable content the binding also commits to"
            ),
            Self::ContextChainBroken { at_hop } => write!(
                f,
                "context hop {at_hop} does not link to its predecessor; a downstream context \
                 that does not chain is a new context wearing an old name"
            ),
            Self::ContextStale {
                at_ms,
                from_ms,
                until_ms,
            } => write!(
                f,
                "the context is valid for [{from_ms}, {until_ms}) and was offered at {at_ms}; a \
                 replayed context is not a live one"
            ),
            Self::ResourceMismatch => write!(
                f,
                "the commitment names a different resource; substituting a tool, an API or a \
                 table changes what was authorized"
            ),
        }
    }
}

impl std::error::Error for EnterpriseError {}

impl From<aip_observation::ObservationError> for EnterpriseError {
    fn from(e: aip_observation::ObservationError) -> Self {
        match e {
            aip_observation::ObservationError::CeilingRaised { class } => {
                Self::CeilingRaised { class }
            }
            aip_observation::ObservationError::UnsupportedVersion { found, supported } => {
                Self::UnsupportedVersion { found, supported }
            }
            aip_observation::ObservationError::Malformed { reason } => Self::Malformed { reason },
            aip_observation::ObservationError::ObserverNotTrusted { .. } => Self::Malformed {
                reason: "the observation batch did not verify against the verifier's anchors",
            },
        }
    }
}
