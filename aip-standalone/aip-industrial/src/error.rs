//! Refusals. Every variant is a path the profile declined to take.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndustrialError {
    /// A structure carried a version this build does not implement.
    UnsupportedVersion { found: u16, supported: u16 },
    /// A field that participates in a security decision was malformed.
    Malformed { reason: &'static str },
    /// A profile tried to declare a ceiling above what the class allows.
    CeilingRaised {
        class: aip_observation::ObservationClass,
    },
    /// A sensing source was offered as an observation mechanism when no
    /// mechanism in this build implements it.
    ///
    /// A pressure transmitter is not a Linux kernel facility, and calling one
    /// a mechanism would put a device-specific value where a verifier expects
    /// a mechanism whose forgeability is characterised.
    NoMechanismForSource {
        source: crate::sensing::ProcessSensingSource,
    },
    /// A protocol interaction was offered as proof that the plant changed.
    ///
    /// The central refusal of this profile. A write that a controller
    /// acknowledged is a message, and a message is not a moved valve.
    ProtocolIsNotProcessEvidence {
        protocol: crate::protocol::IndustrialProtocol,
        claim: crate::process::ProcessClaim,
    },
    /// A command was offered outside the window it was authorized for.
    ///
    /// Replaying yesterday's setpoint write is the cheapest attack on a
    /// control network that has no session cryptography, which is most of
    /// them.
    CommandNotFresh {
        at_ms: u64,
        from_ms: u64,
        until_ms: u64,
    },
    /// An override was offered as authority without a decision behind it.
    ///
    /// "An operator must have done it" is what an unattributed write looks
    /// like from the inside, and it is also what an attacker says.
    OverrideNotAttributed { kind: crate::operator::OverrideKind },
}

impl fmt::Display for IndustrialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found, supported } => write!(
                f,
                "industrial profile version {found} is not implemented by this build \
                 (supported: {supported}); refusing rather than guessing what the fields mean"
            ),
            Self::Malformed { reason } => write!(f, "{reason}"),
            Self::CeilingRaised { class } => write!(
                f,
                "the industrial profile tried to raise the ceiling of {class:?}; a profile may \
                 lower a ceiling and may never raise one"
            ),
            Self::NoMechanismForSource { source } => write!(
                f,
                "{source:?} has no implemented observation mechanism in this build, so it \
                 cannot produce an observation record; its reports remain self-reported however \
                 they are signed"
            ),
            Self::ProtocolIsNotProcessEvidence { protocol, claim } => write!(
                f,
                "a {protocol:?} interaction cannot establish {claim:?}: the interaction is a \
                 message between two computers and the claim is about a plant"
            ),
            Self::CommandNotFresh {
                at_ms,
                from_ms,
                until_ms,
            } => write!(
                f,
                "the command is authorized for [{from_ms}, {until_ms}) and was offered at \
                 {at_ms}; a command outside its window is not a command"
            ),
            Self::OverrideNotAttributed { kind } => write!(
                f,
                "a {kind:?} override was offered as authority with no decision behind it; an \
                 unattributed override explains nothing, because it is what an unauthorized \
                 write also looks like"
            ),
        }
    }
}

impl std::error::Error for IndustrialError {}

impl From<aip_observation::ObservationError> for IndustrialError {
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
