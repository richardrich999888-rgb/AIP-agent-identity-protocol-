//! Refusals. Every variant is a path the profile declined to take.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoboticsError {
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
    /// The central refusal of the robotics profile. A wheel encoder is not a
    /// Linux kernel facility, and calling it one would put a device-specific
    /// value where a verifier expects a mechanism whose forgeability is
    /// characterised.
    NoMechanismForSource {
        source: crate::sensing::SensingSource,
    },
    /// A semantic claim was asserted from a measurement that cannot support it.
    ///
    /// "The range sensor read 1.0 m, therefore separation was safe" is the
    /// canonical instance, and it is refused rather than reported weakly.
    ClaimExceedsMeasurement {
        claim: crate::semantics::SemanticClaim,
        measurement: crate::semantics::Measurement,
    },
}

impl fmt::Display for RoboticsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found, supported } => write!(
                f,
                "robotics profile version {found} is not implemented by this build \
                 (supported: {supported}); refusing rather than guessing what the fields mean"
            ),
            Self::Malformed { reason } => write!(f, "{reason}"),
            Self::CeilingRaised { class } => write!(
                f,
                "the robotics profile tried to raise the ceiling of {class:?}; a profile may \
                 lower a ceiling and may never raise one"
            ),
            Self::NoMechanismForSource { source } => write!(
                f,
                "{source:?} has no implemented observation mechanism in this build, so it \
                 cannot produce an ObservationRecord; its reports remain self-reported however \
                 they are signed"
            ),
            Self::ClaimExceedsMeasurement { claim, measurement } => write!(
                f,
                "{measurement:?} cannot establish {claim:?}: the claim is about the world and \
                 the measurement is about a transducer"
            ),
        }
    }
}

impl std::error::Error for RoboticsError {}

impl From<aip_observation::ObservationError> for RoboticsError {
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
