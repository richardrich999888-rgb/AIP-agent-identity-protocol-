//! Construction and correlation failures. Every variant is a refusal.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationError {
    /// A structure carried a version this build does not implement. Refused
    /// rather than guessed: an unknown version is an unknown meaning.
    UnsupportedVersion { found: u16, supported: u16 },
    /// The attested batch did not verify against the verifier's anchors.
    /// Carries the observer's claimed id for diagnosis; naming an observer
    /// grants nothing.
    ObserverNotTrusted { observer_id: String },
    /// A profile tried to declare a ceiling above the class's own. A profile
    /// may lower a ceiling and may never raise one.
    CeilingRaised {
        class: crate::class::ObservationClass,
    },
    /// A field that participates in a security decision was malformed.
    Malformed { reason: &'static str },
}

impl fmt::Display for ObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObservationError::UnsupportedVersion { found, supported } => write!(
                f,
                "observation structure version {found} is not implemented by \
                 this build (supported: {supported}); refusing rather than \
                 guessing what the fields mean"
            ),
            ObservationError::ObserverNotTrusted { observer_id } => write!(
                f,
                "the batch claiming observer {observer_id:?} did not verify \
                 against this verifier's anchors; no observation is produced"
            ),
            ObservationError::CeilingRaised { class } => write!(
                f,
                "a profile tried to raise the ceiling of {class:?}; a profile \
                 may lower a ceiling and may never raise one"
            ),
            ObservationError::Malformed { reason } => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for ObservationError {}
