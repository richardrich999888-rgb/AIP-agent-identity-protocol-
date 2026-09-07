//! Construction failures. Every variant is a refusal.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    /// A structure carried a version this build does not implement. Refused
    /// rather than guessed: an unknown version is an unknown meaning.
    UnsupportedVersion { found: u16, supported: u16 },
    /// An effect-evidence reference was malformed.
    MalformedEvidence { reason: &'static str },
    /// A profile field was malformed.
    MalformedProfile { reason: &'static str },
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionError::UnsupportedVersion { found, supported } => write!(
                f,
                "execution-model structure version {found} is not implemented by \
                 this build (supported: {supported}); refusing rather than \
                 guessing what the fields mean"
            ),
            ExecutionError::MalformedEvidence { reason } => {
                write!(f, "effect evidence: {reason}")
            }
            ExecutionError::MalformedProfile { reason } => {
                write!(f, "execution profile: {reason}")
            }
        }
    }
}

impl std::error::Error for ExecutionError {}
