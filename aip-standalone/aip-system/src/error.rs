//! Why a value could not be constructed.
//!
//! Every variant is a refusal. There is no variant meaning "accepted with
//! reservations": a descriptor either encodes something well-formed or it does
//! not exist. Construction is the only place this crate can fail closed, so it
//! fails closed here rather than producing a value a later reader must
//! second-guess.

use std::fmt;

/// Construction and decoding failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemError {
    /// A namespaced identifier was empty, over-long, wrongly shaped, or used
    /// characters outside the permitted set.
    MalformedId {
        kind: &'static str,
        reason: &'static str,
    },
    /// An AIP-ID did not validate against `aip_crypto::validate_aip_id`.
    InvalidAgentId,
    /// A structure carried a version this build does not implement.
    ///
    /// Refused rather than guessed: the repository's versioning philosophy is
    /// that an unknown version is an unknown meaning, and a reader that
    /// guesses is a reader that silently reinterprets someone else's bytes.
    UnsupportedVersion { found: u16, supported: u16 },
    /// A profile reference was malformed.
    MalformedProfile { reason: &'static str },
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemError::MalformedId { kind, reason } => {
                write!(f, "{kind}: {reason}")
            }
            SystemError::InvalidAgentId => {
                write!(f, "agent id is not a valid AIP-ID")
            }
            SystemError::UnsupportedVersion { found, supported } => write!(
                f,
                "autonomous-system structure version {found} is not implemented \
                 by this build (supported: {supported}); refusing rather than \
                 guessing what the fields mean"
            ),
            SystemError::MalformedProfile { reason } => {
                write!(f, "profile reference: {reason}")
            }
        }
    }
}

impl std::error::Error for SystemError {}
