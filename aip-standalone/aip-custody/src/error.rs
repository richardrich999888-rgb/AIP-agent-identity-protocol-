//! Why custody could not be established. Every variant is a refusal.

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::policy::{CustodyClass, CustodyPolicy};

#[derive(Debug)]
pub enum CustodyError {
    /// The requested backend's custody class is not acceptable under the
    /// deployment's policy.
    ///
    /// The refusal a production deployment gets when it asks for a
    /// development signer. There is deliberately no downgrade path.
    PolicyRefused {
        policy: CustodyPolicy,
        class: CustodyClass,
    },
    /// No key exists at the configured path. The one recoverable condition:
    /// it is the only case under which creating a key is correct.
    Absent { path: PathBuf },
    /// A key exists but could not be read.
    ///
    /// **Never a licence to generate a new one.** Doing so silently rotates
    /// the identity and invalidates everything already signed under it.
    Unreadable { path: PathBuf, source: io::Error },
    /// The stored material is not a well-formed key.
    Malformed { path: PathBuf, reason: String },
    /// The key file is reachable by group or other.
    Permissions { path: PathBuf, mode: u32 },
    /// A key already exists where one was to be created.
    AlreadyExists { path: PathBuf },
    /// The key could not be written.
    NotWritable { path: PathBuf, source: io::Error },
    /// The signing operation itself failed.
    SigningFailed(String),
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustodyError::PolicyRefused { policy, class } => write!(
                f,
                "custody class {class:?} is not acceptable under the {policy} \
                 policy. There is no fallback: obtain secure custody, or run \
                 with AIP_CUSTODY_POLICY=development and accept that keys are \
                 unprotected."
            ),
            CustodyError::Absent { path } => {
                write!(f, "no key at {}", path.display())
            }
            CustodyError::Unreadable { path, source } => write!(
                f,
                "the key at {} exists but could not be read ({source}). \
                 Refusing to continue: generating a new key here would \
                 silently rotate this identity and invalidate everything \
                 already signed under it.",
                path.display()
            ),
            CustodyError::Malformed { path, reason } => write!(
                f,
                "the key at {} is malformed: {reason}. Restore it from backup, \
                 or move it aside to have a new identity created deliberately.",
                path.display()
            ),
            CustodyError::Permissions { path, mode } => write!(
                f,
                "the key at {} has mode {mode:04o}; group and other must have \
                 no access. Run: chmod 600 {}",
                path.display(),
                path.display()
            ),
            CustodyError::AlreadyExists { path } => write!(
                f,
                "a key already exists at {}; refusing to overwrite it",
                path.display()
            ),
            CustodyError::NotWritable { path, source } => {
                write!(f, "could not write the key to {}: {source}", path.display())
            }
            CustodyError::SigningFailed(why) => write!(f, "signing failed: {why}"),
        }
    }
}

impl std::error::Error for CustodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CustodyError::Unreadable { source, .. } | CustodyError::NotWritable { source, .. } => {
                Some(source)
            }
            _ => None,
        }
    }
}
