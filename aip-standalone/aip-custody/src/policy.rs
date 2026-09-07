//! Custody classes and the policy that decides which are acceptable.
//!
//! # Why a policy exists at all
//!
//! A development backend that keeps a key in memory, or writes it beside the
//! code, is genuinely useful — tests need one and so does anyone running the
//! CLI locally. It becomes a production incident the moment nothing stops it
//! being the backend in production.
//!
//! The policy is that stop. `Production` refuses every class that cannot meet
//! a production custody bar, and the refusal is an error rather than a
//! downgrade: **there is no fallback path from a production policy to a
//! development backend.** A caller that cannot obtain secure custody gets an
//! error and no signer, which is the fail-closed outcome.

use serde::{Deserialize, Serialize};
use std::fmt;

/// How a custodian protects the key it holds.
///
/// Ordered weakest first; `Ord` follows that so a policy can express a
/// minimum. It is **not** an evidence ladder and says nothing about whether a
/// signature is meaningful — only about how hard the key is to steal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CustodyClass {
    /// Key material in process memory, or on disk with no protection.
    ///
    /// **Not production.** Exportable, unprotected, and refused by
    /// [`CustodyPolicy::Production`].
    Development,
    /// Key material in a file the operating system protects by permission:
    /// created exclusively at mode 0600 and refused if it is readable by group
    /// or other.
    ///
    /// Protects against another local user and against a umask accident. Does
    /// **not** protect against root, a process with the same uid, memory
    /// disclosure, or possession of the disk. A file permission is not a
    /// hardware boundary.
    OsProtectedFile,
    /// Key material held in hardware that will not export it.
    ///
    /// **Reserved and unconstructible.** No backend produces it. It exists so
    /// that its absence is visible in the model rather than silently missing
    /// and later mistaken for unnecessary. Implementing it requires ADR-002 to
    /// move from PROPOSED, because a hardware root of trust is a new trust
    /// anchor.
    HardwareBacked,
}

impl CustodyClass {
    pub fn code(self) -> u8 {
        match self {
            Self::Development => 0x01,
            Self::OsProtectedFile => 0x02,
            Self::HardwareBacked => 0x03,
        }
    }

    /// Whether a backend in this build can actually produce this class.
    ///
    /// `false` for [`CustodyClass::HardwareBacked`] and must stay so until
    /// ADR-002 is accepted.
    pub fn is_implemented(self) -> bool {
        !matches!(self, Self::HardwareBacked)
    }

    /// Whether the backing store can hand the raw key back to a caller.
    ///
    /// `true` for `Development` — and saying so plainly is the point. A
    /// development backend is exportable; classifying that honestly is what
    /// lets the policy refuse it, rather than a comment hoping nobody notices.
    pub fn is_exportable(self) -> bool {
        matches!(self, Self::Development)
    }
}

/// What custody a deployment demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyPolicy {
    /// Anything goes, including in-memory keys. For tests and local work.
    Development,
    /// Only classes that meet a production bar.
    Production,
}

impl CustodyPolicy {
    /// Whether `class` is acceptable under this policy.
    ///
    /// The whole security value of this module is one line: `Production`
    /// admits no `Development` custody, and there is no third answer between
    /// "acceptable" and "refused".
    pub fn admits(self, class: CustodyClass) -> bool {
        match self {
            Self::Development => class.is_implemented(),
            Self::Production => {
                class.is_implemented() && !matches!(class, CustodyClass::Development)
            }
        }
    }

    /// Read the deployment's policy from the environment.
    ///
    /// **Production is the default.** Anything other than an explicit
    /// development opt-in is a production policy — including an unset, empty
    /// or unparseable value. A security posture must not weaken because a
    /// variable was missing.
    pub fn from_env() -> Self {
        match std::env::var("AIP_CUSTODY_POLICY").as_deref() {
            Ok("development") | Ok("dev") => Self::Development,
            _ => Self::Production,
        }
    }
}

impl fmt::Display for CustodyPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Development => f.write_str("development"),
            Self::Production => f.write_str("production"),
        }
    }
}
