//! Tool manifests and canonical parameters.
//!
//! A manifest pins a tool to an absolute program path **and** the SHA-256 of
//! that program's contents. The AIP parameter set covers the tool id, the
//! program digest and the exact argv, so an `ExpectedExecution` authorizes
//! one concrete command, not "the tool" in general.

use std::path::{Path, PathBuf};

use aip_authorize::ActionParameters;
use aip_types::ScopeAction;
use serde::{Deserialize, Serialize};

use crate::domain::corpus::Ident;

/// Upper bounds on caller-supplied arguments.
pub const MAX_ARGS: usize = 16;
pub const MAX_ARG_LEN: usize = 256;
/// Upper bound on a tool's wall-clock budget (ms).
pub const MAX_TIMEOUT_MS: u64 = 600_000;
/// AIP custom actions are limited to 64 bytes; "tool:" uses 5.
const ACTION_PREFIX: &str = "tool:";

/// A tool an agent may request. Loaded from an operator-controlled file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolManifest {
    pub id: Ident,
    /// Absolute path of the executable.
    pub program: PathBuf,
    /// Lowercase hex SHA-256 of the executable's contents.
    pub program_sha256: String,
    /// Arguments always passed before caller arguments.
    pub fixed_args: Vec<String>,
    /// Hard wall-clock limit enforced with SIGKILL.
    pub timeout_ms: u64,
}

/// A request to run a tool with caller arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocation {
    pub tool_id: Ident,
    pub args: Vec<String>,
}

/// Why a manifest or invocation is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    RelativeProgramPath,
    BadDigestEncoding,
    TimeoutOutOfRange(u64),
    TooManyArgs(usize),
    ArgTooLong(usize),
    ArgContainsNul,
    ActionNameTooLong,
    WrongTool {
        manifest: String,
        invocation: String,
    },
    Parameters(String),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ToolError {}

impl ToolManifest {
    /// Structural validation (no filesystem access).
    pub fn validate(&self) -> Result<[u8; 32], ToolError> {
        if !self.program.is_absolute() {
            return Err(ToolError::RelativeProgramPath);
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_TIMEOUT_MS {
            return Err(ToolError::TimeoutOutOfRange(self.timeout_ms));
        }
        validate_args(&self.fixed_args)?;
        if ACTION_PREFIX.len() + self.id.as_str().len() > 64 {
            return Err(ToolError::ActionNameTooLong);
        }
        decode_digest(&self.program_sha256)
    }

    /// The AIP action this tool maps to: `Custom("tool:<id>")`.
    pub fn action_kind(&self) -> ScopeAction {
        action_for(&self.id)
    }

    /// Full argv: program path, fixed args, caller args.
    pub fn argv(&self, inv: &ToolInvocation) -> Result<Vec<String>, ToolError> {
        if inv.tool_id != self.id {
            return Err(ToolError::WrongTool {
                manifest: self.id.as_str().into(),
                invocation: inv.tool_id.as_str().into(),
            });
        }
        validate_args(&inv.args)?;
        let mut v = vec![self.program.to_string_lossy().into_owned()];
        v.extend(self.fixed_args.iter().cloned());
        v.extend(inv.args.iter().cloned());
        Ok(v)
    }

    /// The parameter set the decision point signs a digest of.
    pub fn parameters(&self, inv: &ToolInvocation) -> Result<ActionParameters, ToolError> {
        self.validate()?;
        let argv = self.argv(inv)?;
        ActionParameters::from_pairs([
            ("tool", self.id.as_str().as_bytes().to_vec()),
            ("program_sha256", self.program_sha256.as_bytes().to_vec()),
            ("argv", canonical_argv(&argv)),
        ])
        .map_err(|e| ToolError::Parameters(format!("{e:?}")))
    }
}

/// `Custom("tool:<id>")`.
pub fn action_for(id: &Ident) -> ScopeAction {
    ScopeAction::Custom(format!("{ACTION_PREFIX}{}", id.as_str()))
}

/// Unambiguous argv encoding: u32 big-endian count, then each argument as
/// u32 big-endian length + bytes. Distinguishes `["a b"]` from `["a","b"]`.
pub fn canonical_argv(argv: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(argv.len() as u32).to_be_bytes());
    for a in argv {
        out.extend_from_slice(&(a.len() as u32).to_be_bytes());
        out.extend_from_slice(a.as_bytes());
    }
    out
}

fn validate_args(args: &[String]) -> Result<(), ToolError> {
    if args.len() > MAX_ARGS {
        return Err(ToolError::TooManyArgs(args.len()));
    }
    for a in args {
        if a.len() > MAX_ARG_LEN {
            return Err(ToolError::ArgTooLong(a.len()));
        }
        if a.contains('\0') {
            return Err(ToolError::ArgContainsNul);
        }
    }
    Ok(())
}

/// Decode a 64-char lowercase hex digest.
pub fn decode_digest(s: &str) -> Result<[u8; 32], ToolError> {
    if s.len() != 64 || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ToolError::BadDigestEncoding);
    }
    let v = hex::decode(s).map_err(|_| ToolError::BadDigestEncoding)?;
    v.try_into().map_err(|_| ToolError::BadDigestEncoding)
}

/// SHA-256 of a file's contents.
pub fn file_sha256(path: &Path) -> std::io::Result<[u8; 32]> {
    Ok(aip_crypto::sha256(&std::fs::read(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m() -> ToolManifest {
        ToolManifest {
            id: Ident::new("disk-usage").unwrap(),
            program: PathBuf::from("/usr/bin/du"),
            program_sha256: "ab".repeat(32),
            fixed_args: vec!["-s".into()],
            timeout_ms: 5_000,
        }
    }

    fn inv(args: &[&str]) -> ToolInvocation {
        ToolInvocation {
            tool_id: Ident::new("disk-usage").unwrap(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn argv_encoding_is_unambiguous() {
        assert_ne!(
            canonical_argv(&["a b".into()]),
            canonical_argv(&["a".into(), "b".into()])
        );
        assert_ne!(
            canonical_argv(&["ab".into(), "".into()]),
            canonical_argv(&["a".into(), "b".into()])
        );
    }

    #[test]
    fn parameters_bind_args_and_program_digest() {
        let base = m().parameters(&inv(&["/tmp"])).unwrap().digest();
        assert_ne!(base, m().parameters(&inv(&["/etc"])).unwrap().digest());
        let mut other = m();
        other.program_sha256 = "cd".repeat(32);
        assert_ne!(base, other.parameters(&inv(&["/tmp"])).unwrap().digest());
        assert_eq!(
            base,
            m().parameters(&inv(&["/tmp"])).unwrap().digest(),
            "must be deterministic"
        );
    }

    #[test]
    fn invalid_manifests_and_args_refused() {
        let mut r = m();
        r.program = PathBuf::from("du");
        assert_eq!(r.validate(), Err(ToolError::RelativeProgramPath));
        let mut t = m();
        t.timeout_ms = 0;
        assert!(matches!(t.validate(), Err(ToolError::TimeoutOutOfRange(0))));
        let mut d = m();
        d.program_sha256 = "AB".repeat(32);
        assert_eq!(d.validate(), Err(ToolError::BadDigestEncoding));
        assert_eq!(
            m().parameters(&inv(&["a\0b"])).unwrap_err(),
            ToolError::ArgContainsNul
        );
        let many: Vec<&str> = vec!["x"; MAX_ARGS + 1];
        assert!(matches!(
            m().parameters(&inv(&many)),
            Err(ToolError::TooManyArgs(_))
        ));
    }

    #[test]
    fn invocation_for_another_tool_refused() {
        let i = ToolInvocation {
            tool_id: Ident::new("reboot").unwrap(),
            args: vec![],
        };
        assert!(matches!(m().argv(&i), Err(ToolError::WrongTool { .. })));
    }

    #[test]
    fn action_kind_is_namespaced() {
        assert_eq!(
            m().action_kind(),
            ScopeAction::Custom("tool:disk-usage".into())
        );
    }
}
