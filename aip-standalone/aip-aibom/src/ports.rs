//! The discovery port.
//!
//! A discovery is something the **assessor** ran against a source the
//! assessor read. Its result is `Serialize` and not `Deserialize`: a discovery
//! read back from a file somebody handed over is that somebody's word, and
//! would be `SelfReported`, not `Discovered`.

use crate::finding::{SecretIndicator, SecretLocation};
use crate::standing::SourceRef;
use serde::Serialize;

/// How a discovered tool is reached.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum Transport {
    /// A local process. `command` is the program only; arguments are never
    /// recorded, because they are where credentials end up.
    Stdio {
        command: String,
    },
    /// A remote server. `endpoint` has userinfo, query and fragment removed.
    Remote {
        endpoint: String,
    },
    Unknown,
}

/// One tool found in a source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DiscoveredServer {
    pub name: String,
    pub transport: Transport,
    /// Environment variable *names*. Values are never read into this type.
    pub env_names: Vec<String>,
}

/// A credential found inline. Carries where, never what.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SecretExposure {
    pub server: String,
    pub location: SecretLocation,
    pub indicator: SecretIndicator,
}

/// Everything one discovery run found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Discovery {
    pub source: SourceRef,
    pub servers: Vec<DiscoveredServer>,
    pub exposures: Vec<SecretExposure>,
}

/// Why a discovery could not be made. Never carries file content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    Io(String),
    TooLarge {
        max: u64,
    },
    NotJson(String),
    /// The file parsed but is not an MCP client configuration. Refused rather
    /// than read as "no tools", which would be an absence claim from a wrong
    /// file.
    NotAnMcpConfig,
    InvalidServerName(String),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DiscoveryError {}

/// A source of discovered inventory.
pub trait DiscoverySource {
    /// Read the source and report what it contains.
    fn discover(&self) -> Result<Discovery, DiscoveryError>;
}
