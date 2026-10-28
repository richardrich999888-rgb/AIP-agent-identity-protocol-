//! The manifest: what an agent's author says the agent is and may do.
//!
//! **Input, and untrusted.** Every type here is `Deserialize` and every one is
//! `deny_unknown_fields`. None of them has a field in which a *standing* can
//! be written — there is no `verified`, no `basis`, no `trust`. Standing is the
//! assessor's output (`crate::standing`) and is computed only from evidence a
//! core verifier accepts (ADR-017, decision 1).

mod authority;
mod controls;
mod identity;
mod inventory;
pub mod limits;
mod validate;

pub use authority::{
    Amount, ApprovalGate, Limit, LimitPeriod, Permissions, Relationships, Validity,
};
pub use controls::{ControlKind, CryptoPosture, Governance, SecurityControl, SupplyComponent};
pub use identity::AgentIdentity;
pub use inventory::{
    Access, Binary, DataAccess, Environment, Framework, Hosting, Model, NetworkPosture,
    ResourceKind, RuntimeKind, Tool, ToolKind,
};
pub use validate::{ManifestError, Reason};

use serde::{Deserialize, Serialize};

/// The manifest schema this build reads.
pub const AIBOM_SCHEMA_VERSION: u16 = 1;

/// One agent's bill of materials: thirteen components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u16,
    /// C13.
    pub validity: Validity,
    /// C1.
    pub agent: AgentIdentity,
    /// C2.
    #[serde(default)]
    pub models: Vec<Model>,
    /// C3.
    #[serde(default)]
    pub frameworks: Vec<Framework>,
    /// C4.
    #[serde(default)]
    pub tools: Vec<Tool>,
    /// C5.
    #[serde(default)]
    pub permissions: Permissions,
    /// C6.
    #[serde(default)]
    pub data_access: Vec<DataAccess>,
    /// C7.
    pub environment: Environment,
    /// C8.
    #[serde(default)]
    pub relationships: Relationships,
    /// C9.
    #[serde(default)]
    pub security_controls: Vec<SecurityControl>,
    /// C10.
    #[serde(default)]
    pub crypto: CryptoPosture,
    /// C11.
    #[serde(default)]
    pub supply_chain: Vec<SupplyComponent>,
    /// C12.
    #[serde(default)]
    pub governance: Governance,
}

impl Manifest {
    /// Parse and validate a manifest from JSON. Fails closed: an unknown
    /// field, a value out of bounds or a duplicate entry is an error, never a
    /// silent repair.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ManifestError> {
        let m: Manifest = serde_json::from_slice(bytes).map_err(|e| ManifestError {
            path: "$".into(),
            reason: Reason::Malformed(e.to_string()),
        })?;
        m.validate()?;
        Ok(m)
    }

    /// Check every bound, every format and every uniqueness rule.
    pub fn validate(&self) -> Result<(), ManifestError> {
        validate::manifest(self)
    }
}

/// The thirteen components, in a fixed order that every report follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Component {
    Identity,
    Models,
    Frameworks,
    Tools,
    Permissions,
    DataAccess,
    Environment,
    Relationships,
    SecurityControls,
    Cryptography,
    SupplyChain,
    Governance,
    Validity,
}

impl Component {
    /// Every component, in report order.
    pub const ALL: [Component; 13] = [
        Self::Identity,
        Self::Models,
        Self::Frameworks,
        Self::Tools,
        Self::Permissions,
        Self::DataAccess,
        Self::Environment,
        Self::Relationships,
        Self::SecurityControls,
        Self::Cryptography,
        Self::SupplyChain,
        Self::Governance,
        Self::Validity,
    ];

    /// Stable short code, `C01` … `C13`.
    pub fn code(self) -> &'static str {
        match self {
            Self::Identity => "C01",
            Self::Models => "C02",
            Self::Frameworks => "C03",
            Self::Tools => "C04",
            Self::Permissions => "C05",
            Self::DataAccess => "C06",
            Self::Environment => "C07",
            Self::Relationships => "C08",
            Self::SecurityControls => "C09",
            Self::Cryptography => "C10",
            Self::SupplyChain => "C11",
            Self::Governance => "C12",
            Self::Validity => "C13",
        }
    }

    /// Human name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Identity => "agent identity",
            Self::Models => "model inventory",
            Self::Frameworks => "framework dependencies",
            Self::Tools => "tool inventory",
            Self::Permissions => "permissions",
            Self::DataAccess => "data access",
            Self::Environment => "execution environment",
            Self::Relationships => "agent relationships",
            Self::SecurityControls => "security controls",
            Self::Cryptography => "cryptographic posture",
            Self::SupplyChain => "supply-chain provenance",
            Self::Governance => "governance metadata",
            Self::Validity => "validity and revocation",
        }
    }
}
