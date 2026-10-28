//! C9 security controls, C10 cryptographic posture, C11 supply chain,
//! C12 governance.

use aip_types::AlgorithmId;
use serde::{Deserialize, Serialize};

/// The kind of control claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    Sandbox,
    Authentication,
    ApprovalGate,
    RateLimit,
    Other,
}

/// C9 — one security control. Nothing in this system can verify that a
/// sandbox or an approval gate exists; every one is reported as claimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityControl {
    pub kind: ControlKind,
    pub description: String,
}

/// C10 — cryptographic posture.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoPosture {
    /// Checked against a validated identity document when one is carried.
    #[serde(default)]
    pub identity_key_algorithm: Option<AlgorithmId>,
    #[serde(default)]
    pub signing: Vec<String>,
    /// A claim of post-quantum protection. No mechanism here establishes one
    /// (N-10).
    #[serde(default)]
    pub post_quantum: bool,
}

/// C11 — one supply-chain component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyComponent {
    pub component: String,
    pub version: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub origin: Option<String>,
}

/// C12 — governance metadata. Metadata, not a control.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Governance {
    #[serde(default)]
    pub risk_class: Option<String>,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub audit_owner: Option<String>,
}
