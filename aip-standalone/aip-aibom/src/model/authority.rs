//! C5 permissions, C8 relationships, C13 validity.

use aip_types::ScopeAction;
use serde::{Deserialize, Serialize};

/// An amount in integer minor units. Never a float.
///
/// `minor_units = 100_000, currency = "USD", exponent = 2` is $1,000.00. The
/// exponent is explicit because it differs between currencies, and an amount
/// whose scale has to be guessed is an authorisation bug waiting to happen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Amount {
    pub minor_units: u64,
    pub currency: String,
    pub exponent: u8,
}

/// The period a limit applies over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitPeriod {
    PerAction,
    PerDay,
    PerMonth,
}

/// A cap on an action. `CapabilityScope` has no amounts; a per-action cap is
/// carried by a signed spend policy (ADR-018) and verified against it. A
/// per-day or per-month cap is carried by no artifact and stays
/// `SelfReported`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    pub action: ScopeAction,
    pub per: LimitPeriod,
    pub max: Amount,
}

/// A human approval requirement above a threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGate {
    pub action: ScopeAction,
    pub above: Amount,
    pub approver: String,
}

/// C5 — what the agent is authorised to do.
///
/// `allowed` uses the core's own action vocabulary, so a declaration is
/// compared against a verified scope without any translation in between.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    #[serde(default)]
    pub allowed: Vec<ScopeAction>,
    #[serde(default)]
    pub limits: Vec<Limit>,
    #[serde(default)]
    pub approval_gates: Vec<ApprovalGate>,
}

/// C8 — how the agent relates to other agents.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relationships {
    /// Identity lineage: the agent this one was derived from.
    #[serde(default)]
    pub parent_agent: Option<String>,
    /// Principals that delegated authority to this agent.
    #[serde(default)]
    pub delegated_from: Vec<String>,
    /// Agents this one delegates authority to.
    #[serde(default)]
    pub delegates_to: Vec<String>,
}

/// C13 — when this inventory is a true description.
///
/// The component every other AIBOM omits. An inventory with no window is a
/// snapshot that ages silently into a false statement about live authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validity {
    pub issued_at_ms: u64,
    #[serde(default)]
    pub valid_until_ms: Option<u64>,
}
