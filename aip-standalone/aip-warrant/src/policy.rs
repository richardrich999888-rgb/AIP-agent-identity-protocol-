//! Operator policy: severity assignment, protected identities, enablement.
//!
//! **Severity** is the operator's declaration of how serious each
//! reconciliation result would be *if true*. It is assigned per result class
//! by policy and never computed from evidence; evidence strength comes from
//! the reconciler's record and never from policy. The two are separate types
//! set from separate sources (Skill 8 §3).

use std::collections::BTreeSet;

use aip_reconcile::ReconciliationResult;
use serde::Serialize;

/// How serious a finding would be if true. Ordered low → high.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn code(self) -> u8 {
        match self {
            Severity::Low => 0x01,
            Severity::Medium => 0x02,
            Severity::High => 0x03,
            Severity::Critical => 0x04,
        }
    }
}

/// Severity per reconciliation result, as the operator declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeverityAssignment {
    table: Vec<(ReconciliationResult, Severity)>,
}

impl SeverityAssignment {
    /// The shipped table. `CANNOT_PROVE` and `VERIFIED_EXECUTION` are `Low`:
    /// neither is a finding of wrongdoing.
    pub fn default_table() -> Self {
        use ReconciliationResult as R;
        Self {
            table: vec![
                (R::VerifiedExecution, Severity::Low),
                (R::CannotProve, Severity::Low),
                (R::ContinuityFailure, Severity::Medium),
                (R::PhantomClaim, Severity::High),
                (R::LineageViolation, Severity::High),
                (R::UnattributedEffect, Severity::Critical),
                (R::IdentityDivergence, Severity::Critical),
                (R::SensorIntegrityFailure, Severity::Critical),
            ],
        }
    }

    pub fn with(mut self, result: ReconciliationResult, severity: Severity) -> Self {
        self.table.retain(|(r, _)| *r != result);
        self.table.push((result, severity));
        self
    }

    /// A result absent from the table is `Low`: an unknown class is never a
    /// reason to escalate (§26).
    pub fn severity_of(&self, result: ReconciliationResult) -> Severity {
        self.table
            .iter()
            .find(|(r, _)| *r == result)
            .map(|(_, s)| *s)
            .unwrap_or(Severity::Low)
    }
}

impl Default for SeverityAssignment {
    fn default() -> Self {
        Self::default_table()
    }
}

/// Identities that autonomous containment must never touch: the agents,
/// decision points and observers the operator names (§14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ProtectedIdentitySet {
    agents: BTreeSet<String>,
    decision_points: BTreeSet<String>,
    observers: BTreeSet<String>,
}

impl ProtectedIdentitySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn protect_agent(mut self, agent_id: &str) -> Self {
        self.agents.insert(agent_id.to_string());
        self
    }

    pub fn protect_decision_point(mut self, decision_point_id: &str) -> Self {
        self.decision_points.insert(decision_point_id.to_string());
        self
    }

    pub fn protect_observer(mut self, observer_id: &str) -> Self {
        self.observers.insert(observer_id.to_string());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty() && self.decision_points.is_empty() && self.observers.is_empty()
    }

    pub fn contains_agent(&self, id: &str) -> bool {
        self.agents.contains(id)
    }

    pub fn contains_decision_point(&self, id: &str) -> bool {
        self.decision_points.contains(id)
    }

    pub fn contains_observer(&self, id: &str) -> bool {
        self.observers.contains(id)
    }
}

/// Explicit, inspectable operator policy (§15). The default is advisory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WarrantPolicy {
    /// Must be positive; recorded in every warrant.
    pub version: u32,
    /// Whether a `Proven` finding may be warranted `Contain`. Default off.
    pub autonomous_containment: bool,
    /// Whether an `Attested` finding may be warranted `Constrain`. Default off.
    pub allow_constrain_on_attested: bool,
    pub protected: ProtectedIdentitySet,
    pub severity: SeverityAssignment,
    /// How long a warrant stays valid after issue. Must be positive.
    pub validity_ms: u64,
}

impl Default for WarrantPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            autonomous_containment: false,
            allow_constrain_on_attested: false,
            protected: ProtectedIdentitySet::default(),
            severity: SeverityAssignment::default_table(),
            validity_ms: 3_600_000,
        }
    }
}

impl WarrantPolicy {
    pub fn with_severity(mut self, result: ReconciliationResult, severity: Severity) -> Self {
        self.severity = self.severity.with(result, severity);
        self
    }
}
