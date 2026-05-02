//! Capability scopes for AIP v2 delegation tokens.
//!
//! A CapabilityScope is a lattice element: the meet() operation returns the
//! intersection of two scopes' effective allowed sets, implementing the
//! principle of least privilege for delegation chains.
//!
//! PATENT CLAIM (NM-A1): Scope-constrained delegation lattice.
//! Child scope can never exceed parent scope.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ── Action ────────────────────────────────────────────────────────────────────

/// All actions that may be controlled by a capability scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    EvaluateContent,
    SubmitAuditEntry,
    IssueSubDelegation,
    ReadAuditLog,
    RevokeToken,
    Custom(String),
}

// ── CapabilityScope ───────────────────────────────────────────────────────────

/// A set of allowed and denied actions.
///
/// Invariants:
/// - `denied` always wins over `allowed` (`permits()` checks deny first).
/// - `meet()` produces the intersection of two scopes' effective allowed sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityScope {
    pub allowed: HashSet<Action>,
    pub denied: HashSet<Action>,
}

impl CapabilityScope {
    /// Create a scope with a specific allowed and denied set.
    pub fn new(
        allowed: impl IntoIterator<Item = Action>,
        denied: impl IntoIterator<Item = Action>,
    ) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
            denied: denied.into_iter().collect(),
        }
    }

    /// Returns true if this scope permits the given action.
    /// Denied always wins over allowed.
    pub fn permits(&self, action: &Action) -> bool {
        if self.denied.contains(action) {
            return false;
        }
        self.allowed.contains(action)
    }

    /// Lattice MEET: returns the intersection of two scopes' effective allowed sets.
    /// Returns None if the resulting scope allows no actions.
    ///
    /// PATENT CLAIM (NM-A1): Child scope can never exceed parent scope.
    pub fn meet(&self, other: &CapabilityScope) -> Option<CapabilityScope> {
        // Effective allowed = allowed − denied
        let self_effective: HashSet<&Action> = self
            .allowed
            .iter()
            .filter(|a| !self.denied.contains(*a))
            .collect();
        let other_effective: HashSet<&Action> = other
            .allowed
            .iter()
            .filter(|a| !other.denied.contains(*a))
            .collect();

        // Intersection of effective sets
        let intersection: HashSet<Action> = self_effective
            .intersection(&other_effective)
            .map(|a| (*a).clone())
            .collect();

        if intersection.is_empty() {
            return None;
        }

        // Union of deny sets (child inherits all parent denials)
        let combined_denied: HashSet<Action> = self.denied.union(&other.denied).cloned().collect();

        Some(CapabilityScope {
            allowed: intersection,
            denied: combined_denied,
        })
    }

    /// Returns true if all of self's effective allowed actions are a subset of other's.
    pub fn is_subset_of(&self, other: &CapabilityScope) -> bool {
        let self_effective: HashSet<&Action> = self
            .allowed
            .iter()
            .filter(|a| !self.denied.contains(*a))
            .collect();
        let other_effective: HashSet<&Action> = other
            .allowed
            .iter()
            .filter(|a| !other.denied.contains(*a))
            .collect();
        self_effective.is_subset(&other_effective)
    }
}

// ── Named scopes ──────────────────────────────────────────────────────────────

impl CapabilityScope {
    /// Scope for content submission agents: may only evaluate content.
    pub fn submitter() -> Self {
        Self::new([Action::EvaluateContent], [])
    }

    /// Scope for audit readers: may only read the audit log.
    pub fn audit_reader() -> Self {
        Self::new([Action::ReadAuditLog], [])
    }

    /// Scope for orchestrator services: evaluate, audit, delegate, read.
    pub fn orchestrator() -> Self {
        Self::new(
            [
                Action::EvaluateContent,
                Action::SubmitAuditEntry,
                Action::IssueSubDelegation,
                Action::ReadAuditLog,
            ],
            [],
        )
    }

    /// Full admin scope — all actions permitted.
    pub fn admin() -> Self {
        Self::new(
            [
                Action::EvaluateContent,
                Action::SubmitAuditEntry,
                Action::IssueSubDelegation,
                Action::ReadAuditLog,
                Action::RevokeToken,
            ],
            [],
        )
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // T-CAP-1: meet() of two overlapping scopes returns intersection
    #[test]
    fn test_scope_meet_intersection() {
        let a = CapabilityScope::new([Action::EvaluateContent, Action::ReadAuditLog], []);
        let b = CapabilityScope::new([Action::EvaluateContent, Action::SubmitAuditEntry], []);
        let result = a.meet(&b).expect("meet should not be empty");
        assert!(result.permits(&Action::EvaluateContent));
        assert!(!result.permits(&Action::ReadAuditLog));
        assert!(!result.permits(&Action::SubmitAuditEntry));
    }

    // T-CAP-2: meet() of disjoint scopes returns None
    #[test]
    fn test_scope_meet_none() {
        let a = CapabilityScope::new([Action::EvaluateContent], []);
        let b = CapabilityScope::new([Action::ReadAuditLog], []);
        assert!(a.meet(&b).is_none(), "disjoint scopes must meet to None");
    }

    // T-CAP-3: denied always wins
    #[test]
    fn test_denied_wins_over_allowed() {
        let scope = CapabilityScope::new([Action::EvaluateContent], [Action::EvaluateContent]);
        assert!(!scope.permits(&Action::EvaluateContent));
    }

    // T-CAP-4: meet() child cannot exceed parent
    #[test]
    fn test_meet_child_cannot_exceed_parent() {
        let parent = CapabilityScope::submitter(); // only EvaluateContent
        let child_attempt = CapabilityScope::admin(); // all actions
        let child_effective = child_attempt
            .meet(&parent)
            .expect("submitter ∩ admin is non-empty");
        // Child should only have EvaluateContent
        assert!(child_effective.permits(&Action::EvaluateContent));
        assert!(!child_effective.permits(&Action::RevokeToken));
        assert!(!child_effective.permits(&Action::SubmitAuditEntry));
    }

    // T-CAP-5: is_subset_of checks effective set
    #[test]
    fn test_is_subset_of() {
        let sub = CapabilityScope::submitter();
        let orch = CapabilityScope::orchestrator();
        assert!(sub.is_subset_of(&orch));
        assert!(!orch.is_subset_of(&sub));
    }
}
