//! AIP v4 Runtime policy checks.

use crate::attestation::AttestationStrength;
use crate::errors::{AipError, AipResult};
use crate::graph::AccountabilityGraph;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct TrustFloorPolicy {
    default_minimum: AttestationStrength,
    required_by_class: BTreeMap<String, AttestationStrength>,
}

impl TrustFloorPolicy {
    pub fn new(default_minimum: AttestationStrength) -> Self {
        Self {
            default_minimum,
            required_by_class: BTreeMap::new(),
        }
    }

    pub fn require(mut self, decision_class: &str, minimum: AttestationStrength) -> Self {
        self.required_by_class
            .insert(decision_class.to_string(), minimum);
        self
    }

    pub fn enforce(&self, decision_class: &str, graph: &AccountabilityGraph) -> AipResult<()> {
        let required = self
            .required_by_class
            .get(decision_class)
            .copied()
            .unwrap_or(self.default_minimum);
        let floor = graph
            .trust_floor()
            .ok_or_else(|| AipError::ValidationFailed {
                reason: "accountability graph is incomplete".into(),
            })?;

        if floor < required {
            return Err(AipError::ValidationFailed {
                reason: format!(
                    "decision class '{decision_class}' requires {:?}, graph floor is {:?}",
                    required, floor
                ),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{AccountabilityEdge, AccountabilityNode, EdgeRelation, NodeKind};

    fn graph_with_floor(strength: AttestationStrength) -> AccountabilityGraph {
        let mut g = AccountabilityGraph::new([3u8; 32]);
        g.add_node(AccountabilityNode {
            node_id: [1u8; 32],
            kind: NodeKind::Authorization,
            object_ref: [1u8; 32],
        });
        g.add_node(AccountabilityNode {
            node_id: [2u8; 32],
            kind: NodeKind::Agent,
            object_ref: [2u8; 32],
        });
        g.add_node(AccountabilityNode {
            node_id: [3u8; 32],
            kind: NodeKind::Decision,
            object_ref: [3u8; 32],
        });
        g.add_node(AccountabilityNode {
            node_id: [4u8; 32],
            kind: NodeKind::Receipt,
            object_ref: [4u8; 32],
        });
        g.add_edge(AccountabilityEdge {
            from: [1u8; 32],
            to: [2u8; 32],
            relation: EdgeRelation::AuthorizedBy,
            strength: AttestationStrength::CounterpartySigned,
            evidence_ref: [0u8; 32],
        });
        g.add_edge(AccountabilityEdge {
            from: [2u8; 32],
            to: [3u8; 32],
            relation: EdgeRelation::Decided,
            strength: AttestationStrength::CounterpartySigned,
            evidence_ref: [0u8; 32],
        });
        g.add_edge(AccountabilityEdge {
            from: [3u8; 32],
            to: [4u8; 32],
            relation: EdgeRelation::GeneratedReceipt,
            strength,
            evidence_ref: [0u8; 32],
        });
        g
    }

    #[test]
    fn test_policy_accepts_sufficient_floor() {
        let policy = TrustFloorPolicy::new(AttestationStrength::SelfAttested).require(
            "financial.approval",
            AttestationStrength::CounterpartySigned,
        );
        assert!(policy
            .enforce(
                "financial.approval",
                &graph_with_floor(AttestationStrength::CounterpartySigned)
            )
            .is_ok());
    }

    #[test]
    fn test_policy_rejects_low_floor() {
        let policy = TrustFloorPolicy::new(AttestationStrength::SelfAttested).require(
            "financial.approval",
            AttestationStrength::CounterpartySigned,
        );
        assert!(policy
            .enforce(
                "financial.approval",
                &graph_with_floor(AttestationStrength::SelfAttested)
            )
            .is_err());
    }
}
