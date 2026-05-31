//! AIP v4 L3 Evidence: accountability graph.

use crate::attestation::AttestationStrength;
use crate::errors::{AipError, AipResult};
use std::collections::{BTreeMap, BTreeSet};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[repr(u8)]
pub enum NodeKind {
    Human = 0x01,
    Agent = 0x02,
    Authorization = 0x03,
    Decision = 0x04,
    Action = 0x05,
    Output = 0x06,
    Receipt = 0x07,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum EdgeRelation {
    AuthorizedBy = 0x01,
    Decided = 0x02,
    CausedAction = 0x03,
    ProducedOutput = 0x04,
    GeneratedReceipt = 0x05,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountabilityNode {
    pub node_id: [u8; 32],
    pub kind: NodeKind,
    pub object_ref: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountabilityEdge {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub relation: EdgeRelation,
    pub strength: AttestationStrength,
    pub evidence_ref: [u8; 32],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountabilityGraph {
    pub root_decision_id: [u8; 32],
    pub nodes: Vec<AccountabilityNode>,
    pub edges: Vec<AccountabilityEdge>,
}

impl AccountabilityGraph {
    pub fn new(root_decision_id: [u8; 32]) -> Self {
        Self {
            root_decision_id,
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: AccountabilityNode) {
        if !self.nodes.iter().any(|n| n.node_id == node.node_id) {
            self.nodes.push(node);
        }
    }

    pub fn add_edge(&mut self, edge: AccountabilityEdge) {
        self.edges.push(edge);
    }

    pub fn validate(&self) -> AipResult<()> {
        let node_ids: BTreeSet<[u8; 32]> = self.nodes.iter().map(|n| n.node_id).collect();
        if !node_ids.contains(&self.root_decision_id) {
            return Err(AipError::ValidationFailed {
                reason: "root_decision_id is not present as a graph node".into(),
            });
        }

        for edge in &self.edges {
            if !node_ids.contains(&edge.from) {
                return Err(AipError::ValidationFailed {
                    reason: "edge references unknown 'from' node".into(),
                });
            }
            if !node_ids.contains(&edge.to) {
                return Err(AipError::ValidationFailed {
                    reason: "edge references unknown 'to' node".into(),
                });
            }
        }

        if self.has_cycle() {
            return Err(AipError::ValidationFailed {
                reason: "accountability graph must be acyclic".into(),
            });
        }

        Ok(())
    }

    fn has_cycle(&self) -> bool {
        let mut adj: BTreeMap<[u8; 32], Vec<[u8; 32]>> = BTreeMap::new();
        for edge in &self.edges {
            adj.entry(edge.from).or_default().push(edge.to);
        }

        let mut colour: BTreeMap<[u8; 32], u8> = BTreeMap::new();
        for node in &self.nodes {
            if Self::dfs_cycle(node.node_id, &adj, &mut colour) {
                return true;
            }
        }
        false
    }

    fn dfs_cycle(
        node: [u8; 32],
        adj: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
        colour: &mut BTreeMap<[u8; 32], u8>,
    ) -> bool {
        match colour.get(&node) {
            Some(2) => return false,
            Some(1) => return true,
            _ => {}
        }
        colour.insert(node, 1);
        if let Some(children) = adj.get(&node) {
            for child in children {
                if Self::dfs_cycle(*child, adj, colour) {
                    return true;
                }
            }
        }
        colour.insert(node, 2);
        false
    }

    pub fn trust_floor(&self) -> Option<AttestationStrength> {
        let auth = self
            .nodes
            .iter()
            .find(|n| n.kind == NodeKind::Authorization)?;
        let receipt = self.nodes.iter().find(|n| n.kind == NodeKind::Receipt)?;

        let mut adj: BTreeMap<[u8; 32], Vec<&AccountabilityEdge>> = BTreeMap::new();
        for edge in &self.edges {
            adj.entry(edge.from).or_default().push(edge);
        }

        let mut best: Option<AttestationStrength> = None;
        let mut visited: BTreeSet<[u8; 32]> = BTreeSet::new();
        Self::best_floor(
            auth.node_id,
            receipt.node_id,
            &adj,
            &mut visited,
            AttestationStrength::ThirdPartyNotarized,
            &mut best,
        );
        best
    }

    fn best_floor(
        current: [u8; 32],
        target: [u8; 32],
        adj: &BTreeMap<[u8; 32], Vec<&AccountabilityEdge>>,
        visited: &mut BTreeSet<[u8; 32]>,
        path_min: AttestationStrength,
        best: &mut Option<AttestationStrength>,
    ) {
        if current == target {
            *best = Some(match *best {
                Some(existing) => existing.max(path_min),
                None => path_min,
            });
            return;
        }

        visited.insert(current);
        if let Some(children) = adj.get(&current) {
            for edge in children {
                if visited.contains(&edge.to) {
                    continue;
                }
                Self::best_floor(
                    edge.to,
                    target,
                    adj,
                    visited,
                    path_min.min(edge.strength),
                    best,
                );
            }
        }
        visited.remove(&current);
    }

    pub fn is_complete(&self) -> bool {
        self.trust_floor().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u8, kind: NodeKind) -> AccountabilityNode {
        AccountabilityNode {
            node_id: [id; 32],
            kind,
            object_ref: [id; 32],
        }
    }

    fn edge(from: u8, to: u8, rel: EdgeRelation, s: AttestationStrength) -> AccountabilityEdge {
        AccountabilityEdge {
            from: [from; 32],
            to: [to; 32],
            relation: rel,
            strength: s,
            evidence_ref: [0u8; 32],
        }
    }

    fn full_chain(action_strength: AttestationStrength) -> AccountabilityGraph {
        let mut g = AccountabilityGraph::new([4u8; 32]);
        g.add_node(node(1, NodeKind::Human));
        g.add_node(node(2, NodeKind::Agent));
        g.add_node(node(3, NodeKind::Authorization));
        g.add_node(node(4, NodeKind::Decision));
        g.add_node(node(5, NodeKind::Action));
        g.add_node(node(6, NodeKind::Output));
        g.add_node(node(7, NodeKind::Receipt));
        g.add_edge(edge(
            3,
            2,
            EdgeRelation::AuthorizedBy,
            AttestationStrength::CounterpartySigned,
        ));
        g.add_edge(edge(
            2,
            4,
            EdgeRelation::Decided,
            AttestationStrength::CounterpartySigned,
        ));
        g.add_edge(edge(4, 5, EdgeRelation::CausedAction, action_strength));
        g.add_edge(edge(5, 6, EdgeRelation::ProducedOutput, action_strength));
        g.add_edge(edge(
            6,
            7,
            EdgeRelation::GeneratedReceipt,
            AttestationStrength::CounterpartySigned,
        ));
        g
    }

    #[test]
    fn test_validate_ok() {
        let g = full_chain(AttestationStrength::CounterpartySigned);
        assert!(g.validate().is_ok());
    }

    #[test]
    fn test_trust_floor_all_counterparty() {
        let g = full_chain(AttestationStrength::CounterpartySigned);
        assert_eq!(
            g.trust_floor(),
            Some(AttestationStrength::CounterpartySigned)
        );
    }

    #[test]
    fn test_trust_floor_self_attested_gap() {
        let g = full_chain(AttestationStrength::SelfAttested);
        assert_eq!(g.trust_floor(), Some(AttestationStrength::SelfAttested));
    }

    #[test]
    fn test_incomplete_chain_has_no_floor() {
        let mut g = AccountabilityGraph::new([4u8; 32]);
        g.add_node(node(3, NodeKind::Authorization));
        g.add_node(node(2, NodeKind::Agent));
        g.add_node(node(4, NodeKind::Decision));
        g.add_edge(edge(
            3,
            2,
            EdgeRelation::AuthorizedBy,
            AttestationStrength::CounterpartySigned,
        ));
        g.add_edge(edge(
            2,
            4,
            EdgeRelation::Decided,
            AttestationStrength::CounterpartySigned,
        ));
        assert_eq!(g.trust_floor(), None);
        assert!(!g.is_complete());
    }

    #[test]
    fn test_cycle_rejected() {
        let mut g = AccountabilityGraph::new([1u8; 32]);
        g.add_node(node(1, NodeKind::Decision));
        g.add_node(node(2, NodeKind::Action));
        g.add_edge(edge(
            1,
            2,
            EdgeRelation::CausedAction,
            AttestationStrength::SelfAttested,
        ));
        g.add_edge(edge(
            2,
            1,
            EdgeRelation::CausedAction,
            AttestationStrength::SelfAttested,
        ));
        assert!(g.validate().is_err());
    }

    #[test]
    fn test_edge_unknown_node_rejected() {
        let mut g = AccountabilityGraph::new([1u8; 32]);
        g.add_node(node(1, NodeKind::Decision));
        g.add_edge(edge(
            1,
            99,
            EdgeRelation::CausedAction,
            AttestationStrength::SelfAttested,
        ));
        assert!(g.validate().is_err());
    }
}
