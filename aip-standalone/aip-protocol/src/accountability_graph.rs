//! Accountability graph — Human → Authority → Agent → Decision → Action →
//! Receipt, reconstructed from an [`EvidencePacket`].
//!
//! The graph is the audit-facing view of a packet: who authorized whom,
//! through which delegations, to make which decision, performing which
//! actions, producing which receipt. It supports chain validation
//! (connectivity from the root principal to every leaf) and export to JSON
//! and Graphviz DOT for visualization.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::evidence_packet::{EvidencePacket, TrustFloor};
use crate::verification_report::VerificationReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// The root human/organizational principal.
    Principal,
    /// The root scoped token (the authority grant itself).
    AuthorityGrant,
    /// One delegation hop.
    Delegation,
    /// The acting agent.
    Agent,
    /// The decision record.
    Decision,
    /// One performed action.
    Action,
    /// The external receipt.
    Receipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// Principal → AuthorityGrant: the principal issued the root token.
    Issues,
    /// AuthorityGrant/Delegation → Delegation: scope handed down a hop.
    Delegates,
    /// AuthorityGrant/Delegation → Agent: the agent acts under this token.
    ActsUnder,
    /// Agent → Decision.
    Decides,
    /// Decision → Action.
    Performs,
    /// Action → Receipt.
    Produces,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    /// Stable node ID within the graph (e.g. "principal", "delegation:0").
    pub id: String,
    pub kind: NodeKind,
    /// Human-readable label for display.
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub relation: Relation,
}

/// The reconstructed accountability graph for one EvidencePacket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountabilityGraph {
    pub packet_id: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// The floor claimed by the packet producer.
    pub claimed_trust_floor: TrustFloor,
    /// The floor derived by the verifier, when a report has been attached
    /// via [`AccountabilityGraph::with_report`].
    pub derived_trust_floor: Option<TrustFloor>,
}

impl AccountabilityGraph {
    /// Reconstruct the accountability graph from a packet.
    pub fn from_packet(packet: &EvidencePacket) -> Self {
        let mut nodes = vec![];
        let mut edges = vec![];

        let principal_id = "principal".to_string();
        nodes.push(GraphNode {
            id: principal_id.clone(),
            kind: NodeKind::Principal,
            label: format!(
                "{} ({})",
                packet.root_authority.display_role, packet.root_authority.principal_id
            ),
        });

        let grant_id = "authority_grant".to_string();
        nodes.push(GraphNode {
            id: grant_id.clone(),
            kind: NodeKind::AuthorityGrant,
            label: format!(
                "root token {} → {}",
                hex::encode(packet.root_authority.root_token.jti),
                packet.root_authority.root_token.agent_id
            ),
        });
        edges.push(GraphEdge {
            from: principal_id,
            to: grant_id.clone(),
            relation: Relation::Issues,
        });

        // Delegation hops
        let mut prev = grant_id;
        for (i, hop) in packet.delegation_chain.iter().enumerate() {
            let hop_id = format!("delegation:{i}");
            nodes.push(GraphNode {
                id: hop_id.clone(),
                kind: NodeKind::Delegation,
                label: format!(
                    "hop {} (depth {}): {} → {}",
                    i, hop.depth, hop.issuer_id, hop.grantee_id
                ),
            });
            edges.push(GraphEdge {
                from: prev,
                to: hop_id.clone(),
                relation: Relation::Delegates,
            });
            prev = hop_id;
        }

        // Agent acts under the leaf token
        let agent_id = "agent".to_string();
        nodes.push(GraphNode {
            id: agent_id.clone(),
            kind: NodeKind::Agent,
            label: packet.agent.aip_id.clone(),
        });
        edges.push(GraphEdge {
            from: prev,
            to: agent_id.clone(),
            relation: Relation::ActsUnder,
        });

        // Decision
        let decision_id = "decision".to_string();
        nodes.push(GraphNode {
            id: decision_id.clone(),
            kind: NodeKind::Decision,
            label: packet.decision.summary.clone(),
        });
        edges.push(GraphEdge {
            from: agent_id,
            to: decision_id.clone(),
            relation: Relation::Decides,
        });

        // Actions
        let mut action_node_ids = vec![];
        for (i, action) in packet.actions.iter().enumerate() {
            let action_node = format!("action:{i}");
            nodes.push(GraphNode {
                id: action_node.clone(),
                kind: NodeKind::Action,
                label: action.description.clone(),
            });
            edges.push(GraphEdge {
                from: decision_id.clone(),
                to: action_node.clone(),
                relation: Relation::Performs,
            });
            action_node_ids.push(action_node);
        }

        // Receipt
        if let Some(receipt) = &packet.receipt_binding {
            let receipt_node = "receipt".to_string();
            nodes.push(GraphNode {
                id: receipt_node.clone(),
                kind: NodeKind::Receipt,
                label: format!("{} @ {}", receipt.receipt_id, receipt.receipt_system),
            });
            for action_node in &action_node_ids {
                edges.push(GraphEdge {
                    from: action_node.clone(),
                    to: receipt_node.clone(),
                    relation: Relation::Produces,
                });
            }
        }

        Self {
            packet_id: packet.packet_id_hex(),
            nodes,
            edges,
            claimed_trust_floor: packet.claimed_trust_floor,
            derived_trust_floor: None,
        }
    }

    /// Attach a verification report, recording the derived trust floor.
    /// The report must refer to the same packet.
    pub fn with_report(mut self, report: &VerificationReport) -> Self {
        if report.packet_id == self.packet_id {
            self.derived_trust_floor = Some(report.trust_floor);
        }
        self
    }

    /// Validate graph connectivity: exactly one Principal node, and every
    /// node is reachable from it. Returns the list of problems (empty = ok).
    pub fn validate_chain(&self) -> Vec<String> {
        let mut problems = vec![];

        let principals: Vec<&GraphNode> = self
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Principal)
            .collect();
        if principals.len() != 1 {
            problems.push(format!(
                "expected exactly 1 principal node, found {}",
                principals.len()
            ));
            return problems;
        }

        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
        for edge in &self.edges {
            adjacency
                .entry(edge.from.as_str())
                .or_default()
                .push(edge.to.as_str());
        }

        let mut visited: HashSet<&str> = HashSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        let start = principals[0].id.as_str();
        visited.insert(start);
        queue.push_back(start);
        while let Some(node) = queue.pop_front() {
            for next in adjacency.get(node).into_iter().flatten() {
                if visited.insert(next) {
                    queue.push_back(next);
                }
            }
        }

        for node in &self.nodes {
            if !visited.contains(node.id.as_str()) {
                problems.push(format!(
                    "node {} ({:?}) is not reachable from the principal — broken accountability chain",
                    node.id, node.kind
                ));
            }
        }
        problems
    }

    /// Export as JSON for visualization frontends.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export as Graphviz DOT.
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph accountability {\n  rankdir=LR;\n");
        for node in &self.nodes {
            let shape = match node.kind {
                NodeKind::Principal => "house",
                NodeKind::AuthorityGrant => "note",
                NodeKind::Delegation => "cds",
                NodeKind::Agent => "component",
                NodeKind::Decision => "diamond",
                NodeKind::Action => "box",
                NodeKind::Receipt => "tab",
            };
            out.push_str(&format!(
                "  \"{}\" [shape={}, label=\"{}\"];\n",
                node.id,
                shape,
                node.label.replace('"', "'")
            ));
        }
        for edge in &self.edges {
            out.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{:?}\"];\n",
                edge.from, edge.to, edge.relation
            ));
        }
        out.push_str("}\n");
        out
    }
}
