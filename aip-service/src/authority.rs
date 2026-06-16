//! Authority Graph v1 — a derived, queryable index over stored evidence.
//!
//! The graph is **not** a system of record: it is rebuilt on demand from a
//! list of packets supplied by the [`EvidenceStore`](crate::store::EvidenceStore)
//! (any backend). Each EvidencePacket already carries a complete, verifiable
//! authority chain (principal → root token → delegation hops → agent →
//! actions); this module indexes those chains across packets so we can answer
//! cross-packet questions:
//!
//! 1. Who authorized this action?            → [`AuthorityGraph::who_authorized`]
//! 2. Which human delegated authority?       → principal of the chain
//! 3. Which agent executed?                  → acting agent of the chain
//! 4. What scope existed?                    → effective scope from the leaf
//! 5. What evidence proves it?               → the packet id + integrity check
//!
//! It reuses existing AIP primitives only: `EvidencePacket`,
//! `AccountabilityGraph`, and the packet's own integrity self-check. No new
//! cryptographic concepts are introduced.

use std::collections::HashMap;

use aip_protocol::{AccountabilityGraph, EvidencePacket};
use serde::Serialize;

/// The authority path behind a single action, extracted from its packet.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorityPath {
    pub packet_id: String,
    /// Q2: the human/organisational principal at the root.
    pub principal_id: String,
    pub principal_role: String,
    /// Q3: the agent that executed.
    pub agent_id: String,
    /// Ordered issuer→grantee hops (Q1: the delegation that conferred authority).
    pub delegation_hops: Vec<DelegationHop>,
    /// Q4: effective allowed actions at the leaf (most-attenuated scope).
    pub effective_scope_allowed: Vec<String>,
    /// Q5: integrity self-check that does not require external trust keys —
    /// recomputed packet hash matches, and the agent signature payload covers
    /// the current contents. Full trust requires `/evidence/verify` with keys.
    pub integrity_ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DelegationHop {
    pub issuer_id: String,
    pub grantee_id: String,
    pub depth: u8,
}

/// Derived index built from a (tenant-scoped) list of packets.
pub struct AuthorityGraph {
    /// action_id (hex) → packet_id (hex)
    action_to_packet: HashMap<String, String>,
    /// principal_id → packet_ids it authorized
    principal_to_packets: HashMap<String, Vec<String>>,
    /// agent_id → packet_ids it acted in
    agent_to_packets: HashMap<String, Vec<String>>,
    /// packet_id (hex) → packet (so queries need no further store access)
    packets: HashMap<String, EvidencePacket>,
}

impl AuthorityGraph {
    /// Build the index from a list of packets. The caller fetches the packets
    /// from the store for a single tenant, so the graph is tenant-scoped by
    /// construction (storage-backend agnostic).
    pub fn from_packets(packets: Vec<EvidencePacket>) -> Self {
        let mut g = AuthorityGraph {
            action_to_packet: HashMap::new(),
            principal_to_packets: HashMap::new(),
            agent_to_packets: HashMap::new(),
            packets: HashMap::new(),
        };
        for packet in packets {
            g.index(packet);
        }
        g
    }

    fn index(&mut self, packet: EvidencePacket) {
        let pid = packet.packet_id_hex();
        for action in &packet.actions {
            self.action_to_packet
                .insert(hex::encode(action.action_id), pid.clone());
        }
        self.principal_to_packets
            .entry(packet.root_authority.principal_id.clone())
            .or_default()
            .push(pid.clone());
        self.agent_to_packets
            .entry(packet.agent.aip_id.clone())
            .or_default()
            .push(pid.clone());
        self.packets.insert(pid, packet);
    }

    /// Q1/Q5: given an action id (hex), return the authority path proving who
    /// authorized it. `None` if unknown to this tenant's packet set.
    pub fn who_authorized(&self, action_id_hex: &str) -> Option<AuthorityPath> {
        let packet_id = self.action_to_packet.get(action_id_hex)?;
        self.packets.get(packet_id).map(authority_path)
    }

    /// The packet proving a given action (for graph visualization).
    pub fn packet_for_action(&self, action_id_hex: &str) -> Option<&EvidencePacket> {
        let packet_id = self.action_to_packet.get(action_id_hex)?;
        self.packets.get(packet_id)
    }

    /// All packet ids authorized (at the root) by a given principal.
    pub fn packets_for_principal(&self, principal_id: &str) -> Vec<String> {
        self.principal_to_packets
            .get(principal_id)
            .cloned()
            .unwrap_or_default()
    }

    /// All packet ids in which a given agent acted.
    pub fn packets_for_agent(&self, agent_id: &str) -> Vec<String> {
        self.agent_to_packets
            .get(agent_id)
            .cloned()
            .unwrap_or_default()
    }
}

/// Extract the authority path from a packet (no external keys required).
pub fn authority_path(packet: &EvidencePacket) -> AuthorityPath {
    let hops = packet
        .delegation_chain
        .iter()
        .map(|h| DelegationHop {
            issuer_id: h.issuer_id.clone(),
            grantee_id: h.grantee_id.clone(),
            depth: h.depth,
        })
        .collect();

    // Effective (most-attenuated) scope = leaf delegation's scope, or the
    // root token's scope if the agent holds the root directly.
    let effective = packet
        .delegation_chain
        .last()
        .map(|h| &h.scope)
        .unwrap_or(&packet.root_authority.root_token.scope);
    let effective_scope_allowed = effective.allowed.iter().map(|a| format!("{a:?}")).collect();

    // Integrity self-check (no external trust): the recomputed canonical hash
    // matches packet_hash AND the agent signature payload covers it.
    let recomputed = packet.compute_hash();
    let integrity_ok =
        recomputed == packet.packet_hash && packet.agent_sig.payload_hash == recomputed;

    AuthorityPath {
        packet_id: packet.packet_id_hex(),
        principal_id: packet.root_authority.principal_id.clone(),
        principal_role: packet.root_authority.display_role.clone(),
        agent_id: packet.agent.aip_id.clone(),
        delegation_hops: hops,
        effective_scope_allowed,
        integrity_ok,
    }
}

/// Convenience: the full Human→…→Receipt accountability graph for a packet,
/// reusing `aip-protocol`'s per-packet reconstruction.
pub fn graph_for_packet(packet: &EvidencePacket) -> AccountabilityGraph {
    AccountabilityGraph::from_packet(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_packet;

    #[test]
    fn test_who_authorized_resolves_chain() {
        let (packet, _) = sample_packet();
        let graph = AuthorityGraph::from_packets(vec![packet.clone()]);
        let action_hex = hex::encode(packet.actions[0].action_id);
        let p = graph
            .who_authorized(&action_hex)
            .expect("action must resolve to an authority path");

        assert_eq!(p.principal_id, packet.root_authority.principal_id);
        assert_eq!(p.agent_id, packet.agent.aip_id);
        assert_eq!(p.delegation_hops.len(), packet.delegation_chain.len());
        assert!(p.integrity_ok, "freshly built packet must self-verify");
    }

    #[test]
    fn test_authority_graph_scoped_to_supplied_packets() {
        // A graph built from tenant B's (empty) packet set cannot resolve a
        // tenant A action. (Tenant scoping is enforced by the store's
        // all_for_tenant; the graph only sees what it is given.)
        let (packet, _) = sample_packet();
        let graph_b = AuthorityGraph::from_packets(vec![]);
        let action_hex = hex::encode(packet.actions[0].action_id);
        assert!(graph_b.who_authorized(&action_hex).is_none());
    }

    #[test]
    fn test_tamper_breaks_integrity_flag() {
        let (mut packet, _) = sample_packet();
        packet.decision.summary = "ESCALATED".into();
        let p = authority_path(&packet);
        assert!(
            !p.integrity_ok,
            "tampered packet must fail integrity self-check"
        );
    }

    #[test]
    fn test_principal_and_agent_indexes() {
        let (packet, _) = sample_packet();
        let graph = AuthorityGraph::from_packets(vec![packet.clone()]);
        assert_eq!(
            graph.packets_for_principal(&packet.root_authority.principal_id),
            vec![packet.packet_id_hex()]
        );
        assert_eq!(
            graph.packets_for_agent(&packet.agent.aip_id),
            vec![packet.packet_id_hex()]
        );
    }
}
