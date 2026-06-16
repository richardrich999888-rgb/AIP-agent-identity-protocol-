//! Authority Graph v1 — a derived, queryable index over the Evidence Vault.
//!
//! The graph is **not** a system of record: it is rebuilt on demand from the
//! packets in [`crate::vault::Vault`]. Each EvidencePacket already carries a
//! complete, verifiable authority chain (principal → root token → delegation
//! hops → agent → actions); this module indexes those chains across packets
//! so we can answer cross-packet questions:
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

use crate::vault::Vault;

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

/// Derived index built from the vault.
pub struct AuthorityGraph {
    /// action_id (hex) → packet_id (hex)
    action_to_packet: HashMap<String, String>,
    /// principal_id → packet_ids it authorized
    principal_to_packets: HashMap<String, Vec<String>>,
    /// agent_id → packet_ids it acted in
    agent_to_packets: HashMap<String, Vec<String>>,
}

impl AuthorityGraph {
    /// Rebuild the index from every packet belonging to `tenant_id`.
    /// The graph is always tenant-scoped; there is no cross-tenant view.
    pub fn build_for_tenant(vault: &Vault, tenant_id: &str) -> Self {
        let mut g = AuthorityGraph {
            action_to_packet: HashMap::new(),
            principal_to_packets: HashMap::new(),
            agent_to_packets: HashMap::new(),
        };
        for packet in vault.all_for_tenant(tenant_id) {
            g.index(&packet);
        }
        g
    }

    fn index(&mut self, packet: &EvidencePacket) {
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
            .push(pid);
    }

    /// Q1/Q5: given an action id (hex), return the authority path proving who
    /// authorized it. Tenant-scoped: the graph was built for one tenant and
    /// the vault read is tenant-checked, so this cannot resolve another
    /// tenant's action. Returns `None` if unknown to this tenant.
    pub fn who_authorized(
        &self,
        vault: &Vault,
        tenant_id: &str,
        action_id_hex: &str,
    ) -> Option<AuthorityPath> {
        let packet_id = self.action_to_packet.get(action_id_hex)?;
        let packet = vault.get(tenant_id, packet_id)?;
        Some(authority_path(&packet))
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

    fn temp_path() -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("aip_authority_test_{}.jsonl", uuid::Uuid::new_v4()));
        p.to_str().unwrap().to_owned()
    }

    #[test]
    fn test_who_authorized_resolves_chain() {
        let path = temp_path();
        let vault = Vault::load(&path);
        let (packet, _) = sample_packet();
        vault.store("acme", &packet).unwrap();

        let graph = AuthorityGraph::build_for_tenant(&vault, "acme");
        let action_hex = hex::encode(packet.actions[0].action_id);
        let p = graph
            .who_authorized(&vault, "acme", &action_hex)
            .expect("action must resolve to an authority path");

        assert_eq!(p.principal_id, packet.root_authority.principal_id);
        assert_eq!(p.agent_id, packet.agent.aip_id);
        assert_eq!(p.delegation_hops.len(), packet.delegation_chain.len());
        assert!(p.integrity_ok, "freshly built packet must self-verify");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_authority_graph_is_tenant_isolated() {
        let path = temp_path();
        let vault = Vault::load(&path);
        let (packet, _) = sample_packet();
        vault.store("tenant-a", &packet).unwrap();

        // A graph built for another tenant must not resolve the action.
        let graph_b = AuthorityGraph::build_for_tenant(&vault, "tenant-b");
        let action_hex = hex::encode(packet.actions[0].action_id);
        assert!(graph_b
            .who_authorized(&vault, "tenant-b", &action_hex)
            .is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_tamper_breaks_integrity_flag() {
        let (mut packet, _) = sample_packet();
        // Tamper after sealing — the integrity self-check must catch it
        // without needing the vault or external trust keys.
        packet.decision.summary = "ESCALATED".into();
        let p = authority_path(&packet);
        assert!(
            !p.integrity_ok,
            "tampered packet must fail integrity self-check"
        );
    }

    #[test]
    fn test_principal_and_agent_indexes() {
        let path = temp_path();
        let vault = Vault::load(&path);
        let (packet, _) = sample_packet();
        vault.store("acme", &packet).unwrap();
        let graph = AuthorityGraph::build_for_tenant(&vault, "acme");

        assert_eq!(
            graph.packets_for_principal(&packet.root_authority.principal_id),
            vec![packet.packet_id_hex()]
        );
        assert_eq!(
            graph.packets_for_agent(&packet.agent.aip_id),
            vec![packet.packet_id_hex()]
        );
        let _ = std::fs::remove_file(&path);
    }
}
