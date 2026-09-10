//! SD-06 — the delegation graph: who delegated what to whom.
//!
//! Nodes are tokens whose chain `aip_core` verified (signature per hop,
//! attenuation, depth, expiry); edges are `parent_jti` links. The graph is
//! rebuilt from tokens and is never the source of truth for any of them.
//! It answers path queries and reports what it could not verify:
//!
//! - a hop whose parent token is not in hand is **incompleteness**, not a
//!   node — it cannot be checked against its parent's scope;
//! - two verified tokens with one id and different signed terms are a
//!   **conflict** — both are refused (defensive; not reproducible from the
//!   public issuing API, which chooses ids itself);
//! - revocation is a **verifier-supplied** set of token ids, the shape the
//!   packet verifier's rule R9 consumes; the graph decides nothing about
//!   what is revoked.
//!
//! Shape harvested from out-of-tree work (`OUT_OF_TREE_HARVEST_REVIEW.md`
//! §2.1: walk child → root, report the whole path, intersect scope), rebuilt
//! over Ed25519-signed tokens instead of unsigned edges.

use std::collections::{BTreeMap, BTreeSet};

use aip_core::capability::scope_permits;
use aip_types::{CapabilityScope, DelegationToken, ScopeAction};
use serde::Serialize;

use crate::authority::{
    verify_chain_terms, AuthorityChain, ExcludedAuthority, ExclusionReason, IssuerKeys,
};

/// One verified token as a graph node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphNode {
    pub jti: [u8; 16],
    /// `None` for a root token.
    pub parent_jti: Option<[u8; 16]>,
    pub issuer_id: String,
    pub grantee_id: String,
    pub scope: CapabilityScope,
    pub depth: u8,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    /// SHA-256 of the signed canonical terms (`issuer_sig.payload_hash`);
    /// two nodes with one id and different hashes are a conflict.
    pub terms_hash: [u8; 32],
}

/// A hop that could not enter the graph because its parent token was not
/// supplied inside a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DanglingHop {
    pub jti: [u8; 16],
    pub missing_parent_jti: [u8; 16],
    pub issuer_id: String,
    pub grantee_id: String,
}

/// Standing of a path at the graph's `as_of` time. `Revoked` names the
/// nearest-to-root revoked token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PathStanding {
    Valid,
    Expired { at_ms: u64 },
    NotYetValid { from_ms: u64 },
    Revoked { jti: [u8; 16] },
}

/// One root-to-grantee path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphPath {
    /// Root first.
    pub jtis: Vec<[u8; 16]>,
    pub root_issuer: String,
    /// Root issuer, then each hop's issuer, in order.
    pub delegators: Vec<String>,
    pub grantee: String,
    /// The leaf token's scope, which `aip_core` guarantees ⊆ every ancestor.
    pub effective_scope: CapabilityScope,
    pub standing: PathStanding,
}

#[derive(Debug, Clone, Serialize)]
pub struct DelegationGraph {
    nodes: Vec<GraphNode>,
    #[serde(skip)]
    index: BTreeMap<[u8; 16], usize>,
    excluded: Vec<ExcludedAuthority>,
    conflicts: Vec<[u8; 16]>,
    incomplete: Vec<DanglingHop>,
    revoked: BTreeSet<[u8; 16]>,
    as_of_ms: u64,
}

impl DelegationGraph {
    /// Build from chains (each verified whole), loose hops (reported, never
    /// verified alone), verifier-supplied issuer keys and revoked ids.
    pub fn build(
        chains: &[AuthorityChain],
        loose_hops: &[DelegationToken],
        keys: &IssuerKeys,
        revoked_jtis: &[[u8; 16]],
        as_of_ms: u64,
    ) -> Self {
        let mut g = DelegationGraph {
            nodes: Vec::new(),
            index: BTreeMap::new(),
            excluded: Vec::new(),
            conflicts: Vec::new(),
            incomplete: Vec::new(),
            revoked: revoked_jtis.iter().copied().collect(),
            as_of_ms,
        };
        let mut conflicted: BTreeSet<[u8; 16]> = BTreeSet::new();

        for c in chains {
            if let Err(reason) = verify_chain_terms(c, keys) {
                g.excluded.push(ExcludedAuthority {
                    root_jti: c.root.jti,
                    reason,
                });
                continue;
            }
            let root = &c.root;
            let mut fresh = vec![GraphNode {
                jti: root.jti,
                parent_jti: None,
                issuer_id: root.issuer_id.clone(),
                grantee_id: root.agent_id.clone(),
                scope: root.scope.clone(),
                depth: 0,
                issued_at: root.issued_at,
                expires_at: root.expires_at,
                terms_hash: root.issuer_sig.payload_hash,
            }];
            for h in &c.chain {
                fresh.push(GraphNode {
                    jti: h.jti,
                    parent_jti: Some(h.parent_jti),
                    issuer_id: h.issuer_id.clone(),
                    grantee_id: h.grantee_id.clone(),
                    scope: h.scope.clone(),
                    depth: h.depth,
                    issued_at: h.issued_at,
                    expires_at: h.expires_at,
                    terms_hash: h.issuer_sig.payload_hash,
                });
            }
            for n in fresh {
                g.insert(n, &mut conflicted);
            }
        }

        for h in loose_hops {
            if g.index.contains_key(&h.jti) || conflicted.contains(&h.jti) {
                continue; // already verified inside a chain, or refused
            }
            // A hop outside a chain is not verified here: it cannot be checked
            // against its parent's scope without the chain machinery, and the
            // graph must not grow a second verifier. Reported, not admitted.
            g.incomplete.push(DanglingHop {
                jti: h.jti,
                missing_parent_jti: h.parent_jti,
                issuer_id: h.issuer_id.clone(),
                grantee_id: h.grantee_id.clone(),
            });
        }
        g.incomplete.sort_by_key(|d| d.jti);
        g.incomplete.dedup_by_key(|d| d.jti);
        g
    }

    fn insert(&mut self, n: GraphNode, conflicted: &mut BTreeSet<[u8; 16]>) {
        if conflicted.contains(&n.jti) {
            return;
        }
        match self.index.get(&n.jti).copied() {
            None => {
                self.index.insert(n.jti, self.nodes.len());
                self.nodes.push(n);
            }
            Some(i) if self.nodes[i].terms_hash == n.terms_hash => {}
            Some(_) => {
                // One id, two sets of signed terms: refuse both.
                let jti = n.jti;
                self.nodes.retain(|x| x.jti != jti);
                self.index.clear();
                for (i, x) in self.nodes.iter().enumerate() {
                    self.index.insert(x.jti, i);
                }
                conflicted.insert(jti);
                self.conflicts.push(jti);
            }
        }
    }

    pub fn nodes(&self) -> &[GraphNode] {
        &self.nodes
    }

    pub fn node(&self, jti: &[u8; 16]) -> Option<&GraphNode> {
        self.index.get(jti).map(|&i| &self.nodes[i])
    }

    pub fn excluded(&self) -> &[ExcludedAuthority] {
        &self.excluded
    }

    pub fn conflicts(&self) -> &[[u8; 16]] {
        &self.conflicts
    }

    pub fn incomplete(&self) -> &[DanglingHop] {
        &self.incomplete
    }

    /// No dangling hop and no conflict: every token in hand is a node.
    pub fn is_complete(&self) -> bool {
        self.incomplete.is_empty() && self.conflicts.is_empty()
    }

    pub fn as_of_ms(&self) -> u64 {
        self.as_of_ms
    }

    /// Walk from `leaf` to its root; `None` if the walk does not end at a
    /// root node (a parent was refused or absent).
    fn walk_to_root<'s>(&'s self, leaf: &'s GraphNode) -> Option<Vec<&'s GraphNode>> {
        let mut path = vec![leaf];
        let mut current = leaf;
        let mut seen: BTreeSet<[u8; 16]> = BTreeSet::new();
        seen.insert(leaf.jti);
        while let Some(pj) = current.parent_jti {
            let parent = self.node(&pj)?;
            if !seen.insert(parent.jti) {
                return None; // a cycle is not a path
            }
            path.push(parent);
            current = parent;
        }
        path.reverse();
        Some(path)
    }

    fn standing_of(&self, nodes: &[&GraphNode]) -> PathStanding {
        if let Some(r) = nodes.iter().find(|n| self.revoked.contains(&n.jti)) {
            return PathStanding::Revoked { jti: r.jti };
        }
        let issued = nodes.iter().map(|n| n.issued_at).max().unwrap_or(0);
        if self.as_of_ms < issued {
            return PathStanding::NotYetValid { from_ms: issued };
        }
        let expiry = nodes.iter().filter_map(|n| n.expires_at).min();
        if let Some(e) = expiry {
            if self.as_of_ms > e {
                return PathStanding::Expired { at_ms: e };
            }
        }
        PathStanding::Valid
    }

    fn path_of(&self, nodes: &[&GraphNode]) -> GraphPath {
        let leaf = nodes[nodes.len() - 1];
        GraphPath {
            jtis: nodes.iter().map(|n| n.jti).collect(),
            root_issuer: nodes[0].issuer_id.clone(),
            delegators: nodes.iter().map(|n| n.issuer_id.clone()).collect(),
            grantee: leaf.grantee_id.clone(),
            effective_scope: leaf.scope.clone(),
            standing: self.standing_of(nodes),
        }
    }

    /// Every root-reaching path ending at a token whose grantee is `agent`.
    pub fn paths_to(&self, agent: &str) -> Vec<GraphPath> {
        self.nodes
            .iter()
            .filter(|n| n.grantee_id == agent)
            .filter_map(|n| self.walk_to_root(n))
            .map(|nodes| self.path_of(&nodes))
            .collect()
    }

    /// Paths to `agent` standing `Valid` at `as_of`.
    pub fn valid_paths_to(&self, agent: &str) -> Vec<GraphPath> {
        self.paths_to(agent)
            .into_iter()
            .filter(|p| p.standing == PathStanding::Valid)
            .collect()
    }

    /// Valid paths whose effective scope permits `action`.
    pub fn authority_reaching(&self, agent: &str, action: &ScopeAction) -> Vec<GraphPath> {
        self.valid_paths_to(agent)
            .into_iter()
            .filter(|p| scope_permits(&p.effective_scope, action))
            .collect()
    }

    /// Grantees of every token issued by `issuer` or descending from one.
    pub fn agents_under(&self, issuer: &str) -> Vec<String> {
        let mut out: BTreeSet<String> = BTreeSet::new();
        for n in &self.nodes {
            if let Some(path) = self.walk_to_root(n) {
                if path.iter().any(|x| x.issuer_id == issuer) {
                    out.insert(n.grantee_id.clone());
                }
            }
        }
        out.into_iter().collect()
    }

    /// Tokens `agent` issued (its outgoing delegations).
    pub fn delegated_by(&self, agent: &str) -> Vec<&GraphNode> {
        self.nodes.iter().filter(|n| n.issuer_id == agent).collect()
    }

    /// Standing of the path that ends at `jti`, if it reaches a root.
    pub fn standing_at(&self, jti: &[u8; 16]) -> Option<PathStanding> {
        let n = self.node(jti)?;
        self.walk_to_root(n).map(|p| self.standing_of(&p))
    }
}

/// A delegation `agent` issued, as the profile reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutgoingDelegation {
    pub jti: [u8; 16],
    pub grantee_id: String,
    /// Standing of the path from the root to this token, if it has one.
    pub standing: Option<PathStanding>,
}

/// The graph's answers for one agent, carried in the profile's lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct DelegationSummary {
    pub paths_to_agent: Vec<GraphPath>,
    pub delegated_by_agent: Vec<OutgoingDelegation>,
    pub agents_under_agent: Vec<String>,
    pub incomplete: Vec<DanglingHop>,
    pub conflicts: Vec<[u8; 16]>,
    /// Chains the graph could not verify (whole-chain exclusions).
    pub excluded: Vec<ExcludedAuthority>,
}

impl DelegationSummary {
    pub fn for_agent(g: &DelegationGraph, agent: &str) -> Self {
        Self {
            paths_to_agent: g.paths_to(agent),
            delegated_by_agent: g
                .delegated_by(agent)
                .into_iter()
                .map(|n| OutgoingDelegation {
                    jti: n.jti,
                    grantee_id: n.grantee_id.clone(),
                    standing: g.standing_at(&n.jti),
                })
                .collect(),
            agents_under_agent: g.agents_under(agent),
            incomplete: g.incomplete().to_vec(),
            conflicts: g.conflicts().to_vec(),
            excluded: g.excluded().to_vec(),
        }
    }
}

// Keep the exclusion type in scope for `DelegationSummary::excluded`.
#[allow(dead_code)]
fn _exclusion_reason_is_shared(_: &ExclusionReason) {}
