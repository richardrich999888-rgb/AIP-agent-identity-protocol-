//! SD-04 — parent / child lineage, in three kinds that never merge.
//!
//! | kind | fact | established by |
//! |---|---|---|
//! | identity | a parent identity signed `(child_id, child_key)` at creation | the parent's key, verified against the parent's own validated document |
//! | authority | a token chain reaches this agent through named issuers | token signatures (`aip_core`) |
//! | process | a bound instance forked a bound instance that executed an image | collector-signed kernel events ([`LineageEdge`]) |
//!
//! A spawn edge is never an authority edge. The agent at either end of a
//! process edge is a separate fact, established only through a
//! decision-point-signed expectation whose binding matches the observed
//! instance structurally. There is no reconciled lineage verdict yet
//! ([`ReconciledLineage::NotReachable`]) and this module has no way to say
//! "violation".

use std::collections::HashSet;

use aip_authorize::{verify_expected_execution, DecisionPointTrustAnchors, ExpectedExecution};
use aip_core::{validate_aid, validate_aid_with_parent};
use aip_observe::ObservedProcess;
use aip_reconcile::LineageEdge;
use aip_types::{AgentIdentityDocument, ExecutionBinding};
use serde::Serialize;

use crate::authority::{AuthorityProjection, AuthorizedCapability, Standing};
use crate::identity::LineageProofState;
use crate::profile::{ExecutionInstance, InstanceAssertion};

// ─── identity lineage ───

/// How the identity parent named by the lineage proof stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub enum IdentityParent {
    /// No lineage proof: a root identity, or a source that carries none.
    #[default]
    None,
    /// The proof names `parent_id`; the parent's document was not supplied,
    /// so the proof could not be checked against the parent's key.
    Claimed { parent_id: String },
    /// The proof verified against the parent's validated document (or the
    /// key the caller asserted for that parent).
    Endorsed { parent_id: String },
    /// The parent's genuine document was supplied and the proof does **not**
    /// verify against its key: someone else signed it.
    Refused { parent_id: String },
}

/// The only link kind that can appear in `ancestors`: each entry was
/// verified against the ancestor's own validated document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AncestorLink {
    Endorsed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ancestor {
    pub id: String,
    pub link: AncestorLink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExcludedDocument {
    pub id: String,
    /// `IdentityError` rendered `Debug`.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct IdentityLineage {
    pub parent: IdentityParent,
    /// Endorsed ancestors, nearest first, as far as supplied documents allow.
    pub ancestors: Vec<Ancestor>,
    /// `ancestors.len()`: generations rebuilt from proofs, never read from
    /// `lineage_depth`.
    pub generations: u32,
    /// Supplied ancestor documents that did not validate.
    pub excluded_documents: Vec<ExcludedDocument>,
}

/// Upper bound on generations walked; a longer chain is reported up to here.
const MAX_GENERATIONS: usize = 64;

/// Rebuild identity ancestry. `document` is the agent's own validated
/// document (or `None` for a packet summary); `proof_state` is what the
/// identity already established about its proof; `ancestors` are the
/// documents the caller could supply, in any order.
pub(crate) fn identity_lineage(
    document: Option<&AgentIdentityDocument>,
    proof_state: &LineageProofState,
    ancestors: &[AgentIdentityDocument],
) -> IdentityLineage {
    let mut out = IdentityLineage::default();
    let Some(mut current) = document else {
        return out;
    };
    let (first_parent, already_verified) = match proof_state {
        LineageProofState::Absent | LineageProofState::NotCarried => return out,
        LineageProofState::Present {
            signer_id,
            verified,
        } => (signer_id.clone(), *verified == Some(true)),
    };

    // Validate supplied documents once; keep the valid ones by id.
    let mut valid: Vec<&AgentIdentityDocument> = Vec::new();
    for d in ancestors {
        match validate_aid(d) {
            Ok(()) => valid.push(d),
            Err(e) => out.excluded_documents.push(ExcludedDocument {
                id: d.id.clone(),
                reason: format!("{e:?}"),
            }),
        }
    }

    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(current.id.clone());
    let mut parent_id = first_parent;
    let mut first = true;
    while out.ancestors.len() < MAX_GENERATIONS {
        let Some(parent_doc) = valid.iter().find(|d| d.id == parent_id) else {
            if first {
                out.parent = if already_verified {
                    IdentityParent::Endorsed {
                        parent_id: parent_id.clone(),
                    }
                } else {
                    IdentityParent::Claimed {
                        parent_id: parent_id.clone(),
                    }
                };
            }
            break;
        };
        if visited.contains(&parent_doc.id) {
            break; // a cycle cannot be lineage
        }
        match validate_aid_with_parent(current, &parent_doc.id, &parent_doc.primary_key.key_bytes) {
            Ok(()) => {}
            Err(_) => {
                if first {
                    out.parent = IdentityParent::Refused {
                        parent_id: parent_id.clone(),
                    };
                }
                break;
            }
        }
        if first {
            out.parent = IdentityParent::Endorsed {
                parent_id: parent_id.clone(),
            };
            first = false;
        }
        out.ancestors.push(Ancestor {
            id: parent_doc.id.clone(),
            link: AncestorLink::Endorsed,
        });
        visited.insert(parent_doc.id.clone());
        current = parent_doc;
        match &current.lineage_proof {
            Some(sig) => parent_id = sig.signer_id.clone(),
            None => break,
        }
    }
    if first && out.parent == IdentityParent::None {
        // The walk ended before the first parent was classified (e.g. the
        // parent document was found but the loop did not run). Classify it.
        out.parent = if already_verified {
            IdentityParent::Endorsed { parent_id }
        } else {
            IdentityParent::Claimed { parent_id }
        };
    }
    out.generations = u32::try_from(out.ancestors.len()).unwrap_or(u32::MAX);
    out
}

// ─── authority lineage ───

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorityHop {
    pub jti: [u8; 16],
    pub issuer_id: String,
    pub grantee_id: String,
}

/// One verified chain as a path: root issuer → root grantee → … → agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorityPath {
    pub root_jti: [u8; 16],
    pub root_issuer: String,
    pub root_grantee: String,
    pub hops: Vec<AuthorityHop>,
    pub standing: Standing,
}

impl AuthorityPath {
    /// Everyone who conferred authority along the path, root first.
    pub fn delegators(&self) -> Vec<String> {
        let mut out = vec![self.root_issuer.clone()];
        out.extend(self.hops.iter().map(|h| h.issuer_id.clone()));
        out
    }

    fn from_capability(c: &AuthorizedCapability) -> Self {
        Self {
            root_jti: c.root_jti,
            root_issuer: c.root_issuer.clone(),
            root_grantee: c.root_grantee.clone(),
            hops: c.hops.clone(),
            standing: c.standing,
        }
    }
}

pub(crate) fn authority_lineage(p: &AuthorityProjection) -> Vec<AuthorityPath> {
    p.authorized
        .iter()
        .chain(p.not_in_standing.iter())
        .map(AuthorityPath::from_capability)
        .collect()
}

// ─── process lineage ───

/// Which agent an observed instance is — a fact separate from the edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ChildAttribution {
    /// No verified expectation names a binding matching this instance.
    Unattributed,
    /// Exactly one agent's decision-point-signed expectation names it.
    AuthorizedTarget {
        agent_id: String,
        decision_id: [u8; 16],
    },
    /// Verified expectations of different agents name the same instance.
    /// Reported, never resolved.
    Ambiguous { agent_ids: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedSpawn {
    pub child: ObservedProcess,
    pub child_agent: ChildAttribution,
    /// How this agent's parent instance was vouched for.
    pub parent_basis: InstanceAssertion,
    pub edge: LineageEdge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedSpawnedBy {
    pub parent: ObservedProcess,
    pub parent_agent: ChildAttribution,
    /// How this agent's child instance was vouched for.
    pub child_basis: InstanceAssertion,
    pub edge: LineageEdge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExcludedPeerExpectation {
    pub decision_id: [u8; 16],
    pub agent_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ProcessLineage {
    pub spawned: Vec<ObservedSpawn>,
    pub spawned_by: Vec<ObservedSpawnedBy>,
    /// Edges touching none of this agent's instances.
    pub unrelated_edges: u32,
    pub excluded_peer_expectations: Vec<ExcludedPeerExpectation>,
}

struct Peer<'a> {
    binding: &'a ExecutionBinding,
    agent_id: &'a str,
    decision_id: [u8; 16],
}

fn attribute(p: &ObservedProcess, peers: &[Peer<'_>]) -> ChildAttribution {
    let mut agents: Vec<(&str, [u8; 16])> = Vec::new();
    for peer in peers.iter().filter(|x| p.matches_process_of(x.binding)) {
        if !agents.iter().any(|(a, _)| *a == peer.agent_id) {
            agents.push((peer.agent_id, peer.decision_id));
        }
    }
    match agents.as_slice() {
        [] => ChildAttribution::Unattributed,
        [(agent_id, decision_id)] => ChildAttribution::AuthorizedTarget {
            agent_id: agent_id.to_string(),
            decision_id: *decision_id,
        },
        many => ChildAttribution::Ambiguous {
            agent_ids: many.iter().map(|(a, _)| a.to_string()).collect(),
        },
    }
}

pub(crate) fn process_lineage(
    agent_id: &str,
    instances: &[ExecutionInstance],
    edges: &[LineageEdge],
    peer_expectations: &[ExpectedExecution],
    anchors: &DecisionPointTrustAnchors,
) -> ProcessLineage {
    let mut out = ProcessLineage::default();
    let mut peers: Vec<Peer<'_>> = Vec::new();
    for ee in peer_expectations {
        if ee.agent_id == agent_id {
            continue; // not a peer; the agent's own expectations are `instances`
        }
        match verify_expected_execution(ee, anchors) {
            Ok(()) => peers.push(Peer {
                binding: &ee.execution_binding,
                agent_id: &ee.agent_id,
                decision_id: ee.decision_id,
            }),
            Err(e) => out
                .excluded_peer_expectations
                .push(ExcludedPeerExpectation {
                    decision_id: ee.decision_id,
                    agent_id: ee.agent_id.clone(),
                    reason: format!("{e:?}"),
                }),
        }
    }

    for edge in edges {
        let parent_i = instances
            .iter()
            .find(|i| edge.parent.matches_process_of(&i.binding));
        let child_i = instances
            .iter()
            .find(|i| edge.child.matches_process_of(&i.binding));
        if parent_i.is_none() && child_i.is_none() {
            out.unrelated_edges += 1;
            continue;
        }
        if let Some(i) = parent_i {
            out.spawned.push(ObservedSpawn {
                child: edge.child.clone(),
                child_agent: attribute(&edge.child, &peers),
                parent_basis: i.assertion.clone(),
                edge: edge.clone(),
            });
        }
        if let Some(i) = child_i {
            out.spawned_by.push(ObservedSpawnedBy {
                parent: edge.parent.clone(),
                parent_agent: attribute(&edge.parent, &peers),
                child_basis: i.assertion.clone(),
                edge: edge.clone(),
            });
        }
    }
    out
}

// ─── the section ───

/// No reconciler result class speaks about lineage yet (`LINEAGE_VIOLATION`
/// is refused by the central guard). This type has exactly one variant so
/// that no code path can render a verdict before one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ReconciledLineage {
    NotReachable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lineage {
    pub identity: IdentityLineage,
    pub authority: Vec<AuthorityPath>,
    pub process: ProcessLineage,
    pub reconciled: ReconciledLineage,
}
