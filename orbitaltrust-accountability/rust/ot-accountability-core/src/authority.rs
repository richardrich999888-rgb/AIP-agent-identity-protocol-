//! AIP delegated authority: who may invoke which tool, resolved by walking a
//! delegation graph in which scope only ever narrows.
//!
//! This is the Rust port of the TypeScript tier in
//! `apps/ot-vis/src/telemetry/agent-identity/permission-guard.ts` and
//! `.../nexora/delegation-graph.ts`. It exists here rather than only in the
//! browser because three consumers now need authority resolution: the MCP
//! gateway (which must answer "may this agent call this tool?" on the hot
//! path), the offline verifier (which must re-derive the same answer from an
//! exported record), and the browser console.
//!
//! # The attenuation invariant
//!
//! Authority only narrows down the tree. Walking from an agent up to an
//! officer root:
//!
//! - **scope** is the *intersection* of every edge's scope — a child cannot
//!   hold a verb no ancestor conferred;
//! - **multi-sig obligations** are the *union* — an obligation is inherited
//!   and can never be shed by re-delegation;
//! - **clearance** is the *minimum* — the weakest link bounds the path.
//!
//! Resolution walks the live graph every time rather than trusting a cached
//! grant, which is what makes revocation cascade: revoking one mid-tree edge
//! removes authority from its whole subtree at the next resolution, with no
//! invalidation messages to deliver.

use std::collections::BTreeMap;

/// Clearance ladder, low to high. Ordering is the point: see [`ClearanceLevel::meets`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClearanceLevel {
    /// No classification.
    Unclassified,
    /// Restricted distribution.
    Restricted,
    /// Confidential.
    Confidential,
    /// Secret.
    Secret,
    /// Top secret.
    TopSecret,
}

impl ClearanceLevel {
    /// The wire vocabulary, matching the TypeScript tier exactly.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "UNCLASSIFIED",
            Self::Restricted => "RESTRICTED",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::TopSecret => "TOP_SECRET",
        }
    }

    /// Parses the wire vocabulary. `None` for an unrecognised level — an
    /// unknown clearance is a configuration error, not a default.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "UNCLASSIFIED" => Self::Unclassified,
            "RESTRICTED" => Self::Restricted,
            "CONFIDENTIAL" => Self::Confidential,
            "SECRET" => Self::Secret,
            "TOP_SECRET" => Self::TopSecret,
            _ => return None,
        })
    }

    /// True when this clearance admits material requiring `required`.
    pub fn meets(self, required: Self) -> bool {
        self >= required
    }
}

/// How far an input may be trusted. Ordered: `Trusted < Internal < Untrusted`,
/// so "the most untrusted thing in scope" is a `max()`.
///
/// This is the taint dimension. Content an agent reads from outside the trust
/// boundary — a fetched document, a third-party API response, an inbound
/// message — is `Untrusted`, and a tool whose mandate forbids untrusted
/// context in scope cannot be invoked while such content is live. That is the
/// structural control against instruction injection: the attacker's text does
/// not need to be detected, because possessing it removes authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustTier {
    /// Originated inside the trust boundary and is attested.
    Trusted,
    /// Internal but unattested.
    Internal,
    /// Crossed the trust boundary: fetched, received, or user-supplied.
    Untrusted,
}

impl TrustTier {
    /// The wire vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Internal => "INTERNAL",
            Self::Untrusted => "UNTRUSTED",
        }
    }

    /// Parses the wire vocabulary.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "TRUSTED" => Self::Trusted,
            "INTERNAL" => Self::Internal,
            "UNTRUSTED" => Self::Untrusted,
            _ => return None,
        })
    }
}

/// What a tool demands of its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolMandate {
    /// Permission verb the agent must hold via its delegated scope.
    pub required_permission: String,
    /// Minimum clearance for the material the tool touches.
    pub minimum_clearance: ClearanceLevel,
    /// The most-untrusted context tier tolerated in scope when this tool is
    /// invoked. Defaults to [`TrustTier::Untrusted`] (no taint restriction);
    /// a consequential tool should lower it.
    pub max_context_taint: TrustTier,
    /// How far this tool's *output* may be trusted once it lands in context.
    ///
    /// This is what makes taint propagate without anyone annotating it by
    /// hand: a tool that returns fetched web pages or inbound mail declares
    /// [`TrustTier::Untrusted`], so calling it raises the session's taint and
    /// mechanically removes every tool whose `max_context_taint` is lower.
    /// The dangerous combination — read untrusted content, then act — stops
    /// being reachable rather than being detected.
    ///
    /// Defaults to [`TrustTier::Internal`]: a tool's output is not attested,
    /// but neither is it assumed to have crossed the trust boundary.
    pub result_trust: TrustTier,
}

impl ToolMandate {
    /// A mandate with no taint restriction — the permissive default that
    /// matches the TypeScript tier's behaviour before taint existed.
    pub fn new(required_permission: impl Into<String>, minimum_clearance: ClearanceLevel) -> Self {
        Self {
            required_permission: required_permission.into(),
            minimum_clearance,
            max_context_taint: TrustTier::Untrusted,
            result_trust: TrustTier::Internal,
        }
    }

    /// Restricts the tool to context no more tainted than `tier`.
    pub fn with_max_context_taint(mut self, tier: TrustTier) -> Self {
        self.max_context_taint = tier;
        self
    }

    /// Declares how far this tool's output may be trusted in context.
    pub fn with_result_trust(mut self, tier: TrustTier) -> Self {
        self.result_trust = tier;
        self
    }
}

/// Tool name → mandate. **A tool absent from the manifest is denied**; there
/// is no permissive default, which is what makes the manifest the single
/// authority on what is invocable at all.
pub type ToolManifest = BTreeMap<String, ToolMandate>;

/// Lifecycle state of one delegation edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeStatus {
    /// In force.
    Active,
    /// Withdrawn. Retained rather than deleted: "what authority existed when"
    /// is itself audit material.
    Revoked,
}

/// One edge of the delegation graph: a parent conferring an attenuated scope
/// on a child.
///
/// `Eq` is not derived because [`signature`](Self::signature) holds arbitrary
/// JSON; compare with `PartialEq`.
#[derive(Debug, Clone, PartialEq)]
pub struct DelegationEdge {
    /// Stable edge identifier.
    pub edge_id: String,
    /// Officer DID at a root edge; agent DID for sub-agent delegation.
    pub parent_did: String,
    /// The agent receiving authority.
    pub child_did: String,
    /// Tool verbs conferred.
    pub scope: Vec<String>,
    /// Tools additionally requiring a per-invocation supervisor co-signature.
    pub multi_sig_tools: Vec<String>,
    /// Clearance conferred.
    pub clearance_level: ClearanceLevel,
    /// ISO-8601 UTC; the edge is unusable before this.
    pub valid_from_utc: String,
    /// ISO-8601 UTC; the edge is unusable at or after this.
    pub expires_at_utc: String,
    /// Whether the edge is in force.
    pub status: EdgeStatus,
    /// The parent's signature over [`canonical_terms`](Self::canonical_terms),
    /// when the deployment issues signed edges.
    ///
    /// `None` is an unsigned edge, which a signature-checking
    /// [`EdgeVerifier`] refuses. Optional in the type rather than required so
    /// a deployment whose store *is* its trust boundary can keep using
    /// [`TrustedStoreVerifier`] without carrying envelopes it will not check.
    pub signature: Option<serde_json::Value>,
}

impl DelegationEdge {
    /// The edge's terms, in the canonical shape a signature covers.
    ///
    /// Everything that decides what the edge confers, and nothing else — the
    /// signature itself is excluded, or it would have to cover itself. A
    /// verifier recomputes this and compares, so an attacker who widens a
    /// scope or extends an expiry invalidates the signature.
    pub fn canonical_terms(&self) -> serde_json::Value {
        serde_json::json!({
            "edgeId": self.edge_id,
            "parentDid": self.parent_did,
            "childDid": self.child_did,
            "scope": self.scope,
            "multiSigTools": self.multi_sig_tools,
            "clearanceLevel": self.clearance_level.as_str(),
            "validFromUtc": self.valid_from_utc,
            "expiresAtUtc": self.expires_at_utc,
        })
    }
}

/// Where delegation edges are read from. A trait so the gateway can back it
/// with a policy file, the governance hub, or an in-memory fixture.
pub trait AuthorityStore {
    /// Every edge naming `child_did` as its child, in any order.
    fn edges_for_child(&self, child_did: &str) -> Vec<DelegationEdge>;
}

/// Verifies that an edge's terms were issued by the authority it names.
///
/// Separated from the store because *where edges live* and *who vouches for
/// them* are different questions: a deployment reading edges from a trusted
/// database may accept them structurally, while one accepting edges over a
/// network must verify signatures. [`TrustedStoreVerifier`] makes the former
/// choice explicit rather than implicit.
pub trait EdgeVerifier {
    /// True when the edge's terms are authentic.
    fn verify(&self, edge: &DelegationEdge) -> bool;
}

/// Accepts every edge the store returns.
///
/// **Security note:** correct only when the store itself is the trust
/// boundary (a local policy file, or records already verified on ingest). A
/// deployment accepting edges from an untrusted source must supply a
/// signature-checking verifier instead.
pub struct TrustedStoreVerifier;

impl EdgeVerifier for TrustedStoreVerifier {
    fn verify(&self, _edge: &DelegationEdge) -> bool {
        true
    }
}

/// An in-memory store, for tests and single-tenant gateway deployments.
#[derive(Debug, Default, Clone)]
pub struct MemoryAuthorityStore {
    edges: Vec<DelegationEdge>,
}

impl MemoryAuthorityStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an edge.
    pub fn add(&mut self, edge: DelegationEdge) {
        self.edges.push(edge);
    }

    /// Marks an edge revoked. Everything downstream loses authority at the
    /// next resolution — cascade by construction, since resolution walks the
    /// live graph.
    pub fn revoke(&mut self, edge_id: &str) {
        for edge in &mut self.edges {
            if edge.edge_id == edge_id {
                edge.status = EdgeStatus::Revoked;
            }
        }
    }
}

impl AuthorityStore for MemoryAuthorityStore {
    fn edges_for_child(&self, child_did: &str) -> Vec<DelegationEdge> {
        self.edges
            .iter()
            .filter(|e| e.child_did == child_did)
            .cloned()
            .collect()
    }
}

/// Resolved authority for one agent: the intersection along its delegation
/// path, root officer first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveAuthority {
    /// DID path, root delegator → … → agent.
    pub path: Vec<String>,
    /// Edge ids along the path, same order.
    pub edge_ids: Vec<String>,
    /// Tools every hop confers — the intersection.
    pub scope: Vec<String>,
    /// Union of every hop's multi-sig obligations.
    pub multi_sig_tools: Vec<String>,
    /// The weakest clearance on the path.
    pub clearance_level: ClearanceLevel,
}

/// Deeper sub-agent trees are refused: a delegation chain nobody can read is
/// a delegation chain nobody reviews.
pub const MAX_DELEGATION_DEPTH: usize = 16;

/// The DID prefix identifying a human officer — the only kind of root a
/// delegation path may terminate at.
pub const OFFICER_DID_PREFIX: &str = "did:syntriass:officer:";

fn is_officer(did: &str) -> bool {
    did.starts_with(OFFICER_DID_PREFIX)
}

/// The newest usable edge for `child_did`: active, inside its validity
/// window, and vouched for by the verifier. Ties break toward the most
/// recently issued.
fn usable_edge<S: AuthorityStore + ?Sized, V: EdgeVerifier + ?Sized>(
    store: &S,
    verifier: &V,
    child_did: &str,
    now_utc: &str,
) -> Option<DelegationEdge> {
    let mut candidates: Vec<DelegationEdge> = store
        .edges_for_child(child_did)
        .into_iter()
        .filter(|e| e.status == EdgeStatus::Active)
        // ISO-8601 UTC with a fixed shape compares correctly as a string,
        // which keeps this dependency-free and clock-free.
        .filter(|e| now_utc >= e.valid_from_utc.as_str() && now_utc < e.expires_at_utc.as_str())
        .filter(|e| verifier.verify(e))
        .collect();
    candidates.sort_by(|a, b| b.valid_from_utc.cmp(&a.valid_from_utc));
    candidates.into_iter().next()
}

/// Walks from `agent_did` up to an officer root, intersecting scope,
/// unioning multi-sig obligations, and taking the minimum clearance.
///
/// Returns `None` when any hop lacks a usable edge, or when no officer root
/// is reached within [`MAX_DELEGATION_DEPTH`] — unrooted authority is no
/// authority, which is precisely how a mid-tree revocation disables a whole
/// subtree.
pub fn resolve_authority<S: AuthorityStore + ?Sized, V: EdgeVerifier + ?Sized>(
    store: &S,
    verifier: &V,
    agent_did: &str,
    now_utc: &str,
) -> Option<EffectiveAuthority> {
    let mut path = vec![agent_did.to_string()];
    let mut edge_ids: Vec<String> = Vec::new();
    let mut scope: Option<Vec<String>> = None;
    let mut multi_sig_tools: Vec<String> = Vec::new();
    let mut clearance: Option<ClearanceLevel> = None;

    let mut current = agent_did.to_string();
    for _ in 0..MAX_DELEGATION_DEPTH {
        let edge = usable_edge(store, verifier, &current, now_utc)?;
        edge_ids.insert(0, edge.edge_id.clone());
        path.insert(0, edge.parent_did.clone());

        scope = Some(match scope {
            None => edge.scope.clone(),
            Some(acc) => acc
                .into_iter()
                .filter(|tool| edge.scope.contains(tool))
                .collect(),
        });
        for tool in &edge.multi_sig_tools {
            if !multi_sig_tools.contains(tool) {
                multi_sig_tools.push(tool.clone());
            }
        }
        clearance = Some(match clearance {
            None => edge.clearance_level,
            Some(held) => held.min(edge.clearance_level),
        });

        if is_officer(&edge.parent_did) {
            return Some(EffectiveAuthority {
                path,
                edge_ids,
                scope: scope.unwrap_or_default(),
                multi_sig_tools,
                clearance_level: clearance.unwrap_or(ClearanceLevel::Unclassified),
            });
        }
        current = edge.parent_did;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(
        id: &str,
        parent: &str,
        child: &str,
        scope: &[&str],
        clearance: ClearanceLevel,
    ) -> DelegationEdge {
        DelegationEdge {
            edge_id: id.into(),
            parent_did: parent.into(),
            child_did: child.into(),
            scope: scope.iter().map(|s| s.to_string()).collect(),
            multi_sig_tools: Vec::new(),
            clearance_level: clearance,
            valid_from_utc: "2026-01-01T00:00:00.000Z".into(),
            expires_at_utc: "2027-01-01T00:00:00.000Z".into(),
            status: EdgeStatus::Active,
            signature: None,
        }
    }

    const NOW: &str = "2026-06-01T00:00:00.000Z";
    const OFFICER: &str = "did:syntriass:officer:OFF-1";
    const PARENT: &str = "did:syntriass:agent:PARENT";
    const CHILD: &str = "did:syntriass:agent:CHILD";

    #[test]
    fn a_rooted_edge_resolves_to_its_own_terms() {
        let mut store = MemoryAuthorityStore::new();
        store.add(edge(
            "e1",
            OFFICER,
            PARENT,
            &["a", "b"],
            ClearanceLevel::Secret,
        ));
        let auth = resolve_authority(&store, &TrustedStoreVerifier, PARENT, NOW).unwrap();
        assert_eq!(auth.scope, ["a", "b"]);
        assert_eq!(auth.clearance_level, ClearanceLevel::Secret);
        assert_eq!(auth.path, [OFFICER, PARENT]);
    }

    #[test]
    fn scope_intersects_clearance_minimises_and_multisig_unions_down_the_tree() {
        let mut store = MemoryAuthorityStore::new();
        let mut parent = edge(
            "e1",
            OFFICER,
            PARENT,
            &["a", "b", "c"],
            ClearanceLevel::TopSecret,
        );
        parent.multi_sig_tools = vec!["c".into()];
        store.add(parent);
        // The child edge *claims* more than the parent holds and a higher
        // clearance; resolution must not honour either claim.
        store.add(edge(
            "e2",
            PARENT,
            CHILD,
            &["b", "c", "z"],
            ClearanceLevel::Confidential,
        ));

        let auth = resolve_authority(&store, &TrustedStoreVerifier, CHILD, NOW).unwrap();
        // "a" not claimed by the child, "z" not held by the parent.
        assert_eq!(auth.scope, ["b", "c"]);
        // The weakest link bounds the path.
        assert_eq!(auth.clearance_level, ClearanceLevel::Confidential);
        // The parent's obligation is inherited even though the child edge
        // declared none.
        assert_eq!(auth.multi_sig_tools, ["c"]);
        assert_eq!(auth.path, [OFFICER, PARENT, CHILD]);
    }

    #[test]
    fn revoking_a_mid_tree_edge_disables_the_whole_subtree() {
        let mut store = MemoryAuthorityStore::new();
        store.add(edge("e1", OFFICER, PARENT, &["a"], ClearanceLevel::Secret));
        store.add(edge("e2", PARENT, CHILD, &["a"], ClearanceLevel::Secret));
        assert!(resolve_authority(&store, &TrustedStoreVerifier, CHILD, NOW).is_some());

        store.revoke("e1");
        // The child's own edge is untouched and still active…
        assert!(resolve_authority(&store, &TrustedStoreVerifier, CHILD, NOW).is_none());
        // …and the parent is gone too.
        assert!(resolve_authority(&store, &TrustedStoreVerifier, PARENT, NOW).is_none());
    }

    #[test]
    fn an_unrooted_chain_is_no_authority() {
        let mut store = MemoryAuthorityStore::new();
        // Parent is an agent that never received a rooted edge.
        store.add(edge("e2", PARENT, CHILD, &["a"], ClearanceLevel::Secret));
        assert!(resolve_authority(&store, &TrustedStoreVerifier, CHILD, NOW).is_none());
    }

    #[test]
    fn an_expired_or_future_edge_is_unusable() {
        let mut store = MemoryAuthorityStore::new();
        store.add(edge("e1", OFFICER, PARENT, &["a"], ClearanceLevel::Secret));
        assert!(resolve_authority(
            &store,
            &TrustedStoreVerifier,
            PARENT,
            "2025-06-01T00:00:00.000Z"
        )
        .is_none());
        assert!(resolve_authority(
            &store,
            &TrustedStoreVerifier,
            PARENT,
            "2028-06-01T00:00:00.000Z"
        )
        .is_none());
    }

    #[test]
    fn a_verifier_rejecting_an_edge_removes_it_from_consideration() {
        struct RejectAll;
        impl EdgeVerifier for RejectAll {
            fn verify(&self, _: &DelegationEdge) -> bool {
                false
            }
        }
        let mut store = MemoryAuthorityStore::new();
        store.add(edge("e1", OFFICER, PARENT, &["a"], ClearanceLevel::Secret));
        assert!(resolve_authority(&store, &RejectAll, PARENT, NOW).is_none());
    }

    #[test]
    fn clearance_and_trust_ladders_order_correctly() {
        assert!(ClearanceLevel::TopSecret.meets(ClearanceLevel::Secret));
        assert!(!ClearanceLevel::Confidential.meets(ClearanceLevel::Secret));
        assert!(ClearanceLevel::Secret.meets(ClearanceLevel::Secret));
        assert!(TrustTier::Untrusted > TrustTier::Internal);
        assert!(TrustTier::Internal > TrustTier::Trusted);
        assert_eq!(
            ClearanceLevel::parse("SECRET"),
            Some(ClearanceLevel::Secret)
        );
        assert_eq!(ClearanceLevel::parse("NOPE"), None);
    }
}
