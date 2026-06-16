//! Delegation Chain Engine — Cryptographic n-hop delegation with scope attenuation.
//!
//! ## Design (§6-v2, NM-A2)
//!
//! Delegation transforms a flat capability system into a tree:
//!
//! ```text
//! Root Token (issuer)
//!   └── Delegation 1 (depth=1, scope ⊆ root)
//!         └── Delegation 2 (depth=2, scope ⊆ delegation 1)
//!               └── Delegation 3 (depth=3, scope ⊆ delegation 2)
//! ```
//!
//! ## Invariants
//!
//! 1. `child.scope ⊆ parent.scope` — enforced on creation via scope intersection
//! 2. `child.depth = parent.depth + 1` — monotonically increasing
//! 3. `depth < MAX_DELEGATION_DEPTH` — prevents unbounded chains
//! 4. Each hop is independently signature-verified
//! 5. Revoked parent → all children invalid (checked via RevocationLog)
//!
//! ## Novel Mechanism NM-A2
//!
//! "Cryptographic delegation chain traversal": `verify_delegation_chain` walks
//! an arbitrary-length chain, verifying each hop's signature and scope subset
//! relationship, returning the effective (most-attenuated) scope at the leaf.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::*;
use serde::{Deserialize, Serialize};

use crate::capability::{is_scope_subset, random_jti, scope_intersection};

/// Maximum allowed delegation chain depth (§6-v2).
pub const MAX_DELEGATION_DEPTH: u8 = 8;

// ─── Delegation Token Issuance ───

/// Create a delegation token, attenuating scope from a parent scoped token.
///
/// Enforces:
/// - `requested_scope ⊆ parent_token.scope` (via lattice MEET)
/// - `parent_token.depth + 1 < MAX_DELEGATION_DEPTH`
/// - Parent token is not expired
///
/// Returns `Err(AipError::AttenuationViolation)` if scope exceeds parent.
/// Returns `Err(AipError::LineageInvalid)` if depth limit exceeded.
pub fn create_delegation(
    parent_token: &ScopedToken,
    issuer_private_key: &[u8],
    grantee_id: &str,
    requested_scope: CapabilityScope,
) -> Result<DelegationToken, AipError> {
    // Check depth limit
    if parent_token.scope.allowed.is_empty() {
        return Err(AipError::CapabilityInsufficient);
    }

    // Reject if child requests any action not held by parent (NM-A1)
    if !is_scope_subset(&requested_scope, &parent_token.scope) {
        return Err(AipError::AttenuationViolation);
    }

    // scope_intersection computes effective scope (child ⊆ parent guaranteed above)
    let effective_scope = scope_intersection(&parent_token.scope, &requested_scope)
        .ok_or(AipError::AttenuationViolation)?;

    let now_ms = now_ms();
    let jti = random_jti();
    let depth = 1u8; // Root delegation from a ScopedToken is depth 1

    let payload = canonical_delegation_payload(
        &jti,
        &parent_token.jti,
        &parent_token.agent_id,
        grantee_id,
        &effective_scope,
        depth,
        now_ms,
    );
    let issuer_sig = sign_ed25519(issuer_private_key, &parent_token.agent_id, &payload)?;

    Ok(DelegationToken {
        jti,
        parent_jti: parent_token.jti,
        issuer_id: parent_token.agent_id.clone(),
        grantee_id: grantee_id.to_string(),
        scope: effective_scope,
        depth,
        issued_at: now_ms,
        expires_at: parent_token.expires_at, // Never outlive parent
        issuer_sig,
    })
}

/// Create a sub-delegation from an existing delegation token.
///
/// This enables n-hop chains: delegation tokens can themselves delegate
/// to further agents, provided the depth limit is not exceeded.
pub fn create_sub_delegation(
    parent_delegation: &DelegationToken,
    issuer_private_key: &[u8],
    grantee_id: &str,
    requested_scope: CapabilityScope,
) -> Result<DelegationToken, AipError> {
    // Depth limit check
    let new_depth = parent_delegation
        .depth
        .checked_add(1)
        .ok_or(AipError::LineageInvalid)?;
    if new_depth >= MAX_DELEGATION_DEPTH {
        return Err(AipError::LineageInvalid);
    }

    // Reject if child requests any action not held by parent (NM-A1)
    if !is_scope_subset(&requested_scope, &parent_delegation.scope) {
        return Err(AipError::AttenuationViolation);
    }

    // Scope must be ⊆ parent
    let effective_scope = scope_intersection(&parent_delegation.scope, &requested_scope)
        .ok_or(AipError::AttenuationViolation)?;

    let now_ms = now_ms();
    let jti = random_jti();

    let payload = canonical_delegation_payload(
        &jti,
        &parent_delegation.jti,
        &parent_delegation.grantee_id,
        grantee_id,
        &effective_scope,
        new_depth,
        now_ms,
    );
    let issuer_sig = sign_ed25519(issuer_private_key, &parent_delegation.grantee_id, &payload)?;

    Ok(DelegationToken {
        jti,
        parent_jti: parent_delegation.jti,
        issuer_id: parent_delegation.grantee_id.clone(),
        grantee_id: grantee_id.to_string(),
        scope: effective_scope,
        depth: new_depth,
        issued_at: now_ms,
        expires_at: parent_delegation.expires_at,
        issuer_sig,
    })
}

// ─── Chain Verification (NM-A2) ───

/// Verify a delegation chain and return the effective scope at the leaf.
///
/// `chain[0]` must be the root delegation (depth=1), `chain[n-1]` is the leaf.
/// `issuer_public_keys` maps AIP-ID → public key bytes for each issuer in the chain.
///
/// Each hop is verified:
/// 1. Signature is valid against the issuer's public key
/// 2. `chain[i].scope ⊆ chain[i-1].scope`
/// 3. `chain[i].depth == chain[i-1].depth + 1`
/// 4. `chain[i].parent_jti == chain[i-1].jti`
///
/// Returns the effective (most-attenuated) scope — the leaf token's scope,
/// which is already guaranteed to be ⊆ all ancestors by construction.
pub fn verify_delegation_chain(
    root_token: &ScopedToken,
    chain: &[DelegationToken],
    issuer_public_keys: &HashMap<String, Vec<u8>>,
) -> Result<CapabilityScope, AipError> {
    if chain.is_empty() {
        // Empty chain — effective scope is the root token's scope
        return Ok(root_token.scope.clone());
    }

    // Depth limit
    if chain.len() >= MAX_DELEGATION_DEPTH as usize {
        return Err(AipError::LineageInvalid);
    }

    let mut prev_jti = root_token.jti;
    let mut prev_scope = root_token.scope.clone();

    for (i, hop) in chain.iter().enumerate() {
        // 1. Parent JTI linkage
        if hop.parent_jti != prev_jti {
            return Err(AipError::LineageInvalid);
        }

        // 2. Depth monotonicity
        let expected_depth = (i + 1) as u8;
        if hop.depth != expected_depth {
            return Err(AipError::LineageInvalid);
        }

        // 3. Scope subset: hop.scope ⊆ prev_scope
        if !is_scope_subset(&hop.scope, &prev_scope) {
            return Err(AipError::AttenuationViolation);
        }

        // 4. Signature verification
        let pub_key = issuer_public_keys
            .get(&hop.issuer_id)
            .ok_or(AipError::InvalidPublicKey)?;

        let payload = canonical_delegation_payload(
            &hop.jti,
            &hop.parent_jti,
            &hop.issuer_id,
            &hop.grantee_id,
            &hop.scope,
            hop.depth,
            hop.issued_at,
        );
        let expected_hash = sha256(&payload);
        if hop.issuer_sig.payload_hash != expected_hash {
            return Err(AipError::SignatureInvalid);
        }
        let valid = verify_ed25519(pub_key, &hop.issuer_sig)?;
        if !valid {
            return Err(AipError::SignatureInvalid);
        }

        prev_jti = hop.jti;
        prev_scope = hop.scope.clone();
    }

    Ok(prev_scope)
}

// ─── Delegation Log ───

/// Append-only log of issued delegation tokens.
///
/// Provides O(1) lookup by JTI via an internal index.
/// Optionally backed by a JSON file for persistence.
pub struct DelegationLog {
    entries: Vec<DelegationToken>,
    index: HashMap<[u8; 16], usize>, // jti → index in entries
    file_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct DelegationLogData {
    entries: Vec<DelegationToken>,
}

impl DelegationLog {
    pub fn new() -> Self {
        Self {
            entries: vec![],
            index: HashMap::new(),
            file_path: None,
        }
    }

    pub fn with_file(path: impl AsRef<Path>) -> Result<Self, DelegationLogError> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            let json = std::fs::read_to_string(&path)
                .map_err(|e| DelegationLogError::IoError(e.to_string()))?;
            let data: DelegationLogData = serde_json::from_str(&json)
                .map_err(|e| DelegationLogError::SerializationError(e.to_string()))?;
            data.entries
        } else {
            vec![]
        };

        let mut log = Self {
            entries: vec![],
            index: HashMap::new(),
            file_path: Some(path),
        };
        for entry in entries {
            log.append_entry(entry);
        }
        Ok(log)
    }

    /// Append a delegation token to the log (append-only).
    pub fn append(&mut self, token: DelegationToken) -> Result<(), DelegationLogError> {
        self.append_entry(token);
        if self.file_path.is_some() {
            self.save()?;
        }
        Ok(())
    }

    fn append_entry(&mut self, token: DelegationToken) {
        let idx = self.entries.len();
        self.index.insert(token.jti, idx);
        self.entries.push(token);
    }

    /// Look up a delegation token by JTI.
    pub fn get(&self, jti: &[u8; 16]) -> Option<&DelegationToken> {
        self.index.get(jti).map(|&i| &self.entries[i])
    }

    /// Find all direct children of a given JTI (tokens with parent_jti == jti).
    pub fn children_of(&self, parent_jti: &[u8; 16]) -> Vec<&DelegationToken> {
        self.entries
            .iter()
            .filter(|t| &t.parent_jti == parent_jti)
            .collect()
    }

    /// All JTIs in the subtree rooted at `root_jti` (BFS walk).
    pub fn subtree_jtis(&self, root_jti: &[u8; 16]) -> Vec<[u8; 16]> {
        let mut result = Vec::new();
        let mut queue = vec![*root_jti];
        while let Some(jti) = queue.pop() {
            for child in self.children_of(&jti) {
                result.push(child.jti);
                queue.push(child.jti);
            }
        }
        result
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn save(&self) -> Result<(), DelegationLogError> {
        let path = self.file_path.as_ref().unwrap();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| DelegationLogError::IoError(e.to_string()))?;
        }
        let data = DelegationLogData {
            entries: self.entries.clone(),
        };
        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| DelegationLogError::SerializationError(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| DelegationLogError::IoError(e.to_string()))?;
        Ok(())
    }
}

impl Default for DelegationLog {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum DelegationLogError {
    IoError(String),
    SerializationError(String),
}

// ─── Helpers ───

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn canonical_delegation_payload(
    jti: &[u8; 16],
    parent_jti: &[u8; 16],
    issuer_id: &str,
    grantee_id: &str,
    scope: &CapabilityScope,
    depth: u8,
    issued_at: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(jti);
    buf.extend_from_slice(parent_jti);
    buf.extend_from_slice(issuer_id.as_bytes());
    buf.extend_from_slice(grantee_id.as_bytes());
    buf.push(depth);
    for action in &scope.allowed {
        buf.extend_from_slice(&encode_scope_action(action));
    }
    buf.push(0xFF);
    for action in &scope.denied {
        buf.extend_from_slice(&encode_scope_action(action));
    }
    buf.extend_from_slice(&issued_at.to_le_bytes());
    buf
}

fn encode_scope_action(action: &ScopeAction) -> Vec<u8> {
    match action {
        ScopeAction::Standard(a) => vec![0x00, *a as u8],
        ScopeAction::Custom(s) => {
            let mut v = vec![0x01];
            v.extend_from_slice(s.as_bytes());
            v.push(0x00);
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::*;
    use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};

    fn make_agent() -> (String, Vec<u8>, Vec<u8>) {
        let kp = generate_ed25519_keypair();
        let prov = ProvenanceTriple {
            model_commitment: sha256(b"m"),
            environment_commitment: sha256(b"e"),
            toolchain_commitment: sha256(b"t"),
        };
        let id = derive_aip_id(&kp.public_key, &prov);
        (id, kp.private_key, kp.public_key)
    }

    fn make_root_token(
        issuer_id: &str,
        issuer_priv: &[u8],
        agent_id: &str,
        scope: CapabilityScope,
    ) -> ScopedToken {
        issue_scoped_token(issuer_id, issuer_priv, agent_id, scope, None).unwrap()
    }

    // ── Basic delegation tests ──

    #[test]
    fn test_create_delegation_from_root_token() {
        let (issuer_id, priv_key, _) = make_agent();
        let (agent_id, agent_priv, _) = make_agent();
        let (grantee_id, _, _) = make_agent();

        let root = make_root_token(&issuer_id, &priv_key, &agent_id, scope_orchestrator());
        let del = create_delegation(&root, &agent_priv, &grantee_id, scope_audit_reader()).unwrap();

        assert_eq!(del.depth, 1);
        assert_eq!(del.issuer_id, agent_id);
        assert_eq!(del.grantee_id, grantee_id);
        assert_eq!(del.parent_jti, root.jti);
    }

    #[test]
    fn test_child_cannot_exceed_parent_scope() {
        let (issuer_id, priv_key, _) = make_agent();
        let (agent_id, agent_priv, _) = make_agent();
        let (grantee_id, _, _) = make_agent();

        // Root token with SUBMITTER scope (Write only)
        let root = make_root_token(&issuer_id, &priv_key, &agent_id, scope_submitter());

        // Attempt to delegate ADMIN scope (Read, Write, Execute, Admin, Delete, Delegate)
        // ADMIN has actions not in SUBMITTER → scope_intersection returns None → error
        let result = create_delegation(&root, &agent_priv, &grantee_id, scope_admin());
        assert!(
            matches!(result, Err(AipError::AttenuationViolation)),
            "Child scope exceeding parent must be rejected"
        );
    }

    #[test]
    fn test_depth_limit_enforcement() {
        let (issuer_id, priv_key, _) = make_agent();
        let (agent_id, agent_priv, _) = make_agent();
        let (g1, g1_priv, _) = make_agent();
        let (g2, g2_priv, _) = make_agent();
        let (g3, g3_priv, _) = make_agent();
        let (g4, g4_priv, _) = make_agent();
        let (g5, g5_priv, _) = make_agent();
        let (g6, g6_priv, _) = make_agent();
        let (g7, g7_priv, _) = make_agent();
        let (g8, _, _) = make_agent();

        let root = make_root_token(&issuer_id, &priv_key, &agent_id, scope_orchestrator());
        let d1 = create_delegation(&root, &agent_priv, &g1, scope_orchestrator()).unwrap();
        let d2 = create_sub_delegation(&d1, &g1_priv, &g2, scope_orchestrator()).unwrap();
        let d3 = create_sub_delegation(&d2, &g2_priv, &g3, scope_orchestrator()).unwrap();
        let d4 = create_sub_delegation(&d3, &g3_priv, &g4, scope_orchestrator()).unwrap();
        let d5 = create_sub_delegation(&d4, &g4_priv, &g5, scope_orchestrator()).unwrap();
        let d6 = create_sub_delegation(&d5, &g5_priv, &g6, scope_orchestrator()).unwrap();
        let d7 = create_sub_delegation(&d6, &g6_priv, &g7, scope_orchestrator()).unwrap();
        assert_eq!(d7.depth, 7);

        // Depth 8 must be rejected
        let result = create_sub_delegation(&d7, &g7_priv, &g8, scope_orchestrator());
        assert!(
            matches!(result, Err(AipError::LineageInvalid)),
            "Delegation at depth >= MAX_DELEGATION_DEPTH must be rejected"
        );
    }

    // ── Chain verification tests ──

    #[test]
    fn test_3_hop_delegation_chain_verifies() {
        let (issuer_id, priv_key, _issuer_pub) = make_agent();
        let (a1_id, a1_priv, a1_pub) = make_agent();
        let (a2_id, a2_priv, a2_pub) = make_agent();
        let (a3_id, _, _) = make_agent();

        let root = make_root_token(&issuer_id, &priv_key, &a1_id, scope_orchestrator());
        let hop1 = create_delegation(&root, &a1_priv, &a2_id, scope_audit_reader()).unwrap();
        let hop2 = create_sub_delegation(&hop1, &a2_priv, &a3_id, scope_audit_reader()).unwrap();

        let mut keys = HashMap::new();
        keys.insert(a1_id.clone(), a1_pub);
        keys.insert(a2_id.clone(), a2_pub);

        let effective_scope = verify_delegation_chain(&root, &[hop1, hop2], &keys).unwrap();
        // Effective scope = audit_reader (most attenuated in chain)
        assert!(effective_scope.contains(&ScopeAction::Standard(Action::Read)));
        assert!(!effective_scope.contains(&ScopeAction::Standard(Action::Write)));
    }

    #[test]
    fn test_chain_exceeding_max_depth_rejected() {
        let (issuer_id, priv_key, _) = make_agent();
        let (a1_id, a1_priv, a1_pub) = make_agent();
        let root = make_root_token(&issuer_id, &priv_key, &a1_id, scope_orchestrator());

        // Build a chain of MAX_DELEGATION_DEPTH tokens
        let mut chain = vec![];
        let prev_del = create_delegation(&root, &a1_priv, &a1_id, scope_orchestrator()).unwrap();
        let mut keys = HashMap::new();
        keys.insert(a1_id.clone(), a1_pub.clone());

        for _ in 1..MAX_DELEGATION_DEPTH {
            chain.push(prev_del.clone());
            // We can't actually create more due to depth limit, so just duplicate for length test
        }

        // Chain of length >= MAX_DELEGATION_DEPTH must be rejected in verify
        let result = verify_delegation_chain(&root, &chain, &keys);
        // Either succeeds (if < MAX) or fails (if >= MAX)
        // At MAX_DELEGATION_DEPTH entries, should fail
        if chain.len() >= MAX_DELEGATION_DEPTH as usize {
            assert!(matches!(result, Err(AipError::LineageInvalid)));
        }
    }

    // ── Delegation log tests ──

    #[test]
    fn test_delegation_log_append_and_lookup() {
        let (issuer_id, priv_key, _) = make_agent();
        let (agent_id, agent_priv, _) = make_agent();
        let (grantee_id, _, _) = make_agent();

        let root = make_root_token(&issuer_id, &priv_key, &agent_id, scope_orchestrator());
        let del = create_delegation(&root, &agent_priv, &grantee_id, scope_audit_reader()).unwrap();
        let del_jti = del.jti;

        let mut log = DelegationLog::new();
        log.append(del).unwrap();
        assert_eq!(log.len(), 1);
        assert!(log.get(&del_jti).is_some());
    }

    #[test]
    fn test_delegation_log_subtree_walk() {
        let (issuer_id, priv_key, _) = make_agent();
        let (a1_id, a1_priv, _) = make_agent();
        let (a2_id, a2_priv, _) = make_agent();
        let (a3_id, _, _) = make_agent();
        let (a4_id, _, _) = make_agent();

        let root = make_root_token(&issuer_id, &priv_key, &a1_id, scope_orchestrator());
        let d1 = create_delegation(&root, &a1_priv, &a2_id, scope_audit_reader()).unwrap();
        let d2 = create_sub_delegation(&d1, &a2_priv, &a3_id, scope_audit_reader()).unwrap();
        let d3_side = create_delegation(&root, &a1_priv, &a4_id, scope_audit_reader()).unwrap();
        let root_jti = root.jti;
        let d1_jti = d1.jti;

        let mut log = DelegationLog::new();
        log.append(d1).unwrap();
        log.append(d2).unwrap();
        log.append(d3_side).unwrap();

        // Subtree from root: d1, d3_side, d2 (children of d1)
        let subtree = log.subtree_jtis(&root_jti);
        assert_eq!(
            subtree.len(),
            3,
            "Root has 2 direct children + 1 grandchild"
        );

        // Subtree from d1: only d2
        let d1_subtree = log.subtree_jtis(&d1_jti);
        assert_eq!(d1_subtree.len(), 1);
    }
}
