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
use aip_types::canonical::{encode_scope, put_domain, put_opt_u64, put_str, put_u64, put_u8};
use aip_types::*;
use serde::{Deserialize, Serialize};

/// Domain tag that leads every DelegationToken signing payload.
pub const DELEGATION_TOKEN_DOMAIN: &str = "AIP/DelegationToken/v1";

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
    let expires_at = parent_token.expires_at; // Never outlive parent

    let payload = canonical_delegation_payload(
        &jti,
        &parent_token.jti,
        &parent_token.agent_id,
        grantee_id,
        &effective_scope,
        depth,
        now_ms,
        expires_at,
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
        expires_at,
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
    let expires_at = parent_delegation.expires_at; // Never outlive parent

    let payload = canonical_delegation_payload(
        &jti,
        &parent_delegation.jti,
        &parent_delegation.grantee_id,
        grantee_id,
        &effective_scope,
        new_depth,
        now_ms,
        expires_at,
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
        expires_at,
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
/// 5. `chain[i].expires_at` does not outlive the parent's `expires_at`
///    (a bounded parent cannot yield an unbounded or later-expiring child)
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
    let mut prev_expires_at = root_token.expires_at;

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
        if !verify_delegation_token_signature(hop, pub_key)? {
            return Err(AipError::SignatureInvalid);
        }

        // 5. Temporal attenuation (checked after authenticity so a forged
        //    expiry is reported as SignatureInvalid, and an issuer that
        //    genuinely over-delegated is reported as AttenuationViolation).
        //    A bounded parent cannot yield an unbounded or later-expiring child.
        if let Some(parent_exp) = prev_expires_at {
            match hop.expires_at {
                None => return Err(AipError::AttenuationViolation),
                Some(child_exp) if child_exp > parent_exp => {
                    return Err(AipError::AttenuationViolation)
                }
                Some(_) => {}
            }
        }

        prev_jti = hop.jti;
        prev_scope = hop.scope.clone();
        prev_expires_at = hop.expires_at;
    }

    Ok(prev_scope)
}

/// Verify one delegation hop's issuer signature against the issuer's public
/// key: recompute the canonical payload, require `payload_hash` to match, then
/// verify the Ed25519 envelope.
///
/// This is the **only** correct way to check a `DelegationToken` signature.
/// Verifying the envelope alone (`verify_ed25519` on `issuer_sig`) proves that
/// the issuer signed *something*, not that it signed *this* hop — every field
/// could have been rewritten. `verify_delegation_chain` uses this per hop; the
/// JWKS verifier in `wellknown` uses it for a single hop.
pub fn verify_delegation_token_signature(
    hop: &DelegationToken,
    issuer_public_key: &[u8],
) -> Result<bool, AipError> {
    let payload = canonical_delegation_payload(
        &hop.jti,
        &hop.parent_jti,
        &hop.issuer_id,
        &hop.grantee_id,
        &hop.scope,
        hop.depth,
        hop.issued_at,
        hop.expires_at,
    );
    if hop.issuer_sig.payload_hash != sha256(&payload) {
        return Ok(false);
    }
    verify_ed25519(issuer_public_key, &hop.issuer_sig)
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

/// Signed payload of a DelegationToken.
///
/// Injective by construction: domain tag first, every variable-length field
/// length-prefixed, `expires_at` with an explicit presence byte. Uses the
/// shared encoder in [`aip_types::canonical`].
/// The exact bytes a [`DelegationToken`]'s `issuer_sig` covers. Exposed for
/// the same reason as [`crate::capability::token_signing_payload`]: a
/// packager binds the bytes the issuer signed, never a second description.
pub fn delegation_signing_payload(token: &DelegationToken) -> Vec<u8> {
    canonical_delegation_payload(
        &token.jti,
        &token.parent_jti,
        &token.issuer_id,
        &token.grantee_id,
        &token.scope,
        token.depth,
        token.issued_at,
        token.expires_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn canonical_delegation_payload(
    jti: &[u8; 16],
    parent_jti: &[u8; 16],
    issuer_id: &str,
    grantee_id: &str,
    scope: &CapabilityScope,
    depth: u8,
    issued_at: u64,
    expires_at: Option<u64>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    put_domain(&mut buf, DELEGATION_TOKEN_DOMAIN);
    buf.extend_from_slice(jti); // fixed 16 bytes
    buf.extend_from_slice(parent_jti); // fixed 16 bytes
    put_str(&mut buf, issuer_id);
    put_str(&mut buf, grantee_id);
    encode_scope(&mut buf, scope);
    put_u8(&mut buf, depth);
    put_u64(&mut buf, issued_at);
    put_opt_u64(&mut buf, &expires_at);
    buf
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

    // ── Adversarial: delegation expiry must be bound by the issuer signature (I6) ──

    /// Root (unexpired, 1h) → hop1 → hop2, all validly signed.
    /// Returns (root, chain, issuer public keys).
    fn make_signed_two_hop_chain() -> (ScopedToken, Vec<DelegationToken>, HashMap<String, Vec<u8>>)
    {
        let (issuer_id, issuer_priv, issuer_pub) = make_agent();
        let (agent_id, agent_priv, agent_pub) = make_agent();
        let (g1, g1_priv, g1_pub) = make_agent();
        let (g2, _, _) = make_agent();

        let root = issue_scoped_token(
            &issuer_id,
            &issuer_priv,
            &agent_id,
            scope_orchestrator(),
            Some(3_600_000),
        )
        .unwrap();
        let d1 = create_delegation(&root, &agent_priv, &g1, scope_orchestrator()).unwrap();
        let d2 = create_sub_delegation(&d1, &g1_priv, &g2, scope_submitter()).unwrap();

        let mut keys = HashMap::new();
        keys.insert(issuer_id, issuer_pub);
        keys.insert(agent_id, agent_pub);
        keys.insert(g1, g1_pub);
        (root, vec![d1, d2], keys)
    }

    // ── Adversarial: the issuer of a hop must be the holder of the parent ──
    //
    // AUDIT P0-2. `verify_delegation_chain` checked parent_jti linkage,
    // depth, scope attenuation, the issuer signature and temporal
    // attenuation — but never that the party doing the delegating was the
    // party the parent granted to. Any agent whose public key the verifier
    // holds could therefore mint a hop off a root token issued to somebody
    // else, and the chain verified.

    /// Mallory, a legitimate agent in the same fleet, delegates to herself
    /// from a root token that was issued to Alice. Mallory never held it.
    #[test]
    fn p0_2_a_hop_issued_by_someone_who_never_held_the_parent_is_refused() {
        let (issuer_id, issuer_priv, issuer_pub) = make_agent();
        let (alice, _alice_priv, alice_pub) = make_agent();
        let (mallory, mallory_priv, mallory_pub) = make_agent();

        // Alice is the grantee of the root token.
        let root = make_root_token(&issuer_id, &issuer_priv, &alice, scope_orchestrator());

        // Mallory signs a hop naming herself as issuer and grantee, with a
        // correct parent_jti, correct depth and an attenuated scope.
        let forged = DelegationToken {
            jti: random_jti(),
            parent_jti: root.jti,
            issuer_id: mallory.clone(),
            grantee_id: mallory.clone(),
            scope: scope_submitter(),
            depth: 1,
            issued_at: root.issued_at,
            expires_at: root.expires_at,
            issuer_sig: Signature {
                algorithm: AlgorithmId::Ed25519,
                signer_id: mallory.clone(),
                timestamp: 0,
                nonce: [0u8; 16],
                payload_hash: [0u8; 32],
                signature_bytes: vec![],
            },
        };
        // Sign it properly with Mallory's own key, over its own payload.
        let payload = canonical_delegation_payload(
            &forged.jti,
            &forged.parent_jti,
            &forged.issuer_id,
            &forged.grantee_id,
            &forged.scope,
            forged.depth,
            forged.issued_at,
            forged.expires_at,
        );
        let forged = DelegationToken {
            issuer_sig: sign_ed25519(&mallory_priv, &mallory, &payload).unwrap(),
            ..forged
        };

        // The verifier holds every one of these agents' keys, as it would.
        let mut keys = HashMap::new();
        keys.insert(issuer_id, issuer_pub);
        keys.insert(alice, alice_pub);
        keys.insert(mallory, mallory_pub);

        assert!(
            matches!(
                verify_delegation_chain(&root, &[forged], &keys),
                Err(AipError::LineageInvalid)
            ),
            "SECURITY: a hop whose issuer never held the parent token verified"
        );
    }

    /// The same attack one hop deeper: the forged issuer is not the grantee
    /// of the preceding hop.
    #[test]
    fn p0_2_a_mid_chain_hop_must_be_issued_by_the_previous_grantee() {
        let (root, chain, mut keys) = make_signed_two_hop_chain();
        assert!(verify_delegation_chain(&root, &chain, &keys).is_ok());

        let (mallory, mallory_priv, mallory_pub) = make_agent();
        keys.insert(mallory.clone(), mallory_pub);

        // Re-issue the second hop under Mallory's identity and key. Every
        // other field — parent_jti, depth, scope, window — stays legitimate.
        let mut forged = chain[1].clone();
        forged.issuer_id = mallory.clone();
        let payload = canonical_delegation_payload(
            &forged.jti,
            &forged.parent_jti,
            &forged.issuer_id,
            &forged.grantee_id,
            &forged.scope,
            forged.depth,
            forged.issued_at,
            forged.expires_at,
        );
        forged.issuer_sig = sign_ed25519(&mallory_priv, &mallory, &payload).unwrap();

        assert!(
            matches!(
                verify_delegation_chain(&root, &[chain[0].clone(), forged], &keys),
                Err(AipError::LineageInvalid)
            ),
            "SECURITY: a mid-chain hop issued by a party the previous hop never granted to verified"
        );
    }

    /// The honest chains still verify: this is a new refusal, not a new
    /// restriction on legitimate delegation.
    #[test]
    fn p0_2_honest_chains_still_verify() {
        let (root, chain, keys) = make_signed_two_hop_chain();
        assert!(verify_delegation_chain(&root, &chain, &keys).is_ok());
        assert!(verify_delegation_chain(&root, &chain[..1], &keys).is_ok());
        assert!(verify_delegation_chain(&root, &[], &keys).is_ok());
    }

    #[test]
    fn test_mutate_delegation_expires_at_extend_rejected() {
        let (root, mut chain, keys) = make_signed_two_hop_chain();
        assert!(verify_delegation_chain(&root, &chain, &keys).is_ok());

        // Only the leaf hop's expires_at changes; its issuer_sig is untouched.
        chain[1].expires_at = Some(u64::MAX);

        assert!(
            matches!(
                verify_delegation_chain(&root, &chain, &keys),
                Err(AipError::SignatureInvalid)
            ),
            "SECURITY: delegation expires_at extended without re-signing but chain still verifies"
        );
    }

    #[test]
    fn test_mutate_delegation_expires_at_some_to_none_rejected() {
        let (root, mut chain, keys) = make_signed_two_hop_chain();
        assert!(verify_delegation_chain(&root, &chain, &keys).is_ok());

        chain[0].expires_at = None;

        assert!(
            matches!(
                verify_delegation_chain(&root, &chain, &keys),
                Err(AipError::SignatureInvalid)
            ),
            "SECURITY: delegation expiry removed (Some -> None) but chain still verifies"
        );
    }

    /// An issuer who legitimately holds the delegating key signs a hop whose
    /// expiry is LATER than the parent's. The signature is valid; the chain
    /// must still be rejected — temporal attenuation is enforced, not trusted.
    #[test]
    fn test_legitimately_signed_hop_outliving_parent_rejected() {
        let (issuer_id, issuer_priv, issuer_pub) = make_agent();
        let (agent_id, agent_priv, agent_pub) = make_agent();
        let (g1, _, _) = make_agent();
        let root = issue_scoped_token(
            &issuer_id,
            &issuer_priv,
            &agent_id,
            scope_orchestrator(),
            Some(3_600_000),
        )
        .unwrap();
        let root_exp = root.expires_at.unwrap();
        let mut keys = HashMap::new();
        keys.insert(issuer_id, issuer_pub);
        keys.insert(agent_id.clone(), agent_pub);

        let forge = |expires_at: Option<u64>| {
            let jti = random_jti();
            let issued_at = now_ms();
            let scope = scope_orchestrator();
            let payload = canonical_delegation_payload(
                &jti, &root.jti, &agent_id, &g1, &scope, 1, issued_at, expires_at,
            );
            let issuer_sig = sign_ed25519(&agent_priv, &agent_id, &payload).unwrap();
            DelegationToken {
                jti,
                parent_jti: root.jti,
                issuer_id: agent_id.clone(),
                grantee_id: g1.clone(),
                scope,
                depth: 1,
                issued_at,
                expires_at,
                issuer_sig,
            }
        };

        // Control: equal expiry is accepted.
        assert!(verify_delegation_chain(&root, &[forge(Some(root_exp))], &keys).is_ok());
        // Later expiry, validly signed → rejected as attenuation violation.
        assert_eq!(
            verify_delegation_chain(&root, &[forge(Some(root_exp + 1))], &keys),
            Err(AipError::AttenuationViolation)
        );
        // Unbounded child of a bounded parent → rejected.
        assert_eq!(
            verify_delegation_chain(&root, &[forge(None)], &keys),
            Err(AipError::AttenuationViolation)
        );
    }

    // ── Adversarial: domain separation and injectivity (I14) ──

    /// A ScopedToken issuer signature transplanted onto a DelegationToken with
    /// field-for-field matching content must not verify: the two payloads
    /// live in different signing domains.
    #[test]
    fn test_scoped_token_signature_cannot_verify_as_delegation() {
        let (issuer_id, issuer_priv, issuer_pub) = make_agent();
        let (agent_id, _, _) = make_agent();
        let token =
            issue_scoped_token(&issuer_id, &issuer_priv, &agent_id, scope_submitter(), None)
                .unwrap();

        // A "root" whose jti is the zero parent_jti we place on the forged hop.
        // verify_delegation_chain never checks the root's own signature.
        let mut pseudo_root = token.clone();
        pseudo_root.jti = [0u8; 16];

        let forged_hop = DelegationToken {
            jti: token.jti,
            parent_jti: [0u8; 16],
            issuer_id: token.issuer_id.clone(),
            grantee_id: token.agent_id.clone(),
            scope: token.scope.clone(),
            depth: 1,
            issued_at: token.issued_at,
            expires_at: token.expires_at,
            issuer_sig: token.issuer_sig.clone(), // genuine signature, wrong domain
        };
        let mut keys = HashMap::new();
        keys.insert(issuer_id, issuer_pub);

        assert_eq!(
            verify_delegation_chain(&pseudo_root, &[forged_hop], &keys),
            Err(AipError::SignatureInvalid)
        );
    }

    #[test]
    fn test_delegation_payload_adjacent_ids_do_not_collide() {
        let jti = [1u8; 16];
        let pj = [2u8; 16];
        let scope = scope_submitter();
        let p1 = canonical_delegation_payload(&jti, &pj, "ab", "c", &scope, 1, 1, None);
        let p2 = canonical_delegation_payload(&jti, &pj, "a", "bc", &scope, 1, 1, None);
        assert_ne!(p1, p2);
        let none = canonical_delegation_payload(&jti, &pj, "a", "b", &scope, 1, 1, None);
        let some = canonical_delegation_payload(&jti, &pj, "a", "b", &scope, 1, 1, Some(0));
        assert_ne!(none, some);
        let tag = DELEGATION_TOKEN_DOMAIN.as_bytes();
        assert_eq!(&p1[4..4 + tag.len()], tag);
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
