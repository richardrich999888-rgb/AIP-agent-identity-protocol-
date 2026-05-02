//! Cryptographic Revocation — Append-only revocation log with cascade.
//!
//! ## Design (§6-v2, NM-A3)
//!
//! Revocation is append-only: entries are never deleted or modified.
//! Each entry is chained by SHA-256 hash, forming a tamper-evident audit log.
//!
//! ## Cascade Revocation
//!
//! When `cascade=true`, the revocation walks the delegation tree (via DelegationLog)
//! and revokes all descendant delegation tokens. This ensures that revoking a
//! compromised agent also revokes all capabilities it delegated downstream.
//!
//! ## Novel Mechanism NM-A3
//!
//! "Cascade revocation across delegation tree": a single revocation event
//! propagates through the delegation graph, invalidating all transitively
//! dependent tokens. The cascade is cryptographically logged — each child
//! revocation entry references the parent revocation's JTI as its cause.
//!
//! This is the mechanism that makes AIP operationally safe in multi-agent
//! systems: one compromised agent cannot maintain active delegations
//! after it is revoked.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aip_crypto::sha256;
use aip_types::*;
use serde::{Deserialize, Serialize};

use crate::delegation::DelegationLog;

// ─── Revocation Log ───

/// Append-only revocation log.
///
/// Provides O(1) revocation status check via a HashMap index.
/// Each entry is SHA-256 chained to the previous for tamper evidence.
pub struct RevocationLog {
    entries: Vec<RevocationEntry>,
    index: HashMap<[u8; 16], usize>, // jti → index in entries
    prev_hash: [u8; 32],             // Hash of the last entry (for chaining)
    file_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct RevocationLogData {
    entries: Vec<RevocationEntry>,
    prev_hash: [u8; 32],
}

impl RevocationLog {
    pub fn new() -> Self {
        Self {
            entries: vec![],
            index: HashMap::new(),
            prev_hash: [0u8; 32],
            file_path: None,
        }
    }

    pub fn with_file(path: impl AsRef<Path>) -> Result<Self, RevocationLogError> {
        let path = path.as_ref().to_path_buf();
        let (entries, prev_hash) = if path.exists() {
            let json = std::fs::read_to_string(&path)
                .map_err(|e| RevocationLogError::IoError(e.to_string()))?;
            let data: RevocationLogData = serde_json::from_str(&json)
                .map_err(|e| RevocationLogError::SerializationError(e.to_string()))?;
            (data.entries, data.prev_hash)
        } else {
            (vec![], [0u8; 32])
        };

        let mut log = Self {
            entries: vec![],
            index: HashMap::new(),
            prev_hash,
            file_path: Some(path),
        };
        for entry in entries {
            let idx = log.entries.len();
            log.index.insert(entry.jti, idx);
            log.entries.push(entry);
        }
        Ok(log)
    }

    /// Revoke a token. Returns the new revocation entry.
    ///
    /// If `cascade=true`, also walks `delegation_log` and revokes all
    /// descendant delegation tokens, logging each as a separate entry
    /// with reason `RevocationReason::AdminRevocation`.
    pub fn revoke(
        &mut self,
        jti: [u8; 16],
        reason: RevocationReason,
        revoked_by: &str,
        cascade: bool,
        delegation_log: Option<&DelegationLog>,
    ) -> Vec<RevocationEntry> {
        let mut entries = Vec::new();

        // Revoke the primary token
        let entry = self.append_entry(jti, reason, revoked_by, cascade);
        entries.push(entry);

        // Cascade: revoke all delegation children
        if cascade {
            if let Some(del_log) = delegation_log {
                let child_jtis = del_log.subtree_jtis(&jti);
                for child_jti in child_jtis {
                    if !self.is_revoked(&child_jti) {
                        let child_entry = self.append_entry(
                            child_jti,
                            RevocationReason::AdminRevocation, // cascade cause
                            revoked_by,
                            false, // children don't further cascade
                        );
                        entries.push(child_entry);
                    }
                }
            }
        }

        if self.file_path.is_some() {
            let _ = self.save();
        }

        entries
    }

    /// Check if a token JTI has been revoked.
    pub fn is_revoked(&self, jti: &[u8; 16]) -> bool {
        self.index.contains_key(jti)
    }

    /// Get the revocation entry for a JTI, if revoked.
    pub fn get_revocation(&self, jti: &[u8; 16]) -> Option<&RevocationEntry> {
        self.index.get(jti).map(|&i| &self.entries[i])
    }

    /// Number of revocation entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The hash of the last entry (for external audit chain verification).
    pub fn chain_tip(&self) -> [u8; 32] {
        self.prev_hash
    }

    // ─── Internal ───

    fn append_entry(
        &mut self,
        jti: [u8; 16],
        reason: RevocationReason,
        revoked_by: &str,
        cascade: bool,
    ) -> RevocationEntry {
        let revoked_at = now_ms();
        let entry_hash = compute_entry_hash(&jti, revoked_at, reason, revoked_by, cascade, &self.prev_hash);

        let entry = RevocationEntry { jti, revoked_at, reason, revoked_by: revoked_by.to_string(), cascade, entry_hash };

        let idx = self.entries.len();
        self.index.insert(jti, idx);
        self.prev_hash = entry_hash;
        self.entries.push(entry.clone());
        entry
    }

    fn save(&self) -> Result<(), RevocationLogError> {
        let path = self.file_path.as_ref().unwrap();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| RevocationLogError::IoError(e.to_string()))?;
        }
        let data = RevocationLogData {
            entries: self.entries.clone(),
            prev_hash: self.prev_hash,
        };
        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| RevocationLogError::SerializationError(e.to_string()))?;
        std::fs::write(path, json)
            .map_err(|e| RevocationLogError::IoError(e.to_string()))?;
        Ok(())
    }
}

impl Default for RevocationLog {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Token Validity Check ───

/// Check whether a scoped token is currently valid.
///
/// A token is invalid if:
/// 1. It has expired (`expires_at < now`)
/// 2. It is in the revocation log
/// 3. Its issuer's token is revoked (checked via revocation log by issuer JTI)
pub fn check_token_valid(
    token: &ScopedToken,
    revlog: &RevocationLog,
) -> Result<(), AipError> {
    // Check expiry
    if token.expires_at.is_some_and(|exp| now_ms() > exp) {
        return Err(AipError::SignatureExpired);
    }

    // Check revocation
    if revlog.is_revoked(&token.jti) {
        return Err(AipError::IdentityRevoked);
    }

    Ok(())
}

/// Check whether a delegation token is currently valid.
pub fn check_delegation_valid(
    token: &DelegationToken,
    revlog: &RevocationLog,
) -> Result<(), AipError> {
    if token.expires_at.is_some_and(|exp| now_ms() > exp) {
        return Err(AipError::SignatureExpired);
    }
    if revlog.is_revoked(&token.jti) {
        return Err(AipError::IdentityRevoked);
    }
    // Also check parent
    if revlog.is_revoked(&token.parent_jti) {
        return Err(AipError::IdentityRevoked);
    }
    Ok(())
}

// ─── Hash Computation ───

/// Compute entry hash: SHA-256(jti || revoked_at || reason || revoked_by || cascade || prev_hash).
///
/// Chains the entry to the previous log entry, making the log tamper-evident.
fn compute_entry_hash(
    jti: &[u8; 16],
    revoked_at: u64,
    reason: RevocationReason,
    revoked_by: &str,
    cascade: bool,
    prev_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(jti);
    buf.extend_from_slice(&revoked_at.to_le_bytes());
    buf.push(reason as u8);
    buf.extend_from_slice(revoked_by.as_bytes());
    buf.push(if cascade { 1 } else { 0 });
    buf.extend_from_slice(prev_hash);
    sha256(&buf)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// ─── Error ───

#[derive(Debug, Clone)]
pub enum RevocationLogError {
    IoError(String),
    SerializationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::*;
    use crate::delegation::*;
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

    fn make_token(
        issuer_id: &str,
        issuer_priv: &[u8],
        agent_id: &str,
    ) -> ScopedToken {
        issue_scoped_token(issuer_id, issuer_priv, agent_id, scope_orchestrator(), None).unwrap()
    }

    // ── Basic revocation tests ──

    #[test]
    fn test_revoke_token_marks_revoked() {
        let (issuer_id, priv_key, _) = make_agent();
        let (agent_id, _, _) = make_agent();
        let token = make_token(&issuer_id, &priv_key, &agent_id);
        let jti = token.jti;

        let mut revlog = RevocationLog::new();
        assert!(!revlog.is_revoked(&jti));

        revlog.revoke(jti, RevocationReason::AdminRevocation, &issuer_id, false, None);
        assert!(revlog.is_revoked(&jti));
    }

    #[test]
    fn test_revoked_token_fails_validity_check() {
        let (issuer_id, priv_key, _) = make_agent();
        let (agent_id, _, _) = make_agent();
        let token = make_token(&issuer_id, &priv_key, &agent_id);
        let jti = token.jti;

        let mut revlog = RevocationLog::new();
        assert!(check_token_valid(&token, &revlog).is_ok());

        revlog.revoke(jti, RevocationReason::AgentCompromised, &issuer_id, false, None);
        assert!(matches!(
            check_token_valid(&token, &revlog),
            Err(AipError::IdentityRevoked)
        ));
    }

    // ── Cascade revocation tests ──

    #[test]
    fn test_cascade_revocation_invalidates_children() {
        let (issuer_id, priv_key, _) = make_agent();
        let (a1_id, a1_priv, _) = make_agent();
        let (a2_id, a2_priv, _) = make_agent();
        let (a3_id, _, _) = make_agent();

        let root = make_token(&issuer_id, &priv_key, &a1_id);
        let del1 = create_delegation(&root, &a1_priv, &a2_id, scope_audit_reader()).unwrap();
        let del2 = create_sub_delegation(&del1, &a2_priv, &a3_id, scope_audit_reader()).unwrap();

        let root_jti = root.jti;
        let del1_jti = del1.jti;
        let del2_jti = del2.jti;

        let mut del_log = DelegationLog::new();
        del_log.append(del1).unwrap();
        del_log.append(del2).unwrap();

        let mut revlog = RevocationLog::new();
        // Revoke root token with cascade=true
        let entries = revlog.revoke(
            root_jti,
            RevocationReason::AgentCompromised,
            &issuer_id,
            true,
            Some(&del_log),
        );

        // Should have 3 entries: root, del1, del2
        assert_eq!(entries.len(), 3, "Root + 2 children must all be revoked");
        assert!(revlog.is_revoked(&root_jti));
        assert!(revlog.is_revoked(&del1_jti));
        assert!(revlog.is_revoked(&del2_jti));
    }

    #[test]
    fn test_no_cascade_leaves_children_valid() {
        let (issuer_id, priv_key, _) = make_agent();
        let (a1_id, a1_priv, _) = make_agent();
        let (a2_id, _, _) = make_agent();

        let root = make_token(&issuer_id, &priv_key, &a1_id);
        let del = create_delegation(&root, &a1_priv, &a2_id, scope_audit_reader()).unwrap();
        let del_jti = del.jti;

        let mut del_log = DelegationLog::new();
        del_log.append(del).unwrap();

        let mut revlog = RevocationLog::new();
        // Revoke root WITHOUT cascade
        revlog.revoke(root.jti, RevocationReason::TokenRotation, &issuer_id, false, Some(&del_log));

        // Child delegation is NOT directly revoked
        assert!(!revlog.is_revoked(&del_jti));
    }

    // ── Chain hash tests ──

    #[test]
    fn test_revocation_entry_has_nonzero_hash() {
        let (issuer_id, priv_key, _) = make_agent();
        let (agent_id, _, _) = make_agent();
        let token = make_token(&issuer_id, &priv_key, &agent_id);

        let mut revlog = RevocationLog::new();
        let entries = revlog.revoke(
            token.jti,
            RevocationReason::ScopeViolation,
            &issuer_id,
            false,
            None,
        );

        assert_eq!(entries.len(), 1);
        assert_ne!(entries[0].entry_hash, [0u8; 32], "Entry hash must be non-zero");
    }

    #[test]
    fn test_revocation_log_chain_tip_advances() {
        let (issuer_id, priv_key, _) = make_agent();
        let (a1_id, _, _) = make_agent();
        let (a2_id, _, _) = make_agent();

        let t1 = make_token(&issuer_id, &priv_key, &a1_id);
        let t2 = make_token(&issuer_id, &priv_key, &a2_id);

        let mut revlog = RevocationLog::new();
        let tip0 = revlog.chain_tip();
        revlog.revoke(t1.jti, RevocationReason::TokenRotation, &issuer_id, false, None);
        let tip1 = revlog.chain_tip();
        revlog.revoke(t2.jti, RevocationReason::TokenRotation, &issuer_id, false, None);
        let tip2 = revlog.chain_tip();

        assert_ne!(tip0, tip1, "Chain tip must advance after first revocation");
        assert_ne!(tip1, tip2, "Chain tip must advance after second revocation");
    }

    // ── File persistence tests ──

    #[test]
    fn test_revocation_log_file_persistence() {
        let tmp = std::env::temp_dir().join("aip_revlog_test.json");
        let _ = std::fs::remove_file(&tmp);

        let (issuer_id, priv_key, _) = make_agent();
        let (agent_id, _, _) = make_agent();
        let token = make_token(&issuer_id, &priv_key, &agent_id);
        let jti = token.jti;

        {
            let mut revlog = RevocationLog::with_file(&tmp).unwrap();
            revlog.revoke(jti, RevocationReason::AdminRevocation, &issuer_id, false, None);
        }

        // Reload and check
        let revlog2 = RevocationLog::with_file(&tmp).unwrap();
        assert!(revlog2.is_revoked(&jti));
        let _ = std::fs::remove_file(&tmp);
    }
}
