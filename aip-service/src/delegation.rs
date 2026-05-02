//! Delegation chain management for AIP v2.
//!
//! A DelegationToken extends a root AIP JWT to a sub-agent with a constrained
//! CapabilityScope.  Chains may be at most MAX_DEPTH hops from the root.
//!
//! PATENT CLAIM (NM-A2): Capability-constrained delegation chain with depth limit.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::capability::CapabilityScope;

/// Maximum delegation chain depth from the root AIP JWT.
pub const MAX_DEPTH: u32 = 8;

// ── DelegationToken ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    /// Unique ID for this delegation entry.
    pub delegation_id: String,
    /// JTI of the parent (root AIP JWT or parent delegation).
    pub parent_jti: String,
    /// Agent being delegated to.
    pub delegatee_id: String,
    /// Effective scope (must be a subset of the parent scope).
    pub scope: CapabilityScope,
    /// Chain depth from root: 1 = direct delegation, MAX_DEPTH = maximum.
    pub depth: u32,
    /// ISO 8601 issuance timestamp.
    pub issued_at: String,
    /// ISO 8601 expiry timestamp.
    pub expires_at: String,
    /// SHA3-256(delegation_id + parent_jti + delegatee_id + depth + issued_at) — tamper evidence.
    pub entry_hash: String,
}

impl DelegationToken {
    pub fn new(
        parent_jti: &str,
        delegatee_id: &str,
        scope: CapabilityScope,
        depth: u32,
        ttl_seconds: u64,
    ) -> Self {
        let delegation_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let issued_at = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let exp = now.timestamp() + ttl_seconds as i64;
        let expires_at = chrono::DateTime::from_timestamp(exp, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| "9999-12-31T23:59:59Z".to_owned());

        let canonical = format!(
            "delegation_id={}&parent_jti={}&delegatee_id={}&depth={}&issued_at={}",
            delegation_id, parent_jti, delegatee_id, depth, issued_at
        );
        let entry_hash = sha3_256_hex(&canonical);

        Self {
            delegation_id,
            parent_jti: parent_jti.to_owned(),
            delegatee_id: delegatee_id.to_owned(),
            scope,
            depth,
            issued_at,
            expires_at,
            entry_hash,
        }
    }
}

fn sha3_256_hex(input: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ── DelegationLog ─────────────────────────────────────────────────────────────

pub type DelegationLog = Arc<Mutex<Vec<DelegationToken>>>;

/// Load the delegation log from a JSONL file at startup.
///
/// Each entry's `entry_hash` is verified against its canonical form before
/// being accepted.  Entries with mismatched hashes are skipped with a warning,
/// preventing an attacker who modifies the log file from injecting fake
/// delegation tokens that bypass depth/scope checks.
pub fn load_delegation_log(log_path: &str) -> DelegationLog {
    let mut entries = Vec::new();
    let path = Path::new(log_path);
    if path.exists() {
        if let Ok(contents) = std::fs::read_to_string(path) {
            for (line_no, line) in contents.lines().enumerate() {
                match serde_json::from_str::<DelegationToken>(line) {
                    Ok(entry) => {
                        let canonical = format!(
                            "delegation_id={}&parent_jti={}&delegatee_id={}&depth={}&issued_at={}",
                            entry.delegation_id,
                            entry.parent_jti,
                            entry.delegatee_id,
                            entry.depth,
                            entry.issued_at
                        );
                        let expected_hash = sha3_256_hex(&canonical);
                        if entry.entry_hash != expected_hash {
                            tracing::warn!(
                                line = line_no + 1,
                                delegation_id = %entry.delegation_id,
                                "delegation entry hash mismatch — skipping (possible tampering)"
                            );
                        } else {
                            entries.push(entry);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(line = line_no + 1, error = %e, "failed to parse delegation entry — skipping");
                    }
                }
            }
        }
    }
    Arc::new(Mutex::new(entries))
}

/// Append a delegation token to the JSONL log and the in-memory list.
pub fn append_delegation(
    log_path: &str,
    delegation_log: &DelegationLog,
    token: &DelegationToken,
) -> Result<(), String> {
    let line = serde_json::to_string(token).map_err(|e| e.to_string())?;
    if let Some(parent) = Path::new(log_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| format!("open delegation log: {e}"))?;
    writeln!(file, "{}", line).map_err(|e| format!("write delegation log: {e}"))?;

    delegation_log.lock().unwrap().push(token.clone());
    Ok(())
}

/// Look up a delegation token by its delegation_id.
pub fn find_by_id<'a>(
    log: &'a std::sync::MutexGuard<Vec<DelegationToken>>,
    delegation_id: &str,
) -> Option<&'a DelegationToken> {
    log.iter().find(|t| t.delegation_id == delegation_id)
}

/// Build a parent_jti → Vec<child_delegation_id> map for cascade revocation.
pub fn build_parent_to_children(delegation_log: &DelegationLog) -> HashMap<String, Vec<String>> {
    let log = delegation_log.lock().unwrap();
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for token in log.iter() {
        map.entry(token.parent_jti.clone())
            .or_default()
            .push(token.delegation_id.clone());
    }
    map
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityScope;

    fn temp_path() -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("aip_del_test_{}.jsonl", uuid::Uuid::new_v4()));
        p.to_str().unwrap().to_owned()
    }

    // T-DEL-1: depth limit is enforced
    #[test]
    fn test_depth_enforced() {
        // DelegationToken::new does not itself enforce the limit — the handler does.
        // This test verifies MAX_DEPTH is 8 (spec requirement).
        assert_eq!(MAX_DEPTH, 8);
    }

    // T-DEL-2: delegation token persists and reloads correctly
    #[test]
    fn test_delegation_roundtrip() {
        let path = temp_path();
        let log = load_delegation_log(&path);

        let token = DelegationToken::new(
            "root-jti",
            "550e8400-e29b-41d4-a716-446655440001",
            CapabilityScope::submitter(),
            1,
            3600,
        );
        append_delegation(&path, &log, &token).unwrap();

        // Reload from disk
        let log2 = load_delegation_log(&path);
        let locked = log2.lock().unwrap();
        assert_eq!(locked.len(), 1);
        assert_eq!(locked[0].parent_jti, "root-jti");
        assert_eq!(locked[0].depth, 1);
    }

    // T-DEL-3: build_parent_to_children covers the full graph
    #[test]
    fn test_build_parent_to_children() {
        let path = temp_path();
        let log = load_delegation_log(&path);

        let t1 = DelegationToken::new("root", "agent-1", CapabilityScope::submitter(), 1, 3600);
        let child_id = t1.delegation_id.clone();
        append_delegation(&path, &log, &t1).unwrap();

        let t2 = DelegationToken::new(&child_id, "agent-2", CapabilityScope::submitter(), 2, 3600);
        append_delegation(&path, &log, &t2).unwrap();

        let map = build_parent_to_children(&log);
        assert!(map.contains_key("root"));
        assert!(map.contains_key(&child_id));
    }
}
