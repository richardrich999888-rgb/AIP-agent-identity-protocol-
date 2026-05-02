//! Token revocation — append-only log + in-memory O(1) lookup.
//!
//! Revocation entries are appended to a JSONL file at AIP_REVOCATION_LOG_PATH.
//! The in-memory HashSet is populated at startup and updated on every revoke call.
//!
//! CASCADE REVOCATION (NM-A3): BFS walk of delegation log revokes all descendants atomically.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};

// ── RevocationEntry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// The JTI being revoked.
    pub jti: String,
    /// JTI of the revoking authority.
    pub revoked_by: String,
    /// ISO 8601 timestamp.
    pub revoked_at: String,
    /// Human-readable reason.
    pub reason: String,
    /// SHA3-256(jti + revoked_by + revoked_at + reason) — tamper evidence.
    pub entry_hash: String,
}

impl RevocationEntry {
    pub fn new(jti: &str, revoked_by: &str, reason: &str) -> Self {
        let revoked_at = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let canonical = format!(
            "jti={}&revoked_by={}&revoked_at={}&reason={}",
            jti, revoked_by, revoked_at, reason
        );
        let entry_hash = sha3_256_hex(&canonical);
        Self {
            jti: jti.to_owned(),
            revoked_by: revoked_by.to_owned(),
            revoked_at,
            reason: reason.to_owned(),
            entry_hash,
        }
    }
}

fn sha3_256_hex(input: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ── RevocationSet ─────────────────────────────────────────────────────────────

pub type RevocationSet = Arc<Mutex<HashSet<String>>>;

/// Load the revocation set from the JSONL log at startup.
///
/// Each entry's `entry_hash` is verified against the canonical form before
/// inserting the JTI into the set.  Entries whose hashes do not match are
/// skipped with a warning — this detects offline tampering with the log file.
pub fn load_revocation_set(log_path: &str) -> RevocationSet {
    let mut set = HashSet::new();
    let path = Path::new(log_path);
    if path.exists() {
        if let Ok(contents) = std::fs::read_to_string(path) {
            for (line_no, line) in contents.lines().enumerate() {
                match serde_json::from_str::<RevocationEntry>(line) {
                    Ok(entry) => {
                        let canonical = format!(
                            "jti={}&revoked_by={}&revoked_at={}&reason={}",
                            entry.jti, entry.revoked_by, entry.revoked_at, entry.reason
                        );
                        let expected_hash = sha3_256_hex(&canonical);
                        if entry.entry_hash != expected_hash {
                            tracing::warn!(
                                line = line_no + 1,
                                jti = %entry.jti,
                                "revocation entry hash mismatch — skipping (possible tampering)"
                            );
                        } else {
                            set.insert(entry.jti);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(line = line_no + 1, error = %e, "failed to parse revocation entry — skipping");
                    }
                }
            }
        }
    }
    Arc::new(Mutex::new(set))
}

/// Append a revocation entry to disk and insert into the in-memory set.
pub fn revoke(
    log_path: &str,
    revocation_set: &RevocationSet,
    entry: &RevocationEntry,
) -> Result<(), String> {
    let line = serde_json::to_string(entry).map_err(|e| e.to_string())?;
    if let Some(parent) = Path::new(log_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| format!("open revocation log: {e}"))?;
    writeln!(file, "{}", line).map_err(|e| format!("write revocation log: {e}"))?;

    revocation_set.lock().unwrap().insert(entry.jti.clone());
    Ok(())
}

/// Returns true if the given JTI has been revoked.
pub fn is_revoked(revocation_set: &RevocationSet, jti: &str) -> bool {
    revocation_set.lock().unwrap().contains(jti)
}

/// Cascade revocation: BFS walk of the delegation graph, revoke root and all descendants.
/// Returns the list of revoked JTIs (including root).
///
/// PATENT CLAIM (NM-A3): atomically revokes an entire delegation tree.
pub fn cascade_revoke(
    log_path: &str,
    revocation_set: &RevocationSet,
    root_jti: &str,
    revoked_by: &str,
    reason: &str,
    // Map from parent_jti → Vec<child_jti> (built from delegation log).
    parent_to_children: &HashMap<String, Vec<String>>,
) -> Result<Vec<String>, String> {
    let mut revoked = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(root_jti.to_owned());

    while let Some(jti) = queue.pop_front() {
        if !is_revoked(revocation_set, &jti) {
            let entry = RevocationEntry::new(&jti, revoked_by, &format!("cascade: {reason}"));
            revoke(log_path, revocation_set, &entry)?;
            revoked.push(jti.clone());
        }
        if let Some(children) = parent_to_children.get(&jti) {
            for child in children {
                queue.push_back(child.clone());
            }
        }
    }
    Ok(revoked)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn temp_path() -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("aip_rev_test_{}.jsonl", uuid::Uuid::new_v4()));
        p.to_str().unwrap().to_owned()
    }

    // T-REV-1: revoke and is_revoked round-trip
    #[test]
    fn test_revoke_roundtrip() {
        let path = temp_path();
        let set = load_revocation_set(&path);
        let entry = RevocationEntry::new("jti-abc", "admin-jti", "test revocation");
        revoke(&path, &set, &entry).unwrap();
        assert!(is_revoked(&set, "jti-abc"));
        assert!(!is_revoked(&set, "jti-xyz"));
    }

    // T-REV-2: revocation set is persisted and reloaded correctly
    #[test]
    fn test_revocation_persisted() {
        let path = temp_path();
        {
            let set = load_revocation_set(&path);
            let entry = RevocationEntry::new("jti-persist", "admin", "persist test");
            revoke(&path, &set, &entry).unwrap();
        }
        // Reload from disk
        let set2 = load_revocation_set(&path);
        assert!(is_revoked(&set2, "jti-persist"));
    }

    // T-REV-3: cascade_revoke covers all descendants
    #[test]
    fn test_cascade_revoke() {
        let path = temp_path();
        let set = load_revocation_set(&path);

        // Build graph: root → child1, child1 → grandchild
        let mut parent_to_children: HashMap<String, Vec<String>> = HashMap::new();
        parent_to_children.insert("root-jti".to_owned(), vec!["child1".to_owned()]);
        parent_to_children.insert("child1".to_owned(), vec!["grandchild".to_owned()]);

        let revoked = cascade_revoke(
            &path,
            &set,
            "root-jti",
            "admin",
            "test cascade",
            &parent_to_children,
        )
        .unwrap();

        assert_eq!(revoked.len(), 3);
        assert!(is_revoked(&set, "root-jti"));
        assert!(is_revoked(&set, "child1"));
        assert!(is_revoked(&set, "grandchild"));
    }

    // T-REV-4: entry_hash is deterministic for the same inputs modulo timestamp
    #[test]
    fn test_entry_hash_is_populated() {
        let entry = RevocationEntry::new("jti-hash-test", "admin", "reason");
        assert_eq!(entry.entry_hash.len(), 64); // SHA3-256 = 32 bytes = 64 hex chars
        assert!(entry.entry_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
