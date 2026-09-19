//! Token revocation — append-only JSONL log + in-memory lookup, **scoped per
//! tenant**.
//!
//! A revocation is a fact about one tenant's authority. The set is keyed on
//! `(tenant_id, jti)`, so an administrator of tenant A revoking a JTI string
//! has no effect on tenant B's token that happens to carry the same string,
//! and tenant B cannot learn of A's revocation through any query. The tenant
//! never comes from a request body: the revoke handler takes it from the
//! administrator's API key, the JWT verify path from the token's own `tid`
//! claim, and the evidence verify path from the caller's key.
//!
//! Two JTI namespaces share this log:
//! - identity JWTs use a UUID `jti` (as issued by [`crate::tokens::issue`]);
//! - evidence-layer tokens (`aip-core` scoped and delegation tokens) use a
//!   16-byte JTI, written here as 32 lowercase hex characters.
//!
//! [`normalize_jti`] admits exactly those two forms and canonicalises them, so
//! a revocation written once matches however the JTI is later spelled.
//!
//! Pre-tenancy entries (no `tenant_id` on the line) load under
//! [`LEGACY_TENANT`] with their original hash form, so an existing log keeps
//! verifying and keeps applying to the tokens it applied to before.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// The tenant assigned to entries and tokens that predate tenancy. Shared
/// with the evidence store so a "legacy" token and a "legacy" packet mean the
/// same population.
pub use crate::store::LEGACY_TENANT;

/// Upper bound on the free-text fields, so a revocation cannot be used to
/// write an unbounded line into the log.
pub const MAX_TEXT_FIELD_LEN: usize = 1024;

// ── JTI normalisation ─────────────────────────────────────────────────────────

/// Canonicalise a JTI to its 16-byte form written as 32 lowercase hex
/// characters.
///
/// Accepts a UUID in any spelling (hyphenated, simple, any case — the form
/// [`crate::tokens::issue`] stamps into a JWT) or 32 hex characters (an
/// `aip-core` evidence JTI). Both are 16 random bytes, so one canonical
/// spelling serves both namespaces and a revocation written once matches
/// however the JTI is later spelled. Anything else is refused: a revocation
/// for a string that can never appear on a token is a wasted log line at
/// best and a typo that silently fails to revoke at worst.
pub fn normalize_jti(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    match uuid::Uuid::parse_str(trimmed) {
        Ok(u) => Ok(u.simple().to_string()),
        Err(_) => Err("jti must be a UUID or a 16-byte JTI as 32 hex characters".to_owned()),
    }
}

/// Decode a canonical JTI into the 16-byte form the evidence verifier uses.
/// `None` only for a string that is not canonical, which the set never holds.
fn evidence_jti_bytes(jti: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(jti).ok()?;
    <[u8; 16]>::try_from(bytes.as_slice()).ok()
}

// ── RevocationEntry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// The tenant whose authority this revocation is about. `None` only on
    /// lines written before tenancy existed; such lines belong to
    /// [`LEGACY_TENANT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// The JTI being revoked, canonical form (see [`normalize_jti`]).
    pub jti: String,
    /// Who revoked it (an operator identifier; free text, bounded).
    pub revoked_by: String,
    /// ISO 8601 timestamp.
    pub revoked_at: String,
    /// Human-readable reason.
    pub reason: String,
    /// Tamper evidence over every other field. Tenant-scoped entries use a
    /// length-prefixed encoding so no field boundary is ambiguous; legacy
    /// entries keep the `k=v&` form they were written with.
    pub entry_hash: String,
}

impl RevocationEntry {
    /// A new, tenant-scoped entry stamped now. `jti` must already be
    /// canonical (the handler normalises before constructing).
    pub fn new(tenant_id: &str, jti: &str, revoked_by: &str, reason: &str) -> Self {
        let revoked_at = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut entry = Self {
            tenant_id: Some(tenant_id.to_owned()),
            jti: jti.to_owned(),
            revoked_by: revoked_by.to_owned(),
            revoked_at,
            reason: reason.to_owned(),
            entry_hash: String::new(),
        };
        entry.entry_hash = entry.expected_hash();
        entry
    }

    /// The tenant this entry applies to.
    pub fn tenant(&self) -> &str {
        self.tenant_id.as_deref().unwrap_or(LEGACY_TENANT)
    }

    /// Recompute the hash the entry must carry.
    fn expected_hash(&self) -> String {
        match &self.tenant_id {
            Some(tenant) => {
                // v2: domain tag, then every field length-prefixed (u32 BE).
                let mut h = Sha3_256::new();
                h.update(b"AIP/RevocationEntry/v2");
                for field in [
                    tenant,
                    &self.jti,
                    &self.revoked_by,
                    &self.revoked_at,
                    &self.reason,
                ] {
                    h.update((field.len() as u32).to_be_bytes());
                    h.update(field.as_bytes());
                }
                hex::encode(h.finalize())
            }
            None => {
                // Legacy form, kept verbatim so old lines still verify.
                let canonical = format!(
                    "jti={}&revoked_by={}&revoked_at={}&reason={}",
                    self.jti, self.revoked_by, self.revoked_at, self.reason
                );
                let mut h = Sha3_256::new();
                h.update(canonical.as_bytes());
                hex::encode(h.finalize())
            }
        }
    }

    /// True when the carried hash matches the fields.
    pub fn hash_matches(&self) -> bool {
        self.entry_hash == self.expected_hash()
    }
}

// ── RevocationSet ─────────────────────────────────────────────────────────────

/// One revoked JTI within one tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RevokedKey {
    pub tenant_id: String,
    pub jti: String,
}

pub type RevocationSet = Arc<Mutex<HashSet<RevokedKey>>>;

/// Load the revocation set from the JSONL log at startup.
///
/// Each entry's `entry_hash` is verified before the JTI is admitted. Entries
/// whose hashes do not match are skipped with a warning — this detects
/// offline tampering with the log file. Legacy entries (no tenant) load under
/// [`LEGACY_TENANT`].
pub fn load_revocation_set(log_path: &str) -> RevocationSet {
    let mut set = HashSet::new();
    let path = Path::new(log_path);
    if path.exists() {
        if let Ok(contents) = std::fs::read_to_string(path) {
            for (line_no, line) in contents.lines().enumerate() {
                match serde_json::from_str::<RevocationEntry>(line) {
                    Ok(entry) => {
                        if !entry.hash_matches() {
                            tracing::warn!(
                                line = line_no + 1,
                                jti = %entry.jti,
                                "revocation entry hash mismatch — skipping (possible tampering)"
                            );
                            continue;
                        }
                        // Legacy lines carry the JTI as the JWT spelled it
                        // (hyphenated); canonicalise so lookups match.
                        let tenant_id = entry.tenant().to_owned();
                        let jti = normalize_jti(&entry.jti).unwrap_or(entry.jti);
                        set.insert(RevokedKey { tenant_id, jti });
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

    revocation_set.lock().unwrap().insert(RevokedKey {
        tenant_id: entry.tenant().to_owned(),
        jti: normalize_jti(&entry.jti).unwrap_or_else(|_| entry.jti.clone()),
    });
    Ok(())
}

/// Whether `jti` is revoked **within `tenant_id`**. `jti` is normalised
/// first; an unnormalisable string is not revoked (it can never be a token).
pub fn is_revoked(revocation_set: &RevocationSet, tenant_id: &str, jti: &str) -> bool {
    let Ok(jti) = normalize_jti(jti) else {
        return false;
    };
    revocation_set.lock().unwrap().contains(&RevokedKey {
        tenant_id: tenant_id.to_owned(),
        jti,
    })
}

/// Every revoked JTI within `tenant_id` in the 16-byte form the evidence
/// verifier uses, for merging into an evidence verification context. Identity
/// JWT ids are included too: they are 16 random bytes that never coincide with
/// an `aip-core` chain JTI, so their presence is harmless and the export needs
/// no knowledge of which namespace a line came from.
pub fn evidence_jtis_for_tenant(
    revocation_set: &RevocationSet,
    tenant_id: &str,
) -> HashSet<[u8; 16]> {
    revocation_set
        .lock()
        .unwrap()
        .iter()
        .filter(|k| k.tenant_id == tenant_id)
        .filter_map(|k| evidence_jti_bytes(&k.jti))
        .collect()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const JWT_JTI: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const JWT_JTI_CANONICAL: &str = "0f8fad5bd9cb469fa16570867728950e";
    const EVIDENCE_JTI: &str = "00112233445566778899aabbccddeeff";

    fn temp_path() -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("aip_rev_test_{}.jsonl", uuid::Uuid::new_v4()));
        p.to_str().unwrap().to_owned()
    }

    #[test]
    fn revoke_and_lookup_are_tenant_scoped() {
        let path = temp_path();
        let set = load_revocation_set(&path);
        let entry = RevocationEntry::new("bank-a", JWT_JTI_CANONICAL, "ops", "key rotation");
        revoke(&path, &set, &entry).unwrap();
        assert!(is_revoked(&set, "bank-a", JWT_JTI));
        assert!(
            !is_revoked(&set, "bank-b", JWT_JTI),
            "tenant B must not observe tenant A's revocation"
        );
        assert!(!is_revoked(&set, "bank-a", EVIDENCE_JTI));
    }

    #[test]
    fn lookup_normalises_case_and_form() {
        let path = temp_path();
        let set = load_revocation_set(&path);
        revoke(
            &path,
            &set,
            &RevocationEntry::new("t", EVIDENCE_JTI, "ops", "r"),
        )
        .unwrap();
        assert!(is_revoked(&set, "t", &EVIDENCE_JTI.to_ascii_uppercase()));
        assert!(is_revoked(&set, "t", &format!("  {EVIDENCE_JTI} ")));
        assert!(!is_revoked(&set, "t", "not-a-jti"));
    }

    #[test]
    fn persisted_entries_reload_under_their_tenant() {
        let path = temp_path();
        {
            let set = load_revocation_set(&path);
            revoke(
                &path,
                &set,
                &RevocationEntry::new("t1", JWT_JTI_CANONICAL, "a", "r"),
            )
            .unwrap();
        }
        let set2 = load_revocation_set(&path);
        assert!(is_revoked(&set2, "t1", JWT_JTI));
        assert!(!is_revoked(&set2, LEGACY_TENANT, JWT_JTI));
    }

    #[test]
    fn a_tampered_line_is_not_loaded() {
        let path = temp_path();
        let mut entry = RevocationEntry::new("t", JWT_JTI_CANONICAL, "a", "r");
        entry.tenant_id = Some("other-tenant".to_owned()); // move it after hashing
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();
        let set = load_revocation_set(&path);
        assert!(!is_revoked(&set, "other-tenant", JWT_JTI));
        assert!(!is_revoked(&set, "t", JWT_JTI));
    }

    #[test]
    fn legacy_lines_load_under_the_legacy_tenant_with_their_old_hash() {
        let path = temp_path();
        // Exactly what the pre-tenancy code wrote.
        let canonical = format!(
            "jti={}&revoked_by={}&revoked_at={}&reason={}",
            JWT_JTI, "admin", "2026-01-01T00:00:00Z", "old"
        );
        let mut h = Sha3_256::new();
        h.update(canonical.as_bytes());
        let line = serde_json::json!({
            "jti": JWT_JTI,
            "revoked_by": "admin",
            "revoked_at": "2026-01-01T00:00:00Z",
            "reason": "old",
            "entry_hash": hex::encode(h.finalize()),
        });
        std::fs::write(&path, format!("{line}\n")).unwrap();
        let set = load_revocation_set(&path);
        assert!(is_revoked(&set, LEGACY_TENANT, JWT_JTI));
        assert!(!is_revoked(&set, "bank-a", JWT_JTI));
    }

    #[test]
    fn evidence_jtis_are_exported_per_tenant_in_16_byte_form() {
        let path = temp_path();
        let set = load_revocation_set(&path);
        revoke(
            &path,
            &set,
            &RevocationEntry::new("t", EVIDENCE_JTI, "a", "r"),
        )
        .unwrap();
        revoke(
            &path,
            &set,
            &RevocationEntry::new("t", JWT_JTI_CANONICAL, "a", "r"),
        )
        .unwrap();
        revoke(
            &path,
            &set,
            &RevocationEntry::new("u", "ffeeddccbbaa99887766554433221100", "a", "r"),
        )
        .unwrap();
        let t = evidence_jtis_for_tenant(&set, "t");
        assert_eq!(t.len(), 2);
        let want: [u8; 16] = hex::decode(EVIDENCE_JTI).unwrap().try_into().unwrap();
        assert!(t.contains(&want));
        assert_eq!(evidence_jtis_for_tenant(&set, "u").len(), 1);
        assert!(evidence_jtis_for_tenant(&set, "v").is_empty());
    }

    #[test]
    fn normalize_rejects_everything_that_is_not_a_token_id() {
        assert!(normalize_jti("").is_err());
        assert!(normalize_jti("jti-abc").is_err());
        assert!(normalize_jti("0011223344556677").is_err()); // 8 bytes
        assert_eq!(
            normalize_jti("0F8FAD5B-D9CB-469F-A165-70867728950E").unwrap(),
            JWT_JTI_CANONICAL
        );
        assert_eq!(
            normalize_jti(&EVIDENCE_JTI.to_ascii_uppercase()).unwrap(),
            EVIDENCE_JTI
        );
    }
}
