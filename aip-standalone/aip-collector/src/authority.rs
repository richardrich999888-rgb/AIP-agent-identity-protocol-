//! The probe allow-list: which transport public key may submit as which probe
//! id. Loaded from a JSON file the operator controls. A host-side party cannot
//! label its own report with a probe id it does not hold the transport key for,
//! and cannot submit at all unless its exact (id, key) pair is listed.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use aip_transport::ProbeAuthority;

#[derive(Debug, Deserialize)]
struct ProbeEntry {
    probe_id: String,
    /// 64 hex chars = 32-byte Ed25519 transport public key.
    transport_pubkey_hex: String,
}

/// A fixed allow-list keyed by probe id. Exactly one transport key per probe id
/// in this first cut (rotation is a config edit + restart, matching the service
/// tier's API-key posture).
pub struct AllowList {
    keys: HashMap<String, [u8; 32]>,
}

impl AllowList {
    /// Load and validate the allow-list file. Rejects duplicate probe ids and
    /// malformed keys rather than starting with an ambiguous list.
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read probe allow-list {}: {e}", path.display()))?;
        let entries: Vec<ProbeEntry> = serde_json::from_slice(&bytes)
            .map_err(|e| format!("probe allow-list {} is not valid JSON: {e}", path.display()))?;
        if entries.is_empty() {
            return Err(format!(
                "probe allow-list {} is empty; the collector would accept no probe",
                path.display()
            ));
        }
        let mut keys = HashMap::new();
        for e in entries {
            let raw = hex::decode(&e.transport_pubkey_hex).map_err(|err| {
                format!(
                    "probe {:?}: transport_pubkey_hex is not hex: {err}",
                    e.probe_id
                )
            })?;
            let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                format!(
                    "probe {:?}: transport_pubkey_hex must be 32 bytes (64 hex chars), got {}",
                    e.probe_id,
                    raw.len()
                )
            })?;
            if keys.insert(e.probe_id.clone(), key).is_some() {
                return Err(format!("probe id {:?} appears more than once", e.probe_id));
            }
        }
        Ok(Self { keys })
    }

    /// The probe ids in the list, for registering them with the collector.
    pub fn probe_ids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(|s| s.as_str())
    }

    /// How many probes are allowed. (No `is_empty`: `load` rejects an empty
    /// list, so an `AllowList` is never empty.)
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

impl ProbeAuthority for AllowList {
    fn is_authorized(&self, probe_id: &str, transport_pubkey: &[u8; 32]) -> bool {
        // Constant list; the check is an exact (id, key) match. An unknown id or
        // a key that does not match the listed one for that id is refused.
        self.keys.get(probe_id) == Some(transport_pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(name: &str, contents: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("aip-allowlist-{}-{name}", std::process::id()));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn loads_and_authorizes_only_the_listed_pair() {
        let hexkey = "aa".repeat(32);
        let p = write_tmp(
            "ok",
            &format!(r#"[{{"probe_id":"probe-1","transport_pubkey_hex":"{hexkey}"}}]"#),
        );
        let list = AllowList::load(&p).unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.is_authorized("probe-1", &[0xaa; 32]));
        // Wrong key for a known id: refused.
        assert!(!list.is_authorized("probe-1", &[0xbb; 32]));
        // Unknown id: refused.
        assert!(!list.is_authorized("probe-2", &[0xaa; 32]));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_a_short_key() {
        let p = write_tmp(
            "short",
            r#"[{"probe_id":"p","transport_pubkey_hex":"aabb"}]"#,
        );
        assert!(AllowList::load(&p).is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_an_empty_list() {
        let p = write_tmp("empty", "[]");
        assert!(AllowList::load(&p).is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_a_duplicate_probe_id() {
        let hexkey = "cc".repeat(32);
        let p = write_tmp(
            "dup",
            &format!(
                r#"[{{"probe_id":"p","transport_pubkey_hex":"{hexkey}"}},{{"probe_id":"p","transport_pubkey_hex":"{hexkey}"}}]"#
            ),
        );
        assert!(AllowList::load(&p).is_err());
        let _ = std::fs::remove_file(&p);
    }
}
