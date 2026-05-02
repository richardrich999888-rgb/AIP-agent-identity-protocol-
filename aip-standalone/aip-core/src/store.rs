//! Identity & Reputation Store — Persistent storage for AIP identities.
//!
//! Provides in-memory storage backed by optional JSON file persistence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aip_types::{AgentIdentityDocument, KeyPair, ReputationRecord};
use serde::{Deserialize, Serialize};

/// Stored identity entry: the AID document plus its keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredIdentity {
    pub aid: AgentIdentityDocument,
    pub keypair: KeyPair,
}

/// Serializable store format for JSON persistence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreData {
    identities: HashMap<String, StoredIdentity>,
    reputations: HashMap<String, ReputationRecord>,
}

/// Combined identity and reputation store.
///
/// Operates in-memory with optional file-backed persistence.
/// Call `save()` to write to disk and `load()` to read back.
pub struct IdentityStore {
    data: StoreData,
    file_path: Option<PathBuf>,
}

impl IdentityStore {
    /// Create a new in-memory store (no file persistence).
    pub fn new() -> Self {
        Self {
            data: StoreData::default(),
            file_path: None,
        }
    }

    /// Create a store backed by a JSON file.
    /// If the file exists, it will be loaded. Otherwise, an empty store is created.
    pub fn with_file(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let data = if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| StoreError::IoError(e.to_string()))?;
            serde_json::from_str(&contents)
                .map_err(|e| StoreError::SerializationError(e.to_string()))?
        } else {
            StoreData::default()
        };

        Ok(Self {
            data,
            file_path: Some(path),
        })
    }

    // ─── Identity Operations ───

    /// Store an identity and its keypair.
    pub fn put_identity(&mut self, aid: AgentIdentityDocument, keypair: KeyPair) {
        let id = aid.id.clone();
        self.data.identities.insert(id, StoredIdentity { aid, keypair });
    }

    /// Get an identity by AIP-ID.
    pub fn get_identity(&self, id: &str) -> Option<&StoredIdentity> {
        self.data.identities.get(id)
    }

    /// Get a mutable reference to an identity.
    pub fn get_identity_mut(&mut self, id: &str) -> Option<&mut StoredIdentity> {
        self.data.identities.get_mut(id)
    }

    /// Remove an identity.
    pub fn remove_identity(&mut self, id: &str) -> Option<StoredIdentity> {
        self.data.identities.remove(id)
    }

    /// List all stored identity IDs.
    pub fn list_identities(&self) -> Vec<&str> {
        self.data.identities.keys().map(|s| s.as_str()).collect()
    }

    /// Number of stored identities.
    pub fn identity_count(&self) -> usize {
        self.data.identities.len()
    }

    // ─── Reputation Operations ───

    /// Store a reputation record.
    pub fn put_reputation(&mut self, record: ReputationRecord) {
        let id = record.agent_id.clone();
        self.data.reputations.insert(id, record);
    }

    /// Get a reputation record by agent ID.
    pub fn get_reputation(&self, id: &str) -> Option<&ReputationRecord> {
        self.data.reputations.get(id)
    }

    /// Update reputation score for an agent. If no record exists, creates one with defaults.
    pub fn update_reputation(&mut self, agent_id: &str, delta: i32) {
        let record = self
            .data
            .reputations
            .entry(agent_id.to_string())
            .or_insert_with(|| {
                let mut r = ReputationRecord::default();
                r.agent_id = agent_id.to_string();
                r
            });

        let new_score = (record.overall_score as i64 + delta as i64)
            .clamp(0, 1_000_000) as u32;
        record.overall_score = new_score;
        record.version += 1;
        record.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
    }

    /// List all agent IDs with reputation records.
    pub fn list_reputations(&self) -> Vec<&str> {
        self.data.reputations.keys().map(|s| s.as_str()).collect()
    }

    // ─── Persistence ───

    /// Save the store to its backing file (if configured).
    pub fn save(&self) -> Result<(), StoreError> {
        let path = self
            .file_path
            .as_ref()
            .ok_or(StoreError::NoPersistencePath)?;

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| StoreError::IoError(e.to_string()))?;
        }

        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| StoreError::SerializationError(e.to_string()))?;
        std::fs::write(path, json)
            .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(())
    }

    /// Reload the store from its backing file.
    pub fn reload(&mut self) -> Result<(), StoreError> {
        let path = self
            .file_path
            .as_ref()
            .ok_or(StoreError::NoPersistencePath)?;

        if !path.exists() {
            return Ok(()); // Nothing to load
        }

        let contents = std::fs::read_to_string(path)
            .map_err(|e| StoreError::IoError(e.to_string()))?;
        self.data = serde_json::from_str(&contents)
            .map_err(|e| StoreError::SerializationError(e.to_string()))?;
        Ok(())
    }
}

impl Default for IdentityStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from the identity store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    IoError(String),
    SerializationError(String),
    NoPersistencePath,
    IdentityNotFound(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::IoError(e) => write!(f, "Store I/O error: {}", e),
            StoreError::SerializationError(e) => write!(f, "Store serialization error: {}", e),
            StoreError::NoPersistencePath => write!(f, "No persistence path configured"),
            StoreError::IdentityNotFound(id) => write!(f, "Identity not found: {}", id),
        }
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_core_test_helpers::*;

    // Test helpers inline since we can't depend on aip-core from within itself
    mod aip_core_test_helpers {
        use aip_crypto::*;
        use aip_types::*;

        pub fn make_test_identity() -> (AgentIdentityDocument, KeyPair) {
            let kp = generate_ed25519_keypair();
            let prov = ProvenanceTriple {
                model_commitment: sha256(b"test-model"),
                environment_commitment: sha256(b"test-env"),
                toolchain_commitment: sha256(b"test-tool"),
            };
            let id = derive_aip_id(&kp.public_key, &prov);

            let aid = AgentIdentityDocument {
                magic: AID_MAGIC,
                version: AIP_VERSION,
                flags: AidFlags::empty(),
                id,
                created_at: 1000,
                expires_at: None,
                primary_key: PublicKey {
                    algorithm: AlgorithmId::Ed25519,
                    key_bytes: kp.public_key.clone(),
                },
                recovery_key: None,
                encryption_key: None,
                provenance: prov,
                status: IdentityStatus::Active,
                sequence: 0,
                lineage_depth: 0,
                lineage_proof: None,
                capability_root: [0u8; 32],
                reputation_root: [0u8; 32],
                self_signature: None,
            };
            (aid, kp)
        }
    }

    #[test]
    fn test_store_put_get_identity() {
        let mut store = IdentityStore::new();
        let (aid, kp) = make_test_identity();
        let id = aid.id.clone();

        store.put_identity(aid, kp);
        assert_eq!(store.identity_count(), 1);
        assert!(store.get_identity(&id).is_some());
    }

    #[test]
    fn test_store_list_identities() {
        let mut store = IdentityStore::new();
        let (aid1, kp1) = make_test_identity();
        let (aid2, kp2) = make_test_identity();

        store.put_identity(aid1, kp1);
        store.put_identity(aid2, kp2);
        assert_eq!(store.identity_count(), 2);
        assert_eq!(store.list_identities().len(), 2);
    }

    #[test]
    fn test_store_remove_identity() {
        let mut store = IdentityStore::new();
        let (aid, kp) = make_test_identity();
        let id = aid.id.clone();

        store.put_identity(aid, kp);
        assert!(store.remove_identity(&id).is_some());
        assert_eq!(store.identity_count(), 0);
    }

    #[test]
    fn test_store_reputation_update() {
        let mut store = IdentityStore::new();
        store.update_reputation("agent1", 100_000); // +10%
        let rep = store.get_reputation("agent1").unwrap();
        assert_eq!(rep.overall_score, 600_000); // 500K default + 100K
        assert_eq!(rep.version, 1);
    }

    #[test]
    fn test_store_reputation_negative_clamped() {
        let mut store = IdentityStore::new();
        store.update_reputation("agent1", -1_000_000); // Massive penalty
        let rep = store.get_reputation("agent1").unwrap();
        assert_eq!(rep.overall_score, 0); // Clamped at 0
    }

    #[test]
    fn test_store_file_persistence() {
        let tmp_path = std::env::temp_dir().join("aip_test_store.json");
        // Clean up from any previous run
        let _ = std::fs::remove_file(&tmp_path);

        {
            let mut store = IdentityStore::with_file(&tmp_path).unwrap();
            let (aid, kp) = make_test_identity();
            store.put_identity(aid, kp);
            store.update_reputation("test_agent", 50_000);
            store.save().unwrap();
        }

        // Load in a new store instance
        {
            let store = IdentityStore::with_file(&tmp_path).unwrap();
            assert_eq!(store.identity_count(), 1);
            assert!(store.get_reputation("test_agent").is_some());
        }

        // Clean up
        let _ = std::fs::remove_file(&tmp_path);
    }
}
