//! Identity & Reputation Store — Persistent storage for AIP identities.
//!
//! Provides in-memory storage backed by optional JSON file persistence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aip_crypto::custody::{Custodian, InMemoryCustodian};
use aip_types::{AgentIdentityDocument, KeyPair, ReputationRecord};
use serde::{Deserialize, Serialize};

/// Stored identity entry: the AID document plus its keypair.
///
/// The key pair is **private**. There is no accessor that returns it, and the
/// type carries no serialization derive; the on-disk shape is
/// [`StoredIdentityWire`], built at exactly one place in `save`.
///
/// Both properties close a hole a `pub keypair: KeyPair` leaves open. A public
/// field is a key accessor by another name — `store.get_identity(id).keypair
/// .private_key` hands the raw key to any caller — and a `derive(Serialize)`
/// on a type holding key material means every JSON response the type reaches
/// carries the private key. `Persistence::ProductionNoSecrets` stops `save`
/// from writing one; it cannot stop a handler somewhere else from serializing
/// the struct.
///
/// Callers that need a signature call [`Self::sign`]; callers that need to
/// verify use [`Self::public_key`], which is public material.
#[derive(Debug, Clone)]
pub struct StoredIdentity {
    pub aid: AgentIdentityDocument,
    keypair: KeyPair,
}

impl StoredIdentity {
    /// An identity and the key that speaks for it.
    pub fn new(aid: AgentIdentityDocument, keypair: KeyPair) -> Self {
        Self { aid, keypair }
    }

    /// The identity's public key. Safe to publish.
    pub fn public_key(&self) -> &[u8] {
        &self.keypair.public_key
    }

    /// Whether this process can currently sign as this identity.
    ///
    /// False after a `ProductionNoSecrets` round trip, where the stored entry
    /// carries an empty private key.
    pub fn can_sign(&self) -> bool {
        !self.keypair.private_key.is_empty()
    }

    /// Sign `payload` as this identity.
    ///
    /// The controlled signing operation: the key goes in, a signature comes
    /// out, and nothing in between is reachable by the caller. Routed through
    /// [`InMemoryCustodian`] so this store uses the same custody interface as
    /// everything else rather than a private arrangement of its own, and the
    /// envelope is what `sign_ed25519` has always produced — existing
    /// verifiers are unaffected.
    pub fn sign(&self, payload: &[u8]) -> Result<aip_types::Signature, StoreError> {
        if !self.can_sign() {
            return Err(StoreError::NoPrivateKey(self.aid.id.clone()));
        }
        let custodian = InMemoryCustodian::new(&self.keypair.private_key, &self.keypair.public_key)
            .map_err(|e| StoreError::SigningFailed(e.to_string()))?;
        custodian
            .sign(&self.aid.id, payload)
            .map_err(|e: aip_crypto::custody::CustodyError| {
                StoreError::SigningFailed(e.to_string())
            })
    }

    /// Answer a liveness challenge as this identity.
    pub fn respond_to_challenge(
        &self,
        challenge: &crate::LivenessChallenge,
    ) -> Result<crate::LivenessResponse, StoreError> {
        let sig = self.sign(&challenge.nonce)?;
        Ok(crate::assemble_liveness_response(
            challenge,
            sig,
            &self.aid.id,
        ))
    }
}

/// The on-disk shape of a stored identity.
///
/// Byte-identical to what previous builds wrote, so no existing store file
/// becomes unreadable. It is separate from [`StoredIdentity`] so the domain
/// type can carry no derive at all: this is the single, reviewed place where
/// key material is written out, rather than a derive that follows a struct
/// into whatever somebody serializes it into later.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdentityWire {
    aid: AgentIdentityDocument,
    keypair: KeyPair,
}

/// What the store holds in memory. Carries no serialization derive, because
/// the values in it hold key material.
#[derive(Debug, Clone, Default)]
struct StoreData {
    identities: HashMap<String, StoredIdentity>,
    reputations: HashMap<String, ReputationRecord>,
}

/// The on-disk shape of the whole store. Unchanged from previous builds.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreFile {
    identities: HashMap<String, StoredIdentityWire>,
    reputations: HashMap<String, ReputationRecord>,
}

impl StoreFile {
    fn into_memory(self) -> StoreData {
        StoreData {
            identities: self
                .identities
                .into_iter()
                .map(|(id, w)| (id, StoredIdentity::new(w.aid, w.keypair)))
                .collect(),
            reputations: self.reputations,
        }
    }
}

/// What a store is allowed to write.
///
/// Named at construction and never inferred, because the difference is
/// whether private keys reach the disk in the clear and that is not a
/// thing to get wrong by omission (Phase A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persistence {
    /// Writes everything it holds, private keys included, as plaintext
    /// JSON. Development and tests only. The file is still created
    /// owner-only, because a convenience is no reason to be careless.
    DevelopmentPlaintext,
    /// Refuses to write private key material at all. An identity carrying
    /// a keypair makes `save` fail rather than quietly dropping the key —
    /// silently writing less than the caller asked for is how a store ends
    /// up missing the identity somebody needed.
    ///
    /// Production deployments keep signing keys in a custodian
    /// (`aip_crypto::custody`), not in this store.
    ProductionNoSecrets,
}

impl Persistence {
    pub fn is_production(self) -> bool {
        matches!(self, Persistence::ProductionNoSecrets)
    }
}

/// Combined identity and reputation store.
///
/// Operates in-memory with optional file-backed persistence.
/// Call `save()` to write to disk and `load()` to read back.
pub struct IdentityStore {
    data: StoreData,
    file_path: Option<PathBuf>,
    persistence: Persistence,
}

impl IdentityStore {
    /// Create a new in-memory store (no file persistence).
    pub fn new() -> Self {
        Self {
            data: StoreData::default(),
            file_path: None,
            // Nothing is written, so nothing can be written in the clear.
            persistence: Persistence::ProductionNoSecrets,
        }
    }

    /// Create a store backed by a JSON file.
    /// If the file exists, it will be loaded. Otherwise, an empty store is created.
    pub fn with_file(path: impl AsRef<Path>, persistence: Persistence) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let data = if path.exists() {
            let contents =
                std::fs::read_to_string(&path).map_err(|e| StoreError::IoError(e.to_string()))?;
            let file: StoreFile = serde_json::from_str(&contents)
                .map_err(|e| StoreError::SerializationError(e.to_string()))?;
            file.into_memory()
        } else {
            StoreData::default()
        };

        Ok(Self {
            data,
            file_path: Some(path),
            persistence,
        })
    }

    // ─── Identity Operations ───

    /// Store an identity and its keypair.
    pub fn put_identity(&mut self, aid: AgentIdentityDocument, keypair: KeyPair) {
        let id = aid.id.clone();
        self.data
            .identities
            .insert(id, StoredIdentity::new(aid, keypair));
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
            .or_insert_with(|| ReputationRecord {
                agent_id: agent_id.to_string(),
                ..Default::default()
            });

        let new_score = (record.overall_score as i64 + delta as i64).clamp(0, 1_000_000) as u32;
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
            std::fs::create_dir_all(parent).map_err(|e| StoreError::IoError(e.to_string()))?;
        }

        // A production store does not write secrets. Counted and named
        // rather than stripped: writing less than the caller asked for,
        // without saying so, is its own defect.
        if self.persistence.is_production() {
            let with_keys = self
                .data
                .identities
                .values()
                .filter(|i| !i.keypair.private_key.is_empty())
                .count();
            if with_keys > 0 {
                return Err(StoreError::SecretsRefused(with_keys));
            }
        }

        // The single place key material is written out.
        let file = StoreFile {
            identities: self
                .data
                .identities
                .iter()
                .map(|(id, e)| {
                    (
                        id.clone(),
                        StoredIdentityWire {
                            aid: e.aid.clone(),
                            keypair: e.keypair.clone(),
                        },
                    )
                })
                .collect(),
            reputations: self.data.reputations.clone(),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| StoreError::SerializationError(e.to_string()))?;
        // Owner-only, with the mode applied by the open call rather than by a
        // chmod afterwards. `fs::write` creates at `0o666 & !umask`, so a
        // write-then-restrict sequence leaves key material world-readable for
        // the interval between the two syscalls, and a reader only has to win
        // that race once. The temp name carries the process id so two writers
        // do not collide on it, and a failed rename removes the temp file
        // rather than leaving a readable remnant.
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        aip_crypto::custody::write_owner_only_file(&tmp, json.as_bytes())
            .map_err(|e| StoreError::IoError(e.to_string()))?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(StoreError::IoError(e.to_string()));
        }
        restrict(path)?;
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

        let contents =
            std::fs::read_to_string(path).map_err(|e| StoreError::IoError(e.to_string()))?;
        let file: StoreFile = serde_json::from_str(&contents)
            .map_err(|e| StoreError::SerializationError(e.to_string()))?;
        self.data = file.into_memory();
        Ok(())
    }
}

/// Owner-only where the platform has Unix permissions.
fn restrict(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|e| StoreError::IoError(e.to_string()))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| StoreError::IoError(e.to_string()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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
    /// A production store was asked to save identities carrying private
    /// keys. Named with the count so an operator knows how much is
    /// affected, and refused rather than written or silently stripped.
    SecretsRefused(usize),
    /// A signing operation was asked of an identity whose private key this
    /// process does not hold — the shape every entry takes after a
    /// `ProductionNoSecrets` round trip.
    NoPrivateKey(String),
    SigningFailed(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::IoError(e) => write!(f, "Store I/O error: {}", e),
            StoreError::SerializationError(e) => write!(f, "Store serialization error: {}", e),
            StoreError::NoPersistencePath => write!(f, "No persistence path configured"),
            StoreError::SecretsRefused(n) => write!(
                f,
                "refusing to write {n} identity(ies) carrying private keys: this store is \
                 ProductionNoSecrets. Keep signing keys in a custodian (aip_crypto::custody)."
            ),
            StoreError::IdentityNotFound(id) => write!(f, "Identity not found: {}", id),
            StoreError::NoPrivateKey(id) => write!(
                f,
                "cannot sign as {id}: this process does not hold its private key"
            ),
            StoreError::SigningFailed(why) => write!(f, "Signing failed: {why}"),
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
            let mut store =
                IdentityStore::with_file(&tmp_path, Persistence::DevelopmentPlaintext).unwrap();
            let (aid, kp) = make_test_identity();
            store.put_identity(aid, kp);
            store.update_reputation("test_agent", 50_000);
            store.save().unwrap();
        }

        // Load in a new store instance
        {
            let store =
                IdentityStore::with_file(&tmp_path, Persistence::DevelopmentPlaintext).unwrap();
            assert_eq!(store.identity_count(), 1);
            assert!(store.get_reputation("test_agent").is_some());
        }

        // Clean up
        let _ = std::fs::remove_file(&tmp_path);
    }
}
