//! Identity & reputation store.
//!
//! # What changed here, and why
//!
//! This module used to persist an agent's **private key** to disk as plaintext
//! JSON, written with `std::fs::write` — no mode, no exclusive create, no
//! policy. It was the one place in the workspace where the private-key
//! invariant was broken: every other signer in the system keeps its key in a
//! private field and exposes only a signing operation.
//!
//! Three changes close it:
//!
//! 1. **[`StoredIdentity`] no longer exposes its key pair and no longer derives
//!    `Serialize`.** The invariant is now structural. There is no field a caller
//!    can read, and no derive that will carry a key into a JSON response
//!    somebody writes later. Signing happens through [`StoredIdentity::sign`],
//!    which goes via a [`SigningCustodian`].
//! 2. **Persisting key material is an explicit, named, policy-checked choice.**
//!    [`IdentityStore::with_file`] never writes a private key.
//!    [`IdentityStore::with_file_and_plaintext_keys`] does, is named so that a
//!    reviewer cannot miss it at the call site, and is **refused outright**
//!    under [`CustodyPolicy::Production`].
//! 3. **The file is written atomically at mode 0600**, via
//!    [`aip_custody::write_secret_file`], because the same path holds key
//!    material under a development policy.
//!
//! # Migration
//!
//! A store file written by an earlier build contains plaintext key pairs. The
//! wire format is unchanged — the key pair simply became optional — so such a
//! file still parses. But [`IdentityStore::with_file`] **refuses to open it**,
//! reporting [`StoreError::PlaintextKeysPresent`], rather than loading it and
//! dropping the keys on the next `save()`. Silently rewriting the file without
//! them would destroy every private key it holds, which is unrecoverable.
//!
//! Two ways forward, both deliberate:
//!
//! - Move each key into its own [`aip_custody::FileCustodian`] file and rewrite
//!   the store without key material. This is the production path.
//! - Open the file with [`IdentityStore::with_file_and_plaintext_keys`] under an
//!   explicit [`CustodyPolicy::Development`], accepting that the keys are
//!   unprotected. This is the test and local-development path.
//!
//! No existing signature or proof package is invalidated by any of this. Key
//! *storage* changed; key *identity*, the signature envelope and every verifier
//! are untouched.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aip_custody::{CustodyClass, CustodyPolicy, DevCustodian};
use aip_types::{AgentIdentityDocument, KeyPair, ReputationRecord, Signature};
use serde::{Deserialize, Serialize};

use crate::{LivenessChallenge, LivenessResponse};

/// Whether a store's backing file may contain private key material.
///
/// Not a boolean, and not read from the environment inside `save()`: an
/// ambient, process-global switch is untestable in a parallel test binary and
/// invisible at the call site. The choice is made once, explicitly, when the
/// store is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPersistence {
    /// Private key material is never written. The file carries identity
    /// documents and reputation records — public data — and nothing else.
    Never,
    /// Private key material is written in the clear. Development and test
    /// fixtures only; unreachable under [`CustodyPolicy::Production`].
    DevelopmentPlaintext,
}

/// An identity document and, optionally, the key that speaks for it.
///
/// The key pair is **private**. There is no accessor, no `Serialize`, and no
/// `Deref` to one. Callers that need a signature call [`Self::sign`] or
/// [`Self::respond_to_challenge`]; callers that need to verify use
/// [`Self::public_key`], which is public data and always present.
#[derive(Debug, Clone)]
pub struct StoredIdentity {
    pub aid: AgentIdentityDocument,
    keypair: Option<KeyPair>,
}

impl StoredIdentity {
    /// An identity together with its key pair, held in memory.
    pub fn with_keypair(aid: AgentIdentityDocument, keypair: KeyPair) -> Self {
        Self {
            aid,
            keypair: Some(keypair),
        }
    }

    /// An identity this process can verify but cannot speak for.
    ///
    /// The shape every identity takes after a [`KeyPersistence::Never`] reload:
    /// the document is public and complete, and the ability to sign as it lives
    /// with whoever holds the custodian.
    pub fn public_only(aid: AgentIdentityDocument) -> Self {
        Self { aid, keypair: None }
    }

    /// The identity's public key. Always available; safe to publish.
    pub fn public_key(&self) -> &[u8] {
        &self.aid.primary_key.key_bytes
    }

    /// Whether this process can currently sign as this identity.
    pub fn can_sign(&self) -> bool {
        self.keypair.is_some()
    }

    /// How the key is protected, if one is held.
    ///
    /// Always [`CustodyClass::Development`] when present, and that is the
    /// honest answer: a key pair sitting in a `HashMap` in this process's heap
    /// is development custody however it arrived. Reporting it accurately is
    /// what lets [`aip_custody::admits`] refuse it under a production policy.
    pub fn custody_class(&self) -> Option<CustodyClass> {
        self.keypair.as_ref().map(|_| CustodyClass::Development)
    }

    /// Build a custodian over the held key.
    ///
    /// Private: this is the internal adapter that lets the controlled signing
    /// operations below go through the custodian interface. It is not exposed,
    /// because a `DevCustodian` returned to a caller would be a key accessor
    /// wearing a different hat.
    fn custodian(&self) -> Result<DevCustodian, StoreError> {
        let kp = self
            .keypair
            .as_ref()
            .ok_or_else(|| StoreError::NoPrivateKey(self.aid.id.clone()))?;
        Ok(DevCustodian::from_bytes(
            &self.aid.id,
            0,
            &kp.private_key,
            &kp.public_key,
        ))
    }

    /// Sign `payload` as this identity.
    ///
    /// The controlled signing operation: the key goes in, a signature comes
    /// out, and nothing in between is reachable by the caller. The envelope is
    /// byte-for-byte what `aip_crypto::sign_ed25519` produces, so existing
    /// verifiers are unaffected.
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, StoreError> {
        let custodian = self.custodian()?;
        aip_custody::sign_envelope(&custodian, &self.aid.id, payload)
            .map_err(|e| StoreError::SigningFailed(e.to_string()))
    }

    /// Answer a liveness challenge as this identity.
    pub fn respond_to_challenge(
        &self,
        challenge: &LivenessChallenge,
    ) -> Result<LivenessResponse, StoreError> {
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
/// Separate from [`StoredIdentity`] on purpose. The domain type carries no
/// serialization derive at all, so key material cannot leave through one by
/// accident; this type is the single, reviewed place where the question "is the
/// key written?" is answered, and the answer is decided by [`KeyPersistence`]
/// at the one call site that constructs it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdentityWire {
    aid: AgentIdentityDocument,
    /// Absent under [`KeyPersistence::Never`]. `default` keeps files written by
    /// either policy readable, so no historical store becomes unparseable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keypair: Option<KeyPair>,
}

/// The on-disk shape of the whole store.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreFile {
    identities: HashMap<String, StoredIdentityWire>,
    reputations: HashMap<String, ReputationRecord>,
}

/// Combined identity and reputation store.
pub struct IdentityStore {
    identities: HashMap<String, StoredIdentity>,
    reputations: HashMap<String, ReputationRecord>,
    file_path: Option<PathBuf>,
    persistence: KeyPersistence,
}

impl IdentityStore {
    /// An in-memory store with no file behind it.
    ///
    /// Nothing is ever written, so no key can leak through persistence.
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            reputations: HashMap::new(),
            file_path: None,
            persistence: KeyPersistence::Never,
        }
    }

    /// Open a file-backed store that **never writes private keys**.
    ///
    /// The default, and the production path. If the file already contains key
    /// material this returns [`StoreError::PlaintextKeysPresent`] rather than
    /// opening it: loading such a file here and saving it later would rewrite
    /// it without the keys, destroying them irrecoverably. Refusing is the only
    /// safe answer, and it forces the migration to be a decision somebody makes.
    pub fn with_file(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open(path.as_ref(), KeyPersistence::Never)
    }

    /// Open a file-backed store that writes private keys **in the clear**.
    ///
    /// Deliberately verbose: a call site reading
    /// `with_file_and_plaintext_keys` states what it is doing, where a boolean
    /// or a config flag would not.
    ///
    /// Refused under [`CustodyPolicy::Production`] with
    /// [`StoreError::CustodyRefused`]. There is no downgrade, no warning-and-
    /// continue, and no environment variable consulted here — the caller passes
    /// the policy it is operating under, and a caller that does not know its own
    /// policy has a bug this will surface.
    pub fn with_file_and_plaintext_keys(
        path: impl AsRef<Path>,
        policy: CustodyPolicy,
    ) -> Result<Self, StoreError> {
        if !policy.admits(CustodyClass::Development) {
            return Err(StoreError::CustodyRefused(format!(
                "the {policy} custody policy does not permit writing private \
                 keys to {}. Hold keys in an aip_custody::FileCustodian and \
                 open the store with IdentityStore::with_file, which persists \
                 public identity data only.",
                path.as_ref().display()
            )));
        }
        Self::open(path.as_ref(), KeyPersistence::DevelopmentPlaintext)
    }

    fn open(path: &Path, persistence: KeyPersistence) -> Result<Self, StoreError> {
        let mut store = Self {
            identities: HashMap::new(),
            reputations: HashMap::new(),
            file_path: Some(path.to_path_buf()),
            persistence,
        };
        store.reload()?;
        Ok(store)
    }

    /// What this store will and will not write.
    pub fn key_persistence(&self) -> KeyPersistence {
        self.persistence
    }

    // ─── Identity Operations ───

    /// Store an identity and its key pair.
    ///
    /// The key pair is held in memory. Whether it reaches disk is decided by
    /// [`Self::key_persistence`], not here.
    pub fn put_identity(&mut self, aid: AgentIdentityDocument, keypair: KeyPair) {
        let id = aid.id.clone();
        self.identities
            .insert(id, StoredIdentity::with_keypair(aid, keypair));
    }

    /// Store an identity this process can verify but not sign as.
    pub fn put_public_identity(&mut self, aid: AgentIdentityDocument) {
        let id = aid.id.clone();
        self.identities.insert(id, StoredIdentity::public_only(aid));
    }

    /// Get an identity by AIP-ID.
    pub fn get_identity(&self, id: &str) -> Option<&StoredIdentity> {
        self.identities.get(id)
    }

    /// Get a mutable reference to an identity.
    pub fn get_identity_mut(&mut self, id: &str) -> Option<&mut StoredIdentity> {
        self.identities.get_mut(id)
    }

    /// Remove an identity.
    pub fn remove_identity(&mut self, id: &str) -> Option<StoredIdentity> {
        self.identities.remove(id)
    }

    /// List all stored identity IDs.
    pub fn list_identities(&self) -> Vec<&str> {
        self.identities.keys().map(|s| s.as_str()).collect()
    }

    /// Number of stored identities.
    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    // ─── Reputation Operations ───

    /// Store a reputation record.
    pub fn put_reputation(&mut self, record: ReputationRecord) {
        let id = record.agent_id.clone();
        self.reputations.insert(id, record);
    }

    /// Get a reputation record by agent ID.
    pub fn get_reputation(&self, id: &str) -> Option<&ReputationRecord> {
        self.reputations.get(id)
    }

    /// Update reputation score for an agent. If no record exists, creates one with defaults.
    pub fn update_reputation(&mut self, agent_id: &str, delta: i32) {
        let record = self
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
            .unwrap_or_default()
            .as_millis() as u64;
    }

    /// List all agent IDs with reputation records.
    pub fn list_reputations(&self) -> Vec<&str> {
        self.reputations.keys().map(|s| s.as_str()).collect()
    }

    // ─── Persistence ───

    /// Save the store to its backing file (if configured).
    ///
    /// Written atomically at mode 0600 by [`aip_custody::write_secret_file`].
    /// The mode is applied unconditionally, including under
    /// [`KeyPersistence::Never`]: the same path holds key material under a
    /// development policy, and a permission that depends on a mode flag is a
    /// permission that will one day be wrong.
    pub fn save(&self) -> Result<(), StoreError> {
        let path = self
            .file_path
            .as_ref()
            .ok_or(StoreError::NoPersistencePath)?;

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::IoError(e.to_string()))?;
        }

        let file = StoreFile {
            identities: self
                .identities
                .iter()
                .map(|(id, entry)| {
                    let keypair = match self.persistence {
                        // The one branch where key material is written, and it
                        // is unreachable under a production policy because
                        // with_file_and_plaintext_keys is the only constructor
                        // that sets this variant.
                        KeyPersistence::DevelopmentPlaintext => entry.keypair.clone(),
                        KeyPersistence::Never => None,
                    };
                    (
                        id.clone(),
                        StoredIdentityWire {
                            aid: entry.aid.clone(),
                            keypair,
                        },
                    )
                })
                .collect(),
            reputations: self.reputations.clone(),
        };

        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| StoreError::SerializationError(e.to_string()))?;
        aip_custody::write_secret_file(path, json.as_bytes())
            .map_err(|e| StoreError::IoError(e.to_string()))
    }

    /// Reload the store from its backing file.
    ///
    /// A missing file is not an error: an unprovisioned store is empty. Every
    /// other failure — unreadable, malformed, or carrying key material this
    /// store is not permitted to hold — is an error, and the in-memory contents
    /// are left untouched so a failed reload cannot become a truncated save.
    pub fn reload(&mut self) -> Result<(), StoreError> {
        let path = self
            .file_path
            .as_ref()
            .ok_or(StoreError::NoPersistencePath)?
            .clone();

        if !path.exists() {
            return Ok(());
        }

        let contents =
            std::fs::read_to_string(&path).map_err(|e| StoreError::IoError(e.to_string()))?;
        let file: StoreFile = serde_json::from_str(&contents)
            .map_err(|e| StoreError::SerializationError(e.to_string()))?;

        let with_keys = file
            .identities
            .values()
            .filter(|w| w.keypair.is_some())
            .count();
        if with_keys > 0 && self.persistence == KeyPersistence::Never {
            return Err(StoreError::PlaintextKeysPresent {
                path: path.display().to_string(),
                count: with_keys,
            });
        }

        self.identities = file
            .identities
            .into_iter()
            .map(|(id, w)| {
                let entry = match w.keypair {
                    Some(kp) => StoredIdentity::with_keypair(w.aid, kp),
                    None => StoredIdentity::public_only(w.aid),
                };
                (id, entry)
            })
            .collect();
        self.reputations = file.reputations;
        Ok(())
    }
}

impl Default for IdentityStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Counts and configuration only. A store may hold key material; formatting it
/// must not be a way to read that material out, in any format.
impl std::fmt::Debug for IdentityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityStore")
            .field("identities", &self.identities.len())
            .field("reputations", &self.reputations.len())
            .field("file_path", &self.file_path)
            .field("persistence", &self.persistence)
            .finish()
    }
}

/// Errors from the identity store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    IoError(String),
    SerializationError(String),
    NoPersistencePath,
    IdentityNotFound(String),
    /// The store file holds private keys and this store is not permitted to.
    ///
    /// Recoverable only by an explicit migration; see the module documentation.
    PlaintextKeysPresent {
        path: String,
        count: usize,
    },
    /// The requested persistence is not acceptable under the caller's policy.
    CustodyRefused(String),
    /// A signing operation was asked of an identity whose key this process
    /// does not hold.
    NoPrivateKey(String),
    SigningFailed(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::IoError(e) => write!(f, "Store I/O error: {e}"),
            StoreError::SerializationError(e) => write!(f, "Store serialization error: {e}"),
            StoreError::NoPersistencePath => write!(f, "No persistence path configured"),
            StoreError::IdentityNotFound(id) => write!(f, "Identity not found: {id}"),
            StoreError::PlaintextKeysPresent { path, count } => write!(
                f,
                "{path} holds {count} plaintext private key(s) and this store \
                 does not persist key material. Refusing to open it: saving \
                 would rewrite the file without those keys and destroy them. \
                 Migrate each key into an aip_custody::FileCustodian, or open \
                 with IdentityStore::with_file_and_plaintext_keys under an \
                 explicit development policy."
            ),
            StoreError::CustodyRefused(why) => write!(f, "Custody refused: {why}"),
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
