//! AIP identity binding for permissioned distribution peers.
//!
//! Peer IDs authenticate libp2p transport keys only. This module binds those
//! keys to an AIP identity through an issuer-signed statement and a separately
//! signed, freshness-bounded status snapshot. All issuer keys and subject
//! grants are supplied out of band; neither document can establish its own
//! trust anchor.

use aip_core::{validate_aid, validate_aid_with_verifier, SignatureVerifier};
use aip_crypto::{custody::Custodian, sha256, verify_ed25519};
use aip_types::{
    canonical::{
        encode_signature, put_bytes, put_domain, put_opt_signature, put_opt_u64, put_str, put_u16,
        put_u32, put_u64, put_u8,
    },
    AgentIdentityDocument, AlgorithmId, IdentityStatus, Signature,
};
use libp2p::{identity, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PEER_BINDING_VERSION: u16 = 1;
pub const PEER_BINDING_DOMAIN: &str = "AIP/DISTRIBUTION/PEER_BINDING/v1";
pub const AID_DOCUMENT_DIGEST_DOMAIN: &str = "AIP/AID_DOCUMENT_DIGEST/v1";
pub const PEER_STATUS_DOMAIN: &str = "AIP/DISTRIBUTION/PEER_STATUS/v1";
pub const PEER_STATUS_DIGEST_DOMAIN: &str = "AIP/DISTRIBUTION/PEER_STATUS_DIGEST/v1";
pub const PEER_BINDING_MAX_ENCODED_BYTES: usize = 16 * 1024;
pub const PEER_STATUS_MAX_ENCODED_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerBindingError {
    Invalid(String),
    Untrusted(String),
    Crypto(String),
}

impl std::fmt::Display for PeerBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PeerBindingError {}

/// Signed binding between one complete AID document and one libp2p peer key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerBindingStatement {
    pub version: u16,
    pub identity_id: String,
    pub aid_document_sha256: [u8; 32],
    /// libp2p protobuf-encoded Ed25519 public key.
    pub peer_public_key: Vec<u8>,
    /// Canonical libp2p PeerId multihash bytes, not a caller-chosen label.
    pub peer_id: Vec<u8>,
    pub issuer_id: String,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub sequence: u64,
    pub status_epoch: u64,
    pub audience: String,
    pub signature: Signature,
}

impl PeerBindingStatement {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PeerBindingError> {
        validate_text(&self.identity_id, "identity_id")?;
        validate_text(&self.issuer_id, "issuer_id")?;
        validate_text(&self.audience, "audience")?;
        if self.peer_public_key.len() > 128
            || self.peer_id.len() > 128
            || self.sequence == 0
            || self.status_epoch == 0
        {
            return Err(PeerBindingError::Invalid(
                "peer key, PeerId, or sequence fields exceed policy bounds".into(),
            ));
        }
        let mut out = Vec::new();
        put_domain(&mut out, PEER_BINDING_DOMAIN);
        put_u16(&mut out, self.version);
        put_str(&mut out, &self.identity_id);
        out.extend_from_slice(&self.aid_document_sha256);
        put_bytes(&mut out, &self.peer_public_key);
        put_bytes(&mut out, &self.peer_id);
        put_str(&mut out, &self.issuer_id);
        put_u64(&mut out, self.not_before_ms);
        put_u64(&mut out, self.not_after_ms);
        put_u64(&mut out, self.sequence);
        put_u64(&mut out, self.status_epoch);
        put_str(&mut out, &self.audience);
        Ok(out)
    }

    /// Digest used by the independently signed status snapshot to identify
    /// the exact statement, including its signature envelope.
    pub fn statement_digest(&self) -> Result<[u8; 32], PeerBindingError> {
        let mut bytes = self.signing_bytes()?;
        encode_signature(&mut bytes, &self.signature);
        Ok(sha256(&bytes))
    }

    pub fn sign(
        aid: &AgentIdentityDocument,
        peer_public_key: Vec<u8>,
        issuer_id: &str,
        not_before_ms: u64,
        not_after_ms: u64,
        sequence: u64,
        status_epoch: u64,
        audience: &str,
        custodian: &dyn Custodian,
    ) -> Result<Self, PeerBindingError> {
        let decoded = decode_ed25519_peer_key(&peer_public_key)?;
        let peer_id = PeerId::from_public_key(&decoded).to_bytes();
        let mut statement = Self {
            version: PEER_BINDING_VERSION,
            identity_id: aid.id.clone(),
            aid_document_sha256: aid_document_digest(aid),
            peer_public_key,
            peer_id,
            issuer_id: issuer_id.to_string(),
            not_before_ms,
            not_after_ms,
            sequence,
            status_epoch,
            audience: audience.to_string(),
            signature: empty_signature(issuer_id),
        };
        let payload = statement.signing_bytes()?;
        statement.signature = custodian
            .sign(issuer_id, &payload)
            .map_err(|e| PeerBindingError::Crypto(e.to_string()))?;
        verify_signature(
            &statement.signature,
            issuer_id,
            custodian.public_key(),
            &payload,
        )?;
        Ok(statement)
    }
}

/// A signed current-status assertion for one AIP identity and one exact peer
/// binding. Binding sequence and statement digest equality prevent accepting
/// an older binding after the status authority has advanced the subject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentityStatus {
    pub status: IdentityStatus,
    pub aid_sequence: u64,
    pub binding_sequence: u64,
    pub binding_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerStatusSnapshot {
    pub version: u16,
    pub signer_id: String,
    pub epoch: u64,
    pub issued_at_ms: u64,
    pub valid_until_ms: u64,
    pub audience: String,
    pub identities: BTreeMap<String, PeerIdentityStatus>,
    pub signature: Signature,
}

pub fn parse_peer_binding(bytes: &[u8]) -> Result<PeerBindingStatement, PeerBindingError> {
    if bytes.len() > PEER_BINDING_MAX_ENCODED_BYTES {
        return Err(PeerBindingError::Invalid(
            "peer binding exceeds maximum encoded size".into(),
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|e| PeerBindingError::Invalid(format!("malformed peer binding: {e}")))
}

pub fn parse_peer_status_snapshot(bytes: &[u8]) -> Result<PeerStatusSnapshot, PeerBindingError> {
    if bytes.len() > PEER_STATUS_MAX_ENCODED_BYTES {
        return Err(PeerBindingError::Invalid(
            "peer status snapshot exceeds maximum encoded size".into(),
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|e| PeerBindingError::Invalid(format!("malformed peer status snapshot: {e}")))
}

impl PeerStatusSnapshot {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PeerBindingError> {
        validate_text(&self.signer_id, "status signer_id")?;
        validate_text(&self.audience, "status audience")?;
        if self.identities.len() > 100_000 {
            return Err(PeerBindingError::Invalid(
                "status snapshot contains too many identities".into(),
            ));
        }
        let mut out = Vec::new();
        put_domain(&mut out, PEER_STATUS_DOMAIN);
        put_u16(&mut out, self.version);
        put_str(&mut out, &self.signer_id);
        put_u64(&mut out, self.epoch);
        put_u64(&mut out, self.issued_at_ms);
        put_u64(&mut out, self.valid_until_ms);
        put_str(&mut out, &self.audience);
        put_u32(&mut out, self.identities.len() as u32);
        for (identity_id, status) in &self.identities {
            validate_text(identity_id, "status identity_id")?;
            put_str(&mut out, identity_id);
            put_u8(&mut out, status.status as u8);
            put_u64(&mut out, status.aid_sequence);
            put_u64(&mut out, status.binding_sequence);
            out.extend_from_slice(&status.binding_digest);
        }
        if out.len() > PEER_STATUS_MAX_ENCODED_BYTES {
            return Err(PeerBindingError::Invalid(
                "canonical peer status snapshot exceeds maximum size".into(),
            ));
        }
        Ok(out)
    }

    pub fn sign(
        signer_id: &str,
        epoch: u64,
        issued_at_ms: u64,
        valid_until_ms: u64,
        audience: &str,
        identities: BTreeMap<String, PeerIdentityStatus>,
        custodian: &dyn Custodian,
    ) -> Result<Self, PeerBindingError> {
        let mut snapshot = Self {
            version: PEER_BINDING_VERSION,
            signer_id: signer_id.to_string(),
            epoch,
            issued_at_ms,
            valid_until_ms,
            audience: audience.to_string(),
            identities,
            signature: empty_signature(signer_id),
        };
        let payload = snapshot.signing_bytes()?;
        snapshot.signature = custodian
            .sign(signer_id, &payload)
            .map_err(|e| PeerBindingError::Crypto(e.to_string()))?;
        verify_signature(
            &snapshot.signature,
            signer_id,
            custodian.public_key(),
            &payload,
        )?;
        Ok(snapshot)
    }

    pub fn digest(&self) -> Result<[u8; 32], PeerBindingError> {
        let mut bytes = Vec::new();
        put_domain(&mut bytes, PEER_STATUS_DIGEST_DOMAIN);
        bytes.extend_from_slice(&self.signing_bytes()?);
        encode_signature(&mut bytes, &self.signature);
        Ok(sha256(&bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerStatusCheckpoint {
    pub epoch: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct PeerBindingIssuerAnchor {
    public_key: Vec<u8>,
    authorized_subjects: BTreeSet<String>,
}

/// A status-signing key plus the minimum epoch accepted by this verifier.
/// Update the floor from independently trusted, persistent policy state when
/// a newer status epoch has been accepted; this prevents rollback to a signed
/// snapshot from an earlier epoch.
#[derive(Debug, Clone)]
pub struct PeerStatusAuthorityAnchor {
    public_key: Vec<u8>,
    minimum_epoch: u64,
    checkpoint: Option<PeerStatusCheckpoint>,
}

impl PeerStatusAuthorityAnchor {
    pub fn new(public_key: Vec<u8>, minimum_epoch: u64) -> Result<Self, PeerBindingError> {
        if public_key.len() != 32 || minimum_epoch == 0 {
            return Err(PeerBindingError::Untrusted(
                "invalid peer-status authority key or epoch floor".into(),
            ));
        }
        Ok(Self {
            public_key,
            minimum_epoch,
            checkpoint: None,
        })
    }

    /// Create an anchor pinned to a checkpoint received through trusted policy
    /// distribution. Same-epoch conflicting snapshots will be rejected.
    pub fn with_checkpoint(
        public_key: Vec<u8>,
        checkpoint: PeerStatusCheckpoint,
    ) -> Result<Self, PeerBindingError> {
        if public_key.len() != 32 || checkpoint.epoch == 0 || checkpoint.digest == [0; 32] {
            return Err(PeerBindingError::Untrusted(
                "invalid status checkpoint anchor".into(),
            ));
        }
        Ok(Self {
            public_key,
            minimum_epoch: checkpoint.epoch,
            checkpoint: Some(checkpoint),
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn checkpoint_pinned(&self) -> bool {
        self.checkpoint.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct PeerBindingTrustAnchors {
    binding_issuers: BTreeMap<String, PeerBindingIssuerAnchor>,
    status_authorities: BTreeMap<String, PeerStatusAuthorityAnchor>,
    max_binding_lifetime_ms: u64,
    max_status_age_ms: u64,
}

impl PeerBindingTrustAnchors {
    /// Construct from independently provisioned keys and issuer-subject policy.
    pub fn new(
        binding_issuers: BTreeMap<String, PeerBindingIssuerAnchor>,
        status_authorities: BTreeMap<String, PeerStatusAuthorityAnchor>,
        max_binding_lifetime_ms: u64,
        max_status_age_ms: u64,
    ) -> Result<Self, PeerBindingError> {
        if binding_issuers.is_empty()
            || status_authorities.is_empty()
            || max_binding_lifetime_ms == 0
            || max_status_age_ms == 0
        {
            return Err(PeerBindingError::Untrusted(
                "missing peer-binding policy or trust anchors".into(),
            ));
        }
        for (issuer, anchor) in &binding_issuers {
            validate_text(issuer, "issuer_id")?;
            if anchor.public_key.len() != 32 || anchor.authorized_subjects.is_empty() {
                return Err(PeerBindingError::Untrusted(
                    "invalid binding issuer anchor or empty subject policy".into(),
                ));
            }
            for subject in &anchor.authorized_subjects {
                validate_text(subject, "authorized_subject")?;
            }
        }
        for (signer, anchor) in &status_authorities {
            validate_text(signer, "status signer_id")?;
            if anchor.public_key.len() != 32 || anchor.minimum_epoch == 0 {
                return Err(PeerBindingError::Untrusted(
                    "invalid peer-status authority key".into(),
                ));
            }
        }
        Ok(Self {
            binding_issuers,
            status_authorities,
            max_binding_lifetime_ms,
            max_status_age_ms,
        })
    }

    pub fn status_authority(&self, signer_id: &str) -> Option<&PeerStatusAuthorityAnchor> {
        self.status_authorities.get(signer_id)
    }

    pub fn max_status_age_ms(&self) -> u64 {
        self.max_status_age_ms
    }
}

impl PeerBindingIssuerAnchor {
    pub fn new(
        public_key: Vec<u8>,
        authorized_subjects: BTreeSet<String>,
    ) -> Result<Self, PeerBindingError> {
        if public_key.len() != 32 || authorized_subjects.is_empty() {
            return Err(PeerBindingError::Untrusted(
                "invalid issuer key or empty subject set".into(),
            ));
        }
        for subject in &authorized_subjects {
            validate_text(subject, "authorized_subject")?;
        }
        Ok(Self {
            public_key,
            authorized_subjects,
        })
    }
}

/// Canonical complete-document digest. Unlike `identity_signing_payload()`,
/// this commits to every serialized AID field, including expiry and embedded
/// signatures; it does not change the existing AID self-signing format.
pub fn aid_document_digest(aid: &AgentIdentityDocument) -> [u8; 32] {
    let mut out = Vec::new();
    put_domain(&mut out, AID_DOCUMENT_DIGEST_DOMAIN);
    out.extend_from_slice(&aid.magic);
    put_u16(&mut out, aid.version);
    put_u16(&mut out, aid.flags.0);
    put_str(&mut out, &aid.id);
    put_u64(&mut out, aid.created_at);
    put_opt_u64(&mut out, &aid.expires_at);
    encode_public_key(&mut out, &aid.primary_key);
    encode_optional_public_key(&mut out, &aid.recovery_key);
    encode_optional_public_key(&mut out, &aid.encryption_key);
    out.extend_from_slice(&aid.provenance.to_bytes());
    put_u8(&mut out, aid.status as u8);
    put_u64(&mut out, aid.sequence);
    put_u8(&mut out, aid.lineage_depth);
    put_opt_signature(&mut out, &aid.lineage_proof);
    out.extend_from_slice(&aid.capability_root);
    out.extend_from_slice(&aid.reputation_root);
    put_opt_signature(&mut out, &aid.self_signature);
    sha256(&out)
}

/// Verify a peer binding against external issuer anchors and a signed, fresh
/// status snapshot. `signature_verifier` is required for non-Ed25519 AIDs.
pub fn verify_peer_binding(
    statement: &PeerBindingStatement,
    aid: &AgentIdentityDocument,
    status: &PeerStatusSnapshot,
    anchors: &PeerBindingTrustAnchors,
    expected_audience: &str,
    now_ms: u64,
    signature_verifier: Option<&dyn SignatureVerifier>,
) -> Result<PeerId, PeerBindingError> {
    if statement.version != PEER_BINDING_VERSION || status.version != PEER_BINDING_VERSION {
        return Err(PeerBindingError::Invalid(
            "unsupported binding/status version".into(),
        ));
    }
    if aid.primary_key.algorithm == AlgorithmId::Ed25519 {
        validate_aid(aid).map_err(|e| PeerBindingError::Invalid(format!("invalid AID: {e}")))?;
    } else {
        let verifier = signature_verifier.ok_or_else(|| {
            PeerBindingError::Invalid("non-Ed25519 AID requires an external verifier".into())
        })?;
        validate_aid_with_verifier(aid, verifier)
            .map_err(|e| PeerBindingError::Invalid(format!("invalid AID: {e}")))?;
    }
    if aid.status != IdentityStatus::Active
        || aid.expires_at.is_some_and(|expiry| now_ms > expiry)
        || statement.identity_id != aid.id
        || statement.aid_document_sha256 != aid_document_digest(aid)
    {
        return Err(PeerBindingError::Invalid(
            "AID status, expiry, identity, or complete-document digest mismatch".into(),
        ));
    }
    if statement.audience != expected_audience
        || status.audience != expected_audience
        || statement.not_before_ms > now_ms
        || statement.not_after_ms < now_ms
        || statement.not_after_ms <= statement.not_before_ms
        || statement
            .not_after_ms
            .checked_sub(statement.not_before_ms)
            .is_none_or(|lifetime| lifetime > anchors.max_binding_lifetime_ms)
    {
        return Err(PeerBindingError::Invalid(
            "peer binding is invalid for this audience or time".into(),
        ));
    }

    let issuer = anchors
        .binding_issuers
        .get(&statement.issuer_id)
        .filter(|anchor| anchor.authorized_subjects.contains(&aid.id))
        .ok_or_else(|| {
            PeerBindingError::Untrusted("binding issuer is not trusted for subject".into())
        })?;
    let status_key = anchors
        .status_authorities
        .get(&status.signer_id)
        .ok_or_else(|| PeerBindingError::Untrusted("status signer is not trusted".into()))?;

    verify_snapshot(
        status,
        status_key,
        anchors.max_status_age_ms,
        expected_audience,
        now_ms,
    )?;
    if status.epoch != statement.status_epoch {
        return Err(PeerBindingError::Untrusted(
            "binding status epoch is stale".into(),
        ));
    }
    let current = status.identities.get(&aid.id).ok_or_else(|| {
        PeerBindingError::Untrusted("identity is absent from status snapshot".into())
    })?;
    if current.status != IdentityStatus::Active
        || current.aid_sequence != aid.sequence
        || current.binding_sequence != statement.sequence
        || current.binding_digest != statement.statement_digest()?
    {
        return Err(PeerBindingError::Untrusted(
            "binding is revoked, stale, or not the current sequence".into(),
        ));
    }

    let public_key = decode_ed25519_peer_key(&statement.peer_public_key)?;
    let peer_id = PeerId::from_public_key(&public_key);
    if peer_id.to_bytes() != statement.peer_id {
        return Err(PeerBindingError::Invalid(
            "PeerId does not derive from the bound public key".into(),
        ));
    }

    let payload = statement.signing_bytes()?;
    verify_signature(
        &statement.signature,
        &statement.issuer_id,
        &issuer.public_key,
        &payload,
    )?;
    Ok(peer_id)
}

/// Authenticate an application peer against the PeerId already established
/// by the transport. The AIP evidence and all anchors must come from local
/// trusted peer inventory/policy, never from a trust bundle supplied by the
/// remote request.
pub fn verify_authenticated_peer(
    authenticated_peer: &PeerId,
    statement: &PeerBindingStatement,
    aid: &AgentIdentityDocument,
    status: &PeerStatusSnapshot,
    anchors: &PeerBindingTrustAnchors,
    expected_audience: &str,
    now_ms: u64,
    signature_verifier: Option<&dyn SignatureVerifier>,
) -> Result<String, PeerBindingError> {
    let bound_peer = verify_peer_binding(
        statement,
        aid,
        status,
        anchors,
        expected_audience,
        now_ms,
        signature_verifier,
    )?;
    if &bound_peer != authenticated_peer {
        return Err(PeerBindingError::Untrusted(
            "transport-authenticated PeerId does not match trusted AIP binding".into(),
        ));
    }
    Ok(aid.id.clone())
}

fn verify_snapshot(
    snapshot: &PeerStatusSnapshot,
    anchor: &PeerStatusAuthorityAnchor,
    max_age_ms: u64,
    expected_audience: &str,
    now_ms: u64,
) -> Result<(), PeerBindingError> {
    if snapshot.version != PEER_BINDING_VERSION
        || snapshot.audience != expected_audience
        || snapshot.epoch < anchor.minimum_epoch
        || snapshot.issued_at_ms > now_ms
        || snapshot.valid_until_ms < now_ms
        || snapshot.valid_until_ms <= snapshot.issued_at_ms
        || snapshot
            .valid_until_ms
            .checked_sub(snapshot.issued_at_ms)
            .is_none_or(|lifetime| lifetime > max_age_ms)
        || now_ms
            .checked_sub(snapshot.issued_at_ms)
            .is_none_or(|age| age > max_age_ms)
    {
        return Err(PeerBindingError::Untrusted(
            "peer status snapshot is stale or malformed".into(),
        ));
    }
    let payload = snapshot.signing_bytes()?;
    verify_signature(
        &snapshot.signature,
        &snapshot.signer_id,
        &anchor.public_key,
        &payload,
    )?;
    if let Some(checkpoint) = &anchor.checkpoint {
        if snapshot.epoch < checkpoint.epoch
            || (snapshot.epoch == checkpoint.epoch && snapshot.digest()? != checkpoint.digest)
        {
            return Err(PeerBindingError::Untrusted(
                "peer status snapshot rollback or same-epoch equivocation".into(),
            ));
        }
    }
    Ok(())
}

/// Verify a status snapshot without needing a peer binding, returning the
/// exact digest checkpoint that trusted local policy should persist.
pub fn verify_peer_status_snapshot(
    snapshot: &PeerStatusSnapshot,
    anchor: &PeerStatusAuthorityAnchor,
    max_age_ms: u64,
    expected_audience: &str,
    now_ms: u64,
) -> Result<PeerStatusCheckpoint, PeerBindingError> {
    verify_snapshot(snapshot, anchor, max_age_ms, expected_audience, now_ms)?;
    Ok(PeerStatusCheckpoint {
        epoch: snapshot.epoch,
        digest: snapshot.digest()?,
    })
}

fn verify_signature(
    signature: &Signature,
    expected_signer: &str,
    public_key: &[u8],
    payload: &[u8],
) -> Result<(), PeerBindingError> {
    if signature.algorithm != AlgorithmId::Ed25519
        || signature.signer_id != expected_signer
        || signature.payload_hash != sha256(payload)
        || !verify_ed25519(public_key, signature)
            .map_err(|e| PeerBindingError::Crypto(e.to_string()))?
    {
        return Err(PeerBindingError::Crypto(
            "signature verification failed".into(),
        ));
    }
    Ok(())
}

fn decode_ed25519_peer_key(bytes: &[u8]) -> Result<identity::PublicKey, PeerBindingError> {
    let key = identity::PublicKey::try_decode_protobuf(bytes)
        .map_err(|e| PeerBindingError::Invalid(format!("malformed libp2p public key: {e}")))?;
    if key.key_type() != identity::KeyType::Ed25519 {
        return Err(PeerBindingError::Invalid(
            "peer binding requires an Ed25519 libp2p key".into(),
        ));
    }
    Ok(key)
}

fn encode_public_key(out: &mut Vec<u8>, key: &aip_types::PublicKey) {
    put_u8(out, key.algorithm as u8);
    put_bytes(out, &key.key_bytes);
}

fn encode_optional_public_key(out: &mut Vec<u8>, key: &Option<aip_types::PublicKey>) {
    match key {
        Some(key) => {
            put_u8(out, 1);
            encode_public_key(out, key);
        }
        None => put_u8(out, 0),
    }
}

fn empty_signature(signer_id: &str) -> Signature {
    Signature {
        algorithm: AlgorithmId::Ed25519,
        signer_id: signer_id.to_string(),
        timestamp: 0,
        nonce: [0; 16],
        payload_hash: [0; 32],
        signature_bytes: Vec::new(),
    }
}

fn validate_text(value: &str, field: &str) -> Result<(), PeerBindingError> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(PeerBindingError::Invalid(format!("invalid {field}")));
    }
    Ok(())
}
