//! Externally anchored, signed distribution revocation snapshots.
//!
//! A snapshot is a signed point-in-time set, not a replacement for the
//! append-only `aip-core::RevocationLog`. Its signer and epoch policy must be
//! provisioned independently. The returned checkpoint must be persisted by
//! rollback-resistant trusted policy storage to detect later equivocation.

use aip_crypto::{custody::Custodian, sha256, verify_ed25519};
use aip_types::{
    canonical::{encode_signature, put_domain, put_str, put_u16, put_u32, put_u64, put_u8},
    AlgorithmId, RevocationReason, Signature,
};
use serde::{Deserialize, Serialize};

pub const REVOCATION_SNAPSHOT_VERSION: u16 = 1;
pub const REVOCATION_SNAPSHOT_DOMAIN: &str = "AIP/DISTRIBUTION/REVOCATION_SNAPSHOT/v1";
pub const REVOCATION_SNAPSHOT_DIGEST_DOMAIN: &str =
    "AIP/DISTRIBUTION/REVOCATION_SNAPSHOT_DIGEST/v1";
pub const MAX_REVOCATION_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_REVOCATION_ENTRIES: usize = 100_000;

pub fn parse_revocation_snapshot(bytes: &[u8]) -> Result<RevocationSnapshot, SnapshotError> {
    if bytes.len() > MAX_REVOCATION_SNAPSHOT_BYTES {
        return Err(SnapshotError::Invalid(
            "encoded revocation snapshot exceeds maximum size".into(),
        ));
    }
    let snapshot: RevocationSnapshot = serde_json::from_slice(bytes)
        .map_err(|e| SnapshotError::Invalid(format!("malformed revocation snapshot: {e}")))?;
    snapshot.signing_bytes()?;
    Ok(snapshot)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevokedCapability {
    pub jti: [u8; 16],
    pub revoked_at_ms: u64,
    pub reason: RevocationReason,
    pub revoked_by: String,
}

/// Compact current-state snapshot. Entries must be sorted strictly by JTI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevocationSnapshot {
    pub version: u16,
    pub issuer_id: String,
    pub epoch: u64,
    pub issued_at_ms: u64,
    pub valid_until_ms: u64,
    pub audience: String,
    pub revoked: Vec<RevokedCapability>,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    Invalid(String),
    Untrusted(String),
    Signature(String),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SnapshotError {}

impl RevocationSnapshot {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, SnapshotError> {
        if self.version != REVOCATION_SNAPSHOT_VERSION
            || self.epoch == 0
            || self.issued_at_ms >= self.valid_until_ms
            || self.revoked.len() > MAX_REVOCATION_ENTRIES
        {
            return Err(SnapshotError::Invalid(
                "invalid snapshot header or bounds".into(),
            ));
        }
        validate_text(&self.issuer_id, "issuer_id")?;
        validate_text(&self.audience, "audience")?;
        let mut previous: Option<[u8; 16]> = None;
        let mut out = Vec::new();
        put_domain(&mut out, REVOCATION_SNAPSHOT_DOMAIN);
        put_u16(&mut out, self.version);
        put_str(&mut out, &self.issuer_id);
        put_u64(&mut out, self.epoch);
        put_u64(&mut out, self.issued_at_ms);
        put_u64(&mut out, self.valid_until_ms);
        put_str(&mut out, &self.audience);
        put_u32(&mut out, self.revoked.len() as u32);
        for entry in &self.revoked {
            if previous.is_some_and(|jti| jti >= entry.jti) {
                return Err(SnapshotError::Invalid(
                    "revocations must be sorted by unique JTI".into(),
                ));
            }
            validate_text(&entry.revoked_by, "revoked_by")?;
            if entry.revoked_at_ms > self.issued_at_ms {
                return Err(SnapshotError::Invalid(
                    "revocation time is later than snapshot issuance".into(),
                ));
            }
            previous = Some(entry.jti);
            out.extend_from_slice(&entry.jti);
            put_u64(&mut out, entry.revoked_at_ms);
            put_u8(&mut out, entry.reason as u8);
            put_str(&mut out, &entry.revoked_by);
            if out.len() > MAX_REVOCATION_SNAPSHOT_BYTES {
                return Err(SnapshotError::Invalid(
                    "snapshot exceeds maximum size".into(),
                ));
            }
        }
        Ok(out)
    }

    pub fn sign(
        issuer_id: &str,
        epoch: u64,
        issued_at_ms: u64,
        valid_until_ms: u64,
        audience: &str,
        revoked: Vec<RevokedCapability>,
        custodian: &dyn Custodian,
    ) -> Result<Self, SnapshotError> {
        let mut snapshot = Self {
            version: REVOCATION_SNAPSHOT_VERSION,
            issuer_id: issuer_id.to_string(),
            epoch,
            issued_at_ms,
            valid_until_ms,
            audience: audience.to_string(),
            revoked,
            signature: empty_signature(issuer_id),
        };
        let payload = snapshot.signing_bytes()?;
        snapshot.signature = custodian
            .sign(issuer_id, &payload)
            .map_err(|e| SnapshotError::Signature(e.to_string()))?;
        verify_signature(
            &snapshot.signature,
            issuer_id,
            custodian.public_key(),
            &payload,
        )?;
        Ok(snapshot)
    }

    /// Stable digest over the canonical payload and complete signature envelope.
    pub fn digest(&self) -> Result<[u8; 32], SnapshotError> {
        let mut bytes = Vec::new();
        put_domain(&mut bytes, REVOCATION_SNAPSHOT_DIGEST_DOMAIN);
        bytes.extend_from_slice(&self.signing_bytes()?);
        encode_signature(&mut bytes, &self.signature);
        Ok(sha256(&bytes))
    }
}

#[derive(Debug, Clone)]
pub struct RevocationAuthorityAnchor {
    issuer_id: String,
    public_key: Vec<u8>,
    minimum_epoch: u64,
    audience: String,
    maximum_age_ms: u64,
    maximum_lifetime_ms: u64,
}

impl RevocationAuthorityAnchor {
    /// Configure only from independently authenticated policy. This does not
    /// create an organization root or infer trust from the snapshot itself.
    pub fn new(
        issuer_id: String,
        public_key: Vec<u8>,
        minimum_epoch: u64,
        audience: String,
        maximum_age_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<Self, SnapshotError> {
        validate_text(&issuer_id, "issuer_id")?;
        validate_text(&audience, "audience")?;
        if public_key.len() != 32
            || minimum_epoch == 0
            || maximum_age_ms == 0
            || maximum_lifetime_ms == 0
        {
            return Err(SnapshotError::Untrusted(
                "invalid revocation trust policy".into(),
            ));
        }
        Ok(Self {
            issuer_id,
            public_key,
            minimum_epoch,
            audience,
            maximum_age_ms,
            maximum_lifetime_ms,
        })
    }
}

/// Persist this value in independently protected, rollback-resistant policy
/// storage. A plain file copied with the bundle is not a trusted checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCheckpoint {
    pub epoch: u64,
    pub digest: [u8; 32],
}

impl SnapshotCheckpoint {
    pub fn new(epoch: u64, digest: [u8; 32]) -> Result<Self, SnapshotError> {
        if epoch == 0 || digest == [0; 32] {
            return Err(SnapshotError::Untrusted(
                "invalid trusted snapshot checkpoint".into(),
            ));
        }
        Ok(Self { epoch, digest })
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedRevocationSnapshot {
    snapshot: RevocationSnapshot,
    digest: [u8; 32],
    verified_at_ms: u64,
    maximum_age_ms: u64,
    checkpoint: SnapshotCheckpoint,
}

impl VerifiedRevocationSnapshot {
    pub fn checkpoint(&self) -> &SnapshotCheckpoint {
        &self.checkpoint
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn epoch(&self) -> u64 {
        self.snapshot.epoch
    }
    pub fn issuer_id(&self) -> &str {
        &self.snapshot.issuer_id
    }
    pub fn audience(&self) -> &str {
        &self.snapshot.audience
    }

    pub fn ensure_fresh(&self, audience: &str, now_ms: u64) -> Result<(), SnapshotError> {
        if audience != self.snapshot.audience
            || now_ms < self.snapshot.issued_at_ms
            || now_ms > self.snapshot.valid_until_ms
            || now_ms.saturating_sub(self.snapshot.issued_at_ms) > self.maximum_age_ms
            || now_ms.saturating_sub(self.verified_at_ms) > self.maximum_age_ms
        {
            return Err(SnapshotError::Untrusted(
                "revocation snapshot is stale or for another audience".into(),
            ));
        }
        Ok(())
    }

    pub fn is_revoked(&self, jti: &[u8; 16]) -> bool {
        self.snapshot
            .revoked
            .binary_search_by_key(jti, |entry| entry.jti)
            .is_ok()
    }
}

/// Verify signature, anchor, time window, audience, epoch floor, and pinned
/// digest. Equal epochs are idempotent only for the identical signed snapshot;
/// lower epochs and same-epoch equivocation fail closed.
pub fn verify_revocation_snapshot(
    snapshot: &RevocationSnapshot,
    anchor: Option<&RevocationAuthorityAnchor>,
    checkpoint: Option<&SnapshotCheckpoint>,
    audience: &str,
    now_ms: u64,
) -> Result<VerifiedRevocationSnapshot, SnapshotError> {
    let anchor =
        anchor.ok_or_else(|| SnapshotError::Untrusted("missing revocation trust anchor".into()))?;
    if snapshot.issuer_id != anchor.issuer_id
        || snapshot.audience != audience
        || audience != anchor.audience
    {
        return Err(SnapshotError::Untrusted(
            "revocation issuer or audience mismatch".into(),
        ));
    }
    let bytes = snapshot.signing_bytes()?;
    if snapshot.issued_at_ms > now_ms
        || snapshot.valid_until_ms < now_ms
        || now_ms.saturating_sub(snapshot.issued_at_ms) > anchor.maximum_age_ms
        || snapshot
            .valid_until_ms
            .saturating_sub(snapshot.issued_at_ms)
            > anchor.maximum_lifetime_ms
        || snapshot.epoch < anchor.minimum_epoch
    {
        return Err(SnapshotError::Untrusted(
            "revocation snapshot is stale, expired, or below minimum epoch".into(),
        ));
    }
    verify_signature(
        &snapshot.signature,
        &anchor.issuer_id,
        &anchor.public_key,
        &bytes,
    )?;
    let digest = snapshot.digest()?;
    if let Some(previous) = checkpoint {
        if previous.epoch < anchor.minimum_epoch || snapshot.epoch < previous.epoch {
            return Err(SnapshotError::Untrusted(
                "revocation snapshot epoch rollback".into(),
            ));
        }
        if snapshot.epoch == previous.epoch && digest != previous.digest {
            return Err(SnapshotError::Untrusted(
                "same-epoch revocation snapshot equivocation".into(),
            ));
        }
    }
    Ok(VerifiedRevocationSnapshot {
        snapshot: snapshot.clone(),
        digest,
        verified_at_ms: now_ms,
        maximum_age_ms: anchor.maximum_age_ms,
        checkpoint: SnapshotCheckpoint {
            epoch: snapshot.epoch,
            digest,
        },
    })
}

fn verify_signature(
    signature: &Signature,
    issuer: &str,
    key: &[u8],
    payload: &[u8],
) -> Result<(), SnapshotError> {
    if signature.algorithm != AlgorithmId::Ed25519
        || signature.signer_id != issuer
        || signature.payload_hash != sha256(payload)
        || !verify_ed25519(key, signature).map_err(|e| SnapshotError::Signature(e.to_string()))?
    {
        return Err(SnapshotError::Signature(
            "revocation snapshot signature invalid".into(),
        ));
    }
    Ok(())
}

fn empty_signature(issuer: &str) -> Signature {
    Signature {
        algorithm: AlgorithmId::Ed25519,
        signer_id: issuer.to_string(),
        timestamp: 0,
        nonce: [0; 16],
        payload_hash: [0; 32],
        signature_bytes: Vec::new(),
    }
}

fn validate_text(value: &str, label: &str) -> Result<(), SnapshotError> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(SnapshotError::Invalid(format!("invalid {label}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_crypto::custody::InMemoryCustodian;

    const NOW: u64 = 1_800_000_000_000;

    fn fixture(
        epoch: u64,
        jti: u8,
    ) -> (
        RevocationSnapshot,
        InMemoryCustodian,
        RevocationAuthorityAnchor,
    ) {
        let signer = InMemoryCustodian::generate();
        let anchor = RevocationAuthorityAnchor::new(
            "aip:revocation-authority".into(),
            signer.public_key().to_vec(),
            4,
            "/aip/distribution/1.0.0".into(),
            10_000,
            20_000,
        )
        .unwrap();
        let snapshot = RevocationSnapshot::sign(
            "aip:revocation-authority",
            epoch,
            NOW - 10,
            NOW + 5_000,
            "/aip/distribution/1.0.0",
            vec![RevokedCapability {
                jti: [jti; 16],
                revoked_at_ms: NOW - 100,
                reason: RevocationReason::AdminRevocation,
                revoked_by: "aip:admin".into(),
            }],
            &signer,
        )
        .unwrap();
        (snapshot, signer, anchor)
    }

    #[test]
    fn externally_anchored_snapshot_verifies_and_pins_digest() {
        let (snapshot, _, anchor) = fixture(4, 7);
        let verified = verify_revocation_snapshot(
            &snapshot,
            Some(&anchor),
            None,
            "/aip/distribution/1.0.0",
            NOW,
        )
        .unwrap();
        assert!(verified.is_revoked(&[7; 16]));
        assert!(!verified.is_revoked(&[8; 16]));
        assert_eq!(verified.checkpoint().epoch, 4);
        assert!(verify_revocation_snapshot(
            &snapshot,
            Some(&anchor),
            Some(verified.checkpoint()),
            "/aip/distribution/1.0.0",
            NOW
        )
        .is_ok());
    }

    #[test]
    fn missing_anchor_stale_audience_and_rollback_fail_closed() {
        let (snapshot, _, anchor) = fixture(4, 7);
        assert!(
            verify_revocation_snapshot(&snapshot, None, None, "/aip/distribution/1.0.0", NOW)
                .is_err()
        );
        assert!(verify_revocation_snapshot(&snapshot, Some(&anchor), None, "/other", NOW).is_err());
        assert!(verify_revocation_snapshot(
            &snapshot,
            Some(&anchor),
            None,
            "/aip/distribution/1.0.0",
            NOW + 10_001
        )
        .is_err());
        let old = SnapshotCheckpoint::new(5, [9; 32]).unwrap();
        assert!(verify_revocation_snapshot(
            &snapshot,
            Some(&anchor),
            Some(&old),
            "/aip/distribution/1.0.0",
            NOW
        )
        .is_err());
    }

    #[test]
    fn tampering_invalid_signature_and_same_epoch_equivocation_are_rejected() {
        let (snapshot, signer, anchor) = fixture(4, 7);
        let accepted = verify_revocation_snapshot(
            &snapshot,
            Some(&anchor),
            None,
            "/aip/distribution/1.0.0",
            NOW,
        )
        .unwrap();
        let mut tampered = snapshot.clone();
        tampered.revoked[0].jti = [8; 16];
        assert!(verify_revocation_snapshot(
            &tampered,
            Some(&anchor),
            None,
            "/aip/distribution/1.0.0",
            NOW
        )
        .is_err());
        let mut bad_signature = snapshot.clone();
        bad_signature.signature.signature_bytes[0] ^= 1;
        assert!(verify_revocation_snapshot(
            &bad_signature,
            Some(&anchor),
            None,
            "/aip/distribution/1.0.0",
            NOW
        )
        .is_err());
        let conflicting = RevocationSnapshot::sign(
            "aip:revocation-authority",
            4,
            NOW - 10,
            NOW + 5_000,
            "/aip/distribution/1.0.0",
            vec![RevokedCapability {
                jti: [9; 16],
                revoked_at_ms: NOW - 100,
                reason: RevocationReason::AdminRevocation,
                revoked_by: "aip:admin".into(),
            }],
            &signer,
        )
        .unwrap();
        assert!(verify_revocation_snapshot(
            &conflicting,
            Some(&anchor),
            Some(accepted.checkpoint()),
            "/aip/distribution/1.0.0",
            NOW
        )
        .is_err());
        assert_ne!(snapshot.digest().unwrap(), conflicting.digest().unwrap());
    }

    #[test]
    fn entries_must_be_sorted_and_unique() {
        let (mut snapshot, _, _) = fixture(4, 7);
        snapshot.revoked.push(snapshot.revoked[0].clone());
        assert!(snapshot.signing_bytes().is_err());
    }

    #[test]
    fn parser_rejects_unknown_malformed_and_oversized_snapshots() {
        assert!(parse_revocation_snapshot(b"not-json").is_err());
        assert!(parse_revocation_snapshot(br#"{"version":1,"unexpected":true}"#).is_err());
        assert!(parse_revocation_snapshot(&vec![b'x'; MAX_REVOCATION_SNAPSHOT_BYTES + 1]).is_err());
        let (snapshot, _, _) = fixture(4, 7);
        let bytes = serde_json::to_vec(&snapshot).unwrap();
        assert_eq!(parse_revocation_snapshot(&bytes).unwrap(), snapshot);
    }
}
