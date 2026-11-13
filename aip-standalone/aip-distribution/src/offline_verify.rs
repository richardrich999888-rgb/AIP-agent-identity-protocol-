//! Offline verification composition for signed package distribution evidence.
//!
//! Trust anchors are arguments supplied independently of the evidence. This
//! function does not perform installation, execution, network access, or
//! reconciliation into a `VerifiedExecution` result.

use crate::{
    authorization::{authorize_package_operation, PackageOperation, PackageResource},
    peer_binding::{verify_peer_binding, PeerBindingStatement, PeerBindingTrustAnchors},
    revocation_snapshot::{
        verify_revocation_snapshot, RevocationAuthorityAnchor, RevocationSnapshot,
        SnapshotCheckpoint,
    },
    verify_chunk, verify_manifest, TransferChunk, TransferManifest, MAX_TRANSFER_BYTES,
};
use aip_aibom::{
    canonical::manifest_digest_hex,
    seal::{verify_seal, Seal},
    Manifest,
};
use aip_crypto::sha256;
use aip_package::{package_from_export, verify_package_contents, PortablePackageExport};
use aip_types::{AgentIdentityDocument, DelegationToken, ScopedToken};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

pub struct OfflinePackageEvidence<'a> {
    /// Exact portable export bytes whose package signature is checked.
    pub export_bytes: &'a [u8],
    pub aibom_manifest: &'a Manifest,
    pub aibom_seal: &'a Seal,
    pub aid: &'a AgentIdentityDocument,
    pub peer_binding: &'a PeerBindingStatement,
    pub peer_status: &'a crate::peer_binding::PeerStatusSnapshot,
    pub capability: &'a ScopedToken,
    pub delegation_chain: &'a [DelegationToken],
    pub revocation_snapshot: &'a RevocationSnapshot,
    /// Optional proof bundle. If supplied, every chunk must be present in
    /// order, proof-valid, and byte-identical to the package export bytes.
    pub transfer: Option<OfflineTransferEvidence<'a>>,
}

#[derive(Clone, Copy)]
pub struct OfflineTransferEvidence<'a> {
    pub manifest: &'a TransferManifest,
    pub chunks: &'a [TransferChunk],
}

pub struct OfflinePackageTrust<'a> {
    pub publisher_id: &'a str,
    pub publisher_public_key: &'a [u8],
    pub aibom_publishers: &'a BTreeMap<String, Vec<u8>>,
    pub peer_binding_anchors: &'a PeerBindingTrustAnchors,
    pub capability_issuer_keys: &'a HashMap<String, Vec<u8>>,
    pub revocation_authority: Option<&'a RevocationAuthorityAnchor>,
    pub revocation_checkpoint: &'a SnapshotCheckpoint,
    pub expected_audience: &'a str,
    pub recipient_id: &'a str,
    pub operation: PackageOperation,
    pub now_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OfflinePackageVerificationReport {
    pub status: &'static str,
    pub package_name: String,
    pub package_version: String,
    pub publisher_id: String,
    pub archive_sha256: String,
    pub publisher_signature_verified: bool,
    pub aibom_digest: String,
    pub aibom_seal_verified: bool,
    pub peer_id: String,
    pub peer_binding_verified: bool,
    pub peer_status_epoch: u64,
    pub peer_status_snapshot_digest: String,
    pub capability_authorized: bool,
    pub authorization_action: String,
    pub revocation_snapshot_epoch: u64,
    pub revocation_snapshot_digest: String,
    pub transfer_evidence_verified: bool,
    pub execution_status: &'static str,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineVerifyError {
    Invalid(String),
    Untrusted(String),
    Denied(String),
}

impl std::fmt::Display for OfflineVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for OfflineVerifyError {}

/// Verify package, AIBOM seal, AIP peer binding, package capability and signed
/// revocation snapshot using only caller-supplied bytes and external anchors.
pub fn verify_offline_package_evidence(
    evidence: &OfflinePackageEvidence<'_>,
    trust: &OfflinePackageTrust<'_>,
) -> Result<OfflinePackageVerificationReport, OfflineVerifyError> {
    if evidence.export_bytes.is_empty() || evidence.export_bytes.len() as u64 > MAX_TRANSFER_BYTES {
        return Err(OfflineVerifyError::Invalid(
            "package export is empty or oversized".into(),
        ));
    }
    if trust.publisher_public_key.len() != 32 || trust.publisher_id.trim().is_empty() {
        return Err(OfflineVerifyError::Untrusted(
            "missing or malformed external publisher anchor".into(),
        ));
    }
    evidence
        .aibom_manifest
        .validate()
        .map_err(|e| OfflineVerifyError::Invalid(e.to_string()))?;
    let aibom_digest = manifest_digest_hex(evidence.aibom_manifest);
    verify_seal(
        evidence.aibom_seal,
        evidence.aibom_manifest,
        trust.aibom_publishers,
    )
    .map_err(|e| OfflineVerifyError::Untrusted(format!("AIBOM seal: {e}")))?;

    let export: PortablePackageExport = serde_json::from_slice(evidence.export_bytes)
        .map_err(|e| OfflineVerifyError::Invalid(format!("malformed package export: {e}")))?;
    if export.publisher_id != trust.publisher_id {
        return Err(OfflineVerifyError::Untrusted(
            "package publisher differs from external anchor identity".into(),
        ));
    }
    let (package, signature) = package_from_export(export)
        .map_err(|e| OfflineVerifyError::Invalid(format!("package export: {e}")))?;
    let verified = verify_package_contents(
        &package,
        &signature,
        trust.publisher_public_key,
        &aibom_digest,
    )
    .map_err(|e| OfflineVerifyError::Untrusted(format!("package verification: {e}")))?;

    let peer_id = verify_peer_binding(
        evidence.peer_binding,
        evidence.aid,
        evidence.peer_status,
        trust.peer_binding_anchors,
        trust.expected_audience,
        trust.now_ms,
        None,
    )
    .map_err(|e| OfflineVerifyError::Untrusted(format!("peer binding: {e}")))?;

    let peer_status_anchor = trust
        .peer_binding_anchors
        .status_authority(&evidence.peer_status.signer_id)
        .ok_or_else(|| OfflineVerifyError::Untrusted("missing peer-status trust anchor".into()))?;
    if !peer_status_anchor.checkpoint_pinned() {
        return Err(OfflineVerifyError::Untrusted(
            "offline peer-status verification requires a digest-pinned checkpoint".into(),
        ));
    }

    let revocations = verify_revocation_snapshot(
        evidence.revocation_snapshot,
        trust.revocation_authority,
        Some(trust.revocation_checkpoint),
        trust.expected_audience,
        trust.now_ms,
    )
    .map_err(|e| OfflineVerifyError::Untrusted(format!("revocation snapshot: {e}")))?;
    let resource = PackageResource {
        package_id: verified.manifest().name.clone(),
        publisher_id: verified.manifest().publisher_id.clone(),
        release_digest: *verified.archive_sha256(),
        recipient_id: trust.recipient_id.to_string(),
    };
    let authorization = authorize_package_operation(
        trust.operation,
        &resource,
        &evidence.aid.id,
        evidence.capability,
        evidence.delegation_chain,
        trust.capability_issuer_keys,
        &revocations,
        trust.now_ms,
    )
    .map_err(|e| match e {
        crate::authorization::AuthorizationError::Invalid(message) => {
            OfflineVerifyError::Invalid(message)
        }
        crate::authorization::AuthorizationError::Untrusted(message) => {
            OfflineVerifyError::Untrusted(message)
        }
        crate::authorization::AuthorizationError::Denied(message) => {
            OfflineVerifyError::Denied(message)
        }
    })?;

    let transfer_verified = if let Some(transfer) = evidence.transfer {
        verify_offline_transfer(
            transfer,
            trust.publisher_id,
            trust.publisher_public_key,
            &package.manifest.name,
            &package.manifest.version,
            package.manifest.format_version,
            &package.archive_sha256,
            evidence.export_bytes,
        )?;
        true
    } else {
        false
    };

    Ok(OfflinePackageVerificationReport {
        status: "INPUTS_VERIFIED",
        package_name: verified.manifest().name.clone(),
        package_version: verified.manifest().version.clone(),
        publisher_id: verified.manifest().publisher_id.clone(),
        archive_sha256: hex::encode(verified.archive_sha256()),
        publisher_signature_verified: true,
        aibom_digest,
        aibom_seal_verified: true,
        peer_id: peer_id.to_string(),
        peer_binding_verified: true,
        peer_status_epoch: evidence.peer_status.epoch,
        peer_status_snapshot_digest: hex::encode(
            evidence.peer_status.digest().map_err(|e| {
                OfflineVerifyError::Untrusted(format!("peer status snapshot: {e}"))
            })?,
        ),
        capability_authorized: true,
        authorization_action: authorization.resource_action,
        revocation_snapshot_epoch: revocations.epoch(),
        revocation_snapshot_digest: hex::encode(revocations.digest()),
        transfer_evidence_verified: transfer_verified,
        execution_status: "NOT_EVALUATED",
        limitations: vec![
            "INPUTS_VERIFIED authenticates supplied package and authorization inputs; it is not an execution result.",
            "A package signature does not establish package safety or installation permission beyond the checked capability.",
            "Peer binding authenticates the bound libp2p key and AIP claim; it does not prove physical observations or business effects.",
            "If transfer evidence is absent, this report does not attest to chunk receipt or transport history.",
            "Snapshot rollback protection depends on independently persisted trusted checkpoint state.",
        ],
    })
}

fn verify_offline_transfer(
    evidence: OfflineTransferEvidence<'_>,
    publisher_id: &str,
    publisher_key: &[u8],
    package_name: &str,
    package_version: &str,
    package_format_version: u16,
    archive_sha256: &[u8; 32],
    export_bytes: &[u8],
) -> Result<(), OfflineVerifyError> {
    let export_len = u64::try_from(export_bytes.len())
        .map_err(|_| OfflineVerifyError::Invalid("package export length overflow".into()))?;
    let expected_chunk_count = usize::try_from(evidence.manifest.chunk_count)
        .map_err(|_| OfflineVerifyError::Invalid("transfer chunk count overflow".into()))?;
    verify_manifest(evidence.manifest, publisher_id, publisher_key)
        .map_err(|e| OfflineVerifyError::Untrusted(format!("transfer manifest: {e}")))?;
    if evidence.manifest.package_name != package_name
        || evidence.manifest.package_version != package_version
        || evidence.manifest.package_format_version != package_format_version
        || evidence.manifest.archive_sha256 != hex::encode(archive_sha256)
        || evidence.manifest.export_len != export_len
        || evidence.manifest.export_sha256 != hex::encode(sha256(export_bytes))
        || evidence.chunks.len() != expected_chunk_count
    {
        return Err(OfflineVerifyError::Invalid(
            "transfer evidence does not bind the verified package export".into(),
        ));
    }
    let chunk_size = usize::try_from(evidence.manifest.chunk_size)
        .map_err(|_| OfflineVerifyError::Invalid("transfer chunk size overflow".into()))?;
    for (index, chunk) in evidence.chunks.iter().enumerate() {
        let expected_index = u32::try_from(index)
            .map_err(|_| OfflineVerifyError::Invalid("transfer index overflow".into()))?;
        if chunk.index != expected_index {
            return Err(OfflineVerifyError::Invalid(
                "transfer chunks are missing, duplicated, or reordered".into(),
            ));
        }
        verify_chunk(evidence.manifest, chunk)
            .map_err(|e| OfflineVerifyError::Untrusted(format!("transfer chunk proof: {e}")))?;
        let offset = index
            .checked_mul(chunk_size)
            .ok_or_else(|| OfflineVerifyError::Invalid("transfer offset overflow".into()))?;
        let end = offset
            .checked_add(chunk.bytes.len())
            .ok_or_else(|| OfflineVerifyError::Invalid("transfer chunk extent overflow".into()))?;
        if export_bytes.get(offset..end) != Some(chunk.bytes.as_slice()) {
            return Err(OfflineVerifyError::Invalid(
                "chunk bytes differ from the verified package export".into(),
            ));
        }
    }
    Ok(())
}
