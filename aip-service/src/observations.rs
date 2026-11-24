//! Admission and retrieval of historical collector archives. Uses the existing
//! offline verifier and artifact store; never translates a signature check
//! into a current-coverage, off-host-deployment or business-outcome claim.
use crate::{
    artifacts::{ArtifactKind, ArtifactStoreError, StoredArtifact},
    auth::{Principal, Role},
    models::ErrorBody,
    AppState,
};
use aip_observe_verify::{
    report::ChainReport,
    verify::{parse_jsonl, verify_archives},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

type ApiError = (StatusCode, Json<ErrorBody>);
const SCOPE: &str = "historical_signature_integrity";
const MAX_ARCHIVE_BYTES: usize = 512 * 1024;
const MAX_RECORDS: usize = 2048;

fn error(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

/// Public trust anchors supplied by the institution, never by an archive
/// submission. Loading is strict so a typo cannot silently disable checking.
#[derive(Debug, Default)]
pub struct ObserverTrustStore {
    anchors: BTreeMap<(String, String, u32), [u8; 32]>,
    source_sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    anchors: Vec<TrustEntry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustEntry {
    tenant_id: String,
    observer_id: String,
    key_version: u32,
    public_key_hex: String,
}
impl ObserverTrustStore {
    pub fn load(path: Option<&str>) -> Result<Self, String> {
        match path {
            None => Ok(Self::default()),
            Some(path) if path.trim().is_empty() => {
                Err("AIP_OBSERVER_TRUST_PATH must not be empty".into())
            }
            Some(path) => {
                let metadata = std::fs::metadata(path)
                    .map_err(|e| format!("cannot read observer trust file: {e}"))?;
                if metadata.len() > 256 * 1024 {
                    return Err("observer trust file exceeds 256 KiB".into());
                }
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read observer trust file: {e}"))?;
                Self::from_json(&text)
            }
        }
    }
    pub fn from_json(text: &str) -> Result<Self, String> {
        let config: TrustFile = serde_json::from_str(text)
            .map_err(|e| format!("invalid observer trust configuration: {e}"))?;
        if config.anchors.len() > 1024 {
            return Err("too many observer anchors".into());
        }
        let mut result = Self::default();
        for anchor in config.anchors {
            if !valid_id(&anchor.tenant_id)
                || !valid_id(&anchor.observer_id)
                || anchor.key_version == 0
            {
                return Err("invalid tenant, observer identifier or key version".into());
            }
            let public_key = hex::decode(&anchor.public_key_hex)
                .map_err(|_| "observer public key must be hexadecimal")?;
            let public_key: [u8; 32] = public_key
                .try_into()
                .map_err(|_| "observer public key must be 32 bytes")?;
            if result
                .anchors
                .insert(
                    (anchor.tenant_id, anchor.observer_id, anchor.key_version),
                    public_key,
                )
                .is_some()
            {
                return Err("duplicate tenant/observer/key-version anchor".into());
            }
        }
        result.source_sha256 = Some(hex::encode(aip_crypto::sha256(text.as_bytes())));
        Ok(result)
    }
    /// Fingerprint of the loaded public-anchor configuration, for the
    /// institution's deployment audit trail. No signing secrets are loaded.
    pub fn source_sha256(&self) -> Option<&str> {
        self.source_sha256.as_deref()
    }
    fn key(&self, tenant: &str, observer: &str, version: u32) -> Result<&[u8; 32], ApiError> {
        if self.anchors.is_empty() {
            return Err(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "observer archive admission has no configured trust anchors",
            ));
        }
        self.anchors
            .get(&(tenant.into(), observer.into(), version))
            .ok_or_else(|| {
                error(
                    StatusCode::FORBIDDEN,
                    "observer anchor is not approved for this tenant",
                )
            })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationArchive {
    pub observer_id: String,
    pub key_version: u32,
    pub batches_jsonl: String,
    pub health_jsonl: String,
}
impl ObservationArchive {
    fn validate(&self) -> Result<(), ApiError> {
        if !valid_id(&self.observer_id) || self.key_version == 0 {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "invalid observer identifier or key version",
            ));
        }
        if self
            .batches_jsonl
            .len()
            .saturating_add(self.health_jsonl.len())
            > MAX_ARCHIVE_BYTES
        {
            return Err(error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "decoded archives exceed 512 KiB",
            ));
        }
        for text in [&self.batches_jsonl, &self.health_jsonl] {
            let count = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .take(MAX_RECORDS + 1)
                .count();
            if count == 0 || count > MAX_RECORDS {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    "each archive must contain 1..2048 records",
                ));
            }
        }
        Ok(())
    }
    fn report(&self, anchors: &ObserverTrustStore, tenant: &str) -> Result<ChainReport, ApiError> {
        self.validate()?;
        let key = anchors.key(tenant, &self.observer_id, self.key_version)?;
        Ok(verify_archives(
            &self.observer_id,
            self.key_version,
            key,
            Some(parse_jsonl(&self.batches_jsonl)),
            Some(parse_jsonl(&self.health_jsonl)),
        ))
    }
    fn id(&self, tenant: &str) -> Result<String, ApiError> {
        let body = serde_json::to_vec(self)
            .map_err(|_| error(StatusCode::BAD_REQUEST, "archive is not serializable"))?;
        // Struct field order is deterministic; JSON length-encodes and
        // escapes each string. The domain separates this index from all
        // protocol signatures and existing signed-artifact digests.
        let mut input = b"VANIAN/ObserverArchive/v1\0".to_vec();
        // The storage index belongs to the authenticated tenant. Two
        // institutions explicitly trusting the same snapshot must not
        // collide in the shared artifact store or learn each other's rows.
        input.extend_from_slice(&(tenant.len() as u64).to_be_bytes());
        input.extend_from_slice(tenant.as_bytes());
        input.extend(body);
        Ok(hex::encode(aip_crypto::sha256(&input)))
    }
}

#[derive(Serialize)]
pub struct ArchiveFiled {
    pub observation_id: String,
    pub kind: &'static str,
    pub verification_scope: &'static str,
}
fn store_error(e: ArtifactStoreError) -> ApiError {
    match e {
        ArtifactStoreError::TenantConflict => error(StatusCode::NOT_FOUND, "not found"),
        other => {
            tracing::error!(error=%other,"observer artifact store");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "artifact store unavailable",
            )
        }
    }
}

pub async fn submit(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Json(archive): Json<ObservationArchive>,
) -> Result<Json<ArchiveFiled>, ApiError> {
    if principal.role == Role::Reader {
        return Err(error(StatusCode::FORBIDDEN, "writer credential required"));
    }
    let report = archive.report(&state.observer_trust, &principal.tenant_id)?;
    if !report.ok() {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "observer archive signatures or chain did not verify; archive not stored",
        ));
    }
    let id = archive.id(&principal.tenant_id)?;
    let body = serde_json::to_string(&archive)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "archive is not serializable"))?;
    state
        .artifacts
        .put(StoredArtifact {
            id: id.clone(),
            kind: ArtifactKind::ObserverArchive,
            tenant_id: principal.tenant_id,
            agent_id: None,
            from_ms: None,
            to_ms: None,
            stored_at_ms: crate::store::now_ms() as i64,
            body,
        })
        .await
        .map_err(store_error)?;
    Ok(Json(ArchiveFiled {
        observation_id: id,
        kind: "observer_archive",
        verification_scope: SCOPE,
    }))
}

async fn archive(
    state: &AppState,
    principal: &Principal,
    id: &str,
) -> Result<ObservationArchive, ApiError> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid observation identifier",
        ));
    }
    let record = state
        .artifacts
        .get(&principal.tenant_id, ArtifactKind::ObserverArchive, id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "not found"))?;
    let archive: ObservationArchive = serde_json::from_str(&record.body)
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "stored archive is damaged"))?;
    if archive.id(&principal.tenant_id)? != id {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "stored archive digest mismatch",
        ));
    }
    Ok(archive)
}

pub async fn raw(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<ObservationArchive>, ApiError> {
    if principal.role == Role::Reader {
        return Err(error(
            StatusCode::FORBIDDEN,
            "raw archive retrieval requires writer access",
        ));
    }
    Ok(Json(archive(&state, &principal, &id).await?))
}

#[derive(Serialize)]
pub struct ArchiveMetadata {
    pub observation_id: String,
    pub observer_id: String,
    pub key_version: u32,
    pub batch_records: usize,
    pub health_records: usize,
    pub archive_bytes: usize,
    pub verification_scope: &'static str,
    pub current_coverage_established: bool,
    pub offhost_separation_established: bool,
    pub execution_correlation_established: bool,
}
pub async fn metadata(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<ArchiveMetadata>, ApiError> {
    let archive = archive(&state, &principal, &id).await?;
    let report = archive.report(&state.observer_trust, &principal.tenant_id)?;
    if !report.ok() {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "stored observer archive no longer verifies",
        ));
    }
    Ok(Json(ArchiveMetadata {
        observation_id: id,
        observer_id: archive.observer_id,
        key_version: archive.key_version,
        batch_records: report.batches.as_ref().map_or(0, |b| b.records),
        health_records: report.health.as_ref().map_or(0, |h| h.records),
        archive_bytes: archive.batches_jsonl.len() + archive.health_jsonl.len(),
        verification_scope: SCOPE,
        current_coverage_established: false,
        offhost_separation_established: false,
        execution_correlation_established: false,
    }))
}

#[derive(Serialize)]
pub struct ArchiveVerification {
    pub observation_id: String,
    pub verification_scope: &'static str,
    pub verified: bool,
    pub report: ChainReport,
    pub limitations: Vec<&'static str>,
}
pub async fn verification(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<ArchiveVerification>, ApiError> {
    let archive = archive(&state, &principal, &id).await?;
    let report = archive.report(&state.observer_trust, &principal.tenant_id)?;
    Ok(Json(ArchiveVerification { observation_id:id,verification_scope:SCOPE,verified:report.ok(),report,
        limitations:vec!["This verifies historical signatures and archive chain integrity under institution-configured observer anchors.",
            "It does not establish current observation coverage, physical off-host key separation, truthful probe input, execution attribution or a banking business outcome.",
            "An idempotent archive submission is not a stream-level replay or continuity admission check across separate uploaded archives."] }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn configured_observer_trust_fails_closed_and_rejects_ambiguous_anchors() {
        assert!(ObserverTrustStore::load(None).unwrap().anchors.is_empty());
        assert!(ObserverTrustStore::load(Some("")).is_err());
        assert!(ObserverTrustStore::load(Some("/nonexistent/vanian-observer-trust-file")).is_err());
        let entry = json!({"tenant_id":"tenant-a","observer_id":"collector-a","key_version":1,
            "public_key_hex":"11".repeat(32)});
        assert!(ObserverTrustStore::from_json(
            &json!({"anchors":[entry.clone(),entry.clone()]}).to_string()
        )
        .is_err());
        let mut short = entry.clone();
        short["public_key_hex"] = json!("11");
        assert!(ObserverTrustStore::from_json(&json!({"anchors":[short]}).to_string()).is_err());
        let trusted =
            ObserverTrustStore::from_json(&json!({"anchors":[entry]}).to_string()).unwrap();
        assert!(trusted.source_sha256().is_some());
        assert!(trusted.key("tenant-a", "collector-a", 1).is_ok());
        assert!(trusted.key("tenant-b", "collector-a", 1).is_err());
        assert!(trusted.key("tenant-a", "collector-a", 2).is_err());
    }
}
