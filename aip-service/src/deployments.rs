//! Administrator-approved configuration inventory, deliberately outside signed
//! evidence. Registration never installs a probe, grants authority, changes
//! verifier anchors or establishes a workload identity or live coverage.
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use axum::{
    extract::{Path as ApiPath, Query},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{AdminPrincipal, Principal},
    enterprise::{Page, PageQuery},
    models::ErrorBody,
};

const MAX_RECORDS: usize = 10_000;
const MAX_JOURNAL: u64 = 64 * 1024 * 1024;
const MAX_DEFINITION: usize = 24 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRegistration {
    pub host_id: String,
    pub admin_group: String,
    pub probe_id: String,
    pub transport_public_key_hex: String,
    pub logical_agent_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorRegistration {
    pub host_id: String,
    pub admin_group: String,
    pub observer_id: String,
    pub noise_public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentDefinition {
    pub schema_version: String,
    pub deployment_name: String,
    pub workloads: Vec<WorkloadRegistration>,
    pub collector: CollectorRegistration,
    pub retention_days_requested: u32,
    pub contextforge: bool,
    pub evidence_mcp: bool,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn public_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value != "00".repeat(32)
}
impl DeploymentDefinition {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != "vanian.deployment.v1"
            || !identifier(&self.deployment_name)
            || !(1..=20).contains(&self.workloads.len())
            || !(1..=3650).contains(&self.retention_days_requested)
            || !identifier(&self.collector.host_id)
            || !identifier(&self.collector.admin_group)
            || !identifier(&self.collector.observer_id)
            || !public_key(&self.collector.noise_public_key_hex)
        {
            return Err("invalid deployment configuration");
        }
        let mut hosts = std::collections::HashSet::new();
        let mut probes = std::collections::HashSet::new();
        let mut keys = std::collections::HashSet::new();
        for w in &self.workloads {
            if !identifier(&w.host_id)
                || !identifier(&w.admin_group)
                || !identifier(&w.probe_id)
                || !public_key(&w.transport_public_key_hex)
                || w.logical_agent_ids.len() > 20
                || w.logical_agent_ids.iter().any(|id| !identifier(id))
                || w.logical_agent_ids
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    != w.logical_agent_ids.len()
                || w.host_id == self.collector.host_id
                || w.admin_group == self.collector.admin_group
                || !hosts.insert(&w.host_id)
                || !probes.insert(&w.probe_id)
                || !keys.insert(&w.transport_public_key_hex)
            {
                return Err("ambiguous workload references or shared collector administration");
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| "invalid configuration")?
            .len()
            > MAX_DEFINITION
        {
            return Err("deployment configuration exceeds limit");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRecord {
    pub tenant_id: String,
    pub definition: DeploymentDefinition,
    pub registered_at_ms: u64,
    pub registered_by_key_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegistryError {
    Disabled,
    Unavailable,
    Conflict,
    Limit,
}
struct Journal {
    file: File,
    rows: BTreeMap<(String, String), DeploymentRecord>,
    failed: bool,
}
pub struct DeploymentRegistry {
    journal: Option<Mutex<Journal>>,
}

impl DeploymentRegistry {
    pub fn disabled() -> Self {
        Self { journal: None }
    }

    /// Explicit opt-in single-process JSONL registry. Invalid or locked state is
    /// refused; there is no RAM fallback or change to the evidence stores.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Ok(m) = std::fs::symlink_metadata(path) {
            if !m.is_file() || m.len() > MAX_JOURNAL {
                return Err("deployment registry must be a bounded regular file".into());
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|_| "cannot open deployment registry")?;
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect deployment registry")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("deployment registry must not be group/world accessible".into());
            }
        }
        if !metadata.is_file() || metadata.len() > MAX_JOURNAL {
            return Err("invalid deployment registry file".into());
        }
        file.try_lock()
            .map_err(|_| "deployment registry is locked; one writer process is supported")?;
        let mut rows = BTreeMap::new();
        for line in BufReader::new(&file).split(b'\n') {
            let line = line.map_err(|_| "cannot read deployment registry")?;
            if line.is_empty() || line.len() > 32 * 1024 {
                return Err("invalid deployment registry line".into());
            }
            let record: DeploymentRecord =
                serde_json::from_slice(&line).map_err(|_| "corrupt deployment registry")?;
            record.definition.validate()?;
            if record.tenant_id.is_empty()
                || record.tenant_id.len() > 256
                || record.registered_by_key_id.is_empty()
                || record.registered_by_key_id.len() > 256
                || rows.len() >= MAX_RECORDS
                || rows
                    .insert(
                        (
                            record.tenant_id.clone(),
                            record.definition.deployment_name.clone(),
                        ),
                        record,
                    )
                    .is_some()
            {
                return Err("invalid or repeated deployment registry record".into());
            }
        }
        // An uncommitted/truncated final record is never silently repaired.
        if metadata.len() > 0 {
            use std::io::{Read, Seek, SeekFrom};
            let mut check = &file;
            check
                .seek(SeekFrom::End(-1))
                .map_err(|_| "cannot inspect registry tail")?;
            let mut byte = [0];
            check
                .read_exact(&mut byte)
                .map_err(|_| "cannot read registry tail")?;
            if byte != *b"\n" {
                return Err("incomplete deployment registry tail".into());
            }
        }
        file.sync_all()
            .map_err(|_| "cannot sync deployment registry")?;
        #[cfg(unix)]
        File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )
        .and_then(|parent| parent.sync_all())
        .map_err(|_| "cannot sync deployment registry directory")?;
        Ok(Self {
            journal: Some(Mutex::new(Journal {
                file,
                rows,
                failed: false,
            })),
        })
    }

    pub fn register(
        &self,
        record: DeploymentRecord,
    ) -> Result<(DeploymentRecord, bool), RegistryError> {
        record
            .definition
            .validate()
            .map_err(|_| RegistryError::Unavailable)?;
        if record.tenant_id.is_empty()
            || record.tenant_id.len() > 256
            || record.registered_by_key_id.is_empty()
            || record.registered_by_key_id.len() > 256
        {
            return Err(RegistryError::Unavailable);
        }
        let mut journal = self
            .journal
            .as_ref()
            .ok_or(RegistryError::Disabled)?
            .lock()
            .map_err(|_| RegistryError::Unavailable)?;
        if journal.failed {
            return Err(RegistryError::Unavailable);
        }
        let key = (
            record.tenant_id.clone(),
            record.definition.deployment_name.clone(),
        );
        if let Some(existing) = journal.rows.get(&key) {
            return if existing.definition == record.definition {
                Ok((existing.clone(), false))
            } else {
                Err(RegistryError::Conflict)
            };
        }
        if journal.rows.len() >= MAX_RECORDS
            || journal
                .rows
                .values()
                .filter(|r| r.tenant_id == record.tenant_id)
                .count()
                >= 500
        {
            return Err(RegistryError::Limit);
        }
        let mut line = serde_json::to_vec(&record).map_err(|_| RegistryError::Unavailable)?;
        line.push(b'\n');
        let length = journal
            .file
            .metadata()
            .map_err(|_| RegistryError::Unavailable)?
            .len();
        if length + line.len() as u64 > MAX_JOURNAL {
            return Err(RegistryError::Limit);
        }
        if journal
            .file
            .write_all(&line)
            .and_then(|_| journal.file.sync_all())
            .is_err()
        {
            journal.failed = true;
            return Err(RegistryError::Unavailable);
        }
        journal.rows.insert(key, record.clone());
        Ok((record, true))
    }

    pub fn records(&self, tenant: &str) -> Result<Vec<DeploymentRecord>, RegistryError> {
        let journal = self
            .journal
            .as_ref()
            .ok_or(RegistryError::Disabled)?
            .lock()
            .map_err(|_| RegistryError::Unavailable)?;
        if journal.failed {
            return Err(RegistryError::Unavailable);
        }
        Ok(journal
            .rows
            .values()
            .filter(|r| r.tenant_id == tenant)
            .cloned()
            .collect())
    }

    fn summaries(
        &self,
        tenant: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DeploymentSummary>, RegistryError> {
        let journal = self
            .journal
            .as_ref()
            .ok_or(RegistryError::Disabled)?
            .lock()
            .map_err(|_| RegistryError::Unavailable)?;
        if journal.failed {
            return Err(RegistryError::Unavailable);
        }
        Ok(journal
            .rows
            .values()
            .filter(|r| r.tenant_id == tenant)
            .skip(offset)
            .take(limit + 1)
            .map(DeploymentSummary::from)
            .collect())
    }

    fn find(&self, tenant: &str, name: &str) -> Result<Option<DeploymentRecord>, RegistryError> {
        let journal = self
            .journal
            .as_ref()
            .ok_or(RegistryError::Disabled)?
            .lock()
            .map_err(|_| RegistryError::Unavailable)?;
        if journal.failed {
            return Err(RegistryError::Unavailable);
        }
        Ok(journal.rows.get(&(tenant.into(), name.into())).cloned())
    }
}

type ApiError = (StatusCode, Json<ErrorBody>);
fn error(status: StatusCode, message: &str) -> ApiError {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
}
fn store_error(error_kind: RegistryError) -> ApiError {
    match error_kind {
        RegistryError::Conflict => error(
            StatusCode::CONFLICT,
            "deployment name already registered with different configuration",
        ),
        RegistryError::Limit => error(StatusCode::CONFLICT, "deployment registry capacity reached"),
        RegistryError::Disabled => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "deployment registry not configured",
        ),
        RegistryError::Unavailable => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "deployment registry unavailable",
        ),
    }
}

#[derive(Debug, Serialize)]
pub struct DeploymentView {
    #[serde(flatten)]
    pub registration: DeploymentRecord,
    pub provenance: &'static str,
    pub configuration_status: &'static str,
    pub installed: &'static str,
    pub observer_active: &'static str,
    pub signed_evidence_available: &'static str,
    pub authorization_verified: &'static str,
    pub execution_reconciled: &'static str,
    pub pilot_accepted: &'static str,
    pub identity_binding: &'static str,
    pub trust_anchors_modified: bool,
    pub retention_enforced: bool,
}
impl From<DeploymentRecord> for DeploymentView {
    fn from(registration: DeploymentRecord) -> Self {
        Self {
            registration,
            provenance: "ADMIN_API_REGISTRATION",
            configuration_status: "CONFIGURATION_VALID",
            installed: "NOT_ASSESSED",
            observer_active: "NOT_ASSESSED",
            signed_evidence_available: "NOT_ASSESSED",
            authorization_verified: "NOT_ASSESSED",
            execution_reconciled: "NOT_ASSESSED",
            pilot_accepted: "NOT_ASSESSED",
            identity_binding: "NOT_ESTABLISHED",
            trust_anchors_modified: false,
            retention_enforced: false,
        }
    }
}

pub async fn register(
    Extension(registry): Extension<Arc<DeploymentRegistry>>,
    AdminPrincipal(principal): AdminPrincipal,
    payload: Result<Json<DeploymentDefinition>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<DeploymentView>), ApiError> {
    let definition = payload
        .map_err(|rejection| error(rejection.status(), "invalid deployment configuration JSON"))?
        .0;
    definition
        .validate()
        .map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
    let record = DeploymentRecord {
        tenant_id: principal.tenant_id,
        definition,
        registered_by_key_id: principal.key_id,
        registered_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "clock unavailable"))?
            .as_millis() as u64,
    };
    let (record, created) = registry.register(record).map_err(store_error)?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(record.into()),
    ))
}

pub async fn list(
    Extension(registry): Extension<Arc<DeploymentRegistry>>,
    principal: Principal,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Page<DeploymentSummary>>, ApiError> {
    let Query(query) =
        query.map_err(|_| error(StatusCode::BAD_REQUEST, "invalid pagination query"))?;
    query.validate()?;
    let rows = registry
        .summaries(&principal.tenant_id, query.offset, query.limit)
        .map_err(store_error)?;
    Ok(Json(Page::from_items(rows, &query)))
}

#[derive(Debug, Serialize)]
pub struct DeploymentSummary {
    pub deployment_name: String,
    pub workload_count: usize,
    pub registered_at_ms: u64,
    pub provenance: &'static str,
    pub configuration_status: &'static str,
    pub observer_active: &'static str,
    pub execution_reconciled: &'static str,
    pub identity_binding: &'static str,
}
impl From<DeploymentRecord> for DeploymentSummary {
    fn from(record: DeploymentRecord) -> Self {
        Self::from(&record)
    }
}
impl From<&DeploymentRecord> for DeploymentSummary {
    fn from(record: &DeploymentRecord) -> Self {
        Self {
            deployment_name: record.definition.deployment_name.clone(),
            workload_count: record.definition.workloads.len(),
            registered_at_ms: record.registered_at_ms,
            provenance: "ADMIN_API_REGISTRATION",
            configuration_status: "CONFIGURATION_VALID",
            observer_active: "NOT_ASSESSED",
            execution_reconciled: "NOT_ASSESSED",
            identity_binding: "NOT_ESTABLISHED",
        }
    }
}

pub async fn get(
    Extension(registry): Extension<Arc<DeploymentRegistry>>,
    principal: Principal,
    ApiPath(name): ApiPath<String>,
) -> Result<Json<DeploymentView>, ApiError> {
    if !identifier(&name) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid deployment identifier",
        ));
    }
    registry
        .find(&principal.tenant_id, &name)
        .map_err(store_error)?
        .map(|r| Json(r.into()))
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "deployment not found"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn definition() -> DeploymentDefinition {
        serde_json::from_value(serde_json::json!({
            "schema_version":"vanian.deployment.v1", "deployment_name":"test",
            "workloads":[{"host_id":"host", "admin_group":"platform", "probe_id":"probe", "transport_public_key_hex":"ab".repeat(32), "logical_agent_ids":[]}],
            "collector":{"host_id":"collector", "admin_group":"audit", "observer_id":"observer", "noise_public_key_hex":"cd".repeat(32)},
            "retention_days_requested":90, "contextforge":true, "evidence_mcp":true
        })).unwrap()
    }
    fn record(name: &str) -> DeploymentRecord {
        let mut definition = definition();
        definition.deployment_name = name.into();
        DeploymentRecord {
            tenant_id: "tenant".into(),
            definition,
            registered_at_ms: 1,
            registered_by_key_id: "admin".into(),
        }
    }

    #[test]
    fn append_failure_never_creates_a_readable_or_acknowledged_registration() {
        let path = std::env::temp_dir().join(format!("registry-readonly-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"").unwrap();
        let registry = DeploymentRegistry {
            journal: Some(Mutex::new(Journal {
                file: File::open(&path).unwrap(),
                rows: BTreeMap::new(),
                failed: false,
            })),
        };
        assert_eq!(
            registry.register(record("first")),
            Err(RegistryError::Unavailable)
        );
        assert_eq!(registry.records("tenant"), Err(RegistryError::Unavailable));
        assert_eq!(
            registry.register(record("retry")),
            Err(RegistryError::Unavailable)
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        drop(registry);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn repeated_or_incomplete_journal_records_are_not_repaired_into_success() {
        let path =
            std::env::temp_dir().join(format!("registry-duplicate-{}", uuid::Uuid::new_v4()));
        let registry = DeploymentRegistry::open(&path).unwrap();
        registry.register(record("first")).unwrap();
        drop(registry);
        let original = std::fs::read(&path).unwrap();
        std::fs::write(&path, [&original[..], &original[..]].concat()).unwrap();
        assert!(DeploymentRegistry::open(&path).is_err());
        std::fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(DeploymentRegistry::open(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
