//! Storage abstraction for the Evidence Vault.
//!
//! Handlers depend only on the [`EvidenceStore`] trait — never on a concrete
//! backend. Two implementations:
//!
//! - [`JsonlEvidenceStore`]: append-only JSONL file (the original vault; kept
//!   for development, air-gapped single-node use, and migration source).
//! - [`PostgresEvidenceStore`] (feature `postgres`): durable, transactional
//!   PostgreSQL metadata store for enterprise deployment.
//!
//! Tenancy is a **storage envelope**, not part of the signed evidence: the
//! cryptographic EvidencePacket is unchanged and remains independently
//! verifiable. Every read is tenant-checked; a cross-tenant `get` returns
//! `None` (indistinguishable from "not found", so existence does not leak).

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use aip_protocol::EvidencePacket;

#[cfg(feature = "postgres")]
mod pg;
#[cfg(feature = "postgres")]
pub use pg::PostgresEvidenceStore;

/// Tenant assigned to pre-tenancy records found in an existing vault file.
pub const LEGACY_TENANT: &str = "legacy";

/// Storage error surfaced to handlers (kept backend-agnostic).
#[derive(Debug)]
pub enum StoreError {
    /// A packet id already exists under a different tenant.
    TenantConflict,
    /// Any backend/serialization failure.
    Backend(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::TenantConflict => {
                write!(f, "packet id already stored under a different tenant")
            }
            StoreError::Backend(e) => write!(f, "evidence store backend error: {e}"),
        }
    }
}
impl std::error::Error for StoreError {}

/// Integrity self-check status persisted alongside a packet. This is the
/// keys-free check (canonical hash + agent signature payload); full authority
/// verification still requires `/v1/evidence/verify` with trusted keys.
pub fn integrity_status(packet: &EvidencePacket) -> &'static str {
    let recomputed = packet.compute_hash();
    let ok = recomputed == packet.packet_hash && packet.agent_sig.payload_hash == recomputed;
    if ok {
        "integrity_ok"
    } else {
        "integrity_failed"
    }
}

/// The storage interface. All operations are tenant-scoped.
#[async_trait::async_trait]
pub trait EvidenceStore: Send + Sync {
    /// Persist `packet` for `tenant_id`; returns its hex packet id. Idempotent
    /// within the same tenant; `TenantConflict` if the id exists under another.
    async fn store(&self, tenant_id: &str, packet: &EvidencePacket) -> Result<String, StoreError>;

    /// Retrieve a packet by id, only if it belongs to `tenant_id`.
    async fn get(&self, tenant_id: &str, id: &str) -> Result<Option<EvidencePacket>, StoreError>;

    /// All packets belonging to `tenant_id`, oldest first.
    async fn all_for_tenant(&self, tenant_id: &str) -> Result<Vec<EvidencePacket>, StoreError>;

    /// Total packet count across all tenants (for startup logging/metrics).
    async fn count(&self) -> Result<usize, StoreError>;
}

// ─── VaultRecord (JSONL envelope) ───────────────────────────────────────────

/// A tenant-scoped, timestamped envelope around a stored EvidencePacket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecord {
    pub tenant_id: String,
    pub stored_at: u64,
    pub packet: EvidencePacket,
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// ─── JSONL backend ───────────────────────────────────────────────────────────

/// Append-only JSONL EvidenceStore (the original vault).
#[derive(Clone)]
pub struct JsonlEvidenceStore {
    inner: Arc<Mutex<JsonlInner>>,
    path: String,
}

struct JsonlInner {
    by_id: HashMap<String, VaultRecord>,
    order: Vec<String>,
}

impl JsonlEvidenceStore {
    /// Load from `path`, replaying every record into the in-memory index.
    /// Pre-tenancy bare-packet lines are migrated to [`LEGACY_TENANT`].
    pub fn load(path: &str) -> Self {
        let mut inner = JsonlInner {
            by_id: HashMap::new(),
            order: Vec::new(),
        };
        if Path::new(path).exists() {
            if let Ok(contents) = std::fs::read_to_string(path) {
                for (line_no, line) in contents.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let record = match serde_json::from_str::<VaultRecord>(line) {
                        Ok(r) => Some(r),
                        Err(_) => EvidencePacket::from_json(line)
                            .ok()
                            .map(|packet| VaultRecord {
                                tenant_id: LEGACY_TENANT.to_string(),
                                stored_at: 0,
                                packet,
                            }),
                    };
                    match record {
                        Some(r) => {
                            let id = r.packet.packet_id_hex();
                            if inner.by_id.insert(id.clone(), r).is_none() {
                                inner.order.push(id);
                            }
                        }
                        None => tracing::warn!(
                            line = line_no + 1,
                            "vault: skipping unparseable record line"
                        ),
                    }
                }
            }
        }
        JsonlEvidenceStore {
            inner: Arc::new(Mutex::new(inner)),
            path: path.to_owned(),
        }
    }

    /// All stored records (tenant + packet), oldest first. Used by
    /// `aip-migrate` to preserve each record's tenant during import.
    pub fn records(&self) -> Vec<VaultRecord> {
        let inner = self.inner.lock().unwrap();
        inner
            .order
            .iter()
            .filter_map(|id| inner.by_id.get(id).cloned())
            .collect()
    }
}

#[async_trait::async_trait]
impl EvidenceStore for JsonlEvidenceStore {
    async fn store(&self, tenant_id: &str, packet: &EvidencePacket) -> Result<String, StoreError> {
        let id = packet.packet_id_hex();
        let mut inner = self.inner.lock().unwrap();
        if let Some(existing) = inner.by_id.get(&id) {
            if existing.tenant_id != tenant_id {
                return Err(StoreError::TenantConflict);
            }
            return Ok(id);
        }
        let record = VaultRecord {
            tenant_id: tenant_id.to_string(),
            stored_at: now_ms(),
            packet: packet.clone(),
        };
        let line =
            serde_json::to_string(&record).map_err(|e| StoreError::Backend(e.to_string()))?;
        if let Some(parent) = Path::new(&self.path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| StoreError::Backend(format!("open vault: {e}")))?;
        writeln!(file, "{line}").map_err(|e| StoreError::Backend(format!("write vault: {e}")))?;
        inner.by_id.insert(id.clone(), record);
        inner.order.push(id.clone());
        Ok(id)
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<Option<EvidencePacket>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .by_id
            .get(id)
            .filter(|r| r.tenant_id == tenant_id)
            .map(|r| r.packet.clone()))
    }

    async fn all_for_tenant(&self, tenant_id: &str) -> Result<Vec<EvidencePacket>, StoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .order
            .iter()
            .filter_map(|id| inner.by_id.get(id))
            .filter(|r| r.tenant_id == tenant_id)
            .map(|r| r.packet.clone())
            .collect())
    }

    async fn count(&self) -> Result<usize, StoreError> {
        Ok(self.inner.lock().unwrap().by_id.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_packet;

    fn temp_path() -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("aip_vault_test_{}.jsonl", uuid::Uuid::new_v4()));
        p.to_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn test_store_get_roundtrip() {
        let path = temp_path();
        let store = JsonlEvidenceStore::load(&path);
        let (packet, _) = sample_packet();
        let id = store.store("acme", &packet).await.unwrap();
        assert_eq!(id, packet.packet_id_hex());
        let got = store.get("acme", &id).await.unwrap().expect("retrievable");
        assert_eq!(got.packet_hash, packet.packet_hash);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_cross_tenant_get_is_denied() {
        let path = temp_path();
        let store = JsonlEvidenceStore::load(&path);
        let (packet, _) = sample_packet();
        let id = store.store("tenant-a", &packet).await.unwrap();
        assert!(store.get("tenant-b", &id).await.unwrap().is_none());
        assert!(store.get("tenant-a", &id).await.unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_all_for_tenant_isolates() {
        let path = temp_path();
        let store = JsonlEvidenceStore::load(&path);
        let (p1, _) = sample_packet();
        let (p2, _) = sample_packet();
        store.store("tenant-a", &p1).await.unwrap();
        store.store("tenant-b", &p2).await.unwrap();
        assert_eq!(store.all_for_tenant("tenant-a").await.unwrap().len(), 1);
        assert_eq!(store.all_for_tenant("tenant-b").await.unwrap().len(), 1);
        assert_eq!(store.all_for_tenant("tenant-c").await.unwrap().len(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_store_rejects_id_reuse_across_tenants() {
        let path = temp_path();
        let store = JsonlEvidenceStore::load(&path);
        let (packet, _) = sample_packet();
        store.store("tenant-a", &packet).await.unwrap();
        assert!(matches!(
            store.store("tenant-b", &packet).await,
            Err(StoreError::TenantConflict)
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_persist_and_reload_preserves_tenant() {
        let path = temp_path();
        let (packet, _) = sample_packet();
        {
            let store = JsonlEvidenceStore::load(&path);
            store.store("acme", &packet).await.unwrap();
        }
        let reloaded = JsonlEvidenceStore::load(&path);
        assert_eq!(reloaded.count().await.unwrap(), 1);
        assert!(reloaded
            .get("acme", &packet.packet_id_hex())
            .await
            .unwrap()
            .is_some());
        assert!(reloaded
            .get("other", &packet.packet_id_hex())
            .await
            .unwrap()
            .is_none());
        let _ = std::fs::remove_file(&path);
    }
}
