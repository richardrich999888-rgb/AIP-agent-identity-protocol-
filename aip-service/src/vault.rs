//! Evidence Vault v1 — minimal durable store for EvidencePackets, tenant-scoped.
//!
//! Design (deliberately minimal — no blockchain, no distributed systems):
//! - Append-only JSONL file at `AIP_VAULT_PATH` (one [`VaultRecord`] per line).
//! - In-memory index `packet_id_hex → VaultRecord`, loaded at startup.
//! - The vault is the **system of record**; the authority graph
//!   ([`crate::authority`]) is a derived index rebuilt from it.
//!
//! ## Tenant model (Task 2)
//! Tenancy is a **storage envelope**, not part of the signed evidence: the
//! cryptographic EvidencePacket is unchanged and remains independently
//! verifiable. Each stored record carries a `tenant_id`, supplied by the
//! authenticated caller's API key (never by the request body). Every read is
//! tenant-checked; a cross-tenant `get` returns `None` (indistinguishable
//! from "not found", so existence does not leak across tenants).
//!
//! ## Migration
//! Legacy lines written before tenancy were bare `EvidencePacket` JSON. On
//! load, a line that fails to parse as `VaultRecord` is retried as a bare
//! packet and assigned [`LEGACY_TENANT`]. New writes are always `VaultRecord`.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use aip_protocol::EvidencePacket;

/// Tenant assigned to pre-tenancy records found in an existing vault file.
pub const LEGACY_TENANT: &str = "legacy";

/// A tenant-scoped, timestamped envelope around a stored EvidencePacket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecord {
    pub tenant_id: String,
    pub stored_at: u64,
    pub packet: EvidencePacket,
}

/// Thread-safe handle to the in-memory vault index + backing file path.
#[derive(Clone)]
pub struct Vault {
    inner: Arc<Mutex<VaultInner>>,
    path: String,
}

struct VaultInner {
    /// packet_id (hex) → record
    by_id: HashMap<String, VaultRecord>,
    /// insertion order, for stable listing
    order: Vec<String>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

impl Vault {
    /// Load the vault from `path`, replaying every stored record into the
    /// in-memory index. A missing file yields an empty vault.
    pub fn load(path: &str) -> Self {
        let mut inner = VaultInner {
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
                        // Migration: retry as a bare pre-tenancy packet.
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
        Vault {
            inner: Arc::new(Mutex::new(inner)),
            path: path.to_owned(),
        }
    }

    /// Append a packet for `tenant_id` to the vault (durable) and index it.
    /// Idempotent on `packet_id`. A packet already stored under a *different*
    /// tenant is rejected (an evidence id is globally unique to one tenant).
    pub fn store(&self, tenant_id: &str, packet: &EvidencePacket) -> Result<String, String> {
        let id = packet.packet_id_hex();
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(existing) = inner.by_id.get(&id) {
                if existing.tenant_id != tenant_id {
                    return Err("packet id already stored under a different tenant".into());
                }
                return Ok(id); // idempotent within the same tenant
            }
            let record = VaultRecord {
                tenant_id: tenant_id.to_string(),
                stored_at: now_ms(),
                packet: packet.clone(),
            };
            let line = serde_json::to_string(&record).map_err(|e| e.to_string())?;
            if let Some(parent) = Path::new(&self.path).parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .map_err(|e| format!("open vault: {e}"))?;
            writeln!(file, "{line}").map_err(|e| format!("write vault: {e}"))?;
            inner.by_id.insert(id.clone(), record);
            inner.order.push(id.clone());
        }
        Ok(id)
    }

    /// Retrieve a packet by id **only if it belongs to `tenant_id`**.
    /// Returns `None` for both "not found" and "wrong tenant" (no existence
    /// leak across tenants).
    pub fn get(&self, tenant_id: &str, id: &str) -> Option<EvidencePacket> {
        let inner = self.inner.lock().unwrap();
        inner
            .by_id
            .get(id)
            .filter(|r| r.tenant_id == tenant_id)
            .map(|r| r.packet.clone())
    }

    /// All packets belonging to `tenant_id`, in insertion order. Used by the
    /// authority graph to (re)build its per-tenant index.
    pub fn all_for_tenant(&self, tenant_id: &str) -> Vec<EvidencePacket> {
        let inner = self.inner.lock().unwrap();
        inner
            .order
            .iter()
            .filter_map(|id| inner.by_id.get(id))
            .filter(|r| r.tenant_id == tenant_id)
            .map(|r| r.packet.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    #[test]
    fn test_store_get_roundtrip() {
        let path = temp_path();
        let vault = Vault::load(&path);
        let (packet, _) = sample_packet();
        let id = vault.store("acme", &packet).unwrap();
        assert_eq!(id, packet.packet_id_hex());
        let got = vault.get("acme", &id).expect("packet must be retrievable");
        assert_eq!(got.packet_hash, packet.packet_hash);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_cross_tenant_get_is_denied() {
        let path = temp_path();
        let vault = Vault::load(&path);
        let (packet, _) = sample_packet();
        let id = vault.store("tenant-a", &packet).unwrap();
        // Same id, different tenant → must look like "not found".
        assert!(vault.get("tenant-b", &id).is_none());
        assert!(vault.get("tenant-a", &id).is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_all_for_tenant_isolates() {
        let path = temp_path();
        let vault = Vault::load(&path);
        let (p1, _) = sample_packet();
        let (p2, _) = sample_packet();
        vault.store("tenant-a", &p1).unwrap();
        vault.store("tenant-b", &p2).unwrap();
        assert_eq!(vault.all_for_tenant("tenant-a").len(), 1);
        assert_eq!(vault.all_for_tenant("tenant-b").len(), 1);
        assert_eq!(vault.all_for_tenant("tenant-c").len(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_store_rejects_id_reuse_across_tenants() {
        let path = temp_path();
        let vault = Vault::load(&path);
        let (packet, _) = sample_packet();
        vault.store("tenant-a", &packet).unwrap();
        assert!(vault.store("tenant-b", &packet).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_persist_and_reload_preserves_tenant() {
        let path = temp_path();
        let (packet, _) = sample_packet();
        {
            let vault = Vault::load(&path);
            vault.store("acme", &packet).unwrap();
        }
        let reloaded = Vault::load(&path);
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.get("acme", &packet.packet_id_hex()).is_some());
        assert!(reloaded.get("other", &packet.packet_id_hex()).is_none());
        let _ = std::fs::remove_file(&path);
    }
}
