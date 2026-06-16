//! Evidence Vault v1 — minimal durable store for EvidencePackets.
//!
//! Design (deliberately minimal — no blockchain, no distributed systems):
//! - Append-only JSONL file at `AIP_VAULT_PATH` (one packet per line).
//! - In-memory index `packet_id_hex → EvidencePacket`, loaded at startup.
//! - The vault is the **system of record**; the authority graph
//!   ([`crate::authority`]) is a derived index rebuilt from it.
//!
//! Storage requirements: a single writable file path. Each packet is stored
//! verbatim as the canonical JSON produced by `EvidencePacket::to_json`, so
//! the stored bytes round-trip and re-verify identically.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use aip_protocol::EvidencePacket;

/// Thread-safe handle to the in-memory vault index + backing file path.
#[derive(Clone)]
pub struct Vault {
    inner: Arc<Mutex<VaultInner>>,
    path: String,
}

struct VaultInner {
    /// packet_id (hex) → packet
    by_id: HashMap<String, EvidencePacket>,
    /// insertion order, for stable listing
    order: Vec<String>,
}

impl Vault {
    /// Load the vault from `path`, replaying every stored packet into the
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
                    match EvidencePacket::from_json(line) {
                        Ok(packet) => {
                            let id = packet.packet_id_hex();
                            if inner.by_id.insert(id.clone(), packet).is_none() {
                                inner.order.push(id);
                            }
                        }
                        Err(e) => tracing::warn!(
                            line = line_no + 1,
                            error = %e,
                            "vault: skipping unparseable packet line"
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

    /// Append a packet to the vault (durable) and index it in memory.
    /// Idempotent on `packet_id`: storing the same id twice is a no-op write.
    pub fn store(&self, packet: &EvidencePacket) -> Result<String, String> {
        let id = packet.packet_id_hex();
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.by_id.contains_key(&id) {
                return Ok(id); // already stored — idempotent
            }
            let line = packet.to_json_compact().map_err(|e| e.to_string())?;
            if let Some(parent) = Path::new(&self.path).parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .map_err(|e| format!("open vault: {e}"))?;
            writeln!(file, "{line}").map_err(|e| format!("write vault: {e}"))?;
            inner.by_id.insert(id.clone(), packet.clone());
            inner.order.push(id.clone());
        }
        Ok(id)
    }

    /// Retrieve a packet by its hex packet id.
    pub fn get(&self, id: &str) -> Option<EvidencePacket> {
        self.inner.lock().unwrap().by_id.get(id).cloned()
    }

    /// All stored packets, in insertion order. Used by the authority graph
    /// to (re)build its index.
    pub fn all(&self) -> Vec<EvidencePacket> {
        let inner = self.inner.lock().unwrap();
        inner
            .order
            .iter()
            .filter_map(|id| inner.by_id.get(id).cloned())
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
        let id = vault.store(&packet).unwrap();
        assert_eq!(id, packet.packet_id_hex());
        let got = vault.get(&id).expect("packet must be retrievable");
        assert_eq!(got.packet_hash, packet.packet_hash);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_store_is_idempotent() {
        let path = temp_path();
        let vault = Vault::load(&path);
        let (packet, _) = sample_packet();
        vault.store(&packet).unwrap();
        vault.store(&packet).unwrap();
        assert_eq!(vault.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_persist_and_reload() {
        let path = temp_path();
        let (packet, _) = sample_packet();
        {
            let vault = Vault::load(&path);
            vault.store(&packet).unwrap();
        }
        let reloaded = Vault::load(&path);
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.get(&packet.packet_id_hex()).is_some());
        let _ = std::fs::remove_file(&path);
    }
}
