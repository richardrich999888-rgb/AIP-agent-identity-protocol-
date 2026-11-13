//! Institution-controlled public trust anchors for AIP delegation agents.
//! Keys are bound to both tenant_id and agent_id. Request bodies cannot
//! introduce or replace trusted keys.

use std::collections::BTreeMap;

use axum::{http::StatusCode, Json};

use crate::models::ErrorBody;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_ANCHORS: usize = 1024;

#[derive(Debug, Default)]
pub struct AgentTrustStore {
    anchors: BTreeMap<(String, String), [u8; 32]>,
    source_sha256: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    anchors: Vec<TrustEntry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustEntry {
    tenant_id: String,
    agent_id: String,
    public_key_hex: String,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

impl AgentTrustStore {
    /// No configured path means an empty, fail-closed trust store.
    pub fn load(path: Option<&str>) -> Result<Self, String> {
        match path {
            None => Ok(Self::default()),
            Some(path) if path.trim().is_empty() => {
                Err("AIP_AGENT_TRUST_PATH must not be empty".into())
            }
            Some(path) => {
                let metadata = std::fs::metadata(path)
                    .map_err(|e| format!("cannot read agent trust file: {e}"))?;

                if metadata.len() > MAX_CONFIG_BYTES {
                    return Err("agent trust file exceeds 256 KiB".into());
                }

                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read agent trust file: {e}"))?;

                Self::from_json(&text)
            }
        }
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err("agent trust configuration exceeds 256 KiB".into());
        }

        let config: TrustFile = serde_json::from_str(text)
            .map_err(|e| format!("invalid agent trust configuration: {e}"))?;

        if config.anchors.len() > MAX_ANCHORS {
            return Err("too many agent trust anchors".into());
        }

        let mut result = Self::default();

        for anchor in config.anchors {
            if !valid_id(&anchor.tenant_id) || !valid_id(&anchor.agent_id) {
                return Err("invalid tenant or agent identifier".into());
            }

            let decoded = hex::decode(&anchor.public_key_hex)
                .map_err(|_| "agent public key must be hexadecimal")?;

            let public_key: [u8; 32] = decoded
                .try_into()
                .map_err(|_| "agent public key must be 32 bytes")?;

            let key = (anchor.tenant_id, anchor.agent_id);

            if result.anchors.insert(key, public_key).is_some() {
                return Err("duplicate tenant/agent trust anchor".into());
            }
        }

        result.source_sha256 = Some(hex::encode(aip_crypto::sha256(text.as_bytes())));

        Ok(result)
    }

    /// Fingerprint of the administrator-provided trust configuration.
    pub fn source_sha256(&self) -> Option<&str> {
        self.source_sha256.as_deref()
    }

    /// Retrieve an approved key for this exact tenant and agent pair.
    pub fn key(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<&[u8; 32], (StatusCode, Json<ErrorBody>)> {
        if self.anchors.is_empty() {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorBody {
                    error: "delegation verification has no configured agent trust anchors".into(),
                }),
            ));
        }

        self.anchors
            .get(&(tenant_id.to_owned(), agent_id.to_owned()))
            .ok_or_else(|| {
                (
                    StatusCode::FORBIDDEN,
                    Json(ErrorBody {
                        error: "agent key is not approved for this tenant".into(),
                    }),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(tenant: &str, agent: &str, key: &str) -> String {
        serde_json::json!({
            "anchors": [{
                "tenant_id": tenant,
                "agent_id": agent,
                "public_key_hex": key
            }]
        })
        .to_string()
    }

    #[test]
    fn accepts_valid_tenant_bound_anchor() {
        let json = config("tenant-a", "agent-a", &"11".repeat(32));
        let store = AgentTrustStore::from_json(&json).unwrap();

        assert_eq!(store.key("tenant-a", "agent-a").unwrap(), &[0x11; 32]);
        assert!(store.source_sha256().is_some());
    }

    #[test]
    fn rejects_cross_tenant_lookup() {
        let json = config("tenant-a", "agent-a", &"11".repeat(32));
        let store = AgentTrustStore::from_json(&json).unwrap();

        assert_eq!(
            store.key("tenant-b", "agent-a").unwrap_err().0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn rejects_unknown_agent() {
        let json = config("tenant-a", "agent-a", &"11".repeat(32));
        let store = AgentTrustStore::from_json(&json).unwrap();

        assert_eq!(
            store.key("tenant-a", "agent-b").unwrap_err().0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn empty_store_fails_closed() {
        let store = AgentTrustStore::default();

        assert_eq!(
            store.key("tenant-a", "agent-a").unwrap_err().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn rejects_duplicate_tenant_agent_pair() {
        let json = serde_json::json!({
            "anchors": [
                {
                    "tenant_id": "tenant-a",
                    "agent_id": "agent-a",
                    "public_key_hex": "11".repeat(32)
                },
                {
                    "tenant_id": "tenant-a",
                    "agent_id": "agent-a",
                    "public_key_hex": "22".repeat(32)
                }
            ]
        })
        .to_string();

        assert!(AgentTrustStore::from_json(&json).is_err());
    }

    #[test]
    fn rejects_invalid_public_key_length() {
        let json = config("tenant-a", "agent-a", "abcd");
        assert!(AgentTrustStore::from_json(&json).is_err());
    }

    #[test]
    fn rejects_unknown_configuration_fields() {
        let json = serde_json::json!({
            "anchors": [],
            "unexpected": true
        })
        .to_string();

        assert!(AgentTrustStore::from_json(&json).is_err());
    }

    #[test]
    fn rejects_invalid_identifiers() {
        let json = config("../tenant", "agent-a", &"11".repeat(32));
        assert!(AgentTrustStore::from_json(&json).is_err());
    }
}
