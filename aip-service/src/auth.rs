//! Authentication & tenant binding for the pilot deployment.
//!
//! ## Why API keys (Task 1 decision)
//! For a 30-day regulated-pilot target, bearer **API keys** are the simplest
//! production-safe choice:
//! - Service-to-service auth: a `Machine` key per integrating system.
//! - Human admin auth: an `Admin` key per operator.
//! - Tenant isolation: **every key is bound to exactly one `tenant_id`**, and
//!   the tenant is taken from the key — never from the request body — so a
//!   caller cannot address another tenant's data.
//!
//! mTLS / SPIFFE / OAuth2-client-credentials are stronger but require PKI or
//! an IdP that a pilot environment rarely has ready; they are the natural
//! post-pilot upgrade. API keys here **fail closed**: with no keys configured,
//! every authenticated route returns 401.
//!
//! ## Storage
//! Secrets are NEVER stored in plaintext. The key file holds only the
//! SHA-256 hash of each secret. Operators mint a secret out of band and store
//! `sha256(secret)`; e.g. `printf %s "$SECRET" | sha256sum`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

use aip_crypto::sha256;

use crate::models::ErrorBody;
use crate::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Evidence queries and verification only. No issuance, filing or export.
    Reader,
    /// Service-to-service caller (an integrating agent/system).
    Machine,
    /// Human administrator (revocation and other privileged operations).
    Admin,
}

/// The authenticated caller, resolved from a valid API key.
#[derive(Debug, Clone)]
pub struct Principal {
    pub tenant_id: String,
    pub key_id: String,
    pub role: Role,
}

/// On-disk key configuration entry (`AIP_API_KEYS_PATH`).
#[derive(Debug, Clone, Deserialize)]
struct ApiKeyConfig {
    key_id: String,
    tenant_id: String,
    role: Role,
    /// Hex SHA-256 of the bearer secret. The plaintext secret is never stored.
    secret_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiKeysFile {
    keys: Vec<ApiKeyConfig>,
}

#[derive(Debug, Clone)]
struct Entry {
    tenant_id: String,
    key_id: String,
    role: Role,
}

/// Loaded API-key store: maps `sha256(secret) → entry`.
#[derive(Debug, Clone, Default)]
pub struct ApiKeyStore {
    by_hash: HashMap<[u8; 32], Entry>,
}

impl ApiKeyStore {
    /// Load keys from a JSON file. A missing/empty path yields an empty store
    /// (fail closed: every authenticated route then returns 401).
    pub fn load(path: &str) -> Self {
        if path.is_empty() || !Path::new(path).exists() {
            return Self::default();
        }
        let mut store = Self::default();
        match std::fs::read_to_string(path) {
            Ok(contents) => match serde_json::from_str::<ApiKeysFile>(&contents) {
                Ok(file) => {
                    for k in file.keys {
                        match hex::decode(&k.secret_sha256) {
                            Ok(bytes) if bytes.len() == 32 => {
                                let mut h = [0u8; 32];
                                h.copy_from_slice(&bytes);
                                store.by_hash.insert(
                                    h,
                                    Entry {
                                        tenant_id: k.tenant_id,
                                        key_id: k.key_id,
                                        role: k.role,
                                    },
                                );
                            }
                            _ => tracing::warn!(
                                key_id = %k.key_id,
                                "api key: secret_sha256 must be 32-byte hex — skipping"
                            ),
                        }
                    }
                }
                Err(e) => tracing::error!(error = %e, "failed to parse API keys file"),
            },
            Err(e) => tracing::error!(error = %e, "failed to read API keys file"),
        }
        store
    }

    /// Build a store directly (used by tests).
    #[cfg(test)]
    pub fn from_entries(entries: Vec<(&str, &str, &str, Role)>) -> Self {
        // (secret, key_id, tenant_id, role)
        let mut store = Self::default();
        for (secret, key_id, tenant_id, role) in entries {
            store.by_hash.insert(
                sha256(secret.as_bytes()),
                Entry {
                    tenant_id: tenant_id.to_string(),
                    key_id: key_id.to_string(),
                    role,
                },
            );
        }
        store
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Resolve a bearer secret to a [`Principal`], or `None` if unknown.
    /// The secret is hashed before lookup; no plaintext comparison occurs.
    pub fn authenticate(&self, secret: &str) -> Option<Principal> {
        let h = sha256(secret.as_bytes());
        self.by_hash.get(&h).map(|e| Principal {
            tenant_id: e.tenant_id.clone(),
            key_id: e.key_id.clone(),
            role: e.role,
        })
    }
}

fn unauthorized(msg: &str) -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorBody { error: msg.into() }),
    )
}

pub(crate) fn bearer_secret(headers: &axum::http::HeaderMap) -> Option<String> {
    let header = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for Principal {
    type Rejection = (StatusCode, Json<ErrorBody>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let secret = bearer_secret(&parts.headers)
            .ok_or_else(|| unauthorized("missing or malformed Authorization: Bearer header"))?;
        state
            .api_keys
            .authenticate(&secret)
            .ok_or_else(|| unauthorized("invalid API key"))
    }
}

/// Extractor requiring the caller to hold an `Admin` key.
pub struct AdminPrincipal(pub Principal);

#[async_trait]
impl FromRequestParts<Arc<AppState>> for AdminPrincipal {
    type Rejection = (StatusCode, Json<ErrorBody>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let principal = Principal::from_request_parts(parts, state).await?;
        if principal.role != Role::Admin {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorBody {
                    error: "admin role required".into(),
                }),
            ));
        }
        Ok(AdminPrincipal(principal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticate_known_and_unknown() {
        let store = ApiKeyStore::from_entries(vec![
            ("machine-secret", "k1", "acme", Role::Machine),
            ("admin-secret", "k2", "acme", Role::Admin),
        ]);
        let p = store.authenticate("machine-secret").unwrap();
        assert_eq!(p.tenant_id, "acme");
        assert_eq!(p.role, Role::Machine);
        assert_eq!(
            store.authenticate("admin-secret").unwrap().role,
            Role::Admin
        );
        assert!(store.authenticate("wrong").is_none());
    }

    #[test]
    fn test_empty_store_fails_closed() {
        let store = ApiKeyStore::default();
        assert!(store.is_empty());
        assert!(store.authenticate("anything").is_none());
    }

    #[test]
    fn test_keys_bind_distinct_tenants() {
        let store = ApiKeyStore::from_entries(vec![
            ("s-a", "ka", "tenant-a", Role::Machine),
            ("s-b", "kb", "tenant-b", Role::Machine),
        ]);
        assert_eq!(store.authenticate("s-a").unwrap().tenant_id, "tenant-a");
        assert_eq!(store.authenticate("s-b").unwrap().tenant_id, "tenant-b");
    }
}
