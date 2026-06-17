//! airon-aip library: shared modules for the service binary and the
//! `aip-migrate` tool. The deployable surface is a thin layer over
//! `aip-core` + `aip-protocol`.

pub mod auth;
pub mod authority;
pub mod capability;
pub mod delegation;
pub mod evidence;
pub mod handlers;
pub mod keys;
pub mod models;
pub mod revocation;
pub mod store;
pub mod tokens;
pub mod wellknown;

#[cfg(test)]
pub mod test_support;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use jsonwebtoken::{DecodingKey, EncodingKey};

use delegation::DelegationLog;
use revocation::RevocationSet;
use store::EvidenceStore;

/// Shared application state.
pub struct AppState {
    /// PKCS#8 EdDSA encoding key — used only in the issue handler.
    pub encoding_key: EncodingKey,
    /// SPKI EdDSA decoding key — used in the hot-path verify handler.
    pub decoding_key: DecodingKey,
    /// SPKI PEM of the public key — returned from GET /v1/identity/public-key.
    pub public_pem: String,
    /// SHA-256 fingerprint of the public key bytes.
    pub fingerprint: String,
    /// Path to the delegation JSONL log (for append operations).
    pub delegation_log_path: String,
    /// In-memory delegation log.
    pub delegation_log: DelegationLog,
    /// Path to the revocation JSONL log (for append operations).
    pub revocation_log_path: String,
    /// In-memory revocation set.
    pub revocation_set: RevocationSet,
    /// Evidence store (JSONL or PostgreSQL) — the accountability system of
    /// record. Handlers depend only on the trait, never the backend.
    pub store: Arc<dyn EvidenceStore>,
    /// API-key store for authentication + tenant binding. Empty ⇒ fail closed.
    pub api_keys: auth::ApiKeyStore,
    /// Ed25519 seed used to sign audit-export bundle manifests.
    pub signer_seed: [u8; 32],
    /// Ed25519 public key embedded in exported bundles (for offline verify).
    pub signer_public: [u8; 32],
}

/// Build the full router from shared state.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/v1/identity/issue", post(handlers::issue))
        .route("/v1/identity/verify", post(handlers::verify))
        .route("/v1/identity/public-key", get(handlers::public_key))
        .route("/v1/identity/delegate", post(handlers::delegate))
        .route("/v1/identity/verify-chain", post(handlers::verify_chain))
        .route("/v1/identity/revoke", post(handlers::revoke))
        .route(
            "/v1/identity/revocation-status/:jti",
            get(handlers::revocation_status),
        )
        // Accountability layer
        .route("/v1/evidence/generate", post(evidence::generate))
        .route("/v1/evidence/verify", post(evidence::verify))
        .route("/v1/evidence/:id", get(evidence::get_evidence))
        .route("/v1/evidence/:id/export", get(evidence::export_evidence))
        .route("/v1/authority/:id", get(evidence::get_authority))
        // Well-known discovery
        .route(
            "/.well-known/aip-configuration",
            get(wellknown::aip_configuration),
        )
        .route("/.well-known/jwks.json", get(wellknown::jwks))
        .with_state(state)
}
