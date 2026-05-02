//! airon-aip — Agent Identity Protocol service (v2)
//!
//! Issues and verifies Ed25519-signed JWTs that authenticate agents and services
//! within the AIRON Trust Pipeline.  v2 adds capability scopes, delegation chains,
//! cascade revocation, and well-known discovery endpoints.
//!
//! Environment variables:
//!   AIP_PORT                — listen port (default 8081)
//!   AIP_KEY_PATH            — path to persist the Ed25519 seed (default /var/lib/aip/signing.key)
//!   AIP_DELEGATION_LOG_PATH — path to the delegation JSONL log (default /var/lib/aip/delegation.jsonl)
//!   AIP_REVOCATION_LOG_PATH — path to the revocation JSONL log (default /var/lib/aip/revocation.jsonl)
//!   AIP_ISSUER_URL          — base URL returned in /.well-known/aip-configuration (default http://aip:8081)
//!   RUST_LOG                — log filter (default info)

mod capability;
mod delegation;
mod handlers;
mod keys;
mod models;
mod revocation;
mod tokens;
mod wellknown;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use tracing_subscriber::{fmt, EnvFilter};

use delegation::DelegationLog;
use keys::KeyPair;
use revocation::RevocationSet;

// ── Shared application state ──────────────────────────────────────────────────

pub struct AppState {
    /// PKCS#8 EdDSA encoding key — used only in the issue handler.
    pub encoding_key: EncodingKey,
    /// SPKI EdDSA decoding key — used in the hot-path verify handler.
    pub decoding_key: DecodingKey,
    /// SPKI PEM of the public key — returned from GET /v1/identity/public-key.
    pub public_pem: String,
    /// SHA-256 fingerprint of the public key bytes — included in issue responses.
    pub fingerprint: String,
    /// Path to the delegation JSONL log (for append operations).
    pub delegation_log_path: String,
    /// In-memory delegation log (loaded at startup, updated on delegate calls).
    pub delegation_log: DelegationLog,
    /// Path to the revocation JSONL log (for append operations).
    pub revocation_log_path: String,
    /// In-memory revocation set (loaded at startup, O(1) lookup in verify hot path).
    pub revocation_set: RevocationSet,
}

// AppState is behind Arc; all fields are Send + Sync.
// EncodingKey and DecodingKey contain Vec<u8> / Arc<Vec<u8>> — both are Send + Sync.
unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .with_current_span(false)
        .init();

    let port: u16 = std::env::var("AIP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8081);

    let key_path =
        std::env::var("AIP_KEY_PATH").unwrap_or_else(|_| "/var/lib/aip/signing.key".to_owned());

    let delegation_log_path = std::env::var("AIP_DELEGATION_LOG_PATH")
        .unwrap_or_else(|_| "/var/lib/aip/delegation.jsonl".to_owned());

    let revocation_log_path = std::env::var("AIP_REVOCATION_LOG_PATH")
        .unwrap_or_else(|_| "/var/lib/aip/revocation.jsonl".to_owned());

    // Ensure the key directory exists.
    if let Some(parent) = std::path::Path::new(&key_path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(path = %parent.display(), error = %e, "Could not create key directory");
        }
    }

    let kp = KeyPair::load_or_generate(&key_path);

    let encoding_key = EncodingKey::from_ed_pem(kp.private_pem.as_bytes())
        .expect("generated private PEM must always be valid");
    let decoding_key = DecodingKey::from_ed_pem(kp.public_pem.as_bytes())
        .expect("generated public PEM must always be valid");

    // Load delegation and revocation logs from disk into memory.
    let del_log = delegation::load_delegation_log(&delegation_log_path);
    let rev_set = revocation::load_revocation_set(&revocation_log_path);

    tracing::info!(
        delegation_entries = del_log.lock().unwrap().len(),
        revocation_entries = rev_set.lock().unwrap().len(),
        "AIP v2 logs loaded"
    );

    let state = Arc::new(AppState {
        encoding_key,
        decoding_key,
        public_pem: kp.public_pem.clone(),
        fingerprint: kp.fingerprint.clone(),
        delegation_log_path,
        delegation_log: del_log,
        revocation_log_path,
        revocation_set: rev_set,
    });

    let app = Router::new()
        // Core endpoints
        .route("/health", get(handlers::health))
        .route("/v1/identity/issue", post(handlers::issue))
        .route("/v1/identity/verify", post(handlers::verify))
        .route("/v1/identity/public-key", get(handlers::public_key))
        // v2: delegation
        .route("/v1/identity/delegate", post(handlers::delegate))
        .route("/v1/identity/verify-chain", post(handlers::verify_chain))
        // v2: revocation
        .route("/v1/identity/revoke", post(handlers::revoke))
        .route(
            "/v1/identity/revocation-status/:jti",
            get(handlers::revocation_status),
        )
        // v2: well-known discovery
        .route(
            "/.well-known/aip-configuration",
            get(wellknown::aip_configuration),
        )
        .route("/.well-known/jwks.json", get(wellknown::jwks))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!(
        port,
        fingerprint = %kp.fingerprint,
        key_path,
        "airon-aip v2 starting"
    );

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    axum::serve(listener, app).await.expect("server error");
}
