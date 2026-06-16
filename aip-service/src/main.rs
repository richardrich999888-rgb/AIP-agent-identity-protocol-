//! airon-aip — Agent Identity Protocol service (v2).
//!
//! Environment variables:
//!   AIP_PORT                — listen port (default 8081)
//!   AIP_KEY_PATH            — Ed25519 seed path (default /var/lib/aip/signing.key)
//!   AIP_DELEGATION_LOG_PATH — delegation JSONL log (default /var/lib/aip/delegation.jsonl)
//!   AIP_REVOCATION_LOG_PATH — revocation JSONL log (default /var/lib/aip/revocation.jsonl)
//!   AIP_VAULT_PATH          — JSONL evidence vault (jsonl backend)
//!   AIP_API_KEYS_PATH       — API keys file (no keys ⇒ fail closed)
//!   AIP_STORE_BACKEND       — "jsonl" (default) | "postgres"
//!   DATABASE_URL            — PostgreSQL DSN (required when backend=postgres)
//!   RUST_LOG                — log filter (default info)

use std::sync::Arc;

use tracing_subscriber::{fmt, EnvFilter};

use airon_aip::store::{EvidenceStore, JsonlEvidenceStore};
use airon_aip::{auth, delegation, keys::KeyPair, revocation, router, AppState};

async fn build_store() -> Arc<dyn EvidenceStore> {
    let backend = std::env::var("AIP_STORE_BACKEND").unwrap_or_else(|_| "jsonl".to_owned());
    match backend.as_str() {
        "postgres" => {
            #[cfg(feature = "postgres")]
            {
                let url = std::env::var("DATABASE_URL")
                    .expect("AIP_STORE_BACKEND=postgres requires DATABASE_URL");
                let store = airon_aip::store::PostgresEvidenceStore::connect(&url)
                    .await
                    .expect("failed to connect to PostgreSQL");
                tracing::info!("evidence store backend: postgres");
                Arc::new(store)
            }
            #[cfg(not(feature = "postgres"))]
            {
                panic!(
                    "AIP_STORE_BACKEND=postgres but this binary was built without \
                     the `postgres` feature (rebuild with --features postgres)"
                );
            }
        }
        _ => {
            let vault_path = std::env::var("AIP_VAULT_PATH")
                .unwrap_or_else(|_| "/var/lib/aip/evidence.jsonl".to_owned());
            tracing::info!(path = %vault_path, "evidence store backend: jsonl");
            Arc::new(JsonlEvidenceStore::load(&vault_path))
        }
    }
}

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
    let api_keys_path = std::env::var("AIP_API_KEYS_PATH").unwrap_or_default();

    if let Some(parent) = std::path::Path::new(&key_path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(path = %parent.display(), error = %e, "Could not create key directory");
        }
    }

    let kp = KeyPair::load_or_generate(&key_path);
    let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(kp.private_pem.as_bytes())
        .expect("generated private PEM must always be valid");
    let decoding_key = jsonwebtoken::DecodingKey::from_ed_pem(kp.public_pem.as_bytes())
        .expect("generated public PEM must always be valid");

    let del_log = delegation::load_delegation_log(&delegation_log_path);
    let rev_set = revocation::load_revocation_set(&revocation_log_path);
    let store = build_store().await;
    let api_keys = auth::ApiKeyStore::load(&api_keys_path);
    if api_keys.is_empty() {
        tracing::warn!(
            "no API keys configured (AIP_API_KEYS_PATH) — authenticated routes \
             will reject all requests (fail closed)."
        );
    }

    let evidence_packets = store.count().await.unwrap_or(0);
    tracing::info!(
        delegation_entries = del_log.lock().unwrap().len(),
        revocation_entries = rev_set.lock().unwrap().len(),
        evidence_packets,
        api_keys = api_keys.len(),
        "AIP v2 state loaded"
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
        store,
        api_keys,
    });

    let addr = format!("0.0.0.0:{port}");
    tracing::info!(port, fingerprint = %kp.fingerprint, key_path, "airon-aip v2 starting");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    axum::serve(listener, router(state))
        .await
        .expect("server error");
}
