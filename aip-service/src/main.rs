//! airon-aip — Agent Identity Protocol service (v2).
//!
//! Environment variables:
//!   AIP_PORT                — listen port (default 8081)
//!   AIP_KEY_PATH            — Ed25519 seed path (default /var/lib/aip/signing.key)
//!   AIP_REVOCATION_LOG_PATH — revocation JSONL log (default /var/lib/aip/revocation.jsonl)
//!   AIP_VAULT_PATH          — JSONL evidence vault (jsonl backend)
//!   AIP_API_KEYS_PATH       — API keys file (no keys ⇒ fail closed)
//!   AIP_STORE_BACKEND       — "jsonl" (default) | "postgres"
//!   DATABASE_URL            — PostgreSQL DSN (required when backend=postgres)
//!   RUST_LOG                — log filter (default info)

use std::sync::Arc;

use tracing_subscriber::{fmt, EnvFilter};

use airon_aip::store::{EvidenceStore, JsonlEvidenceStore};
use airon_aip::{auth, keys::ServiceKey, revocation, router, AppState, ManagedSigning};

/// The evidence store's connection pool, when there is one.
///
/// A unit on builds without the `postgres` feature, so the wiring below is
/// one code path rather than two.
#[cfg(feature = "postgres")]
type EvidencePool = Option<deadpool_postgres::Pool>;
/// A build without the feature has no pool to share, and the artifact tier
/// falls through to its file backend.
#[cfg(not(feature = "postgres"))]
type EvidencePool = Option<std::convert::Infallible>;

/// The verdict and access-ledger store (R10).
///
/// JSONL by default, beside the evidence vault. A deployment using the
/// PostgreSQL evidence backend should point this at the database too; that
/// wiring shares the evidence pool and is the next step for this tier, so
/// the default is stated here rather than implied.
fn build_artifact_store(
    evidence_pool: EvidencePool,
) -> Arc<dyn airon_aip::artifacts::ArtifactStore> {
    // When the evidence tier is on PostgreSQL the artifact tier must be too:
    // an inspector's answer stored somewhere with weaker controls than the
    // evidence it rests on is the place that answer goes to be edited. The
    // pool is shared rather than duplicated, so both tiers observe the same
    // connection limits and the same tenant-GUC discipline.
    #[cfg(feature = "postgres")]
    if let Some(pool) = evidence_pool {
        tracing::info!("verdict/ledger store: postgres (sharing the evidence pool)");
        return Arc::new(airon_aip::artifacts::pg::PostgresArtifactStore::with_pool(
            pool,
        ));
    }
    let _ = evidence_pool;
    let path = std::env::var("AIP_ARTIFACT_PATH")
        .unwrap_or_else(|_| "/var/lib/aip/artifacts.jsonl".to_string());
    match airon_aip::artifacts::JsonlArtifactStore::open(&path) {
        Ok(s) => {
            tracing::info!(path, "verdict/ledger store: jsonl");
            Arc::new(s)
        }
        Err(e) => {
            // In memory rather than refusing to start: this tier is additive,
            // and an unwritable path must not take down evidence ingest. It
            // is logged at warn because anything filed here is lost on exit.
            tracing::warn!(path, error = %e, "verdict/ledger store unavailable; using memory");
            Arc::new(airon_aip::artifacts::JsonlArtifactStore::in_memory())
        }
    }
}

async fn build_store() -> (Arc<dyn EvidenceStore>, EvidencePool) {
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
                let pool = store.pool();
                (Arc::new(store) as Arc<dyn EvidenceStore>, Some(pool))
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
            (
                Arc::new(JsonlEvidenceStore::load(&vault_path)) as Arc<dyn EvidenceStore>,
                None,
            )
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
    let revocation_log_path = std::env::var("AIP_REVOCATION_LOG_PATH")
        .unwrap_or_else(|_| "/var/lib/aip/revocation.jsonl".to_owned());
    let api_keys_path = std::env::var("AIP_API_KEYS_PATH").unwrap_or_default();

    // The directory must exist before a key can be created in it. A failure
    // here is not fatal on its own — the key may already be present — so it
    // is reported and the key load below decides whether to proceed.
    if let Some(parent) = std::path::Path::new(&key_path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(path = %parent.display(), error = %e, "could not create key directory");
        }
    }

    // Fail closed on the signing identity (AUDIT B-6). A service that cannot
    // read its configured key must not invent one: doing so silently rotates
    // the identity, invalidating every token and audit bundle already signed
    // under it, and leaves nothing to distinguish that from forgery. The only
    // condition under which a key is created is that none exists yet.
    // `AIP_KEY_PASSPHRASE` selects the backend: set, the key is wrapped
    // (Argon2id + XChaCha20-Poly1305, the production backend); unset, it is
    // the legacy plaintext seed, which a production policy refuses below.
    let passphrase = std::env::var("AIP_KEY_PASSPHRASE").ok();
    let kp = match ServiceKey::load_or_create(&key_path, passphrase.as_deref().map(str::as_bytes)) {
        Ok(kp) => kp,
        Err(e) => {
            tracing::error!(key_path, error = %e, "cannot obtain signing key; refusing to start");
            // Written to stderr as well: the JSON tracing subscriber is easy
            // to miss, and this is the last thing the process does.
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        }
    };
    // A production deployment refuses a backend that is not a production one.
    // There is no downgrade: the operator supplies a passphrase, or declares
    // the deployment development.
    let dev_policy = matches!(
        std::env::var("AIP_CUSTODY_POLICY").as_deref(),
        Ok("development") | Ok("dev")
    );
    if !dev_policy && !kp.backend().is_production() {
        let msg = format!(
            "the service signing key is held by the {:?} backend, which is not a \
             production one. Set AIP_KEY_PASSPHRASE to wrap the key, or \
             AIP_CUSTODY_POLICY=development to declare this a development \
             deployment.",
            kp.backend()
        );
        tracing::error!(key_path, backend = ?kp.backend(), "{msg}");
        eprintln!("FATAL: {msg}");
        std::process::exit(1);
    }
    let encoding_key = kp.encoding_key();
    let decoding_key = kp.decoding_key();

    let rev_set = revocation::load_revocation_set(&revocation_log_path);
    let (store, evidence_pool) = build_store().await;
    let artifacts = build_artifact_store(evidence_pool);
    let api_keys = auth::ApiKeyStore::load(&api_keys_path);
    if api_keys.is_empty() {
        tracing::warn!(
            "no API keys configured (AIP_API_KEYS_PATH) — authenticated routes \
             will reject all requests (fail closed)."
        );
    }

    // AUDIT B-7. Off unless a deployment opts in; when it does, say plainly
    // what has been accepted, because the cost is not obvious from the name.
    let managed_signing = ManagedSigning::from_env();
    if managed_signing.is_permitted() {
        tracing::warn!(
            "AIP_ALLOW_MANAGED_SIGNING is set: POST /v1/evidence/generate will \
             accept agent private seeds in request bodies. Those keys will be \
             visible to every proxy and log on the request path, and packets \
             signed this way cannot distinguish the agent from this service."
        );
    } else {
        tracing::info!(
            "managed signing is off: POST /v1/evidence/generate returns 501. \
             Agents sign client-side; the service verifies and ingests."
        );
    }

    let evidence_packets = store.count().await.unwrap_or(0);
    tracing::info!(
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
        revocation_log_path,
        revocation_set: rev_set,
        store,
        // Verdicts and access ledgers (R10). The path defaults beside the
        // evidence vault; a deployment with the PostgreSQL backend points
        // both at the database instead.
        artifacts,
        api_keys,
        signer: Arc::new(kp),
        metrics: Arc::new(Default::default()),
        managed_signing,
    });

    let addr = format!("0.0.0.0:{port}");
    tracing::info!(port, fingerprint = %state.fingerprint, key_path, "airon-aip v2 starting");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    axum::serve(listener, router(state))
        .await
        .expect("server error");
}
