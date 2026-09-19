//! airon-aip library: shared modules for the service binary and the
//! `aip-migrate` tool. The deployable surface is a thin layer over
//! `aip-core` + `aip-protocol`.

pub mod artifacts;
pub mod auth;
pub mod authority;
pub mod evidence;
pub mod handlers;
pub mod keys;
pub mod metrics;
pub mod models;
pub mod revocation;
pub mod store;
pub mod tokens;
pub mod verdicts;
pub mod wellknown;

// Also compiled for the `postgres` feature: the storage-control integration
// tests need a real packet to store, and duplicating the builder there would
// mean two fixtures that can drift apart. It is not compiled into a default
// build.
#[cfg(any(test, feature = "postgres"))]
pub mod test_support;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use jsonwebtoken::{DecodingKey, EncodingKey};

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
    /// Path to the revocation JSONL log (for append operations).
    pub revocation_log_path: String,
    /// In-memory revocation set.
    pub revocation_set: RevocationSet,
    /// Signed verdicts and access ledgers (R10). A separate store from the
    /// evidence one because the documents are separate: an evidence packet
    /// is the agent's account, a verdict is the reconciler's, and a service
    /// that filed them together would invite a reader to treat one as
    /// vouching for the other.
    pub artifacts: Arc<dyn artifacts::ArtifactStore>,
    /// Evidence store (JSONL or PostgreSQL) — the accountability system of
    /// record. Handlers depend only on the trait, never the backend.
    pub store: Arc<dyn EvidenceStore>,
    /// API-key store for authentication + tenant binding. Empty ⇒ fail closed.
    pub api_keys: auth::ApiKeyStore,
    /// The signer for audit-export bundle manifests.
    ///
    /// A signer, not a key. This field previously held the service's raw
    /// 32-byte Ed25519 seed, which made the private key readable from every
    /// HTTP handler in the process — `AppState` is shared with all of them.
    /// `RawSigner` exposes signing and a public key and nothing else.
    pub signer: std::sync::Arc<dyn aip_crypto::custody::RawSigner>,
    /// Operational counters (R15). Aggregate only: no tenant, agent or
    /// document identifier appears in a metric, because a labelled series
    /// on a shared scrape is a cross-tenant disclosure channel.
    pub metrics: Arc<metrics::Metrics>,
    /// Whether `POST /v1/evidence/generate` — which requires the caller to
    /// send an agent's *private* Ed25519 seed in the request body — is
    /// served at all.
    ///
    /// Off unless a deployment sets `AIP_ALLOW_MANAGED_SIGNING=1` (AUDIT
    /// B-7). See [`ManagedSigning`] for what enabling it costs.
    pub managed_signing: ManagedSigning,
}

/// Whether the service will sign on an agent's behalf using a key the caller
/// hands it.
///
/// # Why this is a decision and not a default (AUDIT B-7)
///
/// `/v1/evidence/generate` takes `agent_seed_hex`: the agent's private key,
/// in a JSON body. Two distinct costs follow, and they are not the same cost.
///
/// **Exposure.** The private key crosses the network and comes to rest
/// wherever request bodies come to rest — TLS-terminating proxies, access
/// logs, APM traces, crash reports, the client's own retry buffer. None of
/// those are places a signing key can be withdrawn from once it has been
/// there.
///
/// **Attribution.** The deeper cost. A packet signed this way asserts "this
/// agent acted", but the service held the agent's key, so the service could
/// have signed anything under that identity. The signature no longer
/// distinguishes the agent from the service, and the accountability claim the
/// packet exists to carry is exactly the claim it can no longer support.
///
/// The supported production shape is the opposite one, and the request schema
/// already accommodates it: agents sign client-side and the service is used
/// for verify and ingest, with the authority tokens supplied pre-signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedSigning {
    /// The endpoint is not routed. A caller cannot send a private seed here
    /// because there is nothing listening to deserialize one.
    Refused,
    /// The deployment has explicitly accepted both costs above.
    Permitted,
}

impl ManagedSigning {
    /// Read the deployment's choice from the environment. Anything other than
    /// an explicit opt-in is a refusal — including an unset, empty, or
    /// unparseable value.
    pub fn from_env() -> Self {
        match std::env::var("AIP_ALLOW_MANAGED_SIGNING").as_deref() {
            Ok("1") | Ok("true") => ManagedSigning::Permitted,
            _ => ManagedSigning::Refused,
        }
    }

    /// Whether managed signing has been explicitly permitted.
    pub fn is_permitted(self) -> bool {
        self == ManagedSigning::Permitted
    }
}

/// Build the full router from shared state.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        // Operational metrics (R15).
        //
        // Auth: `Principal` — any role. **Not public.** Request volume is
        // commercially and operationally sensitive, and an unauthenticated
        // counter of filed evidence tells an observer when an institution
        // is busy. A Prometheus scrape sends a bearer token like any other
        // client.
        // Tenant: none. Counters are aggregate; see `metrics`.
        // Cost: reads ten atomics and formats a fixed string. No store
        // access, no signature verification, no unbounded work.
        .route("/metrics", get(handlers::metrics))
        .route("/v1/identity/issue", post(handlers::issue))
        .route("/v1/identity/verify", post(handlers::verify))
        .route("/v1/identity/public-key", get(handlers::public_key))
        .route("/v1/identity/revoke", post(handlers::revoke))
        .route(
            "/v1/identity/revocation-status/:jti",
            get(handlers::revocation_status),
        )
        // Accountability layer.
        //
        // The generate route is chosen here rather than checked inside the
        // handler, so that when managed signing is refused there is no
        // extractor to deserialize a private seed out of a request body
        // (AUDIT B-7). Refusal is a property of the routing table, not of a
        // branch someone can later forget to take.
        .route(
            "/v1/evidence/generate",
            if state.managed_signing.is_permitted() {
                post(evidence::generate)
            } else {
                post(evidence::generate_refused)
            },
        )
        .route("/v1/evidence/verify", post(evidence::verify))
        .route("/v1/evidence/:id", get(evidence::get_evidence))
        .route("/v1/evidence/:id/export", get(evidence::export_evidence))
        .route("/v1/authority/:id", get(evidence::get_authority))
        // Verdicts and access ledgers (R10). Every one is verified under the
        // caller's anchors before it is stored, and returned verbatim, so
        // the answer never depends on trusting this service.
        .route("/v1/verdicts", post(verdicts::submit_verdict))
        .route("/v1/verdicts/:id", get(verdicts::get_verdict))
        .route("/v1/ledgers", post(verdicts::submit_ledger))
        .route("/v1/agents/:agent_id/ledger", get(verdicts::agent_ledger))
        // Well-known discovery
        .route(
            "/.well-known/aip-configuration",
            get(wellknown::aip_configuration),
        )
        .route("/.well-known/jwks.json", get(wellknown::jwks))
        .with_state(state)
}
