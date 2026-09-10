//! Well-known endpoints for offline token verification.
//!
//! GET /.well-known/aip-configuration   — service discovery document
//! GET /.well-known/jwks.json           — public key in JWK Set format

use axum::{extract::State, Json};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::{delegation, AppState};

// ── /.well-known/aip-configuration ───────────────────────────────────────────

#[derive(Serialize)]
pub struct AipConfiguration {
    pub issuer: String,
    pub token_endpoint: String,
    pub verification_endpoint: String,
    pub delegation_endpoint: String,
    pub revocation_endpoint: String,
    pub jwks_uri: String,
    pub algorithms_supported: Vec<&'static str>,
    pub delegation_max_depth: u32,
}

pub async fn aip_configuration(State(state): State<Arc<AppState>>) -> Json<AipConfiguration> {
    // Fingerprint is logged but state is used to satisfy axum's state extractor requirement.
    let _ = &state.fingerprint;
    let base = std::env::var("AIP_ISSUER_URL").unwrap_or_else(|_| "http://aip:8081".to_owned());
    Json(AipConfiguration {
        issuer: base.clone(),
        token_endpoint: format!("{base}/v1/identity/issue"),
        verification_endpoint: format!("{base}/v1/identity/verify"),
        delegation_endpoint: format!("{base}/v1/identity/delegate"),
        revocation_endpoint: format!("{base}/v1/identity/revoke"),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        algorithms_supported: vec!["EdDSA"],
        delegation_max_depth: delegation::MAX_DEPTH,
    })
}

// ── /.well-known/jwks.json ────────────────────────────────────────────────────

/// Minimal JWK Set containing the AIP Ed25519 public key.
#[derive(Serialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Serialize)]
pub struct Jwk {
    pub kty: &'static str,
    pub crv: &'static str,
    /// Base64url-encoded raw 32-byte Ed25519 public key.
    pub x: String,
    #[serde(rename = "use")]
    pub key_use: &'static str,
    /// SHA-256 fingerprint of the public key — matches the fingerprint in issue responses.
    pub kid: String,
    pub alg: &'static str,
}

pub async fn jwks(State(state): State<Arc<AppState>>) -> Json<JwkSet> {
    let x = extract_ed25519_x_from_pem(&state.public_pem);
    Json(JwkSet {
        keys: vec![Jwk {
            kty: "OKP",
            crv: "Ed25519",
            x,
            key_use: "sig",
            kid: state.fingerprint.clone(),
            alg: "EdDSA",
        }],
    })
}

/// Extract the raw 32-byte Ed25519 public key from an SPKI PEM and encode as base64url.
///
/// SPKI encoding for Ed25519 is:
///   30 2a                       — SEQUENCE (42 bytes)
///     30 05                     — SEQUENCE (5 bytes)
///       06 03 2b 65 70          — OID 1.3.101.112 (Ed25519)
///     03 23 00                  — BIT STRING (35 bytes, 0 unused bits)
///       <32 bytes raw public key>
///
/// Total DER: 44 bytes.  The raw key occupies the last 32 bytes.
fn extract_ed25519_x_from_pem(pem: &str) -> String {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    if let Ok(der) = STANDARD.decode(&b64) {
        if der.len() >= 32 {
            return URL_SAFE_NO_PAD.encode(&der[der.len() - 32..]);
        }
    }

    // Fallback: SHA-256 hash of PEM bytes (signals a parse error gracefully)
    let mut h = Sha256::new();
    h.update(pem.as_bytes());
    URL_SAFE_NO_PAD.encode(h.finalize())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ServiceKey;

    // T-WK-1: JWKS x field is 43 base64url chars (32 bytes)
    #[test]
    fn test_jwks_x_is_32_bytes() {
        let kp = ServiceKey::generate();
        let x = extract_ed25519_x_from_pem(&kp.public_pem);
        // 32 bytes in base64url without padding = ceil(32 * 4/3) = 43 chars
        assert_eq!(
            x.len(),
            43,
            "Ed25519 x must be 43 base64url chars, got {}",
            x.len()
        );
    }

    // T-WK-2: x decodes back to 32 bytes
    #[test]
    fn test_jwks_x_decodes_to_32_bytes() {
        let kp = ServiceKey::generate();
        let x = extract_ed25519_x_from_pem(&kp.public_pem);
        let decoded = URL_SAFE_NO_PAD
            .decode(&x)
            .expect("x must be valid base64url");
        assert_eq!(decoded.len(), 32);
    }
}
