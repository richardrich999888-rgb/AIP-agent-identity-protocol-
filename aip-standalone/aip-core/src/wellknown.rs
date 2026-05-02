//! Portable Identity — Well-Known Document Generation (RFC 5785).
//!
//! ## Design (§7-v2, NM-A4)
//!
//! Publishes two standard documents that allow any system to verify AIP tokens
//! without calling the AIP service API:
//!
//! ```text
//! GET /.well-known/aip-configuration   → AipConfiguration JSON
//! GET /.well-known/jwks.json           → JwksDocument JSON
//! ```
//!
//! With the JWKS document, any system can:
//! 1. Fetch the issuer's Ed25519 public key
//! 2. Verify an AIP token signature locally (zero API call)
//! 3. Check revocation status with a single lightweight GET
//!
//! This is the same pattern that makes OAuth 2.0 and OpenID Connect work at
//! internet scale. Publishing at `/.well-known/` signals RFC 5785 compliance.
//!
//! ## Novel Mechanism NM-A4
//!
//! "Portable offline verification for AI agent identity": by publishing the
//! issuer's public key in standard JWK format and the AIP configuration in a
//! well-known location, any external system can cryptographically verify an
//! agent's identity without any dependency on the AIP service uptime.

use aip_types::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::capability::verify_scoped_token;

// ─── Document Generation ───

/// Generate the AIP configuration document for the given base URL.
///
/// Publish at: `GET /.well-known/aip-configuration`
/// Headers: `Content-Type: application/json`, `Cache-Control: max-age=3600`
pub fn generate_aip_configuration(base_url: &str) -> AipConfiguration {
    let base = base_url.trim_end_matches('/');
    AipConfiguration {
        issuer: base.to_string(),
        jwks_uri: format!("{}/.well-known/jwks.json", base),
        revocation_uri: format!("{}/v1/identity/revocation-status", base),
        delegation_verify_uri: format!("{}/v1/identity/verify-chain", base),
        supported_algorithms: vec!["EdDSA".to_string()],
        token_format: "AIP-JWT-v1".to_string(),
        version: "0.3.0".to_string(),
    }
}

/// Generate a JWKS document from an Ed25519 public key.
///
/// Publish at: `GET /.well-known/jwks.json`
/// Headers: `Content-Type: application/json`, `Cache-Control: max-age=3600`
///
/// `kid` should be the AIP-ID of the issuer (the key identifier).
/// `public_key_bytes` must be 32 bytes (Ed25519 public key).
pub fn generate_jwks(public_key_bytes: &[u8], kid: &str) -> Result<JwksDocument, JwksError> {
    if public_key_bytes.len() != 32 {
        return Err(JwksError::InvalidKeyLength(public_key_bytes.len()));
    }

    let x = URL_SAFE_NO_PAD.encode(public_key_bytes);

    Ok(JwksDocument {
        keys: vec![JwksKey {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x,
            kid: kid.to_string(),
            use_: "sig".to_string(),
            alg: "EdDSA".to_string(),
        }],
    })
}

// ─── Local Token Verification (Portable, Zero-API) ───

/// Verify a scoped token's signature using a JWKS document.
///
/// This is the portable verification path: an external system fetches the JWKS
/// document once and can then verify tokens locally without calling the API.
///
/// Returns `true` if:
/// 1. The JWKS contains a key matching `token.issuer_id` (by `kid`)
/// 2. The token signature verifies against that key
pub fn verify_token_with_jwks(
    token: &ScopedToken,
    jwks: &JwksDocument,
) -> Result<bool, JwksError> {
    // Find the key matching this token's issuer
    let key = jwks.keys.iter()
        .find(|k| k.kid == token.issuer_id)
        .ok_or_else(|| JwksError::KeyNotFound(token.issuer_id.clone()))?;

    let pub_key_bytes = URL_SAFE_NO_PAD
        .decode(&key.x)
        .map_err(|e| JwksError::InvalidBase64(e.to_string()))?;

    if pub_key_bytes.len() != 32 {
        return Err(JwksError::InvalidKeyLength(pub_key_bytes.len()));
    }

    // Full verification: recomputes canonical payload hash AND checks Ed25519 signature
    verify_scoped_token(token, &pub_key_bytes)
        .map_err(|e| JwksError::CryptoError(format!("{:?}", e)))
}

/// Verify a delegation token's signature using a JWKS document.
pub fn verify_delegation_with_jwks(
    token: &DelegationToken,
    jwks: &JwksDocument,
) -> Result<bool, JwksError> {
    let key = jwks.keys.iter()
        .find(|k| k.kid == token.issuer_id)
        .ok_or_else(|| JwksError::KeyNotFound(token.issuer_id.clone()))?;

    let pub_key_bytes = URL_SAFE_NO_PAD
        .decode(&key.x)
        .map_err(|e| JwksError::InvalidBase64(e.to_string()))?;

    aip_crypto::verify_ed25519(&pub_key_bytes, &token.issuer_sig)
        .map_err(|e| JwksError::CryptoError(format!("{:?}", e)))
}

/// Serialize the AIP configuration to a JSON string (for the HTTP response body).
pub fn aip_configuration_to_json(config: &AipConfiguration) -> Result<String, JwksError> {
    serde_json::to_string_pretty(config)
        .map_err(|e| JwksError::SerializationError(e.to_string()))
}

/// Serialize the JWKS document to a JSON string (for the HTTP response body).
pub fn jwks_to_json(jwks: &JwksDocument) -> Result<String, JwksError> {
    serde_json::to_string_pretty(jwks)
        .map_err(|e| JwksError::SerializationError(e.to_string()))
}

// ─── Error ───

#[derive(Debug, Clone)]
pub enum JwksError {
    InvalidKeyLength(usize),
    KeyNotFound(String),
    InvalidBase64(String),
    CryptoError(String),
    SerializationError(String),
}

impl std::fmt::Display for JwksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwksError::InvalidKeyLength(n) => write!(f, "Invalid key length: {} (expected 32)", n),
            JwksError::KeyNotFound(id) => write!(f, "No JWKS key found for issuer: {}", id),
            JwksError::InvalidBase64(e) => write!(f, "Base64 decode error: {}", e),
            JwksError::CryptoError(e) => write!(f, "Crypto error: {}", e),
            JwksError::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::*;
    use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};

    fn make_issuer() -> (String, Vec<u8>, Vec<u8>) {
        let kp = generate_ed25519_keypair();
        let prov = ProvenanceTriple {
            model_commitment: sha256(b"m"),
            environment_commitment: sha256(b"e"),
            toolchain_commitment: sha256(b"t"),
        };
        let id = derive_aip_id(&kp.public_key, &prov);
        (id, kp.private_key, kp.public_key)
    }

    // ── AIP Configuration tests ──

    #[test]
    fn test_aip_configuration_has_required_fields() {
        let config = generate_aip_configuration("https://aip.airon.ai");

        assert_eq!(config.issuer, "https://aip.airon.ai");
        assert!(config.jwks_uri.contains("/.well-known/jwks.json"));
        assert!(config.revocation_uri.contains("/v1/identity/revocation-status"));
        assert!(config.delegation_verify_uri.contains("/v1/identity/verify-chain"));
        assert!(!config.supported_algorithms.is_empty());
        assert_eq!(config.token_format, "AIP-JWT-v1");
        assert!(!config.version.is_empty());
    }

    #[test]
    fn test_aip_configuration_trailing_slash_stripped() {
        let config = generate_aip_configuration("https://aip.airon.ai/");
        assert_eq!(config.issuer, "https://aip.airon.ai");
        assert!(config.jwks_uri.starts_with("https://aip.airon.ai/"));
    }

    #[test]
    fn test_aip_configuration_serializes_to_json() {
        let config = generate_aip_configuration("https://aip.airon.ai");
        let json = aip_configuration_to_json(&config).unwrap();
        assert!(json.contains("issuer"));
        assert!(json.contains("jwks_uri"));
        assert!(json.contains("AIP-JWT-v1"));
    }

    // ── JWKS tests ──

    #[test]
    fn test_jwks_generated_for_ed25519_key() {
        let (id, _, pub_key) = make_issuer();
        let jwks = generate_jwks(&pub_key, &id).unwrap();

        assert_eq!(jwks.keys.len(), 1);
        let key = &jwks.keys[0];
        assert_eq!(key.kty, "OKP");
        assert_eq!(key.crv, "Ed25519");
        assert_eq!(key.kid, id);
        assert_eq!(key.use_, "sig");
        assert_eq!(key.alg, "EdDSA");
        assert!(!key.x.is_empty());
    }

    #[test]
    fn test_jwks_invalid_key_length_rejected() {
        let result = generate_jwks(&[0u8; 16], "aip1test");
        assert!(matches!(result, Err(JwksError::InvalidKeyLength(16))));
    }

    #[test]
    fn test_jwks_serializes_to_valid_json() {
        let (id, _, pub_key) = make_issuer();
        let jwks = generate_jwks(&pub_key, &id).unwrap();
        let json = jwks_to_json(&jwks).unwrap();

        // Must contain required JWK fields
        assert!(json.contains("\"kty\""));
        assert!(json.contains("\"OKP\""));
        assert!(json.contains("\"crv\""));
        assert!(json.contains("\"Ed25519\""));
        assert!(json.contains("\"x\""));
    }

    // ── Portable verification tests (NM-A4 core) ──

    #[test]
    fn test_fetch_jwks_and_verify_token_locally_without_api() {
        let (issuer_id, priv_key, pub_key) = make_issuer();
        let (agent_id, _, _) = make_issuer();

        // Step 1: Issue a token (simulates POST /v1/identity/issue)
        let token = issue_scoped_token(
            &issuer_id,
            &priv_key,
            &agent_id,
            scope_orchestrator(),
            Some(3_600_000),
        )
        .unwrap();

        // Step 2: "Fetch" JWKS (simulates GET /.well-known/jwks.json)
        let jwks = generate_jwks(&pub_key, &issuer_id).unwrap();

        // Step 3: Verify locally — ZERO API calls
        let valid = verify_token_with_jwks(&token, &jwks).unwrap();
        assert!(valid, "Token must verify locally using JWKS public key");
    }

    #[test]
    fn test_tampered_token_fails_local_verification() {
        let (issuer_id, priv_key, pub_key) = make_issuer();
        let (agent_id, _, _) = make_issuer();

        let mut token = issue_scoped_token(
            &issuer_id,
            &priv_key,
            &agent_id,
            scope_submitter(),
            None,
        )
        .unwrap();

        // Tamper: escalate scope after issuance
        token.scope = scope_admin();

        let jwks = generate_jwks(&pub_key, &issuer_id).unwrap();
        let valid = verify_token_with_jwks(&token, &jwks).unwrap();
        assert!(!valid, "Tampered token must fail local JWKS verification");
    }

    #[test]
    fn test_wrong_issuer_key_fails_verification() {
        let (issuer_id, priv_key, _) = make_issuer();
        let (_, _, wrong_pub_key) = make_issuer(); // Different key pair
        let (agent_id, _, _) = make_issuer();

        let token = issue_scoped_token(
            &issuer_id,
            &priv_key,
            &agent_id,
            scope_submitter(),
            None,
        )
        .unwrap();

        // JWKS has wrong public key
        let jwks = generate_jwks(&wrong_pub_key, &issuer_id).unwrap();
        let valid = verify_token_with_jwks(&token, &jwks).unwrap();
        assert!(!valid, "Token must fail verification against wrong key");
    }

    #[test]
    fn test_key_not_found_returns_error() {
        let (issuer_id, priv_key, _) = make_issuer();
        let (other_id, _, other_pub) = make_issuer();
        let (agent_id, _, _) = make_issuer();

        let token = issue_scoped_token(
            &issuer_id,
            &priv_key,
            &agent_id,
            scope_submitter(),
            None,
        )
        .unwrap();

        // JWKS contains a different issuer's key
        let jwks = generate_jwks(&other_pub, &other_id).unwrap();
        let result = verify_token_with_jwks(&token, &jwks);
        assert!(matches!(result, Err(JwksError::KeyNotFound(_))));
    }
}
