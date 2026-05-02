//! JWT issuance and verification — EdDSA (Ed25519).
//!
//! Issue:  signs a new JWT with the service's Ed25519 private key.
//! Verify: validates signature, expiry, and algorithm; returns structured result.
//!
//! Claims structure (all fields required):
//!   sub      — agent_id (UUID v4)
//!   agt      — agent_type ("human" | "ai_model" | "service")
//!   meta     — metadata object (may be null)
//!   iat      — issued-at (Unix seconds, i64)
//!   exp      — expiry   (Unix seconds, i64)
//!   jti      — JWT ID   (UUID v4, unique per token)

use chrono::Utc;
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Claims ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the agent_id UUID.
    pub sub: String,
    /// Agent type string.
    pub agt: String,
    /// Optional metadata forwarded from the issue request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Map<String, serde_json::Value>>,
    /// Issued-at (Unix seconds).
    pub iat: i64,
    /// Expiry (Unix seconds).
    pub exp: i64,
    /// JWT ID — unique per token, enables future revocation indexing.
    pub jti: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct IssueResult {
    pub token: String,
    pub issued_at: String,
    pub expires_at: String,
}

/// Sign a new EdDSA JWT.
pub fn issue(
    agent_id: &str,
    agent_type: &str,
    metadata: Option<serde_json::Map<String, serde_json::Value>>,
    ttl_seconds: u64,
    encoding_key: &EncodingKey,
) -> Result<IssueResult, String> {
    let now = Utc::now();
    let iat = now.timestamp();
    let exp = iat + ttl_seconds as i64;

    let claims = Claims {
        sub: agent_id.to_owned(),
        agt: agent_type.to_owned(),
        meta: metadata,
        iat,
        exp,
        jti: Uuid::new_v4().to_string(),
    };

    let token = encode(&Header::new(Algorithm::EdDSA), &claims, encoding_key)
        .map_err(|e| format!("JWT encode error: {e}"))?;

    let fmt = "%Y-%m-%dT%H:%M:%SZ";
    let issued_at = now.format(fmt).to_string();
    let expires_at = chrono::DateTime::from_timestamp(exp, 0)
        .map(|dt| dt.format(fmt).to_string())
        .unwrap_or_else(|| "9999-12-31T23:59:59Z".to_owned());

    Ok(IssueResult {
        token,
        issued_at,
        expires_at,
    })
}

pub struct VerifyResult {
    pub valid: bool,
    pub agent_id: String,
    pub agent_type: String,
    /// JWT ID — used by handlers to check the revocation set.
    pub jti: String,
    pub expired: bool,
    pub reason: Option<String>,
}

/// Verify an EdDSA JWT.  Never panics.
pub fn verify(token: &str, decoding_key: &DecodingKey) -> VerifyResult {
    // Strict validation: no leeway, no aud requirement, EdDSA only.
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_aud = false;
    validation.leeway = 0;

    match decode::<Claims>(token, decoding_key, &validation) {
        Ok(data) => VerifyResult {
            valid: true,
            agent_id: data.claims.sub,
            agent_type: data.claims.agt,
            jti: data.claims.jti,
            expired: false,
            reason: None,
        },
        Err(e) => {
            let (expired, reason) = match e.kind() {
                ErrorKind::ExpiredSignature => (true, "token has expired".to_owned()),
                ErrorKind::InvalidSignature => (false, "signature verification failed".to_owned()),
                ErrorKind::InvalidAlgorithm => (false, "unsupported signing algorithm".to_owned()),
                ErrorKind::InvalidToken => (false, "malformed token".to_owned()),
                ErrorKind::ImmatureSignature => (false, "token not yet valid".to_owned()),
                ErrorKind::Base64(inner) => (false, format!("base64 decode error: {inner}")),
                ErrorKind::Json(inner) => (false, format!("claims parse error: {inner}")),
                _ => (false, format!("invalid token: {e}")),
            };
            VerifyResult {
                valid: false,
                agent_id: String::new(),
                agent_type: String::new(),
                jti: String::new(),
                expired,
                reason: Some(reason),
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    fn test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    fn encoding_key(kp: &KeyPair) -> EncodingKey {
        EncodingKey::from_ed_pem(kp.private_pem.as_bytes()).expect("test keypair PEM must be valid")
    }

    fn decoding_key(kp: &KeyPair) -> DecodingKey {
        DecodingKey::from_ed_pem(kp.public_pem.as_bytes()).expect("test keypair PEM must be valid")
    }

    const AGENT_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    // ── Test 1: issue → verify roundtrip ──────────────────────────────────────

    #[test]
    fn test_issue_verify_roundtrip() {
        let kp = test_keypair();
        let ek = encoding_key(&kp);
        let dk = decoding_key(&kp);

        let result = issue(AGENT_ID, "human", None, 3600, &ek).unwrap();
        assert!(!result.token.is_empty());
        assert!(result.issued_at.contains('T'));
        assert!(result.expires_at.contains('T'));

        let v = verify(&result.token, &dk);
        assert!(v.valid, "token must be valid: {:?}", v.reason);
        assert!(!v.expired);
        assert_eq!(v.agent_id, AGENT_ID);
        assert_eq!(v.agent_type, "human");
        assert!(v.reason.is_none());
    }

    // ── Test 2: issue with ttl=1, wait 2s → expired ───────────────────────────

    #[tokio::test]
    async fn test_expired_token() {
        let kp = test_keypair();
        let ek = encoding_key(&kp);
        let dk = decoding_key(&kp);

        let result = issue(AGENT_ID, "service", None, 1, &ek).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let v = verify(&result.token, &dk);
        assert!(!v.valid, "expired token must not be valid");
        assert!(v.expired, "expired flag must be true");
        assert_eq!(v.reason.as_deref(), Some("token has expired"));
    }

    // ── Test 3: tampered signature → rejected ─────────────────────────────────

    #[test]
    fn test_tampered_token_rejected() {
        let kp = test_keypair();
        let ek = encoding_key(&kp);
        let dk = decoding_key(&kp);

        let result = issue(AGENT_ID, "ai_model", None, 3600, &ek).unwrap();

        // Flip the last character of the Base64url signature segment.
        let mut tampered = result.token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });

        let v = verify(&tampered, &dk);
        assert!(!v.valid, "tampered token must not be valid");
        assert!(!v.expired);
        assert!(
            v.reason.as_deref().unwrap_or("").contains("signature")
                || v.reason.as_deref().unwrap_or("").contains("malformed")
                || v.reason.as_deref().unwrap_or("").contains("base64"),
            "unexpected reason: {:?}",
            v.reason
        );
    }

    // ── Test 4: wrong algorithm (HS256) → rejected ────────────────────────────

    #[test]
    fn test_wrong_algorithm_rejected() {
        let kp = test_keypair();
        let dk = decoding_key(&kp);

        // Build a HS256 token — different algorithm, any secret.
        #[derive(Serialize)]
        struct DummyClaims {
            sub: String,
            exp: i64,
        }
        let dummy = DummyClaims {
            sub: AGENT_ID.to_owned(),
            exp: i64::MAX,
        };
        let hs256_token = encode(
            &Header::new(Algorithm::HS256),
            &dummy,
            &EncodingKey::from_secret(b"irrelevant-secret"),
        )
        .unwrap();

        // Verify against EdDSA validator — must reject due to algorithm mismatch.
        let v = verify(&hs256_token, &dk);
        assert!(!v.valid, "HS256 token must not pass EdDSA verification");
        assert!(!v.expired);
    }

    // ── Test 5: token from different keypair → rejected ───────────────────────

    #[test]
    fn test_wrong_keypair_rejected() {
        let kp_signer = test_keypair();
        let kp_verifier = test_keypair(); // different key

        let ek = encoding_key(&kp_signer);
        let dk = decoding_key(&kp_verifier);

        let result = issue(AGENT_ID, "human", None, 3600, &ek).unwrap();
        let v = verify(&result.token, &dk);
        assert!(!v.valid, "token signed by different key must be rejected");
        assert!(!v.expired);
    }

    // ── Test 6: metadata round-trips correctly ────────────────────────────────

    #[test]
    fn test_metadata_in_claims() {
        let kp = test_keypair();
        let ek = encoding_key(&kp);
        let dk = decoding_key(&kp);

        let mut meta = serde_json::Map::new();
        meta.insert(
            "org".to_owned(),
            serde_json::Value::String("vanian".to_owned()),
        );
        meta.insert("tier".to_owned(), serde_json::Value::Number(1.into()));

        let result = issue(AGENT_ID, "service", Some(meta), 3600, &ek).unwrap();
        let v = verify(&result.token, &dk);
        assert!(v.valid);

        // Decode the claims directly to verify metadata is present.
        let mut val = Validation::new(Algorithm::EdDSA);
        val.validate_aud = false;
        val.leeway = 0;
        let token_data = decode::<Claims>(&result.token, &dk, &val).unwrap();
        let meta_back = token_data.claims.meta.unwrap();
        assert_eq!(
            meta_back.get("org").and_then(|v| v.as_str()),
            Some("vanian")
        );
    }

    // ── Test 7: each issued token has a unique jti ────────────────────────────

    #[test]
    fn test_each_token_has_unique_jti() {
        let kp = test_keypair();
        let ek = encoding_key(&kp);
        let dk = decoding_key(&kp);

        let mut val = Validation::new(Algorithm::EdDSA);
        val.validate_aud = false;
        val.leeway = 0;

        let t1 = issue(AGENT_ID, "human", None, 60, &ek).unwrap().token;
        let t2 = issue(AGENT_ID, "human", None, 60, &ek).unwrap().token;

        let d1 = decode::<Claims>(&t1, &dk, &val).unwrap();
        let d2 = decode::<Claims>(&t2, &dk, &val).unwrap();

        assert_ne!(
            d1.claims.jti, d2.claims.jti,
            "each token must have a unique jti"
        );
    }

    // ── Test 8: verify() latency — must average << 10 ms ─────────────────────
    //
    // Runs 1 000 verify() calls and asserts the mean is well under the 10 ms
    // p99 target.  This is a micro-benchmark, not a load test — for full p99
    // measurement under concurrent load use `wrk` against the running binary.

    #[test]
    fn test_verify_latency_under_1ms_mean() {
        use std::time::Instant;

        let kp = test_keypair();
        let ek = encoding_key(&kp);
        let dk = decoding_key(&kp);

        let token = issue(AGENT_ID, "human", None, 3600, &ek).unwrap().token;
        const ITERS: u32 = 1_000;

        let t0 = Instant::now();
        for _ in 0..ITERS {
            let v = verify(&token, &dk);
            assert!(v.valid);
        }
        let elapsed_us = t0.elapsed().as_micros();
        let mean_us = elapsed_us / ITERS as u128;

        // Assert mean < 1 000 µs (1 ms) — well within the 10 ms p99 budget.
        // On release builds this is typically < 100 µs per call.
        assert!(
            mean_us < 1_000,
            "mean verify() latency {mean_us} µs exceeds 1 ms; p99 budget is 10 ms"
        );
    }
}
