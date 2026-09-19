//! AIP request / response types.

use serde::{Deserialize, Serialize};

// ── agent_type enum ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    Human,
    AiModel,
    Service,
}

impl AgentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentType::Human => "human",
            AgentType::AiModel => "ai_model",
            AgentType::Service => "service",
        }
    }
}

// ── POST /v1/identity/issue ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    /// UUID v4 of the agent requesting a token.
    pub agent_id: String,
    pub agent_type: AgentType,
    /// Arbitrary key-value metadata attached to the token claims (max 10 keys).
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
    /// Token lifetime in seconds. Range: 1..=86400.
    pub ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct IssueResponse {
    /// Signed EdDSA JWT.
    pub token: String,
    pub issued_at: String,
    pub expires_at: String,
    /// SHA-256 hex of the public key bytes — lets callers identify which key signed this token.
    pub public_key_fingerprint: String,
}

// ── POST /v1/identity/verify ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    /// Empty string when valid=false.
    pub agent_id: String,
    /// Empty string when valid=false.
    pub agent_type: String,
    pub expired: bool,
    pub reason: Option<String>,
}

// ── GET /v1/identity/public-key ───────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub public_key_pem: String,
    pub algorithm: &'static str,
    pub fingerprint: String,
}

// ── GET /health ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
    pub key_fingerprint: String,
}

// ── POST /v1/identity/revoke ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    /// JTI of the token to revoke.
    pub jti: String,
    /// JTI of the revoking authority token.
    pub revoked_by: String,
    /// Human-readable reason.
    pub reason: String,
    /// Accepted for wire compatibility and **refused when true**. Cascade
    /// revocation walked the service's unsigned delegation log, which has
    /// been removed; descendants of a JTI are now expressed by signed
    /// `aip-core` delegation chains, which the caller revokes explicitly.
    #[serde(default)]
    pub cascade: bool,
}

#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    pub revoked_count: usize,
    pub revoked_jtis: Vec<String>,
}

// ── GET /v1/identity/revocation-status/{jti} ─────────────────────────────────

#[derive(Debug, Serialize)]
pub struct RevocationStatusResponse {
    pub jti: String,
    /// Whether the JTI is revoked **within the caller's tenant**. A JTI is a
    /// tenant-scoped fact: another tenant's revocation of the same string is
    /// neither visible here nor reported.
    pub revoked: bool,
}

// ── Error body ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}
