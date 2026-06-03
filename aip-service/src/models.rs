//! AIP request / response types.

use aip_core::passport::{AgentPassport, EnvironmentalLock};
use serde::{Deserialize, Serialize};

use crate::capability::CapabilityScope;
use crate::delegation::DelegationToken;

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

// ── POST /v1/identity/delegate ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DelegateRequest {
    /// The parent AIP JWT (or a delegation_id string for sub-delegation).
    pub parent_token: String,
    /// UUID v4 of the agent being delegated to.
    pub delegatee_id: String,
    /// Requested capability scope (must be subset of parent scope).
    pub scope: CapabilityScope,
    /// Token lifetime in seconds. Range: 1..=86400.
    pub ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct DelegateResponse {
    pub delegation: DelegationToken,
}

// ── POST /v1/identity/verify-chain ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct VerifyChainRequest {
    /// The root AIP JWT at the head of the chain.
    pub root_token: String,
    /// Ordered list of delegation_ids from root to leaf (depth 1 first).
    pub delegation_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyChainResponse {
    pub valid: bool,
    pub effective_scope: Option<CapabilityScope>,
    pub chain_depth: u32,
    pub reason: Option<String>,
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
    /// If true, cascade-revoke all delegations that descend from this JTI.
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
    pub revoked: bool,
}

// ── POST /v1/passports/issue ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PassportIssueRequest {
    /// Optional AIP JWT. Callers may also pass it as `Authorization: Bearer ...`
    /// or `AIP-Token: ...`.
    pub aip_token: Option<String>,
    pub friendly_name: String,
    pub capabilities: Vec<String>,
    pub ttl_seconds: Option<u64>,
    pub max_delegation_depth: Option<u32>,
    pub environmental_lock: Option<EnvironmentalLock>,
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
    pub subject_classical_pubkey: Option<String>,
    pub subject_pqc_pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PassportIssueResponse {
    pub passport: AgentPassport,
    pub passport_hash: String,
}

// ── POST /v1/passports/verify ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PassportVerifyRequest {
    pub passport: AgentPassport,
}

#[derive(Debug, Serialize)]
pub struct PassportVerifyResponse {
    pub valid: bool,
    pub status: &'static str,
    pub reason: Option<String>,
    pub passport_id: Option<String>,
    pub agent_id: Option<String>,
    pub capabilities: Vec<String>,
    pub expires_at: Option<u64>,
}

// ── Error body ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}
