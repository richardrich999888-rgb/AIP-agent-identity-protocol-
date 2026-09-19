//! AIP Types — Core data structures for the Agent Identity Protocol v0.3.0.
//!
//! Pure types, no logic. Mirrors the wire format from the AIP spec.
//!
//! The one exception is [`canonical`]: the injective byte encoder shared by
//! every crate that signs or hashes these types.

pub mod canonical;
pub mod window;

pub use window::CoverageWindow;

use serde::{Deserialize, Serialize};

// ─── Algorithm Identifiers (§3.1) ───

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AlgorithmId {
    Ed25519 = 0x01,
    MlDsa65 = 0x02,
    Hybrid = 0x03,
}

// ─── Cryptographic Primitives (§3.2, §3.3) ───

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub algorithm: AlgorithmId,
    pub key_bytes: Vec<u8>,
}

/// A signing key pair.
///
/// `Debug` is implemented by hand and redacts `private_key` so that logging
/// or `{:?}`-formatting a key pair can never leak secret material.
///
/// `Serialize`/`Deserialize` are retained because `aip_core::store` persists
/// identities (including their key pair) as JSON. That persistence is
/// plaintext at rest; protecting it is a key-management concern outside this
/// type. Do not serialize a `KeyPair` anywhere else.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub algorithm: AlgorithmId,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("algorithm", &self.algorithm)
            .field("public_key", &self.public_key)
            .field(
                "private_key",
                &format_args!("<redacted {} bytes>", self.private_key.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: AlgorithmId,
    pub signer_id: String,      // AIP-ID
    pub timestamp: u64,         // Unix ms
    pub nonce: [u8; 16],        // CSPRNG nonce (FIX-1)
    pub payload_hash: [u8; 32], // SHA-256 of signed payload
    pub signature_bytes: Vec<u8>,
}

// ─── Provenance Triple (§4.2.1, NM-1) ───

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceTriple {
    pub model_commitment: [u8; 32],       // SHA-256 of model weights/arch
    pub environment_commitment: [u8; 32], // SHA-256 of runtime env
    pub toolchain_commitment: [u8; 32],   // SHA-256 of toolchain
}

impl ProvenanceTriple {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&self.model_commitment);
        out.extend_from_slice(&self.environment_commitment);
        out.extend_from_slice(&self.toolchain_commitment);
        out
    }
}

// ─── Lifecycle States (§5.1) ───

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IdentityStatus {
    Pending = 0x00,
    Active = 0x01,
    Suspended = 0x02,
    Revoked = 0x03, // Terminal
}

// ─── Feature Flags (§4.3) ───

// ─── Feature Flags (§4.3) ───

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AidFlags(pub u16);

impl AidFlags {
    pub const HAS_RECOVERY: Self = Self(0x0001);
    pub const HAS_ENCRYPTION: Self = Self(0x0002);
    pub const HAS_OPERATOR: Self = Self(0x0004);
    pub const HAS_PARENT: Self = Self(0x0008);
    pub const HAS_EXPIRATION: Self = Self(0x0010);
    pub const HAS_CAPABILITIES: Self = Self(0x0020);
    pub const HAS_EXTENSIONS: Self = Self(0x0040);
    pub const HAS_PROVENANCE: Self = Self(0x0080); // NM-1
    pub const HAS_BEHAVIORAL: Self = Self(0x0100); // NM-2

    pub fn empty() -> Self {
        Self(0)
    }

    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl std::ops::BitOr for AidFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ─── Agent Identity Document (§4.2) ───

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentityDocument {
    // Header
    pub magic: [u8; 4], // 0x41494430 ("AID0")
    pub version: u16,   // 0x0003 for v0.3.0
    pub flags: AidFlags,

    // Core Identity
    pub id: String,      // AIP-ID (permanent)
    pub created_at: u64, // Unix ms, immutable
    pub expires_at: Option<u64>,

    // Cryptographic Material
    pub primary_key: PublicKey,
    pub recovery_key: Option<PublicKey>,
    pub encryption_key: Option<PublicKey>,

    // Provenance (NM-1)
    pub provenance: ProvenanceTriple,

    // Lifecycle
    pub status: IdentityStatus,
    pub sequence: u64,

    // Lineage
    pub lineage_depth: u8,
    pub lineage_proof: Option<Signature>,

    // Merkle root of capabilities
    pub capability_root: [u8; 32],
    pub reputation_root: [u8; 32],

    // Self-signature (last field)
    pub self_signature: Option<Signature>,
}

pub const AID_MAGIC: [u8; 4] = [0x41, 0x49, 0x44, 0x30]; // "AID0"
/// AID document version.
///
/// `0x0004`: the self-signature and lineage-proof payloads switched to the
/// domain-tagged, length-prefixed canonical encoding. AIDs at `0x0003` are
/// rejected with `UnsupportedVersion` rather than failing signature checks
/// with a misleading error.
pub const AIP_VERSION: u16 = 0x0004;

// ─── Error Codes (§4.8) ───

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AipError {
    InvalidMagic = 0x0001,
    UnsupportedVersion = 0x0002,
    SignatureInvalid = 0x0003,
    SignatureExpired = 0x0004,
    IdentityRevoked = 0x0005,
    IdentitySuspended = 0x0006,
    IdentityExpired = 0x0007,
    LineageInvalid = 0x0008,
    CapabilityExpired = 0x0009,
    CapabilityInsufficient = 0x000A,
    AttenuationViolation = 0x000B,
    MerkleRootMismatch = 0x000C,
    EncodingError = 0x000D,
    NonceReuse = 0x000E,
    SequenceViolation = 0x000F,
    InvalidPublicKey = 0x0010,
    InvalidAipId = 0x0011,
    InvalidChecksum = 0x0012,
    FieldTooLong = 0x0013,
    MissingRequiredField = 0x0014,
    CapabilityRevoked = 0x0015,
    RateLimited = 0x0016,
    BehavioralDrift = 0x0017,
    ProvenanceMismatch = 0x0018,
    DelegationFork = 0x0019,
    DecayExhausted = 0x001A,
    EvolutionRequired = 0x001B,
}

impl std::fmt::Display for AipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AIP Error 0x{:04X}: {:?}", *self as u16, self)
    }
}

impl std::error::Error for AipError {}

// ─── Lifecycle Messages (§5.2) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivateIdentity {
    pub agent_id: String,
    pub sequence: u64,
    pub operator_sig: Option<Signature>,
    pub parent_sig: Option<Signature>,
    pub self_sig: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendIdentity {
    pub agent_id: String,
    pub sequence: u64,
    pub reason: String,
    pub authority_sig: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeIdentity {
    pub agent_id: String,
    pub sequence: u64,
    pub reason: String,
    pub authority_sig: Signature,
}

// ─── AIP-3: Capability System (§6) ───

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Action {
    Read = 0x01,
    Write = 0x02,
    Delete = 0x03,
    Admin = 0x04,
    Execute = 0x05,
    Delegate = 0x06,
}

/// Extended scope action — standard Action or a custom named action (§6-v2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeAction {
    Standard(Action),
    Custom(String), // max 64 bytes
}

/// Capability scope: ordered set of allowed/denied actions (§6-v2, NM-A1).
///
/// Scope intersection (MEET): `child.allowed ⊆ parent.allowed`.
/// Used in delegation chain enforcement and token issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScope {
    pub allowed: Vec<ScopeAction>,
    pub denied: Vec<ScopeAction>, // Explicit deny overrides allow
}

impl CapabilityScope {
    pub fn empty() -> Self {
        Self {
            allowed: vec![],
            denied: vec![],
        }
    }

    pub fn all() -> Self {
        Self {
            allowed: vec![
                ScopeAction::Standard(Action::Read),
                ScopeAction::Standard(Action::Write),
                ScopeAction::Standard(Action::Delete),
                ScopeAction::Standard(Action::Execute),
                ScopeAction::Standard(Action::Admin),
                ScopeAction::Standard(Action::Delegate),
            ],
            denied: vec![],
        }
    }

    pub fn contains(&self, action: &ScopeAction) -> bool {
        self.allowed.contains(action) && !self.denied.contains(action)
    }
}

/// A scope-bound token issued to an agent (§6-v2).
///
/// The JTI (token ID) is referenced by the revocation log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedToken {
    pub jti: [u8; 16],     // UUIDv4 token identifier
    pub agent_id: String,  // AIP-ID of the token holder
    pub issuer_id: String, // AIP-ID of the issuing authority
    pub scope: CapabilityScope,
    pub issued_at: u64, // Unix ms
    pub expires_at: Option<u64>,
    pub issuer_sig: Signature,
}

/// A delegation token transferring a subset of scope to another agent (§6-v2, NM-A2).
///
/// `scope` must be ⊆ parent token's scope (enforced by `create_delegation`).
/// `depth` must be < MAX_DELEGATION_DEPTH (8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationToken {
    pub jti: [u8; 16],          // This token's ID
    pub parent_jti: [u8; 16],   // Parent token being delegated from
    pub issuer_id: String,      // Agent delegating (must hold parent)
    pub grantee_id: String,     // Agent receiving delegation
    pub scope: CapabilityScope, // Must be ⊆ parent scope
    pub depth: u8,              // Chain depth (0 = root token)
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub issuer_sig: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub key: String, // max 64 bytes
    pub operator: ConstraintOp,
    pub value: String, // max 256 bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConstraintOp {
    Eq = 0x01,
    NotEq = 0x02,
    LessThan = 0x03,
    GreaterThan = 0x04,
    In = 0x05,
    NotIn = 0x06,
}

/// A capability grant (§6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub id: [u8; 16],       // UUIDv4
    pub grantor_id: String, // AIP-ID
    pub grantee_id: String, // AIP-ID
    pub namespace: String,  // Reverse-domain notation, max 128 bytes
    pub actions: Vec<Action>,
    pub constraints: Vec<Constraint>,
    pub delegatable: bool,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub grantor_sig: Signature,
}

/// Temporal decay policy (NM-8).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TemporalDecayPolicy {
    pub decay_type: DecayType,
    pub half_life_seconds: u64,
    pub minimum_floor: u32, // 0-1_000_000
    pub reauthorization_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DecayType {
    Value = 0x01,
    Rate = 0x02,
    Scope = 0x03,
}

/// Effective capability after resolution (§6.9).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveCapability {
    pub agent_id: String,
    pub namespace: String,
    pub resolved_actions: Vec<Action>,
    pub resolved_constraints: Vec<Constraint>,
    pub contributing_grants: Vec<[u8; 16]>,
    pub resolved_at: u64,
}

// ─── AIP-4: Reputation Protocol (§7) ───

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttesterType {
    Peer = 0x01,
    Authority = 0x02,
    Oracle = 0x03,
    Governance = 0x04,
    SelfAttest = 0x05,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ClaimType {
    TaskCompletion = 0x01,
    VerificationPass = 0x02,
    EconomicSettlement = 0x03,
    Cooperation = 0x04,
    Violation = 0x05,
    DisputeResolution = 0x06,
}

/// A third-party attestation (§7.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub id: [u8; 16],        // UUIDv4
    pub subject_id: String,  // Agent being attested
    pub attester_id: String, // Agent making attestation
    pub attester_type: AttesterType,
    pub claim_type: ClaimType,
    pub claim_value: i32,      // -1_000_000 to +1_000_000
    pub claim_context: String, // max 256 bytes
    pub evidence_hash: Option<[u8; 32]>,
    pub attested_at: u64,
    pub valid_until: Option<u64>,
    pub attester_sig: Signature,
}

/// Reputation record (§7.2).
/// All scores are fixed-point with scale 1_000_000 (1M = 100%).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationRecord {
    pub agent_id: String,
    pub version: u32,
    pub updated_at: u64,

    // Aggregate scores (0 - 1_000_000)
    pub overall_score: u32,
    pub reliability: u32, // Task completion rate
    pub honesty: u32,     // Verification pass rate
    pub economic: u32,    // Economic trustworthiness
    pub governance: u32,  // Governance participation

    // Evidence Merkle root
    pub evidence_root: [u8; 32],
}

impl Default for ReputationRecord {
    fn default() -> Self {
        Self {
            agent_id: String::new(),
            version: 0,
            updated_at: 0,
            overall_score: 500_000,
            reliability: 500_000,
            honesty: 500_000,
            economic: 500_000,
            governance: 500_000,
            evidence_root: [0u8; 32],
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// §4.2 WEAKNESS SOLUTIONS
// ═══════════════════════════════════════════════════════════════

// ─── Solution 1: Hardware Binding (TEE/PUF Attestation) ───

/// Hardware attestation report bound to the AID.
/// Solves §4.2 Weakness 1: "No Hardware Binding."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAttestation {
    pub device_id: [u8; 32], // PUF-derived silicon fingerprint
    pub tee_platform: TeePlatform,
    pub attestation_report: Vec<u8>, // Raw TEE attestation blob
    pub report_hash: [u8; 32],       // SHA-256 of the report
    pub bound_aip_id: String,        // The AIP-ID this hardware is bound to
    pub measured_at: u64,            // Unix ms
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TeePlatform {
    None = 0x00, // Software-only (legacy)
    IntelSgx = 0x01,
    ArmTrustZone = 0x02,
    AppleSep = 0x03, // Apple Secure Enclave
    AmdSev = 0x04,
    RiscVKeystone = 0x05,
}

/// The trust level derived from hardware binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum HardwareTrustLevel {
    Unbound = 0,     // No hardware attestation (§4.2 weakness)
    SoftwareTee = 1, // TEE present but no PUF
    HardwareTee = 2, // TEE + PUF device ID
    FullEnclave = 3, // TEE + PUF + measured boot chain
}

// ─── Solution 2: Liveness Proof (Heartbeat Protocol) ───

/// Liveness challenge-response protocol.
/// Solves §4.2 Weakness 2: "No Liveness."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessChallenge {
    pub challenge_id: [u8; 16],
    pub challenger_id: String, // Who is asking
    pub target_id: String,     // Who must respond
    pub nonce: [u8; 32],       // Random challenge bytes
    pub issued_at: u64,
    pub deadline_ms: u64, // Must respond within this window
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessResponse {
    pub challenge_id: [u8; 16],
    pub responder_id: String,
    pub proof: [u8; 32], // SHA-256(nonce || private_key_sign(nonce))
    pub responded_at: u64,
    pub responder_sig: Signature,
}

/// Summary of an agent's liveness record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessRecord {
    pub agent_id: String,
    pub last_heartbeat: u64,     // Unix ms of last successful response
    pub consecutive_misses: u32, // How many challenges went unanswered
    pub is_alive: bool,          // Derived from consecutive_misses < threshold
}

// ─── Solution 3: Decentralized Reputation (BFT Voting) ───

/// A reputation vote from a peer node.
/// Solves §4.2 Weakness 3: "Centralized Reputation."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationVote {
    pub voter_id: String,   // AIP-ID of the voting node
    pub subject_id: String, // AIP-ID being evaluated
    pub dimension: ReputationDimensionId,
    pub score: u32,              // 0 - 1_000_000
    pub evidence_root: [u8; 32], // Merkle root of voter's evidence
    pub voted_at: u64,
    pub voter_sig: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ReputationDimensionId {
    Reliability = 0x01,
    Honesty = 0x02,
    Economic = 0x03,
    Governance = 0x04,
}

/// BFT-aggregated reputation from multiple independent voters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecentralizedReputationRecord {
    pub agent_id: String,
    pub quorum_size: u32,      // How many nodes voted
    pub quorum_threshold: u32, // Minimum for validity (e.g., 7)
    pub reliability: u32,
    pub honesty: u32,
    pub economic: u32,
    pub governance: u32,
    pub overall_score: u32,
    pub consensus_reached: bool,
    pub computed_at: u64,
}

// ═══════════════════════════════════════════════════════════════
// §6-v2 REVOCATION PROTOCOL (NM-A3)
// ═══════════════════════════════════════════════════════════════

/// Reason a token was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RevocationReason {
    AgentCompromised = 0x01,
    ScopeViolation = 0x02,
    AdminRevocation = 0x03,
    TokenRotation = 0x04,
    ExpiryForced = 0x05,
}

/// An entry in the append-only revocation log (§6-v2, NM-A3).
///
/// `entry_hash = SHA-256(jti || revoked_at || reason || revoked_by || cascade)`
/// This chains entries to the Chrono audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub jti: [u8; 16],   // Token ID being revoked
    pub revoked_at: u64, // Unix ms
    pub reason: RevocationReason,
    pub revoked_by: String,   // AIP-ID of revoking authority
    pub cascade: bool,        // Revoke delegation children?
    pub entry_hash: [u8; 32], // SHA-256 chain hash
}

// ═══════════════════════════════════════════════════════════════
// §7-v2 PORTABLE IDENTITY (WELL-KNOWN, NM-A4)
// ═══════════════════════════════════════════════════════════════

/// An Ed25519 public key in JWK format (RFC 7517 + RFC 8037).
///
/// Allows external systems to verify AIP tokens without calling the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKey {
    pub kty: String, // "OKP"
    pub crv: String, // "Ed25519"
    pub x: String,   // base64url-encoded public key bytes (32 bytes)
    pub kid: String, // Key ID (AIP-ID of the issuer)
    #[serde(rename = "use")]
    pub use_: String, // "sig"
    pub alg: String, // "EdDSA"
}

/// JWKS document containing one or more public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<JwksKey>,
}

/// AIP Well-Known configuration document (RFC 5785).
///
/// Published at `/.well-known/aip-configuration`.
/// Allows any standards-aware system to discover AIP endpoints and verify tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AipConfiguration {
    pub issuer: String,
    pub jwks_uri: String,
    pub revocation_uri: String,
    pub delegation_verify_uri: String,
    pub supported_algorithms: Vec<String>,
    pub token_format: String,
    pub version: String,
}

// ═══════════════════════════════════════════════════════════════
// GHOST STAGE 1 — EXECUTION BINDING
// ═══════════════════════════════════════════════════════════════
//
// Data only. Collection (procfs, executable hashing) lives in
// `aip_core::execution_binding`; digests live there too because this crate
// has no hash dependency.

/// Domain tag leading the full canonical encoding of an [`ExecutionBinding`]
/// (used when the binding is hashed or signed as content).
pub const EXECUTION_BINDING_DOMAIN: &str = "GHOST/ExecutionBinding/v1";
/// Domain tag leading the *identity* encoding of an [`ExecutionBinding`]
/// (the correlation key: who + which process instance + which executable).
pub const EXECUTION_IDENTITY_DOMAIN: &str = "GHOST/ExecutionIdentity/v1";
/// Structure version of [`ExecutionBinding`].
pub const EXECUTION_BINDING_VERSION: u16 = 1;

/// A process *instance* — the minimum tuple that survives PID reuse.
///
/// `pid` alone is recycled by the kernel; `pid_start_time_ticks` (field 22 of
/// `/proc/<pid>/stat`, clock ticks since boot) distinguishes two processes that
/// held the same PID within one boot; `boot_id`
/// (`/proc/sys/kernel/random/boot_id`) distinguishes boots. Equality is over
/// all three fields — never over `pid` alone (I2, I4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInstance {
    pub pid: u32,
    pub pid_start_time_ticks: u64,
    pub boot_id: [u8; 16],
}

/// Binds an agent identity to a specific process instance running a specific
/// executable.
///
/// This is an identity/correlation artifact. It does not grant authority and
/// it is not, by itself, observation: a binding collected by the agent about
/// itself is a **self-report** until an independent observer attests the same
/// facts (I5, I10). Verifiers must never upgrade a self-reported binding into
/// evidence that the execution occurred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBinding {
    /// Structure version; see [`EXECUTION_BINDING_VERSION`].
    pub version: u16,
    /// AIP-ID of the agent this binding is about.
    pub agent_id: String,
    /// The process instance (pid + start ticks + boot id).
    pub process: ProcessInstance,
    /// SHA-256 of the executable's **contents** (`/proc/<pid>/exe`), not of
    /// its path.
    pub exe_content_sha256: [u8; 32],
    /// Executable path as observed. Context only — excluded from
    /// [`ExecutionBinding::identity_bytes`] so two path spellings of the same
    /// binary are the same identity and a same-path different binary is not.
    pub exe_path: String,
    /// Unix ms when the binding was collected. Metadata; not an authorization
    /// window (temporal validity belongs to tokens, I21).
    pub bound_at_ms: u64,
}

impl ExecutionBinding {
    /// Full canonical encoding — every field, domain-tagged, injective. This
    /// is what is hashed/signed when the binding is embedded as content
    /// (e.g. inside an EvidencePacket).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        use canonical::*;
        let mut buf = Vec::new();
        put_domain(&mut buf, EXECUTION_BINDING_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.agent_id);
        put_u32(&mut buf, self.process.pid);
        put_u64(&mut buf, self.process.pid_start_time_ticks);
        buf.extend_from_slice(&self.process.boot_id); // fixed 16
        buf.extend_from_slice(&self.exe_content_sha256); // fixed 32
        put_str(&mut buf, &self.exe_path);
        put_u64(&mut buf, self.bound_at_ms);
        buf
    }

    /// Identity encoding — the reconciliation join key. Covers exactly:
    /// agent, process instance, executable contents. Deliberately excludes
    /// `exe_path` and `bound_at_ms`.
    pub fn identity_bytes(&self) -> Vec<u8> {
        use canonical::*;
        let mut buf = Vec::new();
        put_domain(&mut buf, EXECUTION_IDENTITY_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.agent_id);
        put_u32(&mut buf, self.process.pid);
        put_u64(&mut buf, self.process.pid_start_time_ticks);
        buf.extend_from_slice(&self.process.boot_id);
        buf.extend_from_slice(&self.exe_content_sha256);
        buf
    }

    /// True iff both bindings denote the same execution: same agent, same
    /// process *instance* (all three tuple fields) and same executable
    /// contents. Equal PIDs are never sufficient.
    pub fn same_execution(&self, other: &ExecutionBinding) -> bool {
        self.identity_bytes() == other.identity_bytes()
    }
}
