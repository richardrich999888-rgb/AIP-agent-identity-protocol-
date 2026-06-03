//! AIP Core — Identity creation, AID validation, and lifecycle state machine.
//!
//! Includes modules for:
//! - Identity creation and validation
//! - Lifecycle state machine
//! - Capability attenuation
//! - Reputation calculation (BFT)
//! - Hardware attestation
//! - Liveness challenge-response
//! - Nonce tracking (anti-replay)
//! - Runtime binding
//! - Identity/reputation storage
//! - Multi-node simulation

pub mod nonce;
pub mod passport;
pub mod runtime;
pub mod simulation;
pub mod store;

// ─── AIP v2: The Missing 20% ───
pub mod capability; // NM-A1: Scope intersection, named scopes, token issuance
pub mod delegation; // NM-A2: Delegation chain traversal, depth limit, DelegationLog
pub mod revocation; // NM-A3: Cascade revocation, append-only RevocationLog
pub mod scoped_audit; // NM-A4b: Scope-Constrained Audit Trail Binding (patent-critical)
pub mod wellknown; // NM-A4a: Portable identity — JWKS + AIP config documents

use aip_crypto::*;
use aip_types::*;
use std::collections::{HashMap, HashSet};

/// Create a new Agent Identity Document (§4.6).
pub fn create_identity(
    provenance: ProvenanceTriple,
    parent: Option<(&str, &[u8])>, // (parent_id, parent_private_key)
) -> Result<(AgentIdentityDocument, KeyPair), AipError> {
    let keypair = generate_ed25519_keypair();
    let id = derive_aip_id(&keypair.public_key, &provenance);

    let mut flags = AidFlags::empty();
    flags.insert(AidFlags::HAS_PROVENANCE);

    let lineage_depth = if parent.is_some() {
        flags.insert(AidFlags::HAS_PARENT);
        1u8
    } else {
        0u8
    };

    // Lineage proof from parent
    let lineage_proof = if let Some((parent_id, parent_priv)) = parent {
        let mut lineage_payload = Vec::new();
        lineage_payload.extend_from_slice(id.as_bytes());
        lineage_payload.extend_from_slice(&keypair.public_key);
        let sig = sign_ed25519(parent_priv, parent_id, &lineage_payload)?;
        Some(sig)
    } else {
        None
    };

    let capability_root = merkle_empty();
    let reputation_root = merkle_empty();

    let mut aid = AgentIdentityDocument {
        magic: AID_MAGIC,
        version: AIP_VERSION,
        flags,
        id: id.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        expires_at: None,
        primary_key: PublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: keypair.public_key.clone(),
        },
        recovery_key: None,
        encryption_key: None,
        provenance,
        status: IdentityStatus::Pending, // FIX-11: starts PENDING
        sequence: 0,
        lineage_depth,
        lineage_proof,
        capability_root,
        reputation_root,
        self_signature: None,
    };

    // Self-sign the AID
    let canonical = canonical_encode_aid(&aid);
    let self_sig = sign_ed25519(&keypair.private_key, &id, &canonical)?;
    aid.self_signature = Some(self_sig);

    Ok((aid, keypair))
}

/// Canonical encoding of AID for self-signature (§4.5).
fn canonical_encode_aid(aid: &AgentIdentityDocument) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&aid.magic);
    buf.extend_from_slice(&aid.version.to_le_bytes());
    buf.extend_from_slice(&aid.flags.0.to_le_bytes());
    buf.extend_from_slice(aid.id.as_bytes());
    buf.extend_from_slice(&aid.created_at.to_le_bytes());
    buf.extend_from_slice(&aid.primary_key.key_bytes);
    buf.extend_from_slice(&aid.provenance.to_bytes());
    buf.push(aid.status as u8);
    buf.extend_from_slice(&aid.sequence.to_le_bytes());
    buf.push(aid.lineage_depth);
    buf.extend_from_slice(&aid.capability_root);
    buf.extend_from_slice(&aid.reputation_root);
    buf
}

/// Canonical encoding of capability grant fields for signature verification.
/// Excludes `grantor_sig` itself.
fn canonical_encode_capability_grant(grant: &CapabilityGrant) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&grant.id);
    buf.extend_from_slice(grant.grantor_id.as_bytes());
    buf.extend_from_slice(grant.grantee_id.as_bytes());
    buf.extend_from_slice(grant.namespace.as_bytes());
    for action in &grant.actions {
        buf.push(*action as u8);
    }
    for constraint in &grant.constraints {
        buf.extend_from_slice(constraint.key.as_bytes());
        buf.push(constraint.operator as u8);
        buf.extend_from_slice(constraint.value.as_bytes());
    }
    buf.push(if grant.delegatable { 1 } else { 0 });
    buf.extend_from_slice(&grant.issued_at.to_le_bytes());
    match grant.expires_at {
        Some(ts) => {
            buf.push(1);
            buf.extend_from_slice(&ts.to_le_bytes());
        }
        None => buf.push(0),
    }
    buf
}

fn canonical_encode_lineage_payload(aid: &AgentIdentityDocument) -> Vec<u8> {
    let mut lineage_payload = Vec::new();
    lineage_payload.extend_from_slice(aid.id.as_bytes());
    lineage_payload.extend_from_slice(&aid.primary_key.key_bytes);
    lineage_payload
}

fn canonical_encode_reputation_vote(vote: &ReputationVote) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(vote.voter_id.as_bytes());
    buf.extend_from_slice(vote.subject_id.as_bytes());
    buf.push(vote.dimension as u8);
    buf.extend_from_slice(&vote.score.to_le_bytes());
    buf.extend_from_slice(&vote.evidence_root);
    buf.extend_from_slice(&vote.voted_at.to_le_bytes());
    buf
}

pub trait SignatureVerifier {
    fn verify_signature(
        &self,
        algorithm: AlgorithmId,
        public_key: &[u8],
        signature: &Signature,
    ) -> Result<bool, AipError>;
}

fn verify_signature_with_optional_verifier(
    public_key: &[u8],
    signature: &Signature,
    verifier: Option<&dyn SignatureVerifier>,
) -> Result<bool, AipError> {
    match signature.algorithm {
        AlgorithmId::Ed25519 => verify_ed25519(public_key, signature),
        AlgorithmId::MlDsa65 | AlgorithmId::Hybrid => {
            if let Some(v) = verifier {
                v.verify_signature(signature.algorithm, public_key, signature)
            } else {
                Err(AipError::EvolutionRequired)
            }
        }
    }
}

fn validate_lineage_structure(aid: &AgentIdentityDocument) -> Result<(), AipError> {
    let has_parent_flag = aid.flags.contains(AidFlags::HAS_PARENT);
    match (
        aid.lineage_depth,
        has_parent_flag,
        aid.lineage_proof.is_some(),
    ) {
        (0, false, false) => Ok(()),
        (0, _, _) => Err(AipError::LineageInvalid),
        (_, true, true) => Ok(()),
        _ => Err(AipError::LineageInvalid),
    }
}

fn validate_aid_internal(
    aid: &AgentIdentityDocument,
    verifier: Option<&dyn SignatureVerifier>,
    parent: Option<(&str, &[u8])>,
) -> Result<(), AipError> {
    // 1. Check magic
    if aid.magic != AID_MAGIC {
        return Err(AipError::InvalidMagic);
    }

    // 2. Check version
    if aid.version != AIP_VERSION {
        return Err(AipError::UnsupportedVersion);
    }

    // 3. Validate AIP-ID format
    validate_aip_id(&aid.id)?;

    // 3b. Ensure AIP-ID is actually bound to (primary_key, provenance).
    let expected_id = derive_aip_id(&aid.primary_key.key_bytes, &aid.provenance);
    if aid.id != expected_id {
        return Err(AipError::InvalidAipId);
    }

    // 4. Validate public key length
    match aid.primary_key.algorithm {
        AlgorithmId::Ed25519 => {
            if aid.primary_key.key_bytes.len() != 32 {
                return Err(AipError::InvalidPublicKey);
            }
        }
        AlgorithmId::MlDsa65 => {
            if aid.primary_key.key_bytes.len() != 1952 {
                return Err(AipError::InvalidPublicKey);
            }
        }
        AlgorithmId::Hybrid => {
            if aid.primary_key.key_bytes.len() != 1984 {
                return Err(AipError::InvalidPublicKey);
            }
        }
    }

    // 5. Check status is not REVOKED
    if aid.status == IdentityStatus::Revoked {
        return Err(AipError::IdentityRevoked);
    }

    // 6. Verify self-signature
    if let Some(ref self_sig) = aid.self_signature {
        if self_sig.algorithm != aid.primary_key.algorithm {
            return Err(AipError::SignatureInvalid);
        }

        let canonical = canonical_encode_aid(aid);
        let payload_hash = sha256(&canonical);
        if self_sig.payload_hash != payload_hash {
            return Err(AipError::SignatureInvalid);
        }

        let valid = verify_signature_with_optional_verifier(
            &aid.primary_key.key_bytes,
            self_sig,
            verifier,
        )?;
        if !valid {
            return Err(AipError::SignatureInvalid);
        }
    } else {
        return Err(AipError::MissingRequiredField);
    }

    validate_lineage_structure(aid)?;

    // If parent context is supplied, verify the lineage proof cryptographically.
    if let Some((parent_id, parent_public_key)) = parent {
        let lineage_sig = aid.lineage_proof.as_ref().ok_or(AipError::LineageInvalid)?;
        if lineage_sig.signer_id != parent_id {
            return Err(AipError::LineageInvalid);
        }
        let lineage_payload = canonical_encode_lineage_payload(aid);
        if lineage_sig.payload_hash != sha256(&lineage_payload) {
            return Err(AipError::LineageInvalid);
        }
        let lineage_valid =
            verify_signature_with_optional_verifier(parent_public_key, lineage_sig, verifier)?;
        if !lineage_valid {
            return Err(AipError::LineageInvalid);
        }
    }

    Ok(())
}

/// Validate an AID document (§4.5) without external verifiers or parent context.
pub fn validate_aid(aid: &AgentIdentityDocument) -> Result<(), AipError> {
    validate_aid_internal(aid, None, None)
}

/// Validate an AID with an external verifier for non-Ed25519 algorithms.
pub fn validate_aid_with_verifier(
    aid: &AgentIdentityDocument,
    verifier: &dyn SignatureVerifier,
) -> Result<(), AipError> {
    validate_aid_internal(aid, Some(verifier), None)
}

/// Validate an AID and verify lineage proof against the provided parent identity key.
pub fn validate_aid_with_parent(
    aid: &AgentIdentityDocument,
    parent_id: &str,
    parent_public_key: &[u8],
) -> Result<(), AipError> {
    validate_aid_internal(aid, None, Some((parent_id, parent_public_key)))
}

/// Validate an AID with both lineage parent context and an external signature verifier.
pub fn validate_aid_with_parent_and_verifier(
    aid: &AgentIdentityDocument,
    parent_id: &str,
    parent_public_key: &[u8],
    verifier: &dyn SignatureVerifier,
) -> Result<(), AipError> {
    validate_aid_internal(aid, Some(verifier), Some((parent_id, parent_public_key)))
}

// ─── Lifecycle State Machine (§5.1) ───

/// Activate an identity (PENDING → ACTIVE).
pub fn activate_identity(aid: &mut AgentIdentityDocument) -> Result<(), AipError> {
    match aid.status {
        IdentityStatus::Pending => {
            aid.status = IdentityStatus::Active;
            aid.sequence += 1;
            Ok(())
        }
        IdentityStatus::Active => Ok(()), // Already active, idempotent
        IdentityStatus::Revoked => Err(AipError::IdentityRevoked),
        IdentityStatus::Suspended => Err(AipError::IdentitySuspended),
    }
}

/// Suspend an identity (ACTIVE → SUSPENDED).
pub fn suspend_identity(aid: &mut AgentIdentityDocument) -> Result<(), AipError> {
    match aid.status {
        IdentityStatus::Active => {
            aid.status = IdentityStatus::Suspended;
            aid.sequence += 1;
            Ok(())
        }
        IdentityStatus::Suspended => Ok(()),
        IdentityStatus::Revoked => Err(AipError::IdentityRevoked),
        IdentityStatus::Pending => Err(AipError::MissingRequiredField),
    }
}

/// Reactivate an identity (SUSPENDED → ACTIVE).
pub fn reactivate_identity(aid: &mut AgentIdentityDocument) -> Result<(), AipError> {
    match aid.status {
        IdentityStatus::Suspended => {
            aid.status = IdentityStatus::Active;
            aid.sequence += 1;
            Ok(())
        }
        IdentityStatus::Active => Ok(()),
        IdentityStatus::Revoked => Err(AipError::IdentityRevoked),
        IdentityStatus::Pending => Err(AipError::MissingRequiredField),
    }
}

/// Revoke an identity (ANY → REVOKED). Terminal.
pub fn revoke_identity(aid: &mut AgentIdentityDocument) -> Result<(), AipError> {
    if aid.status == IdentityStatus::Revoked {
        return Ok(()); // Already revoked
    }
    aid.status = IdentityStatus::Revoked;
    aid.sequence += 1;
    Ok(())
}

// ─── AIP-3: Capability Attenuation (§6.9) ───

/// MEET operation: Intersect two capability grants (§6.9).
/// The result is the most restricted combination of both.
pub fn capability_meet(a: &CapabilityGrant, b: &CapabilityGrant) -> Option<EffectiveCapability> {
    if a.namespace != b.namespace {
        return None; // Cannot MEET across namespaces
    }

    // Intersect actions
    let resolved_actions: Vec<Action> = a
        .actions
        .iter()
        .filter(|act| b.actions.contains(act))
        .cloned()
        .collect();

    if resolved_actions.is_empty() {
        return None; // MEET produces ⊥
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    Some(EffectiveCapability {
        agent_id: a.grantee_id.clone(),
        namespace: a.namespace.clone(),
        resolved_actions,
        resolved_constraints: a
            .constraints
            .iter()
            .chain(b.constraints.iter())
            .cloned()
            .collect(), // Union of constraints (more restricted)
        contributing_grants: vec![a.id, b.id],
        resolved_at: now,
    })
}

/// Temporal decay: compute effective value after decay (NM-8, §6.10).
/// Uses integer-only arithmetic per FIX-7.
pub fn effective_decay_value(original: u32, policy: &TemporalDecayPolicy, now_seconds: u64) -> u32 {
    let reauth_at = policy.reauthorization_at.unwrap_or(0);
    if now_seconds <= reauth_at {
        return original;
    }
    let elapsed = now_seconds - reauth_at;
    let periods = elapsed / policy.half_life_seconds;

    let mut effective = original;
    for _ in 0..periods.min(64) {
        // Cap at 64 halvings to prevent infinite loop
        effective /= 2;
    }

    effective.max(policy.minimum_floor)
}

/// Check if a capability grant is expired.
pub fn is_capability_expired(grant: &CapabilityGrant, now_ms: u64) -> bool {
    grant.expires_at.is_some_and(|exp| now_ms > exp)
}

/// Validate a capability grant's basic constraints.
pub fn validate_capability_grant(grant: &CapabilityGrant, now_ms: u64) -> Result<(), AipError> {
    if is_capability_expired(grant, now_ms) {
        return Err(AipError::CapabilityExpired);
    }
    if let Some(exp) = grant.expires_at {
        if exp <= grant.issued_at {
            return Err(AipError::CapabilityExpired);
        }
    }
    if grant.namespace.len() > 128 {
        return Err(AipError::FieldTooLong);
    }
    if grant.actions.is_empty() {
        return Err(AipError::CapabilityInsufficient);
    }
    for constraint in &grant.constraints {
        if constraint.key.len() > 64 || constraint.value.len() > 256 {
            return Err(AipError::FieldTooLong);
        }
    }
    Ok(())
}

/// Verify a capability grant signature against the grantor public key.
pub fn verify_capability_grant_signature(
    grant: &CapabilityGrant,
    grantor_public_key: &[u8],
) -> Result<bool, AipError> {
    if grant.grantor_sig.signer_id != grant.grantor_id {
        return Ok(false);
    }

    let canonical = canonical_encode_capability_grant(grant);
    let expected_hash = sha256(&canonical);
    if grant.grantor_sig.payload_hash != expected_hash {
        return Ok(false);
    }

    verify_signature_with_optional_verifier(grantor_public_key, &grant.grantor_sig, None)
}

/// Full capability validation including signature verification.
pub fn validate_capability_grant_with_key(
    grant: &CapabilityGrant,
    grantor_public_key: &[u8],
    now_ms: u64,
) -> Result<(), AipError> {
    validate_capability_grant(grant, now_ms)?;
    if !verify_capability_grant_signature(grant, grantor_public_key)? {
        return Err(AipError::SignatureInvalid);
    }
    Ok(())
}

/// Verify a reputation vote signature against a registered voter public key.
pub fn verify_reputation_vote_signature(
    vote: &ReputationVote,
    voter_public_key: &[u8],
) -> Result<bool, AipError> {
    verify_reputation_vote_signature_with_verifier(vote, voter_public_key, None)
}

pub fn verify_reputation_vote_signature_with_verifier(
    vote: &ReputationVote,
    voter_public_key: &[u8],
    verifier: Option<&dyn SignatureVerifier>,
) -> Result<bool, AipError> {
    if vote.voter_sig.signer_id != vote.voter_id {
        return Ok(false);
    }

    let canonical = canonical_encode_reputation_vote(vote);
    let expected_hash = sha256(&canonical);
    if vote.voter_sig.payload_hash != expected_hash {
        return Ok(false);
    }

    verify_signature_with_optional_verifier(voter_public_key, &vote.voter_sig, verifier)
}

// ─── AIP-4: Reputation Calculation (§7.4) ───

/// Weight attestations by attester type (basis points, FIX-7).
pub fn attester_weight_bps(attester_type: AttesterType, attester_reputation: u32) -> u32 {
    match attester_type {
        AttesterType::Authority => 10_000, // 1.0
        AttesterType::Oracle => 9_000,     // 0.9
        AttesterType::Governance => 8_500, // 0.85
        AttesterType::Peer => (5_000u64 * attester_reputation as u64 / 1_000_000) as u32,
        AttesterType::SelfAttest => 1_000, // 0.1
    }
}

/// Apply time decay to an attestation weight (§7.4 step 4).
/// decay_rate = 0.99 per 30-day period, integer arithmetic.
pub fn decay_weight(weight_bps: u32, attestation_day: u64, current_day: u64) -> u32 {
    if current_day <= attestation_day {
        return weight_bps;
    }
    let periods = (current_day - attestation_day) / 30;
    let mut decayed = weight_bps;
    for _ in 0..periods.min(1000) {
        decayed = (decayed as u64 * 9900 / 10000) as u32;
    }
    decayed
}

/// Map claim types to reputation dimensions.
fn claim_to_dimension(claim: ClaimType) -> ReputationDimension {
    match claim {
        ClaimType::TaskCompletion => ReputationDimension::Reliability,
        ClaimType::VerificationPass => ReputationDimension::Honesty,
        ClaimType::EconomicSettlement => ReputationDimension::Economic,
        ClaimType::Cooperation => ReputationDimension::Governance,
        ClaimType::DisputeResolution => ReputationDimension::Governance,
        ClaimType::Violation => ReputationDimension::Honesty, // Negative signal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReputationDimension {
    Reliability,
    Honesty,
    Economic,
    Governance,
}

/// Calculate deterministic reputation from attestations (§7.4).
/// All arithmetic is fixed-point integer (scale 1_000_000).
pub fn calculate_reputation(
    agent_id: &str,
    attestations: &[Attestation],
    current_day: u64,
) -> ReputationRecord {
    let mut reliability_sum: u64 = 0;
    let mut reliability_weight: u64 = 0;
    let mut honesty_sum: u64 = 0;
    let mut honesty_weight: u64 = 0;
    let mut economic_sum: u64 = 0;
    let mut economic_weight: u64 = 0;
    let mut governance_sum: u64 = 0;
    let mut governance_weight: u64 = 0;

    for att in attestations {
        // Skip expired
        if let Some(valid_until) = att.valid_until {
            let valid_day = valid_until / 86_400_000; // ms to days
            if current_day > valid_day {
                continue;
            }
        }

        let base_weight = attester_weight_bps(att.attester_type, 500_000); // Assume 50% for peers
        let att_day = att.attested_at / 86_400_000; // ms to days
        let decayed = decay_weight(base_weight, att_day, current_day);

        let clamped_value = att.claim_value.clamp(0, 1_000_000) as u64;
        let dim = claim_to_dimension(att.claim_type);

        let (sum, weight) = match dim {
            ReputationDimension::Reliability => (&mut reliability_sum, &mut reliability_weight),
            ReputationDimension::Honesty => (&mut honesty_sum, &mut honesty_weight),
            ReputationDimension::Economic => (&mut economic_sum, &mut economic_weight),
            ReputationDimension::Governance => (&mut governance_sum, &mut governance_weight),
        };

        *sum += decayed as u64 * clamped_value;
        *weight += decayed as u64;
    }

    let score = |sum: u64, weight: u64| -> u32 {
        if weight > 0 {
            ((sum / weight).min(1_000_000)) as u32
        } else {
            500_000 // Default 50%
        }
    };

    let reliability = score(reliability_sum, reliability_weight);
    let honesty = score(honesty_sum, honesty_weight);
    let economic = score(economic_sum, economic_weight);
    let governance = score(governance_sum, governance_weight);

    // Overall: weighted average (equal weights for now)
    let overall = (reliability as u64 + honesty as u64 + economic as u64 + governance as u64) / 4;

    ReputationRecord {
        agent_id: agent_id.to_string(),
        version: 1,
        updated_at: current_day * 86_400_000,
        overall_score: overall as u32,
        reliability,
        honesty,
        economic,
        governance,
        evidence_root: merkle_empty(),
    }
}

// ═══════════════════════════════════════════════════════════════
// §4.2 WEAKNESS SOLUTIONS — DOMAIN LOGIC
// ═══════════════════════════════════════════════════════════════

// ─── Solution 1: Hardware Attestation Validation ───

/// Determine the trust level of a hardware attestation.
pub fn evaluate_hardware_trust(att: &HardwareAttestation) -> HardwareTrustLevel {
    // Verify the report hash
    let computed_hash = sha256(&att.attestation_report);
    if computed_hash != att.report_hash {
        return HardwareTrustLevel::Unbound;
    }

    match att.tee_platform {
        TeePlatform::None => HardwareTrustLevel::Unbound,
        _ => {
            // Check if PUF device ID is non-zero (real silicon)
            let has_puf = att.device_id != [0u8; 32];
            if has_puf {
                // Check if attestation report contains measured boot marker
                // (simplified: look for a magic byte sequence in the report)
                if att.attestation_report.len() >= 64
                    && att
                        .attestation_report
                        .windows(4)
                        .any(|w| w == [0x4D, 0x42, 0x4F, 0x54])
                // "MBOT"
                {
                    HardwareTrustLevel::FullEnclave
                } else {
                    HardwareTrustLevel::HardwareTee
                }
            } else {
                HardwareTrustLevel::SoftwareTee
            }
        }
    }
}

/// Bind a hardware attestation to an AID.
/// Returns error if the attestation's bound_aip_id doesn't match.
pub fn bind_hardware_to_aid(
    aid: &AgentIdentityDocument,
    attestation: &HardwareAttestation,
) -> Result<HardwareTrustLevel, AipError> {
    if attestation.bound_aip_id != aid.id {
        return Err(AipError::ProvenanceMismatch);
    }
    Ok(evaluate_hardware_trust(attestation))
}

// ─── Solution 2: Liveness Challenge-Response ───

const LIVENESS_MISS_THRESHOLD: u32 = 3;

/// Issue a liveness challenge to an agent.
pub fn issue_liveness_challenge(challenger_id: &str, target_id: &str) -> LivenessChallenge {
    let mut nonce = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut challenge_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut challenge_id);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    LivenessChallenge {
        challenge_id,
        challenger_id: challenger_id.to_string(),
        target_id: target_id.to_string(),
        nonce,
        issued_at: now,
        deadline_ms: 30_000, // 30 seconds to respond
    }
}

/// Create a liveness response by signing the challenge nonce.
pub fn respond_to_challenge(
    challenge: &LivenessChallenge,
    responder_private_key: &[u8],
    responder_id: &str,
) -> Result<LivenessResponse, AipError> {
    let sig = sign_ed25519(responder_private_key, responder_id, &challenge.nonce)?;

    // Proof = SHA-256(nonce || signature_bytes)
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&challenge.nonce);
    proof_input.extend_from_slice(&sig.signature_bytes);
    let proof = sha256(&proof_input);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    Ok(LivenessResponse {
        challenge_id: challenge.challenge_id,
        responder_id: responder_id.to_string(),
        proof,
        responded_at: now,
        responder_sig: sig,
    })
}

/// Verify a liveness response.
pub fn verify_liveness(
    challenge: &LivenessChallenge,
    response: &LivenessResponse,
    responder_public_key: &[u8],
) -> Result<bool, AipError> {
    // Check challenge ID matches
    if challenge.challenge_id != response.challenge_id {
        return Ok(false);
    }

    // Check it was answered to the right target
    if challenge.target_id != response.responder_id {
        return Ok(false);
    }

    // Enforce challenge deadline.
    let deadline_at = challenge.issued_at.saturating_add(challenge.deadline_ms);
    if response.responded_at > deadline_at {
        return Ok(false);
    }

    if response.responder_sig.signer_id != response.responder_id {
        return Ok(false);
    }

    // Signature payload must be exactly the challenge nonce.
    let expected_payload_hash = sha256(&challenge.nonce);
    if response.responder_sig.payload_hash != expected_payload_hash {
        return Ok(false);
    }

    // Verify signature over the nonce
    let sig_valid = verify_ed25519(responder_public_key, &response.responder_sig)?;
    if !sig_valid {
        return Ok(false);
    }

    // Verify proof = SHA-256(nonce || sig_bytes)
    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&challenge.nonce);
    proof_input.extend_from_slice(&response.responder_sig.signature_bytes);
    let expected_proof = sha256(&proof_input);

    Ok(response.proof == expected_proof)
}

/// Update liveness record after a challenge round.
pub fn update_liveness_record(record: &mut LivenessRecord, responded: bool) {
    if responded {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        record.last_heartbeat = now;
        record.consecutive_misses = 0;
        record.is_alive = true;
    } else {
        record.consecutive_misses += 1;
        record.is_alive = record.consecutive_misses < LIVENESS_MISS_THRESHOLD;
    }
}

// ─── Solution 3: Decentralized BFT Reputation ───

/// Aggregate reputation votes using Byzantine-tolerant median.
/// Requires quorum_threshold votes to produce a valid result.
pub fn aggregate_reputation_votes(
    subject_id: &str,
    votes: &[ReputationVote],
    quorum_threshold: u32,
) -> DecentralizedReputationRecord {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    if (votes.len() as u32) < quorum_threshold {
        return DecentralizedReputationRecord {
            agent_id: subject_id.to_string(),
            quorum_size: votes.len() as u32,
            quorum_threshold,
            reliability: 500_000,
            honesty: 500_000,
            economic: 500_000,
            governance: 500_000,
            overall_score: 500_000,
            consensus_reached: false,
            computed_at: now,
        };
    }

    let reliability = median_dimension_score(votes, ReputationDimensionId::Reliability);
    let honesty = median_dimension_score(votes, ReputationDimensionId::Honesty);
    let economic = median_dimension_score(votes, ReputationDimensionId::Economic);
    let governance = median_dimension_score(votes, ReputationDimensionId::Governance);
    let overall = (reliability as u64 + honesty as u64 + economic as u64 + governance as u64) / 4;

    DecentralizedReputationRecord {
        agent_id: subject_id.to_string(),
        quorum_size: votes.len() as u32,
        quorum_threshold,
        reliability,
        honesty,
        economic,
        governance,
        overall_score: overall as u32,
        consensus_reached: true,
        computed_at: now,
    }
}

fn median_dimension_score(votes: &[ReputationVote], dim: ReputationDimensionId) -> u32 {
    let mut scores: Vec<u32> = votes
        .iter()
        .filter(|v| v.dimension == dim)
        .map(|v| v.score.min(1_000_000))
        .collect();
    if scores.is_empty() {
        return 500_000;
    }
    scores.sort_unstable();
    // Byzantine-tolerant: trim top f and bottom f (f = (n-1)/3)
    let f = (scores.len().saturating_sub(1)) / 3;
    let trimmed = if f > 0 && scores.len() > 2 * f {
        &scores[f..scores.len() - f]
    } else {
        &scores[..]
    };
    // Median of trimmed set
    trimmed[trimmed.len() / 2]
}

/// Verified aggregation with anti-sybil checks:
/// 1) one vote per voter_id
/// 2) one identity per key fingerprint in the round
/// 3) required per-vote signature verification against allowlisted voter keys
pub fn aggregate_reputation_votes_verified(
    subject_id: &str,
    votes: &[ReputationVote],
    quorum_threshold: u32,
    voter_public_keys: &HashMap<String, Vec<u8>>,
) -> DecentralizedReputationRecord {
    aggregate_reputation_votes_verified_with_verifier(
        subject_id,
        votes,
        quorum_threshold,
        voter_public_keys,
        None,
    )
}

pub fn aggregate_reputation_votes_verified_with_verifier(
    subject_id: &str,
    votes: &[ReputationVote],
    quorum_threshold: u32,
    voter_public_keys: &HashMap<String, Vec<u8>>,
    verifier: Option<&dyn SignatureVerifier>,
) -> DecentralizedReputationRecord {
    let mut filtered: Vec<ReputationVote> = Vec::new();
    let mut seen_voters: HashSet<String> = HashSet::new();
    let mut seen_key_fingerprints: HashSet<[u8; 32]> = HashSet::new();

    for vote in votes {
        if vote.subject_id != subject_id {
            continue;
        }

        if !seen_voters.insert(vote.voter_id.clone()) {
            continue; // duplicate voter_id
        }

        let Some(voter_pk) = voter_public_keys.get(&vote.voter_id) else {
            continue; // unknown/unregistered voter
        };

        // Anti-sybil: reject multiple voter IDs sharing the same key in a single round.
        let key_fp = fingerprint(voter_pk);
        if !seen_key_fingerprints.insert(key_fp) {
            continue;
        }

        let sig_ok = verify_reputation_vote_signature_with_verifier(vote, voter_pk, verifier)
            .unwrap_or(false);
        if !sig_ok {
            continue;
        }

        let mut normalized = vote.clone();
        normalized.score = normalized.score.min(1_000_000);
        filtered.push(normalized);
    }

    aggregate_reputation_votes(subject_id, &filtered, quorum_threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provenance() -> ProvenanceTriple {
        ProvenanceTriple {
            model_commitment: sha256(b"test-model-v1"),
            environment_commitment: sha256(b"test-env"),
            toolchain_commitment: sha256(b"test-toolchain"),
        }
    }

    // ─── AIP-1 / AIP-2 Tests ───

    #[test]
    fn test_create_identity() {
        let (aid, kp) = create_identity(test_provenance(), None).unwrap();
        assert_eq!(aid.magic, AID_MAGIC);
        assert_eq!(aid.version, AIP_VERSION);
        assert_eq!(aid.status, IdentityStatus::Pending);
        assert_eq!(aid.lineage_depth, 0);
        assert!(aid.self_signature.is_some());
        assert!(aid.id.starts_with("aip1"));
        assert_eq!(kp.public_key.len(), 32);
    }

    #[test]
    fn test_create_child_identity() {
        let (parent_aid, parent_kp) = create_identity(test_provenance(), None).unwrap();
        let (child_aid, _) = create_identity(
            test_provenance(),
            Some((&parent_aid.id, &parent_kp.private_key)),
        )
        .unwrap();
        assert_eq!(child_aid.lineage_depth, 1);
        assert!(child_aid.lineage_proof.is_some());
    }

    #[test]
    fn test_validate_child_identity_with_parent_context() {
        let (parent_aid, parent_kp) = create_identity(test_provenance(), None).unwrap();
        let (child_aid, _) = create_identity(
            test_provenance(),
            Some((&parent_aid.id, &parent_kp.private_key)),
        )
        .unwrap();
        assert!(
            validate_aid_with_parent(&child_aid, &parent_aid.id, &parent_kp.public_key).is_ok()
        );
    }

    #[test]
    fn test_validate_child_identity_with_wrong_parent_rejected() {
        let (parent_aid, parent_kp) = create_identity(test_provenance(), None).unwrap();
        let (child_aid, _) = create_identity(
            test_provenance(),
            Some((&parent_aid.id, &parent_kp.private_key)),
        )
        .unwrap();

        let wrong_parent = generate_ed25519_keypair();
        assert_eq!(
            validate_aid_with_parent(&child_aid, &parent_aid.id, &wrong_parent.public_key),
            Err(AipError::LineageInvalid)
        );
    }

    #[test]
    fn test_validate_aid() {
        let (aid, _) = create_identity(test_provenance(), None).unwrap();
        assert!(validate_aid(&aid).is_ok());
    }

    #[test]
    fn test_validate_aid_bad_magic() {
        let (mut aid, _) = create_identity(test_provenance(), None).unwrap();
        aid.magic = [0xFF; 4];
        assert_eq!(validate_aid(&aid), Err(AipError::InvalidMagic));
    }

    #[test]
    fn test_validate_aid_rejects_unbound_id() {
        let (mut aid, _) = create_identity(test_provenance(), None).unwrap();
        let other_kp = generate_ed25519_keypair();
        aid.id = derive_aip_id(&other_kp.public_key, &aid.provenance);
        assert_eq!(validate_aid(&aid), Err(AipError::InvalidAipId));
    }

    struct MlDsaAcceptVerifier;

    impl SignatureVerifier for MlDsaAcceptVerifier {
        fn verify_signature(
            &self,
            algorithm: AlgorithmId,
            _public_key: &[u8],
            _signature: &Signature,
        ) -> Result<bool, AipError> {
            Ok(matches!(algorithm, AlgorithmId::MlDsa65))
        }
    }

    #[test]
    fn test_validate_aid_with_external_verifier_for_mldsa() {
        let (mut aid, _) = create_identity(test_provenance(), None).unwrap();

        aid.primary_key.algorithm = AlgorithmId::MlDsa65;
        aid.primary_key.key_bytes = vec![0x11; 1952];
        aid.id = derive_aip_id(&aid.primary_key.key_bytes, &aid.provenance);

        let canonical = canonical_encode_aid(&aid);
        aid.self_signature = Some(Signature {
            algorithm: AlgorithmId::MlDsa65,
            signer_id: aid.id.clone(),
            timestamp: 1,
            nonce: [7u8; 16],
            payload_hash: sha256(&canonical),
            signature_bytes: vec![0xAA; 64],
        });

        assert_eq!(validate_aid(&aid), Err(AipError::EvolutionRequired));
        let verifier = MlDsaAcceptVerifier;
        assert!(validate_aid_with_verifier(&aid, &verifier).is_ok());
    }

    #[test]
    fn test_lifecycle_pending_to_active() {
        let (mut aid, _) = create_identity(test_provenance(), None).unwrap();
        assert_eq!(aid.status, IdentityStatus::Pending);
        activate_identity(&mut aid).unwrap();
        assert_eq!(aid.status, IdentityStatus::Active);
    }

    #[test]
    fn test_lifecycle_active_to_suspended() {
        let (mut aid, _) = create_identity(test_provenance(), None).unwrap();
        activate_identity(&mut aid).unwrap();
        suspend_identity(&mut aid).unwrap();
        assert_eq!(aid.status, IdentityStatus::Suspended);
    }

    #[test]
    fn test_lifecycle_suspended_to_active() {
        let (mut aid, _) = create_identity(test_provenance(), None).unwrap();
        activate_identity(&mut aid).unwrap();
        suspend_identity(&mut aid).unwrap();
        reactivate_identity(&mut aid).unwrap();
        assert_eq!(aid.status, IdentityStatus::Active);
    }

    #[test]
    fn test_lifecycle_revoke_is_terminal() {
        let (mut aid, _) = create_identity(test_provenance(), None).unwrap();
        activate_identity(&mut aid).unwrap();
        revoke_identity(&mut aid).unwrap();
        assert_eq!(aid.status, IdentityStatus::Revoked);
        assert_eq!(activate_identity(&mut aid), Err(AipError::IdentityRevoked));
        assert_eq!(suspend_identity(&mut aid), Err(AipError::IdentityRevoked));
        assert_eq!(
            reactivate_identity(&mut aid),
            Err(AipError::IdentityRevoked)
        );
    }

    #[test]
    fn test_sequence_increments() {
        let (mut aid, _) = create_identity(test_provenance(), None).unwrap();
        assert_eq!(aid.sequence, 0);
        activate_identity(&mut aid).unwrap();
        assert_eq!(aid.sequence, 1);
        suspend_identity(&mut aid).unwrap();
        assert_eq!(aid.sequence, 2);
        reactivate_identity(&mut aid).unwrap();
        assert_eq!(aid.sequence, 3);
        revoke_identity(&mut aid).unwrap();
        assert_eq!(aid.sequence, 4);
    }

    // ─── AIP-3: Capability Tests ───

    fn make_grant(namespace: &str, actions: Vec<Action>, grantee: &str) -> CapabilityGrant {
        let kp = generate_ed25519_keypair();
        let sig = sign_ed25519(&kp.private_key, "grantor", b"grant").unwrap();
        CapabilityGrant {
            id: [0u8; 16],
            grantor_id: "grantor".into(),
            grantee_id: grantee.into(),
            namespace: namespace.into(),
            actions,
            constraints: vec![],
            delegatable: true,
            issued_at: 0,
            expires_at: None,
            grantor_sig: sig,
        }
    }

    #[test]
    fn test_capability_meet_same_namespace() {
        let a = make_grant(
            "com.test",
            vec![Action::Read, Action::Write, Action::Delete],
            "agent",
        );
        let b = make_grant("com.test", vec![Action::Read, Action::Write], "agent");
        let effective = capability_meet(&a, &b).unwrap();
        assert_eq!(
            effective.resolved_actions,
            vec![Action::Read, Action::Write]
        );
    }

    #[test]
    fn test_capability_meet_disjoint_actions() {
        let a = make_grant("com.test", vec![Action::Read], "agent");
        let b = make_grant("com.test", vec![Action::Write], "agent");
        assert!(capability_meet(&a, &b).is_none(), "Disjoint actions → ⊥");
    }

    #[test]
    fn test_capability_meet_different_namespace() {
        let a = make_grant("com.alpha", vec![Action::Read], "agent");
        let b = make_grant("com.beta", vec![Action::Read], "agent");
        assert!(capability_meet(&a, &b).is_none());
    }

    #[test]
    fn test_temporal_decay_no_elapsed() {
        let policy = TemporalDecayPolicy {
            decay_type: DecayType::Value,
            half_life_seconds: 3600,
            minimum_floor: 100,
            reauthorization_at: Some(1000),
        };
        assert_eq!(effective_decay_value(1_000_000, &policy, 1000), 1_000_000);
    }

    #[test]
    fn test_temporal_decay_one_half_life() {
        let policy = TemporalDecayPolicy {
            decay_type: DecayType::Value,
            half_life_seconds: 3600,
            minimum_floor: 0,
            reauthorization_at: Some(0),
        };
        // After 1 half-life: 1_000_000 / 2 = 500_000
        assert_eq!(effective_decay_value(1_000_000, &policy, 3600), 500_000);
    }

    #[test]
    fn test_temporal_decay_respects_floor() {
        let policy = TemporalDecayPolicy {
            decay_type: DecayType::Value,
            half_life_seconds: 100,
            minimum_floor: 50_000,
            reauthorization_at: Some(0),
        };
        // After many half-lives, should not drop below floor
        let result = effective_decay_value(1_000_000, &policy, 100_000);
        assert!(
            result >= 50_000,
            "Value {} dropped below floor 50_000",
            result
        );
    }

    #[test]
    fn test_capability_expiration() {
        let mut grant = make_grant("com.test", vec![Action::Read], "agent");
        grant.expires_at = Some(1000);
        assert!(!is_capability_expired(&grant, 500));
        assert!(is_capability_expired(&grant, 1001));
    }

    #[test]
    fn test_validate_capability_constraint_length() {
        let mut grant = make_grant("com.test", vec![Action::Read], "agent");
        grant.constraints.push(Constraint {
            key: "k".repeat(65),
            operator: ConstraintOp::Eq,
            value: "v".to_string(),
        });
        assert_eq!(
            validate_capability_grant(&grant, 0),
            Err(AipError::FieldTooLong)
        );
    }

    #[test]
    fn test_validate_capability_expiry_order() {
        let mut grant = make_grant("com.test", vec![Action::Read], "agent");
        grant.issued_at = 100;
        grant.expires_at = Some(100);
        assert_eq!(
            validate_capability_grant(&grant, 0),
            Err(AipError::CapabilityExpired)
        );
    }

    #[test]
    fn test_validate_capability_grant_with_key() {
        let kp = generate_ed25519_keypair();
        let placeholder_sig = sign_ed25519(&kp.private_key, "grantor", b"placeholder").unwrap();
        let mut grant = CapabilityGrant {
            id: [7u8; 16],
            grantor_id: "grantor".into(),
            grantee_id: "agent".into(),
            namespace: "com.test".into(),
            actions: vec![Action::Read, Action::Write],
            constraints: vec![],
            delegatable: true,
            issued_at: 1,
            expires_at: Some(10_000),
            grantor_sig: placeholder_sig,
        };

        let payload = canonical_encode_capability_grant(&grant);
        grant.grantor_sig = sign_ed25519(&kp.private_key, "grantor", &payload).unwrap();
        assert!(validate_capability_grant_with_key(&grant, &kp.public_key, 2).is_ok());

        // Tampering after signing must invalidate grant signature.
        grant.namespace = "com.evil".into();
        assert_eq!(
            validate_capability_grant_with_key(&grant, &kp.public_key, 2),
            Err(AipError::SignatureInvalid)
        );
    }

    // ─── AIP-4: Reputation Tests ───

    fn make_attestation(
        claim_type: ClaimType,
        attester_type: AttesterType,
        value: i32,
        attested_at_day: u64,
    ) -> Attestation {
        let kp = generate_ed25519_keypair();
        let sig = sign_ed25519(&kp.private_key, "attester", b"attest").unwrap();
        Attestation {
            id: [0u8; 16],
            subject_id: "subject".into(),
            attester_id: "attester".into(),
            attester_type,
            claim_type,
            claim_value: value,
            claim_context: "test".into(),
            evidence_hash: None,
            attested_at: attested_at_day * 86_400_000,
            valid_until: None,
            attester_sig: sig,
        }
    }

    #[test]
    fn test_reputation_calculation_basic() {
        let attestations = vec![
            make_attestation(
                ClaimType::TaskCompletion,
                AttesterType::Authority,
                900_000,
                0,
            ),
            make_attestation(
                ClaimType::VerificationPass,
                AttesterType::Authority,
                800_000,
                0,
            ),
        ];
        let rep = calculate_reputation("agent", &attestations, 0);
        assert!(rep.reliability > 0, "Reliability should be > 0");
        assert!(rep.honesty > 0, "Honesty should be > 0");
        assert!(rep.overall_score > 0, "Overall should be > 0");
    }

    #[test]
    fn test_reputation_default_for_no_attestations() {
        let rep = calculate_reputation("new_agent", &[], 0);
        assert_eq!(rep.reliability, 500_000, "Default should be 50%");
        assert_eq!(rep.honesty, 500_000);
        assert_eq!(rep.economic, 500_000);
        assert_eq!(rep.governance, 500_000);
    }

    #[test]
    fn test_attester_weight_authority_highest() {
        let auth = attester_weight_bps(AttesterType::Authority, 0);
        let peer = attester_weight_bps(AttesterType::Peer, 500_000);
        let self_att = attester_weight_bps(AttesterType::SelfAttest, 0);
        assert!(auth > peer);
        assert!(peer > self_att);
    }

    #[test]
    fn test_decay_weight_reduces_over_time() {
        let w0 = decay_weight(10_000, 0, 0); // No decay
        let w1 = decay_weight(10_000, 0, 30); // 1 period
        let w2 = decay_weight(10_000, 0, 60); // 2 periods
        assert!(w0 > w1, "Weight should decrease after 1 period");
        assert!(w1 > w2, "Weight should decrease after 2 periods");
    }

    // ─── §4.2 Solution 1: Hardware Attestation Tests ───

    #[test]
    fn test_hardware_trust_none() {
        let att = HardwareAttestation {
            device_id: [0u8; 32],
            tee_platform: TeePlatform::None,
            attestation_report: vec![0u8; 64],
            report_hash: sha256(&[0u8; 64]),
            bound_aip_id: "aip1test".into(),
            measured_at: 0,
        };
        assert_eq!(evaluate_hardware_trust(&att), HardwareTrustLevel::Unbound);
    }

    #[test]
    fn test_hardware_trust_software_tee() {
        let report = vec![0xABu8; 64];
        let att = HardwareAttestation {
            device_id: [0u8; 32], // No PUF
            tee_platform: TeePlatform::IntelSgx,
            attestation_report: report.clone(),
            report_hash: sha256(&report),
            bound_aip_id: "aip1test".into(),
            measured_at: 0,
        };
        assert_eq!(
            evaluate_hardware_trust(&att),
            HardwareTrustLevel::SoftwareTee
        );
    }

    #[test]
    fn test_hardware_trust_hardware_tee_with_puf() {
        let report = vec![0xCDu8; 64];
        let att = HardwareAttestation {
            device_id: [0xFFu8; 32], // Non-zero PUF
            tee_platform: TeePlatform::ArmTrustZone,
            attestation_report: report.clone(),
            report_hash: sha256(&report),
            bound_aip_id: "aip1test".into(),
            measured_at: 0,
        };
        assert_eq!(
            evaluate_hardware_trust(&att),
            HardwareTrustLevel::HardwareTee
        );
    }

    #[test]
    fn test_hardware_trust_full_enclave() {
        let mut report = vec![0xAAu8; 64];
        report[10..14].copy_from_slice(&[0x4D, 0x42, 0x4F, 0x54]); // "MBOT" marker
        let att = HardwareAttestation {
            device_id: [0xFFu8; 32],
            tee_platform: TeePlatform::AppleSep,
            attestation_report: report.clone(),
            report_hash: sha256(&report),
            bound_aip_id: "aip1test".into(),
            measured_at: 0,
        };
        assert_eq!(
            evaluate_hardware_trust(&att),
            HardwareTrustLevel::FullEnclave
        );
    }

    #[test]
    fn test_hardware_trust_tampered_report() {
        let report = vec![0xBBu8; 64];
        let att = HardwareAttestation {
            device_id: [0xFFu8; 32],
            tee_platform: TeePlatform::IntelSgx,
            attestation_report: report,
            report_hash: [0u8; 32], // Wrong hash!
            bound_aip_id: "aip1test".into(),
            measured_at: 0,
        };
        assert_eq!(
            evaluate_hardware_trust(&att),
            HardwareTrustLevel::Unbound,
            "Tampered report hash must result in Unbound"
        );
    }

    #[test]
    fn test_bind_hardware_wrong_aid() {
        let (aid, _) = create_identity(test_provenance(), None).unwrap();
        let report = vec![0u8; 64];
        let att = HardwareAttestation {
            device_id: [0u8; 32],
            tee_platform: TeePlatform::None,
            attestation_report: report.clone(),
            report_hash: sha256(&report),
            bound_aip_id: "aip1WRONGID".into(),
            measured_at: 0,
        };
        assert_eq!(
            bind_hardware_to_aid(&aid, &att),
            Err(AipError::ProvenanceMismatch)
        );
    }

    // ─── §4.2 Solution 2: Liveness Tests ───

    #[test]
    fn test_liveness_challenge_response_roundtrip() {
        let kp = generate_ed25519_keypair();
        let prov = test_provenance();
        let agent_id = derive_aip_id(&kp.public_key, &prov);

        let challenge = issue_liveness_challenge("verifier", &agent_id);
        let response = respond_to_challenge(&challenge, &kp.private_key, &agent_id).unwrap();
        let valid = verify_liveness(&challenge, &response, &kp.public_key).unwrap();
        assert!(valid, "Valid liveness response must verify");
    }

    #[test]
    fn test_liveness_wrong_responder() {
        let kp_b = generate_ed25519_keypair();

        let challenge = issue_liveness_challenge("verifier", "agent_a");
        let response = respond_to_challenge(&challenge, &kp_b.private_key, "agent_b").unwrap();
        let valid = verify_liveness(&challenge, &response, &kp_b.public_key).unwrap();
        assert!(!valid, "Response from wrong agent must fail");
    }

    #[test]
    fn test_liveness_expired_response() {
        let kp = generate_ed25519_keypair();
        let id = derive_aip_id(&kp.public_key, &test_provenance());
        let challenge = issue_liveness_challenge("verifier", &id);
        let mut response = respond_to_challenge(&challenge, &kp.private_key, &id).unwrap();
        response.responded_at = challenge
            .issued_at
            .saturating_add(challenge.deadline_ms)
            .saturating_add(1);

        let valid = verify_liveness(&challenge, &response, &kp.public_key).unwrap();
        assert!(!valid, "Responses after deadline must fail");
    }

    #[test]
    fn test_liveness_payload_hash_mismatch() {
        let kp = generate_ed25519_keypair();
        let id = derive_aip_id(&kp.public_key, &test_provenance());
        let challenge = issue_liveness_challenge("verifier", &id);
        let mut response = respond_to_challenge(&challenge, &kp.private_key, &id).unwrap();
        response.responder_sig.payload_hash[0] ^= 0xFF;

        let valid = verify_liveness(&challenge, &response, &kp.public_key).unwrap();
        assert!(!valid, "Liveness signature payload mismatch must fail");
    }

    #[test]
    fn test_liveness_record_heartbeat() {
        let mut record = LivenessRecord {
            agent_id: "test".into(),
            last_heartbeat: 0,
            consecutive_misses: 0,
            is_alive: true,
        };

        // 3 misses → dead
        update_liveness_record(&mut record, false);
        assert!(record.is_alive);
        update_liveness_record(&mut record, false);
        assert!(record.is_alive);
        update_liveness_record(&mut record, false);
        assert!(!record.is_alive, "3 consecutive misses → agent is dead");

        // Responding brings it back
        update_liveness_record(&mut record, true);
        assert!(record.is_alive, "Responding resets liveness");
        assert_eq!(record.consecutive_misses, 0);
    }

    // ─── §4.2 Solution 3: Decentralized Reputation Tests ───

    fn make_vote(dimension: ReputationDimensionId, score: u32) -> ReputationVote {
        let kp = generate_ed25519_keypair();
        let mut vote = ReputationVote {
            voter_id: "voter".into(),
            subject_id: "subject".into(),
            dimension,
            score,
            evidence_root: [0u8; 32],
            voted_at: 0,
            voter_sig: sign_ed25519(&kp.private_key, "voter", b"placeholder").unwrap(),
        };
        let payload = canonical_encode_reputation_vote(&vote);
        vote.voter_sig = sign_ed25519(&kp.private_key, "voter", &payload).unwrap();
        vote
    }

    #[test]
    fn test_bft_reputation_below_quorum() {
        let votes = vec![make_vote(ReputationDimensionId::Reliability, 900_000)];
        let result = aggregate_reputation_votes("agent", &votes, 7);
        assert!(!result.consensus_reached);
        assert_eq!(result.overall_score, 500_000, "Below quorum → default 50%");
    }

    #[test]
    fn test_bft_reputation_with_quorum() {
        let votes: Vec<ReputationVote> = (0..7)
            .map(|_| make_vote(ReputationDimensionId::Reliability, 800_000))
            .collect();
        let result = aggregate_reputation_votes("agent", &votes, 7);
        assert!(result.consensus_reached);
        assert_eq!(result.reliability, 800_000);
    }

    #[test]
    fn test_bft_reputation_byzantine_trimming() {
        // 7 votes: 2 Byzantine liars (0 and 1M), 5 honest (800K)
        let votes = vec![
            make_vote(ReputationDimensionId::Honesty, 0), // Byzantine
            make_vote(ReputationDimensionId::Honesty, 1_000_000), // Byzantine
            make_vote(ReputationDimensionId::Honesty, 800_000),
            make_vote(ReputationDimensionId::Honesty, 800_000),
            make_vote(ReputationDimensionId::Honesty, 800_000),
            make_vote(ReputationDimensionId::Honesty, 800_000),
            make_vote(ReputationDimensionId::Honesty, 800_000),
        ];
        let result = aggregate_reputation_votes("agent", &votes, 7);
        assert!(result.consensus_reached);
        // After trimming top/bottom f=2, median of [800K,800K,800K] = 800K
        assert_eq!(result.honesty, 800_000, "Byzantine votes should be trimmed");
    }

    fn signed_vote_with_key(
        voter_id: &str,
        subject_id: &str,
        dimension: ReputationDimensionId,
        score: u32,
        kp: &KeyPair,
    ) -> ReputationVote {
        let mut vote = ReputationVote {
            voter_id: voter_id.to_string(),
            subject_id: subject_id.to_string(),
            dimension,
            score,
            evidence_root: sha256(voter_id.as_bytes()),
            voted_at: 42,
            voter_sig: sign_ed25519(&kp.private_key, voter_id, b"placeholder").unwrap(),
        };
        let payload = canonical_encode_reputation_vote(&vote);
        vote.voter_sig = sign_ed25519(&kp.private_key, voter_id, &payload).unwrap();
        vote
    }

    #[test]
    fn test_verified_reputation_aggregation_rejects_invalid_and_duplicates() {
        let kp_a = generate_ed25519_keypair();
        let kp_b = generate_ed25519_keypair();
        let kp_c = generate_ed25519_keypair();

        let mut voter_keys = HashMap::new();
        voter_keys.insert("a".to_string(), kp_a.public_key.clone());
        voter_keys.insert("b".to_string(), kp_b.public_key.clone());
        voter_keys.insert("c".to_string(), kp_c.public_key.clone());

        let vote_a = signed_vote_with_key(
            "a",
            "subject",
            ReputationDimensionId::Reliability,
            800_000,
            &kp_a,
        );
        let vote_b = signed_vote_with_key(
            "b",
            "subject",
            ReputationDimensionId::Reliability,
            850_000,
            &kp_b,
        );
        let mut vote_c = signed_vote_with_key(
            "c",
            "subject",
            ReputationDimensionId::Reliability,
            900_000,
            &kp_c,
        );
        // Tamper c after signing to break signature binding.
        vote_c.score = 10;

        // Duplicate voter_id "a" should be ignored.
        let dup_a = signed_vote_with_key(
            "a",
            "subject",
            ReputationDimensionId::Reliability,
            100_000,
            &kp_a,
        );

        let result = aggregate_reputation_votes_verified(
            "subject",
            &[vote_a, vote_b, vote_c, dup_a],
            2,
            &voter_keys,
        );
        assert!(result.consensus_reached);
        assert_eq!(result.quorum_size, 2);
        assert_eq!(result.reliability, 850_000);
    }

    #[test]
    fn test_verified_reputation_aggregation_sybil_same_key_rejected() {
        let kp = generate_ed25519_keypair();
        let vote_a = signed_vote_with_key(
            "id_a",
            "subject",
            ReputationDimensionId::Honesty,
            900_000,
            &kp,
        );
        let vote_b = signed_vote_with_key(
            "id_b",
            "subject",
            ReputationDimensionId::Honesty,
            100_000,
            &kp,
        );

        let mut voter_keys = HashMap::new();
        // Two IDs registered to the same key in this round.
        voter_keys.insert("id_a".to_string(), kp.public_key.clone());
        voter_keys.insert("id_b".to_string(), kp.public_key.clone());

        let result =
            aggregate_reputation_votes_verified("subject", &[vote_a, vote_b], 2, &voter_keys);
        assert!(
            !result.consensus_reached,
            "same-key multi-ID should not satisfy quorum"
        );
    }
}
