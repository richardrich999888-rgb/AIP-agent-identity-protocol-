//! Skill 10 Gate 10 — the portable representation.
//!
//! ```text
//! export_proof ─▶ bytes ─▶ (any transport) ─▶ import_proof ─▶ verify
//! ```
//!
//! # Trust anchors travel separately, and that is the point
//!
//! A package that carried the keys that check it would prove nothing: a
//! forger would ship their own. So the proof file carries **evidence**, and
//! the anchors are the verifier's own decision, obtained out of band. The
//! anchor file here exists because a demonstration has to move them
//! somehow; in a deployment the verifier provisions them itself, and
//! importing anchors from beside the proof is exactly what it must not do.
//!
//! # The container is not security-relevant
//!
//! JSON, with no maps and no floats, so field order is the struct's. But
//! nothing rests on that: every hash and signature is over the canonical
//! encoding recomputed from the parsed structure, so whitespace, key order
//! and pretty-printing cannot change a verdict. `proof_id` is the identity,
//! and it survives any reformatting.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::commitment::NexoraTrustAnchors;
use crate::proof::{NexoraProof, NEXORA_PROOF_VERSION};
use crate::verify::VerifierAnchors;

/// Why a file could not be read as a proof.
#[derive(Debug)]
pub enum ExportError {
    /// The bytes are not the container at all.
    Malformed(String),
    /// A proof of a format version this build does not implement. Named,
    /// never guessed at.
    UnsupportedVersion(u16),
    Encode(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::Malformed(e) => write!(f, "not a NEXORA proof: {e}"),
            ExportError::UnsupportedVersion(v) => {
                write!(f, "proof format version {v} is not implemented here")
            }
            ExportError::Encode(e) => write!(f, "could not encode: {e}"),
        }
    }
}

impl std::error::Error for ExportError {}

/// Serialise a proof for transport.
pub fn export_proof(proof: &NexoraProof) -> Result<Vec<u8>, ExportError> {
    serde_json::to_vec(proof).map_err(|e| ExportError::Encode(e.to_string()))
}

/// Read a proof back. Refuses anything that is not one, and refuses a
/// format version this build does not implement rather than parsing what
/// it can and hoping.
pub fn import_proof(bytes: &[u8]) -> Result<NexoraProof, ExportError> {
    let proof: NexoraProof =
        serde_json::from_slice(bytes).map_err(|e| ExportError::Malformed(e.to_string()))?;
    if proof.version != NEXORA_PROOF_VERSION {
        return Err(ExportError::UnsupportedVersion(proof.version));
    }
    Ok(proof)
}

// ─── Anchors, moved deliberately and separately ───

/// A verifier's anchors in transportable form.
///
/// **This is not part of a proof.** It exists so a demonstration can hand
/// a second machine the keys it would otherwise provision itself. A
/// verifier that takes its anchors from beside the artifact it is checking
/// has verified nothing, and the file says so in its own `note`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorFile {
    pub version: u16,
    /// Present in every file this crate writes, so a reader who never read
    /// this doc comment still meets the warning.
    pub note: String,
    /// decision point id → public key
    pub decision_points: Vec<(String, Vec<u8>)>,
    /// (observer id, key version) → public key
    pub observers: Vec<(String, u32, Vec<u8>)>,
    /// warrant authority id → public key
    pub warrant_authorities: Vec<(String, Vec<u8>)>,
    /// (NEXORA signer or assembler id, key version) → public key
    pub nexora: Vec<(String, u32, Vec<u8>)>,
    /// issuer AIP-ID → public key
    pub issuers: Vec<(String, Vec<u8>)>,
    /// The observed agent's public key, when the verifier holds it.
    pub agent_public_key: Option<Vec<u8>>,
}

const ANCHOR_NOTE: &str = "these are the verifier's own trust anchors; a verifier that takes \
                           them from beside the proof it is checking has verified nothing";

/// Write anchors out. Every field is a key the verifier chose to trust.
pub fn export_anchors(a: &VerifierAnchors) -> Result<Vec<u8>, ExportError> {
    let file = AnchorFile {
        version: NEXORA_PROOF_VERSION,
        note: ANCHOR_NOTE.to_string(),
        decision_points: a.decision_point.entries(),
        observers: a.observer.entries(),
        warrant_authorities: a.warrant.entries(),
        nexora: a.nexora.entries(),
        issuers: a
            .issuers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        agent_public_key: a.agent_public_key.clone(),
    };
    serde_json::to_vec_pretty(&file).map_err(|e| ExportError::Encode(e.to_string()))
}

/// Read anchors a verifier chose to provision this way.
pub fn import_anchors(bytes: &[u8]) -> Result<VerifierAnchors, ExportError> {
    let file: AnchorFile =
        serde_json::from_slice(bytes).map_err(|e| ExportError::Malformed(e.to_string()))?;
    if file.version != NEXORA_PROOF_VERSION {
        return Err(ExportError::UnsupportedVersion(file.version));
    }
    let mut decision_point = aip_authorize::DecisionPointTrustAnchors::new();
    for (id, key) in &file.decision_points {
        decision_point = decision_point.trust(id, key);
    }
    let mut observer = aip_observe::ObserverTrustAnchors::new();
    for (id, version, key) in &file.observers {
        observer = observer.trust(id, *version, key);
    }
    let mut warrant = aip_warrant::WarrantTrustAnchors::new();
    for (id, key) in &file.warrant_authorities {
        warrant = warrant.trust(id, key);
    }
    let mut nexora = NexoraTrustAnchors::new();
    for (id, version, key) in &file.nexora {
        nexora = nexora.trust(id, *version, key);
    }
    let mut issuers = HashMap::new();
    for (id, key) in &file.issuers {
        issuers.insert(id.clone(), key.clone());
    }
    Ok(VerifierAnchors {
        decision_point,
        observer,
        warrant,
        nexora,
        issuers,
        agent_public_key: file.agent_public_key,
        // Bounds are the verifier's own judgement and are deliberately not
        // transported: a package must not be able to tell a verifier what
        // it will accept.
        max_declared_health_age_ms: None,
        max_declared_window_tolerance_ms: None,
        // Nor does a package get to tell a verifier what time it is.
        present_time_ms: None,
    })
}
