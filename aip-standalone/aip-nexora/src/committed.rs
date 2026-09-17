//! SD-10 — committing a signed verdict to the log, and checking it offline.
//!
//! SD-09 made a reconciliation verdict *attributable*: a
//! [`SignedReconciliation`] carries the reconciler's signature. This module
//! puts that signed verdict into the commitment log as its own leaf kind and
//! gives an offline party one function that answers two questions at once:
//!
//! 1. **Was it committed?** — the inclusion proof and its signed head verify
//!    under the NEXORA anchors the verifier holds ([`verify_proof`]).
//! 2. **Who vouches for it?** — the reconciler's signature over the verdict
//!    verifies under the reconciler anchors the verifier holds
//!    ([`SignedReconciliation::verify`]).
//!
//! and one binding between them: the committed bytes must be *this* signed
//! verdict's canonical encoding, recomputed from the struct the verifier
//! holds — never taken from the proof's own word.
//!
//! # What this does not do
//!
//! It does not restate, raise, or interpret the verdict. A committed
//! `CANNOT_PROVE` is exactly as committed as a committed `VERIFIED_EXECUTION`,
//! and the result and strength are carried verbatim. It does not replace the
//! [`crate::verify::verify_nexora_proof`] re-derivation path, which recomputes
//! a verdict from its evidence; it complements it with attribution. Anchors of
//! both kinds come from the verifier, never from the artifact.

use serde::{Deserialize, Serialize};

use aip_reconcile::{
    EvidenceStrength, ReconcilerTrustAnchors, ReconciliationAttestationError, ReconciliationResult,
    SignedReconciliation,
};

use crate::commitment::{
    verify_proof, CommitmentLog, NexoraError, NexoraTrustAnchors, ProofObject, VerifiedInclusion,
};
use crate::merkle::LeafKind;

/// Append a signed verdict to `log` as a [`LeafKind::SignedReconciliation`]
/// leaf; returns its position. The committed bytes are
/// [`SignedReconciliation::canonical_bytes`], which include the signature.
pub fn commit_signed_verdict(log: &mut CommitmentLog, signed: &SignedReconciliation) -> u64 {
    log.append(LeafKind::SignedReconciliation, &signed.canonical_bytes())
}

/// What an offline party can say after [`verify_committed_verdict`]: where
/// the signed verdict was committed, which reconciler key vouches for it, and
/// the verdict's result and strength **verbatim**. Nothing here is a
/// statement about the world in NEXORA's own voice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedVerdict {
    pub inclusion: VerifiedInclusion,
    pub reconciler_id: String,
    pub key_version: u32,
    /// Carried from the signed verdict. Never restated or raised.
    pub result: ReconciliationResult,
    /// Carried from the signed verdict. Never raised.
    pub strength: EvidenceStrength,
}

/// Why a committed verdict was refused. Each is a refusal, never a warning.
#[derive(Debug)]
pub enum CommittedVerdictError {
    /// The reconciler's signature over the verdict did not verify under the
    /// verifier's reconciler anchors.
    Attestation(ReconciliationAttestationError),
    /// The inclusion proof or its signed head did not verify under the
    /// verifier's NEXORA anchors.
    Commitment(NexoraError),
    /// The proof commits a leaf of another kind — for example a bare
    /// `Reconciliation` — not a signed verdict. A bare verdict relabelled as an
    /// attributed one is refused here.
    WrongLeafKind(LeafKind),
    /// The proof's committed bytes are not this signed verdict's canonical
    /// bytes: the proof is for some other record.
    RecordMismatch,
}

impl std::fmt::Display for CommittedVerdictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Attestation(e) => write!(f, "reconciler attestation: {e}"),
            Self::Commitment(e) => write!(f, "commitment: {e}"),
            Self::WrongLeafKind(k) => write!(f, "committed leaf is {k:?}, not a signed verdict"),
            Self::RecordMismatch => {
                write!(
                    f,
                    "committed bytes are not this signed verdict's canonical bytes"
                )
            }
        }
    }
}

impl std::error::Error for CommittedVerdictError {}

/// Verify that `signed` is a reconciler-attested verdict **and** that `proof`
/// commits exactly it under a head the verifier anchors.
///
/// Order, and why: the attestation is checked first, so a verdict nobody the
/// verifier trusts vouches for is refused before the log is consulted; then
/// the commitment; then that the committed leaf is a signed-verdict leaf; then
/// that its bytes are this verdict's — recomputed from `signed`, so the proof
/// cannot smuggle in different bytes. All four must hold.
pub fn verify_committed_verdict(
    signed: &SignedReconciliation,
    proof: &ProofObject,
    nexora_anchors: &NexoraTrustAnchors,
    reconciler_anchors: &ReconcilerTrustAnchors,
) -> Result<CommittedVerdict, CommittedVerdictError> {
    signed
        .verify(reconciler_anchors)
        .map_err(CommittedVerdictError::Attestation)?;
    let inclusion =
        verify_proof(proof, nexora_anchors).map_err(CommittedVerdictError::Commitment)?;
    if inclusion.kind != LeafKind::SignedReconciliation {
        return Err(CommittedVerdictError::WrongLeafKind(inclusion.kind));
    }
    if proof.record != signed.canonical_bytes() {
        return Err(CommittedVerdictError::RecordMismatch);
    }
    let verdict = signed.reconciliation();
    Ok(CommittedVerdict {
        inclusion,
        reconciler_id: signed.reconciler_id.clone(),
        key_version: signed.key_version,
        result: verdict.result,
        strength: verdict.strength,
    })
}
