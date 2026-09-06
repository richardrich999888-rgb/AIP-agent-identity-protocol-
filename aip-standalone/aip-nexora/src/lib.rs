//! aip-nexora — the portable commitment layer (Skill 10).
//!
//! NEXORA commits to verified execution history; it does not authorize,
//! observe, reconcile, decide policy or contain (`NEXORA_BOUNDARY.md`).
//! Gate 6 builds the Merkle commitment underneath it: an append-only tree
//! over domain-separated leaves with inclusion and consistency proofs that
//! an offline verifier can check against a root it obtained elsewhere.
//! Signed heads, proof objects and the offline verifier are Gate 7.

pub mod commitment;
pub mod export;
pub mod merkle;
pub mod proof;
pub mod verify;

pub use commitment::{
    verify_proof, verify_signed_head, Advance, AnchorSink, CommitmentLog, HeadTracker,
    MemoryAnchor, NexoraError, NexoraSigner, NexoraTrustAnchors, ProofObject, SignedHead,
    VerifiedInclusion, HEAD_DOMAIN, NEXORA_VERSION, PROOF_DOMAIN,
};
pub use merkle::{
    leaf_hash, root_of, verify_consistency, verify_inclusion, ConsistencyProof, InclusionProof,
    LeafKind, MerkleError, MerkleTree, LEAF_DOMAIN,
};
pub use proof::{
    verify_envelope, AuthorityEvidence, BindingFault, Component, DeclaredParameters, Envelope,
    LineageEvidence, NexoraProof, ObserverBundle, ProofAssembler, ProofBuilder, ProofFault,
    StructuralFault, Subject, NEXORA_PROOF_VERSION, PROOF_BUNDLE_DOMAIN, PROOF_ENVELOPE_DOMAIN,
};
pub use verify::{
    verify_nexora_proof, Completeness, ComponentVerdict, ContinuityStanding, Coverage,
    Independence, InvalidReason, LineageReport, LineageStanding, ObservationCoverage, ProofVerdict,
    VerifiedProof, VerifierAnchors,
};
