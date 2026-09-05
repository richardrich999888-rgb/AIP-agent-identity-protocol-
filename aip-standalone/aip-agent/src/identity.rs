//! SD-01 — a validated agent identity.
//!
//! An [`AgentIdentity`] is never taken from a string. It is produced only by
//! re-deriving the AIP-ID from the key and provenance presented and, for a
//! document, by verifying the document's own signature through
//! `aip_core::validate_aid`. Everything it says about lifecycle is the
//! agent's own statement ([`LifecycleAssertion::SelfAsserted`]) because no
//! party other than the agent signs a lifecycle transition anywhere in the
//! repository (`tests/characterization.rs`, c01).

use aip_core::{validate_aid, validate_aid_with_parent};
use aip_crypto::{derive_aip_id, validate_aip_id};
use aip_protocol::AgentIdentitySummary;
use aip_types::{
    AgentIdentityDocument, AipError, AlgorithmId, ExecutionBinding, IdentityStatus,
    ProvenanceTriple, PublicKey,
};
use serde::Serialize;

/// Where the identity was read from. A document carries the agent's
/// self-signature and lifecycle statement; a packet summary carries only the
/// (id, key, provenance) triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IdentitySource {
    Document,
    PacketSummary,
}

/// The agent's lifecycle statement. There is deliberately no variant that a
/// reader could take as authoritative: the repository has no lifecycle
/// authority (`SNIFFER_DOG_2_0_GAP_MATRIX.md` A.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum LifecycleAssertion {
    /// The source carried no lifecycle statement at all.
    NotEstablished,
    /// The agent's own signed document states this status and sequence.
    SelfAsserted {
        status: IdentityStatus,
        sequence: u64,
    },
}

/// The state of the parent lineage proof on a document: the parent identity's
/// signature over `(child_id, child_public_key)` at creation. Reported as a
/// proof, not as a "parent" — the four-way parent classification is Phase C.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum LineageProofState {
    /// The source cannot carry a proof (a packet summary).
    NotCarried,
    /// A root document: no parent signed it.
    Absent,
    /// A proof by `signer_id` is present. `verified` is `Some(true)` only
    /// when the caller supplied that signer's key and the proof checked out;
    /// `None` when no key was supplied. A proof that fails against the
    /// supplied key is an error, never `Some(false)`.
    Present {
        signer_id: String,
        verified: Option<bool>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// `aip_core::validate_aid*` refused the document.
    Document(AipError),
    /// The AIP-ID does not derive from the presented key and provenance.
    DerivationMismatch,
    /// The AIP-ID is not well-formed.
    MalformedId(AipError),
    /// The key length is impossible for the declared algorithm.
    KeyLength { expected: usize, actual: usize },
    /// Only Ed25519 is an implemented capability (I7).
    UnsupportedAlgorithm(AlgorithmId),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for IdentityError {}

/// A validated identity: the persistent agent, distinct from any execution
/// instance ([`ExecutionBinding`]) and from any process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentIdentity {
    id: String,
    public_key: PublicKey,
    provenance: ProvenanceTriple,
    source: IdentitySource,
    lifecycle: LifecycleAssertion,
    lineage_proof: LineageProofState,
}

impl AgentIdentity {
    /// From the agent's identity document. `parent`, when supplied, is the
    /// `(parent_id, parent_public_key)` the caller asserts; the lineage proof
    /// is then verified against it and a mismatch refuses the document.
    pub fn from_document(
        aid: &AgentIdentityDocument,
        parent: Option<(&str, &[u8])>,
    ) -> Result<Self, IdentityError> {
        match parent {
            Some((pid, pk)) => validate_aid_with_parent(aid, pid, pk),
            None => validate_aid(aid),
        }
        .map_err(IdentityError::Document)?;
        Ok(Self {
            id: aid.id.clone(),
            public_key: aid.primary_key.clone(),
            provenance: aid.provenance.clone(),
            source: IdentitySource::Document,
            lifecycle: LifecycleAssertion::SelfAsserted {
                status: aid.status,
                sequence: aid.sequence,
            },
            lineage_proof: match &aid.lineage_proof {
                None => LineageProofState::Absent,
                Some(sig) => LineageProofState::Present {
                    signer_id: sig.signer_id.clone(),
                    verified: parent.map(|_| true),
                },
            },
        })
    }

    /// From the identity summary an `EvidencePacket` carries. Mirrors packet
    /// rule R2 (the id must derive from key and provenance) so the summary
    /// can be validated outside `verify_packet`.
    pub fn from_summary(s: &AgentIdentitySummary) -> Result<Self, IdentityError> {
        validate_aip_id(&s.aip_id).map_err(IdentityError::MalformedId)?;
        if s.public_key.algorithm != AlgorithmId::Ed25519 {
            return Err(IdentityError::UnsupportedAlgorithm(s.public_key.algorithm));
        }
        if s.public_key.key_bytes.len() != 32 {
            return Err(IdentityError::KeyLength {
                expected: 32,
                actual: s.public_key.key_bytes.len(),
            });
        }
        if derive_aip_id(&s.public_key.key_bytes, &s.provenance) != s.aip_id {
            return Err(IdentityError::DerivationMismatch);
        }
        Ok(Self {
            id: s.aip_id.clone(),
            public_key: s.public_key.clone(),
            provenance: s.provenance.clone(),
            source: IdentitySource::PacketSummary,
            lifecycle: LifecycleAssertion::NotEstablished,
            lineage_proof: LineageProofState::NotCarried,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn provenance(&self) -> &ProvenanceTriple {
        &self.provenance
    }

    pub fn source(&self) -> IdentitySource {
        self.source
    }

    pub fn lifecycle(&self) -> &LifecycleAssertion {
        &self.lifecycle
    }

    pub fn lineage_proof(&self) -> &LineageProofState {
        &self.lineage_proof
    }

    /// Whether an execution binding names this identity. The link is the
    /// validated AIP-ID and nothing else — never pid, path or start time —
    /// and it is the binding's *claim* to belong to this agent.
    pub fn names_binding(&self, b: &ExecutionBinding) -> bool {
        b.agent_id == self.id
    }
}
