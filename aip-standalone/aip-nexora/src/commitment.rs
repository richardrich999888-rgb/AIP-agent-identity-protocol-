//! Gate 7 — NEXORA's proof layer over the Gate 6 commitment: signed heads,
//! proof objects, an offline verifier, an offline party's head tracker, and
//! the interface through which heads leave NEXORA's custody.
//!
//! ```text
//! records ── append ──▶ CommitmentLog ── head(signer, t) ──▶ SignedHead
//!                             │                                (chained: prev_head)
//!                             └── proof_for(i, head) ──▶ ProofObject
//!                                                              │
//!                             verify_proof(proof, anchors) ────┘ offline
//!                                        ▼
//!                             VerifiedInclusion { log, size, root, index,
//!                                                 kind, record digest }
//! ```
//!
//! **What a head is.** NEXORA's own signature, under its own domain and
//! key, over (log id, size, root, previous head digest, time). Heads chain:
//! each names the digest of the one before it, the first names zero. A
//! head is what leaves NEXORA — through an [`AnchorSink`] — so that a party
//! outside it holds the log's size and root at a moment. Without that, a
//! prefix of the history verifies exactly as well as the whole
//! (`NEXORA_BOUNDARY.md` §5).
//!
//! **What a proof object is.** One record's bytes, its kind, the head it
//! was proven under and the inclusion path. [`verify_proof`] needs nothing
//! but the proof and the verifier's anchors: it checks the head's
//! signature, that the proof and the head speak of one log at one size,
//! recomputes the leaf from the kind and the bytes, and walks the path to
//! the root. What it returns names *where* the bytes were committed and
//! their digest — and nothing about whether the record's own claims hold.
//! A committed `CANNOT_PROVE` is exactly as committed as a committed
//! `VERIFIED_EXECUTION`; the record's own verifier reads the record.
//!
//! **What NEXORA is not.** Not an authority (rule 17): no field here says
//! permitted, verified or trusted; no path from a proof reaches a decision,
//! a warrant or a containment. Not a replay of anything: the bytes are what
//! was committed, no more.

use std::cell::RefCell;
use std::collections::HashMap;

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u32, put_u64, put_u8};
use aip_types::{AipError, Signature};
use serde::{Deserialize, Serialize};

use crate::merkle::{
    leaf_hash, verify_consistency, verify_inclusion, ConsistencyProof, InclusionProof, LeafKind,
    MerkleError, MerkleTree,
};

pub const NEXORA_VERSION: u16 = 1;
/// Domain tag leading a head's signing preimage.
pub const HEAD_DOMAIN: &str = "SYNTRIASS/NEXORA/HEAD/v1";
/// Domain tag leading a proof object's canonical bytes.
pub const PROOF_DOMAIN: &str = "SYNTRIASS/NEXORA/PROOF/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NexoraError {
    UnsupportedVersion(u16),
    InvalidKeyLength(usize),
    EmptySignerId,
    /// No anchor for this `(signer_id, key_version)`.
    UntrustedKey {
        signer_id: String,
        key_version: u32,
    },
    /// The signature names another signer than the head.
    SignerMismatch,
    /// The signature's payload hash is not the head's preimage: the head
    /// was altered after signing.
    PayloadHashMismatch,
    SignatureInvalid,
    Crypto(AipError),
    /// The proof, the head and the tracker do not speak of one log.
    LogMismatch {
        expected: [u8; 16],
        got: [u8; 16],
    },
    /// The proof was made at one size, the head names another.
    SizeMismatch {
        proof: u64,
        head: u64,
    },
    IndexOutOfRange {
        index: u64,
        size: u64,
    },
    SizeOutOfRange {
        requested: u64,
        size: u64,
    },
    /// The leaf recomputed from the kind and the bytes is not under the
    /// head's root at the proof's index.
    LeafNotIncluded,
    /// A head smaller than the one already accepted.
    Rollback {
        from: u64,
        to: u64,
    },
    /// A different head at the size already accepted.
    Fork {
        size: u64,
    },
    /// A larger head offered without a consistency proof.
    ConsistencyMissing,
    /// The consistency proof does not take the accepted root to the offered
    /// one.
    ConsistencyInvalid,
    /// The offered head does not name the accepted head as its predecessor.
    HeadChainBroken,
}

impl std::fmt::Display for NexoraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for NexoraError {}

impl From<MerkleError> for NexoraError {
    fn from(e: MerkleError) -> Self {
        match e {
            MerkleError::IndexOutOfRange { index, size } => {
                NexoraError::IndexOutOfRange { index, size }
            }
            MerkleError::SizeOutOfRange { requested, size } => {
                NexoraError::SizeOutOfRange { requested, size }
            }
        }
    }
}

// ─── Signed head ───

/// NEXORA's statement about one log at one moment: its size and root, the
/// head before it, and when. Signed under [`HEAD_DOMAIN`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHead {
    pub version: u16,
    pub log_id: [u8; 16],
    pub size: u64,
    pub root: [u8; 32],
    /// Digest of the previous head of this log; zero for the first.
    pub prev_head: [u8; 32],
    pub issued_at_ms: u64,
    pub signer_id: String,
    pub key_version: u32,
    pub signature: Signature,
}

impl SignedHead {
    pub fn signing_preimage(&self) -> Vec<u8> {
        head_preimage(
            self.version,
            &self.log_id,
            self.size,
            &self.root,
            &self.prev_head,
            self.issued_at_ms,
            &self.signer_id,
            self.key_version,
        )
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.signing_preimage())
    }
}

#[allow(clippy::too_many_arguments)]
fn head_preimage(
    version: u16,
    log_id: &[u8; 16],
    size: u64,
    root: &[u8; 32],
    prev_head: &[u8; 32],
    issued_at_ms: u64,
    signer_id: &str,
    key_version: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    put_domain(&mut buf, HEAD_DOMAIN);
    put_u16(&mut buf, version);
    buf.extend_from_slice(log_id);
    put_u64(&mut buf, size);
    buf.extend_from_slice(root);
    buf.extend_from_slice(prev_head);
    put_u64(&mut buf, issued_at_ms);
    put_str(&mut buf, signer_id);
    put_u32(&mut buf, key_version);
    buf
}

/// NEXORA's key. A fifth trust root beside the issuer, the decision point,
/// the collector and the warrant engine; it signs heads and nothing else.
pub struct NexoraSigner {
    id: String,
    key_version: u32,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for NexoraSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NexoraSigner")
            .field("id", &self.id)
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl NexoraSigner {
    pub fn new(
        id: &str,
        key_version: u32,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, NexoraError> {
        if id.is_empty() {
            return Err(NexoraError::EmptySignerId);
        }
        if private_key.len() != 32 {
            return Err(NexoraError::InvalidKeyLength(private_key.len()));
        }
        if public_key.len() != 32 {
            return Err(NexoraError::InvalidKeyLength(public_key.len()));
        }
        Ok(Self {
            id: id.to_string(),
            key_version,
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign a head over exactly the fields given; the signer fields are
    /// this key's.
    pub fn resign(&self, mut head: SignedHead) -> Result<SignedHead, NexoraError> {
        head.signer_id = self.id.clone();
        head.key_version = self.key_version;
        head.signature = sign_ed25519(&self.private_key, &self.id, &head.signing_preimage())
            .map_err(NexoraError::Crypto)?;
        Ok(head)
    }
}

/// `(signer_id, key_version)` → public key, as the verifier provisions it.
#[derive(Debug, Clone, Default)]
pub struct NexoraTrustAnchors {
    keys: HashMap<(String, u32), Vec<u8>>,
}

impl NexoraTrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, signer_id: &str, key_version: u32, public_key: &[u8]) -> Self {
        self.keys
            .insert((signer_id.to_string(), key_version), public_key.to_vec());
        self
    }

    pub fn get(&self, signer_id: &str, key_version: u32) -> Option<&[u8]> {
        self.keys
            .get(&(signer_id.to_string(), key_version))
            .map(Vec::as_slice)
    }

    /// Every anchor, in a deterministic order, so a written file is stable.
    pub fn entries(&self) -> Vec<(String, u32, Vec<u8>)> {
        let mut v: Vec<(String, u32, Vec<u8>)> = self
            .keys
            .iter()
            .map(|((id, ver), key)| (id.clone(), *ver, key.clone()))
            .collect();
        v.sort();
        v
    }
}

/// Verify a head against the verifier's anchors: version, anchored key,
/// signer identity, payload hash over the recomputed preimage, signature.
pub fn verify_signed_head(
    head: &SignedHead,
    anchors: &NexoraTrustAnchors,
) -> Result<(), NexoraError> {
    if head.version != NEXORA_VERSION {
        return Err(NexoraError::UnsupportedVersion(head.version));
    }
    let key = anchors
        .get(&head.signer_id, head.key_version)
        .ok_or_else(|| NexoraError::UntrustedKey {
            signer_id: head.signer_id.clone(),
            key_version: head.key_version,
        })?;
    if head.signature.signer_id != head.signer_id {
        return Err(NexoraError::SignerMismatch);
    }
    if head.signature.payload_hash != sha256(&head.signing_preimage()) {
        return Err(NexoraError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &head.signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(NexoraError::SignatureInvalid),
        Err(e) => Err(NexoraError::Crypto(e)),
    }
}

// ─── The log ───

/// An append-only log of records of stated kinds, with its Merkle
/// commitment and the last head issued for it.
///
/// Issuing a head does not change the committed history, only the chain
/// of heads, so heads are issued through a shared reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentLog {
    log_id: [u8; 16],
    tree: MerkleTree,
    kinds: Vec<LeafKind>,
    records: Vec<Vec<u8>>,
    last_head: RefCell<Option<SignedHead>>,
}

impl CommitmentLog {
    pub fn new(log_id: [u8; 16]) -> Self {
        Self {
            log_id,
            tree: MerkleTree::new(),
            kinds: Vec::new(),
            records: Vec::new(),
            last_head: RefCell::new(None),
        }
    }

    pub fn log_id(&self) -> [u8; 16] {
        self.log_id
    }

    pub fn size(&self) -> u64 {
        self.tree.size()
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// Append one record of one kind; returns its position.
    pub fn append(&mut self, kind: LeafKind, record: &[u8]) -> u64 {
        self.kinds.push(kind);
        self.records.push(record.to_vec());
        self.tree.append(kind, record)
    }

    pub fn kind(&self, index: u64) -> Option<LeafKind> {
        self.kinds.get(index as usize).copied()
    }

    pub fn record(&self, index: u64) -> Option<&[u8]> {
        self.records.get(index as usize).map(Vec::as_slice)
    }

    /// The last head issued for this log, if any.
    pub fn last_head(&self) -> Option<SignedHead> {
        self.last_head.borrow().clone()
    }

    /// Adopt a head as the predecessor of the next one (a log resumed from
    /// an anchor, or a test constructing a chain by hand).
    pub fn set_last_head(&mut self, head: SignedHead) {
        *self.last_head.borrow_mut() = Some(head);
    }

    /// Issue a signed head for the current state, chained to the last one.
    pub fn head(
        &self,
        signer: &NexoraSigner,
        issued_at_ms: u64,
    ) -> Result<SignedHead, NexoraError> {
        let prev_head = self
            .last_head
            .borrow()
            .as_ref()
            .map(SignedHead::digest)
            .unwrap_or([0u8; 32]);
        let unsigned = SignedHead {
            version: NEXORA_VERSION,
            log_id: self.log_id,
            size: self.size(),
            root: self.root(),
            prev_head,
            issued_at_ms,
            signer_id: signer.id().to_string(),
            key_version: signer.key_version(),
            signature: Signature {
                algorithm: aip_types::AlgorithmId::Ed25519,
                signer_id: signer.id().to_string(),
                timestamp: 0,
                nonce: [0u8; 16],
                payload_hash: [0u8; 32],
                signature_bytes: Vec::new(),
            },
        };
        let head = signer.resign(unsigned)?;
        *self.last_head.borrow_mut() = Some(head.clone());
        Ok(head)
    }

    /// A proof object for `index` under `head`, which must be this log's
    /// current state.
    pub fn proof_for(&self, index: u64, head: &SignedHead) -> Result<ProofObject, NexoraError> {
        if head.log_id != self.log_id {
            return Err(NexoraError::LogMismatch {
                expected: self.log_id,
                got: head.log_id,
            });
        }
        if head.size != self.size() || head.root != self.root() {
            return Err(NexoraError::SizeMismatch {
                proof: self.size(),
                head: head.size,
            });
        }
        let inclusion = self.tree.inclusion_proof(index)?;
        Ok(ProofObject {
            version: NEXORA_VERSION,
            log_id: self.log_id,
            head: head.clone(),
            kind: self.kinds[index as usize],
            record: self.records[index as usize].clone(),
            inclusion,
        })
    }

    /// Consistency proof from the log's state at `old_size` to now.
    pub fn consistency_since(&self, old_size: u64) -> Result<ConsistencyProof, NexoraError> {
        Ok(self.tree.consistency_proof(old_size)?)
    }
}

// ─── Proof objects and the offline verifier ───

/// Everything an offline party needs to check that `record` of `kind` was
/// committed at `inclusion.index` under `head`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofObject {
    pub version: u16,
    pub log_id: [u8; 16],
    pub head: SignedHead,
    pub kind: LeafKind,
    pub record: Vec<u8>,
    pub inclusion: InclusionProof,
}

impl ProofObject {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, PROOF_DOMAIN);
        put_u16(&mut buf, self.version);
        buf.extend_from_slice(&self.log_id);
        buf.extend_from_slice(&self.head.digest());
        put_u8(&mut buf, self.kind.code());
        put_bytes(&mut buf, &self.record);
        put_u64(&mut buf, self.inclusion.index);
        put_u64(&mut buf, self.inclusion.size);
        put_u32(&mut buf, self.inclusion.path.len() as u32);
        for h in &self.inclusion.path {
            buf.extend_from_slice(h);
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

/// What an offline verifier can say after [`verify_proof`]: where bytes
/// with this digest were committed, and under which head. Nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedInclusion {
    pub log_id: [u8; 16],
    pub size: u64,
    pub root: [u8; 32],
    pub index: u64,
    pub kind: LeafKind,
    pub record_digest: [u8; 32],
    pub head_digest: [u8; 32],
}

/// Verify a proof object with nothing but the verifier's anchors.
pub fn verify_proof(
    proof: &ProofObject,
    anchors: &NexoraTrustAnchors,
) -> Result<VerifiedInclusion, NexoraError> {
    if proof.version != NEXORA_VERSION {
        return Err(NexoraError::UnsupportedVersion(proof.version));
    }
    verify_signed_head(&proof.head, anchors)?;
    if proof.log_id != proof.head.log_id {
        return Err(NexoraError::LogMismatch {
            expected: proof.log_id,
            got: proof.head.log_id,
        });
    }
    if proof.inclusion.size != proof.head.size {
        return Err(NexoraError::SizeMismatch {
            proof: proof.inclusion.size,
            head: proof.head.size,
        });
    }
    let leaf = leaf_hash(proof.kind, &proof.record);
    if !verify_inclusion(&leaf, &proof.inclusion, &proof.head.root) {
        return Err(NexoraError::LeafNotIncluded);
    }
    Ok(VerifiedInclusion {
        log_id: proof.log_id,
        size: proof.head.size,
        root: proof.head.root,
        index: proof.inclusion.index,
        kind: proof.kind,
        record_digest: sha256(&proof.record),
        head_digest: proof.head.digest(),
    })
}

// ─── The offline party's memory ───

/// What advancing a tracker established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advance {
    /// The first head accepted for this log.
    First,
    /// The accepted head grew from `from` to `to` leaves, consistently.
    Extended { from: u64, to: u64 },
    /// The head already accepted, offered again: nothing changed.
    Same,
}

/// The last head an offline party accepted for one log, and the only way
/// to move it: forward, with a consistency proof from the accepted size.
#[derive(Debug, Clone, Default)]
pub struct HeadTracker {
    last: Option<SignedHead>,
}

impl HeadTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn head(&self) -> Option<&SignedHead> {
        self.last.as_ref()
    }

    pub fn size(&self) -> Option<u64> {
        self.last.as_ref().map(|h| h.size)
    }

    pub fn advance(
        &mut self,
        head: &SignedHead,
        consistency: Option<&ConsistencyProof>,
        anchors: &NexoraTrustAnchors,
    ) -> Result<Advance, NexoraError> {
        verify_signed_head(head, anchors)?;
        let Some(last) = &self.last else {
            self.last = Some(head.clone());
            return Ok(Advance::First);
        };
        if head.log_id != last.log_id {
            return Err(NexoraError::LogMismatch {
                expected: last.log_id,
                got: head.log_id,
            });
        }
        if head.digest() == last.digest() {
            return Ok(Advance::Same);
        }
        if head.size < last.size {
            return Err(NexoraError::Rollback {
                from: last.size,
                to: head.size,
            });
        }
        if head.size == last.size {
            return Err(NexoraError::Fork { size: head.size });
        }
        if head.prev_head != last.digest() {
            return Err(NexoraError::HeadChainBroken);
        }
        let Some(proof) = consistency else {
            return Err(NexoraError::ConsistencyMissing);
        };
        if proof.old_size != last.size
            || proof.new_size != head.size
            || !verify_consistency(&last.root, &head.root, proof)
        {
            return Err(NexoraError::ConsistencyInvalid);
        }
        let from = last.size;
        self.last = Some(head.clone());
        Ok(Advance::Extended {
            from,
            to: head.size,
        })
    }
}

// ─── Anchoring ───

/// Where heads go so that a party outside NEXORA holds them. A sink that
/// merely stores is enough for a verifier to refuse truncation later; what
/// makes it *external* is where it runs, which is an operator's decision.
pub trait AnchorSink {
    fn publish(&mut self, head: &SignedHead) -> Result<(), NexoraError>;
}

/// An in-memory sink: the shape of an anchor, not its independence.
#[derive(Debug, Clone, Default)]
pub struct MemoryAnchor {
    heads: Vec<SignedHead>,
}

impl MemoryAnchor {
    pub fn heads(&self) -> &[SignedHead] {
        &self.heads
    }

    /// Publish only a head that verifies against `anchors`.
    pub fn publish_verified(
        &mut self,
        head: &SignedHead,
        anchors: &NexoraTrustAnchors,
    ) -> Result<(), NexoraError> {
        verify_signed_head(head, anchors)?;
        self.publish(head)
    }
}

impl AnchorSink for MemoryAnchor {
    fn publish(&mut self, head: &SignedHead) -> Result<(), NexoraError> {
        self.heads.push(head.clone());
        Ok(())
    }
}
