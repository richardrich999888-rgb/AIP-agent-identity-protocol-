//! Gate 6 — the Merkle commitment: an append-only tree over
//! domain-separated leaves, with inclusion and consistency proofs an
//! offline verifier checks against roots it obtained elsewhere.
//!
//! **Shape.** RFC 6962 / RFC 9162: the root of `n > 1` leaves is
//! `internal(root(first k), root(rest))` with `k` the largest power of two
//! strictly below `n`; the root of one leaf is that leaf's hash; the root of
//! no leaves is the repository's `merkle_empty()`. Hashing uses the
//! repository's `merkle_leaf` (`0x00 ‖ …`) and `merkle_internal`
//! (`0x01 ‖ l ‖ r`), so a leaf can never be mistaken for an internal node.
//!
//! **Leaves.** A leaf commits to one record of one kind. Its preimage is
//! `LEAF_DOMAIN ‖ kind code ‖ length-prefixed record bytes`, so the same
//! bytes committed as a reconciliation record and as an attested batch are
//! different leaves, and a bare record hash is never a leaf.
//!
//! **Proofs.** An inclusion proof names an index and the tree size it was
//! made at; it verifies only against the root of exactly that size, so it
//! cannot be replayed against a later root or moved to another tree. A
//! consistency proof shows that the root at an earlier size is a prefix of
//! the root at a later size; it is produced forward only, and two roots at
//! one size are consistent only if they are equal — a rollback is a
//! refusal, a fork is two roots no proof reconciles.
//!
//! **What this is not.** A tree in memory is not a commitment anyone else
//! can rely on: without a signed, externally anchored head a prefix of the
//! history verifies as well as the whole (`NEXORA_BOUNDARY.md` §5). Signed
//! heads and proof objects are Gate 7.

use aip_crypto::{merkle_empty, merkle_internal, merkle_leaf};
use aip_types::canonical::{put_bytes, put_domain, put_u8};
use serde::{Deserialize, Serialize};

/// Domain tag inside every leaf preimage.
pub const LEAF_DOMAIN: &str = "SYNTRIASS/NEXORA/LEAF/v1";

/// What kind of record a leaf commits to. The code is inside the preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeafKind {
    /// A `Reconciliation` record's canonical bytes.
    Reconciliation,
    /// An `AttestedBatch`'s canonical bytes.
    AttestedBatch,
    /// A `SignedSensorHealth`'s canonical bytes.
    SignedHealth,
    /// A `Warrant`'s canonical bytes.
    Warrant,
    /// An `ExpectedExecution`'s canonical bytes.
    Expectation,
    /// A `SignedContinuityReport`'s canonical bytes (Gate 8 of the
    /// completion mandate).
    ContinuityReport,
    /// A `ContainmentRecord`'s canonical bytes (Skill 9).
    ContainmentRecord,
    /// A `NexoraProof`'s canonical bytes (Skill 10).
    ProofBundle,
    /// An `AiriEvent`'s signing preimage (AI-stack extension).
    ///
    /// Committing the *preimage* rather than a re-serialisation means the
    /// committed bytes are exactly the bytes the agent signed, so a verifier
    /// checks one artefact rather than trusting a round-trip. The kind code
    /// keeps an AIRI event from being replayed as any other leaf.
    AiriEvent,
}

impl LeafKind {
    pub fn code(&self) -> u8 {
        match self {
            LeafKind::Reconciliation => 0x01,
            LeafKind::AttestedBatch => 0x02,
            LeafKind::SignedHealth => 0x03,
            LeafKind::Warrant => 0x04,
            LeafKind::Expectation => 0x05,
            LeafKind::ContinuityReport => 0x06,
            LeafKind::ContainmentRecord => 0x07,
            LeafKind::ProofBundle => 0x08,
            LeafKind::AiriEvent => 0x09,
        }
    }

    /// Codes 0x01–0x05 are frozen: a leaf committed before Skill 10 keeps
    /// verifying. New kinds append.
    pub const ALL: [LeafKind; 9] = [
        LeafKind::Reconciliation,
        LeafKind::AttestedBatch,
        LeafKind::SignedHealth,
        LeafKind::Warrant,
        LeafKind::Expectation,
        LeafKind::ContinuityReport,
        LeafKind::ContainmentRecord,
        LeafKind::ProofBundle,
        LeafKind::AiriEvent,
    ];
}

/// The leaf hash of one record of one kind.
pub fn leaf_hash(kind: LeafKind, record: &[u8]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(LEAF_DOMAIN.len() + record.len() + 16);
    put_domain(&mut pre, LEAF_DOMAIN);
    put_u8(&mut pre, kind.code());
    put_bytes(&mut pre, record);
    merkle_leaf(&pre)
}

/// Largest power of two strictly below `n` (`n ≥ 2`).
fn split_point(n: u64) -> u64 {
    let mut k = 1u64;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// RFC 6962 tree head over already-hashed leaves.
pub fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => merkle_empty(),
        1 => leaves[0],
        n => {
            let k = split_point(n as u64) as usize;
            merkle_internal(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    IndexOutOfRange { index: u64, size: u64 },
    SizeOutOfRange { requested: u64, size: u64 },
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for MerkleError {}

/// Proof that the leaf at `index` is in the tree of `size` leaves whose
/// root the verifier holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub index: u64,
    pub size: u64,
    pub path: Vec<[u8; 32]>,
}

/// Proof that the tree of `old_size` leaves is a prefix of the tree of
/// `new_size` leaves, given both roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub path: Vec<[u8; 32]>,
}

/// An append-only Merkle tree over leaf hashes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Append one record of one kind; returns its position.
    pub fn append(&mut self, kind: LeafKind, record: &[u8]) -> u64 {
        self.append_hash(leaf_hash(kind, record))
    }

    /// Append an already-computed leaf hash; returns its position.
    pub fn append_hash(&mut self, leaf: [u8; 32]) -> u64 {
        self.leaves.push(leaf);
        (self.leaves.len() - 1) as u64
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn leaf(&self, index: u64) -> Option<[u8; 32]> {
        self.leaves.get(index as usize).copied()
    }

    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    pub fn root(&self) -> [u8; 32] {
        root_of(&self.leaves)
    }

    /// Root of the first `size` leaves.
    pub fn root_at(&self, size: u64) -> Result<[u8; 32], MerkleError> {
        if size > self.size() {
            return Err(MerkleError::SizeOutOfRange {
                requested: size,
                size: self.size(),
            });
        }
        Ok(root_of(&self.leaves[..size as usize]))
    }

    /// RFC 6962 audit path for `index` in the current tree.
    pub fn inclusion_proof(&self, index: u64) -> Result<InclusionProof, MerkleError> {
        if index >= self.size() {
            return Err(MerkleError::IndexOutOfRange {
                index,
                size: self.size(),
            });
        }
        Ok(InclusionProof {
            index,
            size: self.size(),
            path: audit_path(index as usize, &self.leaves),
        })
    }

    /// RFC 6962 consistency proof from the tree of `old_size` leaves to the
    /// current tree. Forward only: an `old_size` beyond the tree is refused.
    pub fn consistency_proof(&self, old_size: u64) -> Result<ConsistencyProof, MerkleError> {
        if old_size > self.size() {
            return Err(MerkleError::SizeOutOfRange {
                requested: old_size,
                size: self.size(),
            });
        }
        let path = if old_size == 0 || old_size == self.size() {
            Vec::new()
        } else {
            subproof(old_size as usize, &self.leaves, true)
        };
        Ok(ConsistencyProof {
            old_size,
            new_size: self.size(),
            path,
        })
    }
}

fn audit_path(m: usize, d: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = d.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split_point(n as u64) as usize;
    if m < k {
        let mut p = audit_path(m, &d[..k]);
        p.push(root_of(&d[k..]));
        p
    } else {
        let mut p = audit_path(m - k, &d[k..]);
        p.push(root_of(&d[..k]));
        p
    }
}

fn subproof(m: usize, d: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
    let n = d.len();
    if m == n {
        return if b { Vec::new() } else { vec![root_of(d)] };
    }
    let k = split_point(n as u64) as usize;
    if m <= k {
        let mut p = subproof(m, &d[..k], b);
        p.push(root_of(&d[k..]));
        p
    } else {
        let mut p = subproof(m - k, &d[k..], false);
        p.push(root_of(&d[..k]));
        p
    }
}

/// RFC 9162 §2.1.3.2. `leaf` is the leaf hash; the proof must have been made
/// at exactly the size whose `root` is supplied.
pub fn verify_inclusion(leaf: &[u8; 32], proof: &InclusionProof, root: &[u8; 32]) -> bool {
    if proof.size == 0 || proof.index >= proof.size {
        return false;
    }
    let mut fn_ = proof.index;
    let mut sn = proof.size - 1;
    let mut r = *leaf;
    for p in &proof.path {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = merkle_internal(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = merkle_internal(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

/// RFC 9162 §2.1.4.2. Forward only; equal sizes are consistent only when
/// the roots are equal; size zero is consistent with anything only from
/// the empty root.
pub fn verify_consistency(
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    proof: &ConsistencyProof,
) -> bool {
    let (first, second) = (proof.old_size, proof.new_size);
    if first > second {
        return false;
    }
    if first == second {
        return proof.path.is_empty() && old_root == new_root;
    }
    if first == 0 {
        return proof.path.is_empty() && *old_root == merkle_empty();
    }
    if proof.path.is_empty() {
        return false;
    }
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(proof.path.len() + 1);
    if first.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(&proof.path);
    let mut fn_ = first - 1;
    let mut sn = second - 1;
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let mut fr = path[0];
    let mut sr = path[0];
    for c in &path[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = merkle_internal(c, &fr);
            sr = merkle_internal(c, &sr);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            sr = merkle_internal(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && fr == *old_root && sr == *new_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_point_is_the_largest_power_of_two_below_n() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);
    }

    #[test]
    fn leaf_preimage_is_length_prefixed_and_injective() {
        let a = leaf_hash(LeafKind::Warrant, b"ab");
        let b = leaf_hash(LeafKind::Warrant, b"a");
        assert_ne!(a, b);
        assert_ne!(leaf_hash(LeafKind::Warrant, b""), merkle_leaf(b""));
    }
}
