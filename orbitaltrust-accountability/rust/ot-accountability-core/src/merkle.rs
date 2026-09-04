//! Merkle root over an execution evidence set.
//!
//! The hash chain proves *order and integrity*; the Merkle root gives a
//! single commitment over the *set* that a certifier can publish and a
//! verifier can recompute without walking the chain — the digest a signed
//! after-action report or a transparency log would carry.
//!
//! Construction: leaves are the packets' own sealed hashes (already
//! SHA-256, already canonical). Interior nodes are
//! `SHA-256(left + right)` over the hex strings — the same string-domain
//! hashing the rest of the stack uses, so a JavaScript consumer reproduces
//! it with `crypto.subtle` alone. An odd node is promoted unchanged (no
//! duplication, so a single-leaf tree's root is the leaf itself and the
//! CVE-2012-2459-style duplicate ambiguity cannot arise). An empty set
//! commits to the published genesis constant.

use crate::{sha256_hex, GENESIS_HASH};

/// Computes the Merkle root of an ordered set of hex-string leaf hashes.
pub fn merkle_root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return GENESIS_HASH.to_string();
    }
    let mut level: Vec<String> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => next.push(sha256_hex(&format!("{left}{right}"))),
                [odd] => next.push(odd.clone()),
                _ => unreachable!("chunks(2) yields one- or two-element slices"),
            }
        }
        level = next;
    }
    level
        .into_iter()
        .next()
        .expect("non-empty level reduces to a root")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set_commits_to_genesis() {
        assert_eq!(merkle_root(&[]), GENESIS_HASH);
    }

    #[test]
    fn single_leaf_is_its_own_root() {
        let leaf = sha256_hex("packet-1");
        assert_eq!(merkle_root(std::slice::from_ref(&leaf)), leaf);
    }

    #[test]
    fn two_leaves_hash_pairwise() {
        let a = sha256_hex("a");
        let b = sha256_hex("b");
        assert_eq!(
            merkle_root(&[a.clone(), b.clone()]),
            sha256_hex(&format!("{a}{b}"))
        );
    }

    #[test]
    fn odd_leaf_promotes_unchanged() {
        let a = sha256_hex("a");
        let b = sha256_hex("b");
        let c = sha256_hex("c");
        let ab = sha256_hex(&format!("{a}{b}"));
        assert_eq!(
            merkle_root(&[a, b, c.clone()]),
            sha256_hex(&format!("{ab}{c}")),
        );
    }

    #[test]
    fn any_leaf_change_changes_the_root() {
        let leaves: Vec<String> = (0..5).map(|i| sha256_hex(&format!("p{i}"))).collect();
        let root = merkle_root(&leaves);
        let mut forged = leaves.clone();
        forged[3] = sha256_hex("forged");
        assert_ne!(merkle_root(&forged), root);
    }
}
