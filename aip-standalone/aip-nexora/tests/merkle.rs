//! Gate 6 — the Merkle commitment layer, RED.
//!
//! A commitment is only a commitment if it binds one ordered set of
//! records and lets a party who holds nothing but a root check that a
//! record is in it and that a later root extends an earlier one. The
//! repository has had `merkle_leaf` / `merkle_internal` / `merkle_empty`
//! since Stage 0 and, per I15, nothing else: no tree, no proof, no
//! verifier. This suite defines them:
//!
//! - leaves are domain-separated by **what kind of record** they commit
//!   to, so a batch cannot be presented as a reconciliation record;
//! - the tree is append-only in the RFC 6962 shape (the root of `n`
//!   leaves is `internal(root(first 2^k), root(rest))` with `2^k` the
//!   largest power of two below `n`), so that a root over an earlier
//!   prefix can be shown to be extended by a later root;
//! - an inclusion proof is bound to an index **and a tree size**, so it
//!   cannot be replayed against a later root or transplanted to another
//!   tree; a consistency proof refuses to run backwards, so a rollback is
//!   a refusal and a fork is two roots that no proof reconciles.
//!
//! The adversarial cases the mandate names — changed, swapped, omitted and
//! duplicated leaves; a changed root; proof transplantation; cross-domain;
//! rollback; fork; replay — are each one test below.

use aip_crypto::{merkle_empty, merkle_internal, merkle_leaf, sha256};
use aip_nexora::merkle::*;

fn rec(i: u32) -> Vec<u8> {
    format!("reconciliation-record-{i}").into_bytes()
}

fn tree_of(n: u32) -> MerkleTree {
    let mut t = MerkleTree::new();
    for i in 0..n {
        t.append(LeafKind::Reconciliation, &rec(i));
    }
    t
}

fn flip(mut h: [u8; 32]) -> [u8; 32] {
    h[0] ^= 0x01;
    h
}

// ═══ Shape ═══

#[test]
fn m01_the_empty_tree_and_the_single_leaf() {
    let t = MerkleTree::new();
    assert_eq!(t.size(), 0);
    assert_eq!(
        t.root(),
        merkle_empty(),
        "the empty root is the repository's"
    );
    let mut t = MerkleTree::new();
    let pos = t.append(LeafKind::Reconciliation, &rec(0));
    assert_eq!(pos, 0);
    assert_eq!(t.size(), 1);
    assert_eq!(t.root(), leaf_hash(LeafKind::Reconciliation, &rec(0)));
    assert_eq!(t.leaf(0), Some(t.root()));
    assert_eq!(t.leaf(1), None);
}

#[test]
fn m02_the_root_has_the_rfc_6962_shape_over_the_repository_primitives() {
    let l: Vec<[u8; 32]> = (0..5)
        .map(|i| leaf_hash(LeafKind::Reconciliation, &rec(i)))
        .collect();
    let t = tree_of(5);
    // MTH(5) = internal(MTH(first 4), MTH(last 1)); MTH(4) = internal(internal(l0,l1), internal(l2,l3)).
    let left = merkle_internal(
        &merkle_internal(&l[0], &l[1]),
        &merkle_internal(&l[2], &l[3]),
    );
    assert_eq!(t.root(), merkle_internal(&left, &l[4]));
    assert_eq!(root_of(&l), t.root());
    // Three leaves: internal(internal(l0,l1), l2).
    assert_eq!(
        tree_of(3).root(),
        merkle_internal(&merkle_internal(&l[0], &l[1]), &l[2])
    );
}

#[test]
fn m03_leaves_are_domain_separated_by_kind_and_never_raw() {
    let r = rec(7);
    let a = leaf_hash(LeafKind::Reconciliation, &r);
    let b = leaf_hash(LeafKind::AttestedBatch, &r);
    assert_ne!(
        a, b,
        "the same bytes as a batch and as a record are different leaves"
    );
    assert_ne!(a, merkle_leaf(&r), "a leaf is never the bare record hash");
    assert_ne!(a, sha256(&r));
    // Explicit domain and kind code inside the preimage.
    let mut pre = Vec::new();
    aip_types::canonical::put_domain(&mut pre, LEAF_DOMAIN);
    aip_types::canonical::put_u8(&mut pre, LeafKind::Reconciliation.code());
    aip_types::canonical::put_bytes(&mut pre, &r);
    assert_eq!(a, merkle_leaf(&pre));
    let mut codes: Vec<u8> = LeafKind::ALL.iter().map(|k| k.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), LeafKind::ALL.len());
    assert!(LEAF_DOMAIN.starts_with("SYNTRIASS/NEXORA/"));
}

// ═══ Inclusion ═══

#[test]
fn m04_every_leaf_of_every_small_tree_is_provably_included() {
    for n in 1..=20u32 {
        let t = tree_of(n);
        let root = t.root();
        for i in 0..n as u64 {
            let p = t.inclusion_proof(i).unwrap();
            assert_eq!(p.index, i);
            assert_eq!(p.size, n as u64);
            assert!(
                verify_inclusion(&t.leaf(i).unwrap(), &p, &root),
                "n={n} i={i}"
            );
        }
        assert!(matches!(
            t.inclusion_proof(n as u64),
            Err(MerkleError::IndexOutOfRange { .. })
        ));
    }
}

#[test]
fn m05_a_changed_leaf_is_not_included() {
    let t = tree_of(9);
    let p = t.inclusion_proof(4).unwrap();
    let altered = leaf_hash(LeafKind::Reconciliation, b"reconciliation-record-4 ");
    assert!(!verify_inclusion(&altered, &p, &t.root()));
    let other_kind = leaf_hash(LeafKind::AttestedBatch, &rec(4));
    assert!(
        !verify_inclusion(&other_kind, &p, &t.root()),
        "cross-domain"
    );
}

#[test]
fn m06_swapped_leaves_change_the_root_and_invalidate_the_old_proofs() {
    let a = tree_of(8);
    let mut b = MerkleTree::new();
    for i in [0u32, 1, 2, 4, 3, 5, 6, 7] {
        b.append(LeafKind::Reconciliation, &rec(i));
    }
    assert_ne!(a.root(), b.root());
    let p3 = a.inclusion_proof(3).unwrap();
    assert!(!verify_inclusion(&a.leaf(3).unwrap(), &p3, &b.root()));
    assert!(!verify_inclusion(&b.leaf(3).unwrap(), &p3, &b.root()));
}

#[test]
fn m07_an_omitted_leaf_changes_the_root_and_nothing_from_the_full_tree_verifies() {
    let full = tree_of(10);
    let mut short = MerkleTree::new();
    for i in (0..10u32).filter(|i| *i != 6) {
        short.append(LeafKind::Reconciliation, &rec(i));
    }
    assert_ne!(full.root(), short.root());
    for i in 0..10u64 {
        let p = full.inclusion_proof(i).unwrap();
        assert!(!verify_inclusion(&full.leaf(i).unwrap(), &p, &short.root()));
    }
}

#[test]
fn m08_a_duplicated_record_is_two_positions_and_a_proof_names_one() {
    let mut t = tree_of(5);
    let first = t.append(LeafKind::Reconciliation, &rec(2));
    assert_eq!(first, 5);
    assert_eq!(t.leaf(2), t.leaf(5), "same bytes, same leaf hash");
    let p2 = t.inclusion_proof(2).unwrap();
    let mut p_as_5 = p2.clone();
    p_as_5.index = 5;
    assert!(verify_inclusion(&t.leaf(2).unwrap(), &p2, &t.root()));
    assert!(
        !verify_inclusion(&t.leaf(5).unwrap(), &p_as_5, &t.root()),
        "a proof for position 2 does not prove position 5"
    );
    let p5 = t.inclusion_proof(5).unwrap();
    assert!(verify_inclusion(&t.leaf(5).unwrap(), &p5, &t.root()));
    assert_ne!(p2.path, p5.path);
}

#[test]
fn m09_a_changed_root_verifies_nothing() {
    let t = tree_of(12);
    let p = t.inclusion_proof(7).unwrap();
    assert!(verify_inclusion(&t.leaf(7).unwrap(), &p, &t.root()));
    assert!(!verify_inclusion(&t.leaf(7).unwrap(), &p, &flip(t.root())));
    assert!(!verify_inclusion(&t.leaf(7).unwrap(), &p, &merkle_empty()));
}

#[test]
fn m10_a_proof_cannot_be_transplanted_to_another_tree_holding_the_same_leaf() {
    let a = tree_of(6);
    let mut b = MerkleTree::new();
    for i in [100u32, 3, 200] {
        b.append(LeafKind::Reconciliation, &rec(i));
    }
    let leaf3 = leaf_hash(LeafKind::Reconciliation, &rec(3));
    assert_eq!(a.leaf(3), Some(leaf3));
    assert_eq!(b.leaf(1), Some(leaf3));
    let pa = a.inclusion_proof(3).unwrap();
    assert!(!verify_inclusion(&leaf3, &pa, &b.root()));
    let pb = b.inclusion_proof(1).unwrap();
    assert!(!verify_inclusion(&leaf3, &pb, &a.root()));
}

// ═══ Consistency ═══

#[test]
fn m11_every_prefix_root_is_shown_extended_by_every_later_root() {
    let mut roots = vec![MerkleTree::new().root()];
    let mut t = MerkleTree::new();
    for i in 0..16u32 {
        t.append(LeafKind::Reconciliation, &rec(i));
        roots.push(t.root());
    }
    for old in 0..=16u64 {
        let p = t.consistency_proof(old).unwrap();
        assert_eq!((p.old_size, p.new_size), (old, 16));
        assert!(
            verify_consistency(&roots[old as usize], &t.root(), &p),
            "old={old}"
        );
        // Against the wrong old root the proof fails.
        if old > 0 {
            assert!(!verify_consistency(&roots[old as usize - 1], &t.root(), &p));
        }
    }
    // Intermediate sizes too.
    let mut u = tree_of(11);
    let p = u.consistency_proof(5).unwrap();
    assert!(verify_consistency(&roots[5], &u.root(), &p));
    u.append(LeafKind::Reconciliation, &rec(11));
    assert!(
        !verify_consistency(&roots[5], &u.root(), &p),
        "the proof is bound to the new size"
    );
}

#[test]
fn m12_a_rollback_is_refused_never_proven() {
    let t = tree_of(9);
    assert!(matches!(
        t.consistency_proof(10),
        Err(MerkleError::SizeOutOfRange { .. })
    ));
    let bigger = tree_of(12);
    let p = bigger.consistency_proof(9).unwrap();
    // A verifier that holds size 12 and is offered size 9: the proof
    // direction is old→new only; a backwards claim verifies nothing.
    let backwards = ConsistencyProof {
        old_size: 12,
        new_size: 9,
        path: p.path.clone(),
    };
    assert!(!verify_consistency(&bigger.root(), &t.root(), &backwards));
    assert!(verify_consistency(&t.root(), &bigger.root(), &p));
}

#[test]
fn m13_a_fork_is_two_roots_at_one_size_that_no_proof_reconciles() {
    let a = tree_of(5);
    let mut b = tree_of(4);
    b.append(LeafKind::Reconciliation, b"a different fifth record");
    assert_eq!(a.size(), b.size());
    assert_ne!(a.root(), b.root());
    let prefix = tree_of(3).root();
    let pa = a.consistency_proof(3).unwrap();
    let pb = b.consistency_proof(3).unwrap();
    assert!(verify_consistency(&prefix, &a.root(), &pa));
    assert!(verify_consistency(&prefix, &b.root(), &pb));
    assert!(
        !verify_consistency(&prefix, &b.root(), &pa),
        "A's proof does not reach B's root"
    );
    assert!(!verify_consistency(&prefix, &a.root(), &pb));
    // Equal sizes: only identical roots are consistent.
    let same = ConsistencyProof {
        old_size: 5,
        new_size: 5,
        path: vec![],
    };
    assert!(verify_consistency(&a.root(), &a.root(), &same));
    assert!(!verify_consistency(&a.root(), &b.root(), &same));
}

#[test]
fn m14_an_inclusion_proof_is_bound_to_a_size_and_cannot_be_replayed_against_a_later_root() {
    let mut t = tree_of(7);
    let p = t.inclusion_proof(2).unwrap();
    let leaf = t.leaf(2).unwrap();
    let root7 = t.root();
    t.append(LeafKind::Reconciliation, &rec(7));
    assert!(verify_inclusion(&leaf, &p, &root7));
    assert!(
        !verify_inclusion(&leaf, &p, &t.root()),
        "size 7 proof, size 8 root"
    );
    let mut resized = p.clone();
    resized.size = 8;
    assert!(
        !verify_inclusion(&leaf, &resized, &t.root()),
        "a relabelled size is not a new proof"
    );
    assert!(verify_inclusion(
        &leaf,
        &t.inclusion_proof(2).unwrap(),
        &t.root()
    ));
}

#[test]
fn m15_malformed_proofs_verify_nothing() {
    let t = tree_of(6);
    let p = t.inclusion_proof(1).unwrap();
    let leaf = t.leaf(1).unwrap();
    let mut short = p.clone();
    short.path.pop();
    assert!(!verify_inclusion(&leaf, &short, &t.root()));
    let mut long = p.clone();
    long.path.push([0u8; 32]);
    assert!(!verify_inclusion(&leaf, &long, &t.root()));
    let mut zero = p.clone();
    zero.size = 0;
    assert!(!verify_inclusion(&leaf, &zero, &t.root()));
    let mut oob = p.clone();
    oob.index = 6;
    assert!(!verify_inclusion(&leaf, &oob, &t.root()));
    let c = t.consistency_proof(2).unwrap();
    let mut c_short = c.clone();
    c_short.path.pop();
    assert!(!verify_consistency(&tree_of(2).root(), &t.root(), &c_short));
    let mut c_long = c.clone();
    c_long.path.push([0u8; 32]);
    assert!(!verify_consistency(&tree_of(2).root(), &t.root(), &c_long));
    assert!(
        !verify_consistency(
            &tree_of(2).root(),
            &t.root(),
            &ConsistencyProof {
                old_size: 0,
                new_size: 6,
                path: vec![]
            }
        ),
        "size 0 → n needs no path but the old root must be the empty root"
    );
    assert!(verify_consistency(
        &merkle_empty(),
        &t.root(),
        &ConsistencyProof {
            old_size: 0,
            new_size: 6,
            path: vec![]
        }
    ));
}

#[test]
fn m16_the_tree_is_append_only_and_its_history_is_a_consistent_chain() {
    let mut t = MerkleTree::new();
    let mut prev_root = t.root();
    let mut prev_size = 0u64;
    let mut leaves = Vec::new();
    for i in 0..33u32 {
        let pos = t.append(LeafKind::Reconciliation, &rec(i));
        assert_eq!(pos, i as u64);
        leaves.push(t.leaf(pos).unwrap());
        for (j, l) in leaves.iter().enumerate() {
            assert_eq!(t.leaf(j as u64), Some(*l), "earlier leaves never change");
        }
        let p = t.consistency_proof(prev_size).unwrap();
        assert!(verify_consistency(&prev_root, &t.root(), &p));
        prev_root = t.root();
        prev_size = t.size();
    }
    // Serialisable proofs (they travel to an offline verifier).
    let p = t.inclusion_proof(20).unwrap();
    let json = serde_json::to_string(&p).unwrap();
    let back: InclusionProof = serde_json::from_str(&json).unwrap();
    assert!(verify_inclusion(&t.leaf(20).unwrap(), &back, &t.root()));
}
