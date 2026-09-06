//! aip-nexora — the portable commitment layer (Skill 10).
//!
//! NEXORA commits to verified execution history; it does not authorize,
//! observe, reconcile, decide policy or contain (`NEXORA_BOUNDARY.md`).
//! Gate 6 builds the Merkle commitment underneath it: an append-only tree
//! over domain-separated leaves with inclusion and consistency proofs that
//! an offline verifier can check against a root it obtained elsewhere.
//! Signed heads, proof objects and the offline verifier are Gate 7.

pub mod merkle;
