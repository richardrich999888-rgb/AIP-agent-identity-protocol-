//! Headless offline verifier for ASC SENTINEL certified mission dossiers.
//!
//! The browser console seals three hash chains — NEXORA lifecycle anchors,
//! AIP evidence packets, and the agent action ledger — and certifies the
//! exported dossier under one root digest. This crate recomputes all of it
//! from the exported file alone: no network, no IndexedDB, no trust in the
//! exporter. A `[PASS]` here is a mathematical statement about the bytes on
//! disk, which is exactly what an air-gapped audit cell needs.
//!
//! All cryptographic and chain logic lives in `ot-accountability-core` —
//! the same crate the browser consumes as WASM — so the CLI and the console
//! cannot disagree about a single byte. This crate owns only what a CLI
//! owns: the dossier schema walk, the finding report, and the exit code.

pub mod report;
pub mod verify;

pub use ot_accountability_core::{
    canonical_json, is_hex_digest, is_placeholder_digest, sha256_hex, GENESIS_HASH,
};
