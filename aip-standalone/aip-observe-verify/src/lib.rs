//! `aip-observe-verify` — the auditor's side of the observer evidence chain.
//!
//! # Why this crate exists
//!
//! The Phase 1 exit gate reads: *a real agent process is observed; its batch
//! is signed by a collector on a different host; **the verifier accepts it
//! offline**.* The workspace already shipped [`aip_verify`][1] for
//! `EvidencePacket`s, but nothing an auditor could run against the
//! **observer's** archives — the attested batches and the signed health
//! records the collector writes. Verification existed only as library calls
//! inside the project's own tests, which is verification the project does to
//! itself, not verification an outside party can perform.
//!
//! [1]: ../aip-verify
//!
//! # What "offline" means here
//!
//! Two files and a public key. No network, no collector, no service, and
//! nothing supplied by the party being audited except the evidence itself
//! and the anchor, which the institution holds independently. The verifier
//! opens no socket and reads no environment.
//!
//! # What a pass means, and what it does not
//!
//! A pass means: *the anchored observer key signed exactly these records, in
//! this order, with each record's `prev_head` equal to the recomputed head
//! of the one before it.* Heads are **recomputed from the record**, never
//! read from a field, so there is no supplied hash to trust.
//!
//! It does not mean the observations are true. A host with root can lie to
//! its own probe; the collector attests what it received, not what happened.
//! It also does not mean the window was continuously covered — that is what
//! the health records state, and they state it including the times the
//! observer could not see (`IntegrityUnknown`, no coverage).
//!
//! # Structure
//!
//! Core logic here is pure: it takes parsed records and anchors and returns a
//! [`report::ChainReport`]. All IO — reading files, printing, the exit code —
//! lives in `main.rs`. The two are separable so the core is testable without
//! a filesystem.

pub mod cli;
pub mod report;
pub mod verify;
