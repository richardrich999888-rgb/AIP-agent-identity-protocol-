//! `aip-sentinel-feed` — render AIP's attested kernel evidence as an effect
//! log that an out-of-band reconciler can tail.
//!
//! ```text
//!   AttestedBatch*  (collector-signed, kernel-derived)
//!         │
//!         ├─ verify under the observer's anchor        ← fail closed here
//!         │
//!         ├─ aip-reconcile: derive_executions / derive_transitions / derive_sends
//!         │
//!         └─ effect log (JSONL)  ──▶  an independent reconciler's sensor input
//! ```
//!
//! # Why this crate exists
//!
//! Everything else in this system is *inline*: it proves what went through the
//! funnel. It has no answer for an agent that declines to use the funnel at
//! all, and a stricter funnel does not help, because a stricter funnel is
//! still one an agent can route around. Catching that needs reconciliation
//! against a sensor outside the governed channel.
//!
//! A reconciler for exactly that exists in this repository
//! (`orbitaltrust-accountability/rust/ot-sentinel`). Its effect sensor reads
//! a JSONL log of process spawns and network egress — and, in its own words,
//! that detector "had nothing feeding it". The logs it was designed to tail
//! are written by the very components being watched: a tool server's access
//! log is the tool server's account of itself. Self-reported evidence is the
//! weakest possible root for a bypass detector.
//!
//! AIP observes spawns and connections **from the kernel**, binds them to
//! process instances through pidfd, and has a collector off the host sign the
//! result. This crate hands that evidence to the reconciler, replacing the
//! weakest trust root in the detection path with the strongest one available.
//!
//! # The boundary is a file, deliberately
//!
//! This repository holds two hash-chained evidence constructions that are not
//! byte-compatible; `docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md` records the
//! decision to keep them apart. This crate does **not** link the reconciler
//! and does not depend on its chain. It writes a file; the reconciler tails a
//! file. That is the whole coupling.
//!
//! The conflict between the two constructions is on the *evidence* side —
//! sealed packets and the chain under them. This feed touches only the
//! *observation* side, which carries no chain at all: it is a list of things a
//! sensor saw. So no packet ever crosses formats, no record is re-sealed, and
//! no authority is asked to vouch for another's bytes — which is precisely
//! what the ADR rejected a translation layer for.
//!
//! # What this is not
//!
//! It is **not independent corroboration**. The reconciler on the far side of
//! this file was written by the same people as AIP. Corroboration means an
//! observer built by someone else — that is what `aip-corroborate` (bpftrace,
//! auditd) and `aip-spiffe` (SPIRE) are for. This crate completes an
//! architecture; it does not validate one, and it must not be described as
//! though it did.
//!
//! # Guarantees
//!
//! * **Nothing is rendered from evidence that did not verify.** The binary
//!   verifies the archive under the observer's anchor and produces no output
//!   at all if that fails.
//! * **Nothing is approximated.** An event that cannot be rendered honestly is
//!   dropped and counted in [`ScopeReport`], so a coverage limit is visible
//!   rather than silently filling with plausible-looking records.
//! * **The same input is the same bytes.** Records carry a total order over
//!   evidence position and serialise with sorted keys.

pub mod endpoint;
pub mod feed;
pub mod record;

pub use feed::{feed, Feed, ScopeReport};
pub use record::{EffectDetail, EffectKind, EffectRecord};
