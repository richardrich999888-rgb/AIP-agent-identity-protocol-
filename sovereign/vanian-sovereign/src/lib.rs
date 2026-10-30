//! VANIAN Sovereign AI OS — slice 1.
//!
//! One vertical path, every hop local:
//!
//! ```text
//! principal ──► corpus (SQLite FTS5, ACL in the WHERE clause)
//!           ──► prompt (deterministic, numbered sources)
//!           ──► inference (llama.cpp on a loopback IP literal only)
//!           ──► citation check (cited ids ⊆ retrieved ids)
//!
//! agent ──► AIP decision point ──► ExpectedExecution (signed)
//!       ──► runner re-derives parameter digest, refuses on mismatch
//!       ──► sandbox (new user+net namespace, empty env, hard timeout)
//!       ──► RunRecord (runner-signed) ──► offline verifier
//! ```
//!
//! # Layering
//!
//! - [`domain`] and [`policy`]: pure types and decisions, no IO.
//! - [`ports`]: the traits the orchestration depends on.
//! - [`adapters`]: SQLite, HTTP-to-loopback, namespace sandbox.
//! - [`rag`] and [`agent`]: orchestration over ports.
//!
//! # What this slice does not claim
//!
//! The run record is signed by the runner, a component that sits beside the
//! workload. It is **not** independent kernel observation; every record
//! carries [`agent::evidence::Observation::CannotProve`] until a Sniffer Dog
//! observer is attached, and the verifier never returns a verified-execution
//! verdict.

pub mod adapters;
pub mod agent;
pub mod app;
pub mod domain;
pub mod policy;
pub mod ports;
pub mod rag;
