//! SYNTRIASS intelligence runtime v0.1.
//!
//! ```text
//! request ─► principal (OS uid map, Sovereign) ─► authorized knowledge (ACL in SQL)
//!         ─► task features ─► controller: strategy A exact | B interpreter | C SLM
//!                                         | D larger local model | E capability | refuse
//!         ─► execute (scoped inference cache) ─► validate ─► grounded result
//!         ─► cost record + evidence; permitted experience feedback
//! ```
//!
//! Layering: [`domain`] and [`capability`] are pure; [`controller`] is a pure
//! decision over features; [`ports`] are the interfaces; [`adapters`] do IO;
//! [`app`] orchestrates. Reused unchanged from `vanian-sovereign`: corpus ACL,
//! grounded RAG and its validator, egress policy, AIP-authorized tool runner.
//!
//! Not claimed: independent execution observation (records carry
//! `CannotProve`), production readiness, GPU behaviour.

pub mod adapters;
pub mod app;
pub mod capability;
pub mod controller;
pub mod domain;
pub mod learning;
pub mod ports;
