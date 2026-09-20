//! `aip-collector` library — the collector daemon's building blocks, exposed so
//! integration tests exercise the real code (the allow-list, the runtime sink)
//! rather than a copy. The daemon entry point is `src/main.rs`.
//!
//! See `docs/pilot/PHASE1_DAEMONS.md` for the design and the trust model.

pub mod authority;
pub mod config;
pub mod noise_key;
pub mod sink;
