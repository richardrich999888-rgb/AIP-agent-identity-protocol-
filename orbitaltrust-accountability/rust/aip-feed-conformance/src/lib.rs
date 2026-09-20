//! Conformance between the AIP effect feed and the reconciler that consumes it.
//!
//! This crate ships **no code**. It exists so that one claim is checked rather
//! than believed: that the JSONL `aip-sentinel-feed` writes is actually parsed
//! by `ot-sentinel`'s effect sensor, and actually drives its detectors.
//!
//! # Why it is a separate crate, and why it is here
//!
//! `docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md` (closed under option A) keeps two
//! hash-chained evidence constructions apart, and forbids any crate under
//! `aip-standalone/` or `aip-service/` from reaching the imported one —
//! including transitively, and including through `[dev-dependencies]`, which
//! is the cheapest way to reintroduce exactly what the rule forbids.
//!
//! `ot-sentinel` depends on that construction. So a test that links both
//! `aip-sentinel-feed` and `ot-sentinel` cannot live in `aip-sentinel-feed`.
//! It lives here instead, inside the import root, which is the bounded region
//! the ADR draws: the one place the two worlds are allowed to meet.
//!
//! The boundary survives it. This crate links both **in a test binary only**.
//! Nothing here seals, signs or stores anything, no evidence crosses formats,
//! and the production coupling between the two systems remains what it was:
//! one writes a file, the other tails it.
