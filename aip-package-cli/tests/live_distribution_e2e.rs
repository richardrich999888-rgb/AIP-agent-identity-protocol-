#![cfg(all(feature = "live-distribution-e2e", unix))]

// Reuse the real managed loopback transfer test from aip-distribution, placing
// the AIBOM/offline-verifier composition at this higher-level crate boundary.
#[path = "../../aip-standalone/aip-distribution/tests/live_network.rs"]
mod managed_loopback;
