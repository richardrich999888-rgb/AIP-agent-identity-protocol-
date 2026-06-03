//! Aegis-Quantum User-Space Controller
//!
//! This is the main user-space application that:
//! 1. Loads the compiled eBPF/XDP program into the Linux kernel.
//! 2. Attaches it to a specified network interface (e.g., `eth0`).
//! 3. Reads `PacketEvent` structs from the BPF Ring Buffer.
//! 4. Performs Kyber-768 key encapsulation for each new TCP SYN connection.
//! 5. Updates the BPF Session Map with the derived shared secret hash.
//! 6. Runs the Circuit Breaker to detect and block rogue AI agent loops.
//!
//! # Usage
//! ```bash
//! sudo RUST_LOG=info cargo run --package aegis-quantum-userspace -- --iface eth0
//! ```

pub mod pqc;
pub mod controller;

use tracing_subscriber::{fmt, EnvFilter};

fn main() {
    // Initialize structured logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Aegis-Quantum (AQ-1) User-Space Controller v0.1.0");
    tracing::info!("Mode: TRL-4 Laboratory Validation");

    // In TRL-4 mode, we run the PQC validation suite directly
    // (actual eBPF loading requires a Linux kernel with CAP_BPF).
    tracing::info!("Running PQC key exchange validation...");

    let report = pqc::run_pqc_validation();
    tracing::info!("PQC Validation Report:");
    tracing::info!("  Algorithm:       {}", report.algorithm);
    tracing::info!("  Key Generation:  {} μs", report.keygen_us);
    tracing::info!("  Encapsulation:   {} μs", report.encaps_us);
    tracing::info!("  Decapsulation:   {} μs", report.decaps_us);
    tracing::info!("  Secrets Match:   {}", report.secrets_match);
    tracing::info!("  Status:          {}", if report.secrets_match { "PASS" } else { "FAIL" });

    tracing::info!("Running Circuit Breaker validation...");
    let cb_result = controller::run_circuit_breaker_validation();
    tracing::info!("Circuit Breaker Report:");
    tracing::info!("  Total Events:    {}", cb_result.total_events);
    tracing::info!("  Trips Triggered: {}", cb_result.trips_triggered);
    tracing::info!("  Status:          {}", if cb_result.trips_triggered > 0 { "PASS" } else { "FAIL" });

    tracing::info!("TRL-4 Laboratory Validation Complete.");
}
