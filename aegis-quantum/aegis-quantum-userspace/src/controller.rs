//! Controller Module — Ring Buffer event processing and Circuit Breaker integration.
//!
//! In production, this module:
//! 1. Reads `PacketEvent` structs from the BPF Ring Buffer asynchronously.
//! 2. Feeds each event into the Circuit Breaker for loop detection.
//! 3. If the circuit breaker trips, writes a `BlocklistValue` to the BPF Blocklist Map.
//! 4. Initiates PQC key exchange for legitimate new connections.
//!
//! For TRL-4 lab validation, we simulate the full pipeline with synthetic events.

use aegis_quantum_circuit_breaker::CircuitBreaker;
use aegis_quantum_common::{ConnectionKey, PacketEvent};

/// Result of the circuit breaker validation run.
///
/// Separates the initial breach detection (primary violation) from
/// subsequent packet drops to provide accurate telemetry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CircuitBreakerReport {
    /// Total number of events processed in the simulation.
    pub total_events: usize,
    /// Number of unique breach detections (circuit breaker trip events).
    /// Should be exactly 1 for a single rogue agent.
    pub primary_violations: usize,
    /// Number of subsequent packets blocked after the initial trip.
    pub subsequent_blocked: usize,
    /// Connections that were blocked.
    pub blocked_connections: Vec<String>,
    /// Sliding window duration in milliseconds.
    pub window_ms: u64,
    /// Threshold (max events per window before trip).
    pub threshold: usize,
}

/// Run the circuit breaker validation with synthetic adversarial traffic.
///
/// Simulates a "rogue AI agent" scenario:
/// - 150 rapid-fire TCP SYN packets from the same source within 10ms
/// - The circuit breaker should trip after the configured threshold (100 requests)
/// - After tripping, all subsequent packets from that source should be blocked
///
/// Telemetry is split into:
/// - `primary_violations`: The first time the breaker trips for a connection (1 breach)
/// - `subsequent_blocked`: All subsequent blocked packets after the trip (49 drops)
pub fn run_circuit_breaker_validation() -> CircuitBreakerReport {
    let window_ms = 10;
    let threshold = 100;
    let mut cb = CircuitBreaker::new(window_ms, threshold);

    let mut primary_violations: usize = 0;
    let mut subsequent_blocked: usize = 0;
    let mut blocked_connections: Vec<String> = Vec::new();

    let rogue_key = ConnectionKey {
        src_addr: 0xC0A80164,  // 192.168.1.100 (rogue AI agent)
        dst_addr: 0x0A000001,  // 10.0.0.1 (target API server)
        src_port: 55000,
        dst_port: 443,
    };

    let legitimate_key = ConnectionKey {
        src_addr: 0xC0A80101,  // 192.168.1.1 (legitimate user)
        dst_addr: 0x0A000001,
        src_port: 44000,
        dst_port: 443,
    };

    let mut breach_detected = false;

    // Simulate 150 rapid-fire requests from the rogue agent
    for i in 0..150 {
        let event = PacketEvent {
            src_addr: rogue_key.src_addr,
            dst_addr: rogue_key.dst_addr,
            src_port: rogue_key.src_port,
            dst_port: rogue_key.dst_port,
            pkt_len: 64,
            timestamp_ns: i as u64 * 50_000, // 50μs apart = 150 in 7.5ms
            tcp_flags: 0x02,
            _pad: [0u8; 7],
        };

        let tripped = cb.record_event(&rogue_key, event.timestamp_ns);

        if tripped {
            if !breach_detected {
                // First trip — this is the PRIMARY VIOLATION
                breach_detected = true;
                primary_violations += 1;
                blocked_connections.push(format!(
                    "{}:{} -> {}:{}",
                    rogue_key.src_addr, rogue_key.src_port,
                    rogue_key.dst_addr, rogue_key.dst_port
                ));
                tracing::warn!(
                    "[AEGIS-CIRCUIT-BREAKER] STATUS: DETONATED"
                );
                tracing::warn!(
                    "────────────────────────────────────────────────────────"
                );
                tracing::warn!(
                    "Primary Violations: {} Breach Detected (Threshold: {})",
                    primary_violations, threshold
                );
                tracing::warn!(
                    "Trigger Point: Event #{} (0-indexed) from rogue agent {}:{}",
                    i, rogue_key.src_addr, rogue_key.src_port
                );
            } else {
                // Already tripped — this is a SUBSEQUENT BLOCK
                subsequent_blocked += 1;
            }
        }
    }

    // Verify legitimate traffic is NOT blocked
    let legit_event = PacketEvent {
        src_addr: legitimate_key.src_addr,
        dst_addr: legitimate_key.dst_addr,
        src_port: legitimate_key.src_port,
        dst_port: legitimate_key.dst_port,
        pkt_len: 64,
        timestamp_ns: 1_000_000, // 1ms
        tcp_flags: 0x02,
        _pad: [0u8; 7],
    };

    let legit_tripped = cb.record_event(&legitimate_key, legit_event.timestamp_ns);
    assert!(
        !legit_tripped,
        "Legitimate traffic must NOT trigger the circuit breaker"
    );

    tracing::warn!(
        "Subsequent Countermeasures: {} Attack Packets Dropped Inline",
        subsequent_blocked
    );
    tracing::warn!(
        "Target Classification: Malicious Agentic Loop Isolated"
    );
    tracing::warn!(
        "Legitimate Traffic: Unaffected (verified)"
    );
    tracing::warn!(
        "────────────────────────────────────────────────────────"
    );

    CircuitBreakerReport {
        total_events: 150,
        primary_violations,
        subsequent_blocked,
        blocked_connections,
        window_ms,
        threshold,
    }
}
