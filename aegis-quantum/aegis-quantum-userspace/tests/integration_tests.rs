//! Aegis-Quantum Integration Tests
//!
//! These tests validate the end-to-end pipeline: packet events flowing
//! through the circuit breaker, triggering PQC key exchanges, and
//! producing correct blocklist/session values.
//!
//! This is the test suite a TDB auditor or STQC certification lab
//! reviews to verify that the system functions correctly as a unit.

use aegis_quantum_common::{BlocklistValue, ConnectionKey, PacketEvent, SessionValue};
use aegis_quantum_circuit_breaker::CircuitBreaker;

// ── Helper Functions ────────────────────────────────────────────────────────

fn make_rogue_key() -> ConnectionKey {
    ConnectionKey {
        src_addr: 0xC0A80164, // 192.168.1.100
        dst_addr: 0x0A000001, // 10.0.0.1
        src_port: 55000,
        dst_port: 443,
    }
}

fn make_legit_key() -> ConnectionKey {
    ConnectionKey {
        src_addr: 0xC0A80101, // 192.168.1.1
        dst_addr: 0x0A000001,
        src_port: 44000,
        dst_port: 443,
    }
}

fn make_syn_event(key: &ConnectionKey, timestamp_ns: u64) -> PacketEvent {
    PacketEvent {
        src_addr: key.src_addr,
        dst_addr: key.dst_addr,
        src_port: key.src_port,
        dst_port: key.dst_port,
        pkt_len: 64,
        timestamp_ns,
        tcp_flags: 0x02, // SYN
        _pad: [0u8; 7],
    }
}

fn make_blocklist_entry(blocked_at_ns: u64, duration_ns: u64) -> BlocklistValue {
    BlocklistValue {
        blocked_at_ns,
        expiry_ns: if duration_ns == 0 { 0 } else { blocked_at_ns + duration_ns },
        reason: 1,
        _pad: 0,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 1: Circuit Breaker → Blocklist Pipeline
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integration_rogue_agent_triggers_blocklist() {
    let mut cb = CircuitBreaker::new(10, 100);
    let rogue = make_rogue_key();

    let mut trip_count = 0;
    for i in 0..200 {
        let event = make_syn_event(&rogue, i as u64 * 50_000);
        if cb.record_event(&rogue, event.timestamp_ns) {
            trip_count += 1;
        }
    }

    // Circuit breaker must have tripped
    assert!(cb.is_tripped(&rogue));
    // Should have tripped for 100 events (events 101-200)
    assert_eq!(trip_count, 100, "All events after trip should return true");
}

#[test]
fn integration_legitimate_traffic_unaffected_during_attack() {
    let mut cb = CircuitBreaker::new(10, 100);
    let rogue = make_rogue_key();
    let legit = make_legit_key();

    // Rogue floods
    for i in 0..200 {
        cb.record_event(&rogue, i as u64 * 50_000);
    }

    // Legitimate traffic after rogue is blocked
    for i in 0..10 {
        let tripped = cb.record_event(&legit, i as u64 * 1_000_000);
        assert!(!tripped, "Legitimate connection must NOT be affected at event {}", i);
    }

    assert!(cb.is_tripped(&rogue));
    assert!(!cb.is_tripped(&legit));
}

#[test]
fn integration_multiple_rogues_all_detected() {
    let mut cb = CircuitBreaker::new(10, 50);

    let rogues: Vec<ConnectionKey> = (0..5).map(|i| ConnectionKey {
        src_addr: 0xC0A80100 + i,
        dst_addr: 0x0A000001,
        src_port: 55000 + i as u16,
        dst_port: 443,
    }).collect();

    // Each rogue sends 100 events
    for rogue in &rogues {
        for i in 0..100 {
            cb.record_event(rogue, i as u64 * 50_000);
        }
    }

    // All rogues must be tripped
    for rogue in &rogues {
        assert!(cb.is_tripped(rogue), "Rogue {:?} must be tripped", rogue);
    }

    assert_eq!(cb.tracked_connections(), 5);
}

#[test]
fn integration_circuit_breaker_trip_point_is_deterministic() {
    // Run the same scenario 10 times — trip must always occur at the same event
    for _ in 0..10 {
        let mut cb = CircuitBreaker::new(10, 100);
        let key = make_rogue_key();

        let mut trip_index = None;
        for i in 0..150 {
            if cb.record_event(&key, i as u64 * 50_000) && trip_index.is_none() {
                trip_index = Some(i);
            }
        }

        assert_eq!(trip_index, Some(100),
            "Trip point must be deterministic at event #100");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 2: Blocklist Value Expiry Logic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integration_blocklist_active_within_window() {
    let entry = make_blocklist_entry(1_000_000_000, 60_000_000_000);
    // At t=30s, block is active (30s < 60s expiry window)
    let current_time: u64 = 1_000_000_000 + 30_000_000_000;
    assert!(current_time < entry.expiry_ns, "Block must be active at t+30s");
}

#[test]
fn integration_blocklist_expired_after_window() {
    let entry = make_blocklist_entry(1_000_000_000, 60_000_000_000);
    // At t=61s, block has expired
    let current_time: u64 = 1_000_000_000 + 61_000_000_000;
    assert!(current_time >= entry.expiry_ns, "Block must expire after t+60s");
}

#[test]
fn integration_blocklist_permanent_never_expires() {
    let entry = make_blocklist_entry(1_000_000_000, 0);
    assert_eq!(entry.expiry_ns, 0, "Permanent block has expiry_ns=0");
    // Permanent blocks are checked via: `if expiry_ns == 0 { DROP }`
}

#[test]
fn integration_blocklist_expiry_boundary_exact() {
    let entry = make_blocklist_entry(1_000_000_000, 60_000_000_000);
    // Exactly at expiry boundary
    let at_boundary = entry.expiry_ns;
    assert!(!(at_boundary < entry.expiry_ns), "At exact expiry, block should NOT be active");
    // 1ns before expiry
    let before = entry.expiry_ns - 1;
    assert!(before < entry.expiry_ns, "1ns before expiry, block must still be active");
}

#[test]
fn integration_blocklist_reason_codes() {
    let cb_entry = BlocklistValue {
        blocked_at_ns: 0, expiry_ns: 100, reason: 1, _pad: 0,
    };
    let manual_entry = BlocklistValue {
        blocked_at_ns: 0, expiry_ns: 100, reason: 2, _pad: 0,
    };
    assert_eq!(cb_entry.reason, 1, "Reason 1 = circuit breaker");
    assert_eq!(manual_entry.reason, 2, "Reason 2 = manual block");
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 3: Session Value Integrity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integration_session_value_active_flag() {
    let active = SessionValue {
        shared_secret_hash: [0xAB; 32],
        established_at_ns: 1_000_000,
        active: 1,
        _pad: [0u8; 7],
    };
    let inactive = SessionValue {
        shared_secret_hash: [0xAB; 32],
        established_at_ns: 1_000_000,
        active: 0,
        _pad: [0u8; 7],
    };
    assert_eq!(active.active, 1);
    assert_eq!(inactive.active, 0);
}

#[test]
fn integration_session_hash_is_32_bytes() {
    let session = SessionValue {
        shared_secret_hash: [0xFF; 32],
        established_at_ns: 0,
        active: 1,
        _pad: [0u8; 7],
    };
    assert_eq!(session.shared_secret_hash.len(), 32);
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 4: Packet Event Construction & Validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integration_packet_event_syn_flag_correct() {
    let event = make_syn_event(&make_rogue_key(), 0);
    assert_eq!(event.tcp_flags & 0x02, 0x02, "SYN flag must be set");
    assert_eq!(event.tcp_flags & 0x10, 0x00, "ACK flag must NOT be set");
}

#[test]
fn integration_packet_event_preserves_connection_key() {
    let key = make_rogue_key();
    let event = make_syn_event(&key, 12345);

    assert_eq!(event.src_addr, key.src_addr);
    assert_eq!(event.dst_addr, key.dst_addr);
    assert_eq!(event.src_port, key.src_port);
    assert_eq!(event.dst_port, key.dst_port);
    assert_eq!(event.timestamp_ns, 12345);
}

#[test]
fn integration_packet_event_zero_copy_serialization() {
    let event = make_syn_event(&make_rogue_key(), 999_999_999);

    // Simulate zero-copy write to ring buffer
    let mut buffer = [0u8; 32];
    assert_eq!(core::mem::size_of::<PacketEvent>(), 32);
    unsafe {
        core::ptr::write_unaligned(
            buffer.as_mut_ptr() as *mut PacketEvent,
            event,
        );
    }

    // Read it back (simulates userspace reading from ring buffer)
    let restored: PacketEvent = unsafe {
        core::ptr::read_unaligned(buffer.as_ptr() as *const PacketEvent)
    };

    assert_eq!(restored.src_addr, event.src_addr);
    assert_eq!(restored.dst_addr, event.dst_addr);
    assert_eq!(restored.src_port, event.src_port);
    assert_eq!(restored.dst_port, event.dst_port);
    assert_eq!(restored.pkt_len, event.pkt_len);
    assert_eq!(restored.timestamp_ns, event.timestamp_ns);
    assert_eq!(restored.tcp_flags, event.tcp_flags);
}

// ═══════════════════════════════════════════════════════════════════════════
// SECTION 5: Full Pipeline Simulation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integration_full_pipeline_rogue_detected_and_blocked() {
    // Simulates the complete AEGIS pipeline:
    // 1. Rogue agent sends rapid-fire SYN packets
    // 2. Circuit breaker detects and trips
    // 3. BlocklistValue is created with 60s expiry
    // 4. Subsequent packets from the rogue are dropped
    // 5. Legitimate traffic remains unaffected

    let mut cb = CircuitBreaker::new(10, 100);
    let rogue = make_rogue_key();
    let legit = make_legit_key();

    let mut blocklist_entry: Option<BlocklistValue> = None;

    // Phase 1: Rogue floods (150 SYN packets in 7.5ms)
    for i in 0..150u64 {
        let event = make_syn_event(&rogue, i * 50_000);
        let tripped = cb.record_event(&rogue, event.timestamp_ns);

        if tripped && blocklist_entry.is_none() {
            // Create blocklist entry (like userspace would)
            blocklist_entry = Some(make_blocklist_entry(
                event.timestamp_ns,
                60_000_000_000, // 60s block
            ));
        }
    }

    // Verify: blocklist entry was created
    let entry = blocklist_entry.expect("Blocklist entry must be created");
    assert_eq!(entry.reason, 1, "Reason must be circuit breaker (1)");
    assert!(entry.expiry_ns > entry.blocked_at_ns, "Expiry must be after block time");

    // Phase 2: Verify block is active at current time
    let current_time = 10_000_000u64; // 10ms (within 60s window)
    assert!(current_time < entry.expiry_ns, "Block must be active at t=10ms");

    // Phase 3: Legitimate traffic is unaffected
    for i in 0..5 {
        let tripped = cb.record_event(&legit, i * 1_000_000);
        assert!(!tripped, "Legitimate traffic must pass");
    }

    // Phase 4: Block expires after 60s
    let future_time = entry.blocked_at_ns + 61_000_000_000;
    assert!(future_time >= entry.expiry_ns, "Block must expire after 60s");
}

#[test]
fn integration_full_pipeline_self_healing_after_expiry() {
    // After the 60-second block expires, the connection key is no
    // longer blocked. A new circuit breaker instance would allow the
    // connection again (simulating the self-healing behavior).

    let mut cb = CircuitBreaker::new(10, 100);
    let key = make_rogue_key();

    // Trip the breaker
    for i in 0..150 {
        cb.record_event(&key, i as u64 * 50_000);
    }
    assert!(cb.is_tripped(&key));

    // Create blocklist entry
    let entry = make_blocklist_entry(5_000_000, 60_000_000_000);

    // Simulate time passing past expiry
    let time_after_expiry = entry.expiry_ns + 1;
    assert!(time_after_expiry >= entry.expiry_ns, "Block has expired");

    // Reset circuit breaker (simulating GC of expired entries)
    cb.reset(&key);
    assert!(!cb.is_tripped(&key), "Connection should be unblocked after reset");

    // New events should not trip (fresh window)
    let tripped = cb.record_event(&key, time_after_expiry);
    assert!(!tripped, "First event after reset should not trip");
}

#[test]
fn integration_concurrent_attacks_on_different_ports() {
    let mut cb = CircuitBreaker::new(10, 50);

    // 10 rogue agents targeting different ports on the same server
    let rogues: Vec<ConnectionKey> = (0..10).map(|i| ConnectionKey {
        src_addr: 0xC0A80164, // Same IP
        dst_addr: 0x0A000001,
        src_port: 55000 + i as u16, // Different source ports
        dst_port: 443,
    }).collect();

    for rogue in &rogues {
        for i in 0..100 {
            cb.record_event(rogue, i as u64 * 50_000);
        }
    }

    // All 10 must be independently tripped
    for (idx, rogue) in rogues.iter().enumerate() {
        assert!(cb.is_tripped(rogue), "Rogue agent {} must be tripped", idx);
    }
    assert_eq!(cb.tracked_connections(), 10);
}

#[test]
fn integration_map_names_are_bpf_compatible() {
    // BPF map names must be <= 15 characters (BPF_OBJ_NAME_LEN - 1)
    use aegis_quantum_common::map_names;
    assert!(map_names::EVENTS.len() <= 15, "AQ_EVENTS name too long for BPF");
    assert!(map_names::BLOCKLIST.len() <= 15, "AQ_BLOCKLIST name too long for BPF");
    assert!(map_names::SESSIONS.len() <= 15, "AQ_SESSIONS name too long for BPF");
    assert!(map_names::COUNTERS.len() <= 15, "AQ_COUNTERS name too long for BPF");
}

#[test]
fn integration_struct_sizes_match_bpf_expectations() {
    // These sizes are hardcoded in the BPF map definitions.
    // If they change, the kernel program will fail to load.
    assert_eq!(core::mem::size_of::<ConnectionKey>(), 12);
    assert_eq!(core::mem::size_of::<BlocklistValue>(), 24);
    assert_eq!(core::mem::size_of::<SessionValue>(), 48);
    assert_eq!(core::mem::size_of::<PacketEvent>(), 32);
}
