//! Aegis-Quantum Circuit Breaker — Sliding Window Loop Detector
//!
//! Detects autonomous AI agent cascade failures by tracking the rate of
//! requests per connection within a sliding time window.  When the rate
//! exceeds a configurable threshold, the circuit breaker "trips," signaling
//! the user-space controller to insert a blocklist entry into the BPF map.
//!
//! # Algorithm
//!
//! For each `ConnectionKey`, we maintain a ring buffer of timestamps.
//! On each new event:
//! 1. Append the current timestamp.
//! 2. Evict all timestamps older than `window_ns` from the front.
//! 3. If the remaining count exceeds `threshold`, the breaker trips.
//!
//! This is an O(1) amortized operation per event (each timestamp is
//! inserted once and removed at most once).
//!
//! # Design Rationale
//!
//! Traditional rate limiters (token bucket, leaky bucket) are designed for
//! bandwidth control.  The circuit breaker is designed for **intent detection**:
//! it distinguishes between "many legitimate users" and "one rogue agent
//! hammering an endpoint in a tight loop."  The per-connection tracking
//! ensures that a single malicious agent cannot hide behind aggregate traffic.

use std::collections::{HashMap, VecDeque};

use aegis_quantum_common::ConnectionKey;

/// The core circuit breaker state machine.
pub struct CircuitBreaker {
    /// Sliding window duration in nanoseconds.
    window_ns: u64,
    /// Maximum number of events allowed within the window before tripping.
    threshold: usize,
    /// Per-connection event timestamp queues.
    connections: HashMap<ConnectionKey, ConnectionState>,
}

/// Per-connection state: a deque of event timestamps and trip status.
struct ConnectionState {
    /// Ring buffer of event timestamps (nanoseconds).
    timestamps: VecDeque<u64>,
    /// Whether this connection's breaker has been tripped.
    tripped: bool,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given window (in milliseconds)
    /// and threshold (max events per window).
    pub fn new(window_ms: u64, threshold: usize) -> Self {
        Self {
            window_ns: window_ms * 1_000_000, // Convert ms → ns
            threshold,
            connections: HashMap::new(),
        }
    }

    /// Record a new event for the given connection.
    ///
    /// Returns `true` if the circuit breaker has tripped (i.e., the connection
    /// should be blocked).  Once tripped, always returns `true` for that
    /// connection until explicitly reset.
    pub fn record_event(&mut self, key: &ConnectionKey, timestamp_ns: u64) -> bool {
        let state = self
            .connections
            .entry(*key)
            .or_insert_with(|| ConnectionState {
                timestamps: VecDeque::new(),
                tripped: false,
            });

        // If already tripped, short-circuit
        if state.tripped {
            return true;
        }

        // Add the new timestamp
        state.timestamps.push_back(timestamp_ns);

        // Evict expired timestamps from the front
        let cutoff = timestamp_ns.saturating_sub(self.window_ns);
        while let Some(&front) = state.timestamps.front() {
            if front < cutoff {
                state.timestamps.pop_front();
            } else {
                break;
            }
        }

        // Check threshold
        if state.timestamps.len() > self.threshold {
            state.tripped = true;
            return true;
        }

        false
    }

    /// Check whether the circuit breaker is tripped for a given connection.
    pub fn is_tripped(&self, key: &ConnectionKey) -> bool {
        self.connections
            .get(key)
            .map_or(false, |state| state.tripped)
    }

    /// Reset the circuit breaker for a specific connection.
    pub fn reset(&mut self, key: &ConnectionKey) {
        if let Some(state) = self.connections.get_mut(key) {
            state.tripped = false;
            state.timestamps.clear();
        }
    }

    /// Reset all circuit breakers.
    pub fn reset_all(&mut self) {
        self.connections.clear();
    }

    /// Get the number of tracked connections.
    pub fn tracked_connections(&self) -> usize {
        self.connections.len()
    }

    /// Get the current event count within the window for a connection.
    pub fn event_count(&self, key: &ConnectionKey) -> usize {
        self.connections
            .get(key)
            .map_or(0, |state| state.timestamps.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(src: u32, dst: u32) -> ConnectionKey {
        ConnectionKey {
            src_addr: src,
            dst_addr: dst,
            src_port: 55000,
            dst_port: 443,
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Original 8 tests — preserved exactly
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_below_threshold_does_not_trip() {
        let mut cb = CircuitBreaker::new(10, 100); // 10ms window, 100 threshold
        let key = make_key(1, 2);

        // Send exactly 100 events within 10ms (at threshold, not over)
        for i in 0..100 {
            let tripped = cb.record_event(&key, i * 50_000); // 50μs apart
            assert!(!tripped, "Should not trip at event #{}", i);
        }
    }

    #[test]
    fn test_exceeding_threshold_trips() {
        let mut cb = CircuitBreaker::new(10, 100);
        let key = make_key(1, 2);

        // Send 101 events within 10ms — should trip on the 101st
        let mut trip_index = None;
        for i in 0..150 {
            let tripped = cb.record_event(&key, i * 50_000);
            if tripped && trip_index.is_none() {
                trip_index = Some(i);
            }
        }

        assert!(trip_index.is_some(), "Circuit breaker must trip");
        assert_eq!(trip_index.unwrap(), 100, "Should trip on event #100 (0-indexed, 101st event)");
    }

    #[test]
    fn test_once_tripped_stays_tripped() {
        let mut cb = CircuitBreaker::new(10, 5);
        let key = make_key(1, 2);

        // Trip the breaker
        for i in 0..10 {
            cb.record_event(&key, i * 100_000);
        }

        assert!(cb.is_tripped(&key));

        // Subsequent events should still return tripped
        assert!(cb.record_event(&key, 999_999_999));
    }

    #[test]
    fn test_reset_clears_trip() {
        let mut cb = CircuitBreaker::new(10, 5);
        let key = make_key(1, 2);

        for i in 0..10 {
            cb.record_event(&key, i * 100_000);
        }

        assert!(cb.is_tripped(&key));

        cb.reset(&key);
        assert!(!cb.is_tripped(&key));
        assert_eq!(cb.event_count(&key), 0);
    }

    #[test]
    fn test_different_connections_are_independent() {
        let mut cb = CircuitBreaker::new(10, 5);
        let rogue = make_key(1, 2);
        let legit = make_key(3, 4);

        // Trip the rogue connection
        for i in 0..10 {
            cb.record_event(&rogue, i * 100_000);
        }

        // Legitimate connection should NOT be affected
        let tripped = cb.record_event(&legit, 500_000);
        assert!(!tripped, "Legitimate connection must not be affected by rogue");
        assert!(!cb.is_tripped(&legit));
        assert!(cb.is_tripped(&rogue));
    }

    #[test]
    fn test_sliding_window_eviction() {
        let mut cb = CircuitBreaker::new(1, 5); // 1ms window, threshold 5
        let key = make_key(1, 2);

        // Send 4 events at t=0
        for i in 0..4 {
            cb.record_event(&key, i * 100_000); // 100μs apart
        }

        // Jump forward 2ms — old events should be evicted
        let tripped = cb.record_event(&key, 2_000_000);
        assert!(!tripped, "Old events should have been evicted from the window");
        assert_eq!(cb.event_count(&key), 1); // Only the latest event remains
    }

    #[test]
    fn test_100_rapid_fire_in_10ms_trips() {
        // This is the exact TRL-4 validation requirement:
        // 100 rapid-fire requests within 10ms triggers a MAP_UPDATE to the Blocklist.
        let mut cb = CircuitBreaker::new(10, 100);
        let key = make_key(0xC0A80164, 0x0A000001);

        let mut tripped_at = None;
        for i in 0..150 {
            // 50μs apart = 150 events in 7.5ms (well within the 10ms window)
            let tripped = cb.record_event(&key, i as u64 * 50_000);
            if tripped && tripped_at.is_none() {
                tripped_at = Some(i);
            }
        }

        assert!(tripped_at.is_some(), "Circuit breaker MUST trip for 150 events in 7.5ms");
        assert!(
            tripped_at.unwrap() <= 101,
            "Must trip at or before event #101, tripped at #{}",
            tripped_at.unwrap()
        );
    }

    #[test]
    fn test_tracked_connections_count() {
        let mut cb = CircuitBreaker::new(10, 100);

        cb.record_event(&make_key(1, 2), 0);
        cb.record_event(&make_key(3, 4), 0);
        cb.record_event(&make_key(5, 6), 0);

        assert_eq!(cb.tracked_connections(), 3);

        cb.reset_all();
        assert_eq!(cb.tracked_connections(), 0);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Threshold Precision Tests (tests 9–13)
    // ══════════════════════════════════════════════════════════════════════

    /// threshold=10, send exactly 11 events — must trip on event #10 (0-indexed).
    #[test]
    fn test_trips_at_exactly_threshold_plus_one() {
        let mut cb = CircuitBreaker::new(100, 10); // 100ms window, threshold 10
        let key = make_key(10, 20);

        let mut trip_index = None;
        for i in 0..11 {
            let tripped = cb.record_event(&key, i * 100_000); // 100μs apart
            if tripped && trip_index.is_none() {
                trip_index = Some(i);
            }
        }

        assert!(trip_index.is_some(), "Must trip when exceeding threshold by 1");
        assert_eq!(
            trip_index.unwrap(),
            10,
            "Must trip exactly on event #10 (0-indexed, the 11th event)"
        );
    }

    /// threshold=10, send exactly 10 events — must NOT trip.
    #[test]
    fn test_does_not_trip_at_exactly_threshold() {
        let mut cb = CircuitBreaker::new(100, 10);
        let key = make_key(10, 20);

        for i in 0..10 {
            let tripped = cb.record_event(&key, i * 100_000);
            assert!(
                !tripped,
                "Must NOT trip at exactly threshold (event #{})",
                i
            );
        }
        assert!(!cb.is_tripped(&key));
    }

    /// threshold=1, 2 events should trip on the second event.
    #[test]
    fn test_threshold_one_trips_on_second_event() {
        let mut cb = CircuitBreaker::new(100, 1);
        let key = make_key(10, 20);

        let first = cb.record_event(&key, 1_000);
        assert!(!first, "First event must not trip at threshold=1");

        let second = cb.record_event(&key, 2_000);
        assert!(second, "Second event must trip at threshold=1");
    }

    /// threshold=1, a single event should NOT trip.
    #[test]
    fn test_threshold_one_does_not_trip_on_single_event() {
        let mut cb = CircuitBreaker::new(100, 1);
        let key = make_key(10, 20);

        let tripped = cb.record_event(&key, 1_000);
        assert!(!tripped, "Single event must not trip at threshold=1");
        assert!(!cb.is_tripped(&key));
    }

    /// threshold=1000, send 1001 events — must trip on the 1001st.
    #[test]
    fn test_large_threshold_1000() {
        let mut cb = CircuitBreaker::new(1000, 1000); // 1s window, threshold 1000
        let key = make_key(10, 20);

        // 1000 events: should not trip
        for i in 0..1000 {
            let tripped = cb.record_event(&key, i * 1_000); // 1μs apart
            assert!(!tripped, "Must not trip at event #{}", i);
        }

        // 1001st event: should trip
        let tripped = cb.record_event(&key, 1000 * 1_000);
        assert!(tripped, "Must trip on the 1001st event");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Sliding Window Precision Tests (tests 14–18)
    // ══════════════════════════════════════════════════════════════════════

    /// Events at exactly the cutoff timestamp should NOT be evicted.
    /// cutoff = current_ts - window_ns.  Eviction uses `front < cutoff`
    /// (strictly less than), so events at exactly cutoff are retained.
    #[test]
    fn test_events_exactly_at_window_boundary_are_kept() {
        let window_ms = 10;
        let window_ns: u64 = window_ms * 1_000_000; // 10_000_000 ns
        let mut cb = CircuitBreaker::new(window_ms, 100);
        let key = make_key(30, 40);

        // Event at t=0
        cb.record_event(&key, 0);

        // New event at t = window_ns.  cutoff = window_ns - window_ns = 0.
        // Event at t=0 has timestamp == cutoff → must NOT be evicted.
        cb.record_event(&key, window_ns);
        assert_eq!(
            cb.event_count(&key),
            2,
            "Event at exactly cutoff must be retained"
        );
    }

    /// Events 1ns before the cutoff SHOULD be evicted.
    #[test]
    fn test_events_just_before_window_boundary_are_evicted() {
        let window_ms = 10;
        let window_ns: u64 = window_ms * 1_000_000;
        let mut cb = CircuitBreaker::new(window_ms, 100);
        let key = make_key(30, 40);

        // Event at t=0
        cb.record_event(&key, 0);

        // New event at t = window_ns + 1.  cutoff = window_ns + 1 - window_ns = 1.
        // Event at t=0 has timestamp 0 < 1 → evicted.
        cb.record_event(&key, window_ns + 1);
        assert_eq!(
            cb.event_count(&key),
            1,
            "Event 1ns before cutoff must be evicted"
        );
    }

    /// 1ms window: events at 0, 500μs, 999μs. Then a new event at 1ms+1ns.
    /// The first event (t=0) should be evicted, the others retained.
    #[test]
    fn test_window_1ms_precision() {
        let mut cb = CircuitBreaker::new(1, 100); // 1ms window
        let key = make_key(30, 40);

        cb.record_event(&key, 0);           // t=0
        cb.record_event(&key, 500_000);     // t=500μs
        cb.record_event(&key, 999_000);     // t=999μs

        // t = 1ms + 1ns = 1_000_001ns.  cutoff = 1_000_001 - 1_000_000 = 1.
        // t=0 < 1 → evicted.  t=500_000 >= 1 → kept.  t=999_000 >= 1 → kept.
        cb.record_event(&key, 1_000_001);
        assert_eq!(
            cb.event_count(&key),
            3,
            "Only the t=0 event should be evicted"
        );
    }

    /// Burst of 50, gap of 2× window, another burst of 50 — should NOT trip
    /// if threshold is 100.  The gap evicts the first burst entirely.
    #[test]
    fn test_window_resets_after_gap() {
        let window_ms = 10;
        let window_ns: u64 = window_ms * 1_000_000;
        let mut cb = CircuitBreaker::new(window_ms, 100);
        let key = make_key(30, 40);

        // First burst: 50 events at 100μs intervals starting at t=0
        for i in 0u64..50 {
            let tripped = cb.record_event(&key, i * 100_000);
            assert!(!tripped, "First burst event #{} should not trip", i);
        }

        // Gap of 2× window (20ms)
        let gap_start = 2 * window_ns + 50 * 100_000;

        // Second burst: 50 events at 100μs intervals
        for i in 0u64..50 {
            let tripped = cb.record_event(&key, gap_start + i * 100_000);
            assert!(
                !tripped,
                "Second burst event #{} should not trip (first burst evicted)",
                i
            );
        }

        assert!(!cb.is_tripped(&key));
    }

    /// window=0ms means window_ns=0.  cutoff = ts - 0 = ts.
    /// All previous events have timestamp < ts → evicted.
    /// So only the current event remains.  threshold=1 → 2nd event
    /// at the same instant trips (both at same ts, so both retained).
    #[test]
    fn test_zero_window_trips_immediately() {
        let mut cb = CircuitBreaker::new(0, 1); // 0ms window, threshold 1
        let key = make_key(30, 40);

        // First event at t=1000
        let first = cb.record_event(&key, 1000);
        assert!(!first, "First event must not trip");

        // Second event at t=1001: cutoff = 1001 - 0 = 1001.  t=1000 < 1001 → evicted.
        // Only 1 event remains → does not exceed threshold 1.
        let second = cb.record_event(&key, 1001);
        assert!(!second, "With 0 window, previous events are evicted");

        // Two events at the SAME timestamp: cutoff = 2000. t=1001 < 2000 → evicted.
        // Then re-insert at 2000: only 1 event.  Let's put 2 events at same ts.
        cb.record_event(&key, 3000);
        let same_ts = cb.record_event(&key, 3000);
        // cutoff = 3000 - 0 = 3000.  Previous event at 3000 is NOT < 3000 → kept.
        // Now we have 2 events → exceeds threshold of 1 → trips.
        assert!(same_ts, "Two events at exact same instant must trip with 0 window");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Multi-Connection Isolation Tests (tests 19–22)
    // ══════════════════════════════════════════════════════════════════════

    /// 1000 independent connections with 1 event each — none should trip.
    #[test]
    fn test_1000_independent_connections() {
        let mut cb = CircuitBreaker::new(10, 5);

        for i in 0u32..1000 {
            let key = make_key(i, i + 10_000);
            let tripped = cb.record_event(&key, 100_000);
            assert!(
                !tripped,
                "Connection {} must not trip on a single event",
                i
            );
        }

        assert_eq!(cb.tracked_connections(), 1000);
    }

    /// 1000 connections with 1 event each, 1 rogue with 200 events.
    /// Only the rogue trips.
    #[test]
    fn test_one_rogue_among_1000_legitimate() {
        let mut cb = CircuitBreaker::new(100, 50); // 100ms window, threshold 50
        let rogue_key = make_key(0xDEAD, 0xBEEF);

        // 1000 legitimate connections
        for i in 0u32..1000 {
            let key = make_key(i, i + 10_000);
            cb.record_event(&key, 1_000_000);
        }

        // Rogue sends 200 events
        for i in 0u64..200 {
            cb.record_event(&rogue_key, i * 1_000); // 1μs apart
        }

        // Verify only rogue is tripped
        assert!(cb.is_tripped(&rogue_key), "Rogue must be tripped");

        for i in 0u32..1000 {
            let key = make_key(i, i + 10_000);
            assert!(
                !cb.is_tripped(&key),
                "Legitimate connection {} must not be tripped",
                i
            );
        }
    }

    /// Trip 2 connections, reset 1 — the other must stay tripped.
    #[test]
    fn test_reset_one_does_not_affect_others() {
        let mut cb = CircuitBreaker::new(100, 3);
        let key_a = make_key(1, 2);
        let key_b = make_key(3, 4);

        // Trip both
        for i in 0..10 {
            cb.record_event(&key_a, i * 1_000);
            cb.record_event(&key_b, i * 1_000);
        }

        assert!(cb.is_tripped(&key_a));
        assert!(cb.is_tripped(&key_b));

        // Reset only key_a
        cb.reset(&key_a);
        assert!(!cb.is_tripped(&key_a), "key_a must be un-tripped after reset");
        assert!(cb.is_tripped(&key_b), "key_b must remain tripped");
    }

    /// Trip 5 connections, reset_all — all must be cleared, tracked_connections = 0.
    #[test]
    fn test_reset_all_clears_everything() {
        let mut cb = CircuitBreaker::new(100, 3);

        let keys: Vec<ConnectionKey> = (0..5).map(|i| make_key(i * 10, i * 10 + 1)).collect();

        // Trip all 5
        for key in &keys {
            for i in 0..10 {
                cb.record_event(key, i * 1_000);
            }
            assert!(cb.is_tripped(key));
        }

        assert_eq!(cb.tracked_connections(), 5);

        cb.reset_all();
        assert_eq!(cb.tracked_connections(), 0);

        for key in &keys {
            assert!(!cb.is_tripped(key), "All connections must be cleared");
            assert_eq!(cb.event_count(key), 0);
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // State Machine Tests (tests 23–28)
    // ══════════════════════════════════════════════════════════════════════

    /// Unknown connection returns false for is_tripped.
    #[test]
    fn test_is_tripped_false_for_unknown_key() {
        let cb = CircuitBreaker::new(10, 100);
        let key = make_key(99, 100);
        assert!(!cb.is_tripped(&key));
    }

    /// Unknown connection returns 0 for event_count.
    #[test]
    fn test_event_count_zero_for_unknown_key() {
        let cb = CircuitBreaker::new(10, 100);
        let key = make_key(99, 100);
        assert_eq!(cb.event_count(&key), 0);
    }

    /// Send 50 events within the window — event_count must be 50.
    #[test]
    fn test_event_count_matches_events_sent() {
        let mut cb = CircuitBreaker::new(100, 1000); // large threshold so we don't trip
        let key = make_key(50, 60);

        for i in 0u64..50 {
            cb.record_event(&key, i * 1_000); // 1μs apart, well within 100ms window
        }

        assert_eq!(cb.event_count(&key), 50);
    }

    /// Send events, wait past window, send 1 more — count should be 1.
    #[test]
    fn test_event_count_decreases_after_window_expires() {
        let window_ms = 5;
        let window_ns: u64 = window_ms * 1_000_000; // 5ms
        let mut cb = CircuitBreaker::new(window_ms, 1000);
        let key = make_key(50, 60);

        // 20 events at t=0..19μs
        for i in 0u64..20 {
            cb.record_event(&key, i * 1_000);
        }
        assert_eq!(cb.event_count(&key), 20);

        // New event well past the window (t = window_ns + 100μs)
        // cutoff = window_ns + 100_000 - window_ns = 100_000
        // All 20 events are at t < 100_000 → all evicted.
        cb.record_event(&key, window_ns + 100_000);
        assert_eq!(
            cb.event_count(&key),
            1,
            "Only the latest event should remain after window expires"
        );
    }

    /// Trip, then send 10000 more events — must still be tripped.
    #[test]
    fn test_tripped_connection_still_returns_true_after_many_events() {
        let mut cb = CircuitBreaker::new(10, 5);
        let key = make_key(70, 80);

        // Trip
        for i in 0..10 {
            cb.record_event(&key, i * 100_000);
        }
        assert!(cb.is_tripped(&key));

        // 10000 more events
        for i in 0u64..10_000 {
            let tripped = cb.record_event(&key, 5_000_000 + i);
            assert!(tripped, "Must remain tripped at event #{}", i);
        }
        assert!(cb.is_tripped(&key));
    }

    /// Trip → reset → re-trip: the breaker must be re-armable.
    #[test]
    fn test_reset_allows_retripping() {
        let mut cb = CircuitBreaker::new(100, 5);
        let key = make_key(70, 80);

        // First trip
        for i in 0..10 {
            cb.record_event(&key, i * 1_000);
        }
        assert!(cb.is_tripped(&key), "First trip must succeed");

        // Reset
        cb.reset(&key);
        assert!(!cb.is_tripped(&key), "Reset must clear trip");
        assert_eq!(cb.event_count(&key), 0);

        // Re-trip
        let base_ts = 50_000_000u64; // 50ms later, well within 100ms window from first new event
        for i in 0..10 {
            cb.record_event(&key, base_ts + i * 1_000);
        }
        assert!(
            cb.is_tripped(&key),
            "Circuit breaker must be re-trippable after reset"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Stress / Performance Tests (tests 29–30)
    // ══════════════════════════════════════════════════════════════════════

    /// 10K events on a single connection in a tight loop.  Must trip and must
    /// not panic or overflow any internal structure.
    #[test]
    fn test_10000_events_single_connection_performance() {
        let mut cb = CircuitBreaker::new(1000, 100); // 1s window, threshold 100
        let key = make_key(200, 201);

        let mut tripped = false;
        for i in 0u64..10_000 {
            if cb.record_event(&key, i * 1_000) {
                tripped = true;
            }
        }

        assert!(tripped, "Must trip with 10K events against threshold 100");
        assert!(cb.is_tripped(&key));
    }

    /// 100 connections × 100 events each.  Threshold=100, so exactly at
    /// boundary — none should trip.
    #[test]
    fn test_100_connections_100_events_each() {
        let mut cb = CircuitBreaker::new(1000, 100); // 1s window, threshold 100

        for conn in 0u32..100 {
            let key = make_key(conn, conn + 5000);
            for event in 0u64..100 {
                let tripped = cb.record_event(&key, event * 1_000);
                assert!(
                    !tripped,
                    "Connection {} must not trip at exactly threshold (event #{})",
                    conn, event
                );
            }
        }

        assert_eq!(cb.tracked_connections(), 100);

        // Verify none are tripped
        for conn in 0u32..100 {
            let key = make_key(conn, conn + 5000);
            assert!(
                !cb.is_tripped(&key),
                "Connection {} must not be tripped",
                conn
            );
            assert_eq!(cb.event_count(&key), 100);
        }
    }
}

