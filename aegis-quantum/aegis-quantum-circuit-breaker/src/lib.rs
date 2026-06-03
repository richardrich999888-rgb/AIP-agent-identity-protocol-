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
}
