use aegis_quantum_stress_tests::{
    make_connection, simulate_lru_saturation, synthetic_session_value, MockLruSessionMap,
};

#[test]
fn lru_saturation_evicts_to_declared_capacity() {
    let capacity = 16_384;
    let overflow_factor = 3;

    let stats = simulate_lru_saturation(capacity, overflow_factor);

    assert_eq!(stats.attempted_inserts, capacity * overflow_factor);
    assert_eq!(stats.retained_entries, capacity);
    assert_eq!(stats.evictions, capacity * (overflow_factor - 1));
    assert_eq!(stats.duplicate_updates, 0);
}

#[test]
fn lru_saturation_retains_newest_sessions() {
    let capacity = 8;
    let mut map = MockLruSessionMap::new(capacity);

    for idx in 0..capacity * 2 {
        map.insert(
            make_connection(idx as u64),
            synthetic_session_value(idx as u64),
        );
    }

    assert_eq!(map.len(), capacity);
    assert_eq!(map.capacity(), capacity);
    assert_eq!(map.evictions(), capacity);

    for idx in 0..capacity {
        assert!(
            !map.contains_key(&make_connection(idx as u64)),
            "old session {idx} should have been evicted"
        );
    }

    for idx in capacity..capacity * 2 {
        assert!(
            map.contains_key(&make_connection(idx as u64)),
            "new session {idx} must remain resident"
        );
    }
}
