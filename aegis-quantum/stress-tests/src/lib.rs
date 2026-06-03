use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::Duration;
use std::time::Instant;

use aegis_quantum_common::{ConnectionKey, SessionValue};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SaturationStats {
    pub capacity: usize,
    pub attempted_inserts: usize,
    pub retained_entries: usize,
    pub evictions: usize,
    pub duplicate_updates: usize,
    pub duration_us: u64,
}

pub struct MockLruSessionMap {
    capacity: usize,
    entries: HashMap<ConnectionKey, SessionValue>,
    order: VecDeque<ConnectionKey>,
    evictions: usize,
    duplicate_updates: usize,
}

impl MockLruSessionMap {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "LRU session map capacity must be non-zero");
        Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            evictions: 0,
            duplicate_updates: 0,
        }
    }

    pub fn insert(&mut self, key: ConnectionKey, value: SessionValue) {
        if self.entries.contains_key(&key) {
            self.entries.insert(key, value);
            self.duplicate_updates += 1;
            return;
        }

        if self.entries.len() == self.capacity {
            while let Some(oldest) = self.order.pop_front() {
                if self.entries.remove(&oldest).is_some() {
                    self.evictions += 1;
                    break;
                }
            }
        }

        self.entries.insert(key, value);
        self.order.push_back(key);
    }

    pub fn contains_key(&self, key: &ConnectionKey) -> bool {
        self.entries.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn evictions(&self) -> usize {
        self.evictions
    }

    pub fn duplicate_updates(&self) -> usize {
        self.duplicate_updates
    }
}

pub fn simulate_lru_saturation(capacity: usize, overflow_factor: usize) -> SaturationStats {
    assert!(overflow_factor >= 1, "overflow factor must be at least 1");

    let attempted_inserts = capacity
        .checked_mul(overflow_factor)
        .expect("LRU saturation input overflowed usize");
    let started_at = Instant::now();
    let mut map = MockLruSessionMap::new(capacity);

    for idx in 0..attempted_inserts {
        map.insert(
            make_connection(idx as u64),
            synthetic_session_value(idx as u64),
        );
    }

    let duration_us = started_at.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;

    SaturationStats {
        capacity,
        attempted_inserts,
        retained_entries: map.len(),
        evictions: map.evictions(),
        duplicate_updates: map.duplicate_updates(),
        duration_us,
    }
}

pub fn make_connection(idx: u64) -> ConnectionKey {
    let src_addr = Ipv4Addr::new(
        10,
        ((idx >> 16) & 0xff) as u8,
        ((idx >> 8) & 0xff) as u8,
        (idx & 0xff) as u8,
    );

    ConnectionKey {
        src_addr: u32::from(src_addr),
        dst_addr: u32::from(Ipv4Addr::new(192, 168, 1, 10)),
        src_port: 1024 + (idx % 50_000) as u16,
        dst_port: 443,
    }
}

pub fn synthetic_session_value(idx: u64) -> SessionValue {
    let mut shared_secret_hash = [0_u8; 32];
    for (offset, byte) in shared_secret_hash.iter_mut().enumerate() {
        *byte = (idx >> ((offset % 8) * 8)) as u8 ^ (offset as u8).wrapping_mul(17);
    }

    SessionValue {
        shared_secret_hash,
        established_at_ns: idx.saturating_mul(1_000_000),
        active: 1,
        _pad: [0; 7],
    }
}

pub fn percentile_micros(samples: &[Duration], percentile: f64) -> u128 {
    assert!(
        !samples.is_empty(),
        "percentile requires at least one sample"
    );
    assert!(
        (0.0..=100.0).contains(&percentile),
        "percentile must be between 0 and 100"
    );

    let mut sorted: Vec<u128> = samples.iter().map(Duration::as_micros).collect();
    sorted.sort_unstable();
    let rank = ((percentile / 100.0) * (sorted.len().saturating_sub(1) as f64)).ceil() as usize;
    sorted[rank.min(sorted.len() - 1)]
}
