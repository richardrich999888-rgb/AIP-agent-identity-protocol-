//! TRL-4 Benchmark: Agentic AI Circuit Breaker
//!
//! Measures the throughput and latency of the sliding window loop detector
//! under various load patterns.
//!
//! Target metrics:
//!   - Event recording:      < 1 μs per event
//!   - Trip detection:       < 1 μs
//!   - 10K connections:      < 10 ms total processing
//!
//! Run with:
//!   cargo bench --package aegis-quantum-benchmarks --bench circuit_breaker_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use aegis_quantum_circuit_breaker::CircuitBreaker;
use aegis_quantum_common::ConnectionKey;

fn make_key(src: u32) -> ConnectionKey {
    ConnectionKey {
        src_addr: src,
        dst_addr: 0x0A000001,
        src_port: 55000,
        dst_port: 443,
    }
}

/// Benchmark: single event recording (amortized cost)
fn bench_single_event(c: &mut Criterion) {
    let mut cb = CircuitBreaker::new(10, 100);
    let key = make_key(1);
    let mut ts = 0u64;

    c.bench_function("circuit_breaker/single_event", |b| {
        b.iter(|| {
            ts += 50_000; // 50μs increment
            let result = cb.record_event(black_box(&key), black_box(ts));
            black_box(result);
        });
    });
}

/// Benchmark: burst of 100 events (within threshold, no trip)
fn bench_burst_100_no_trip(c: &mut Criterion) {
    c.bench_function("circuit_breaker/burst_100_no_trip", |b| {
        b.iter(|| {
            let mut cb = CircuitBreaker::new(10, 200); // threshold=200, so 100 won't trip
            let key = make_key(42);
            for i in 0..100 {
                cb.record_event(&key, i * 50_000);
            }
            black_box(cb.is_tripped(&key));
        });
    });
}

/// Benchmark: burst of 150 events causing a trip
fn bench_burst_150_with_trip(c: &mut Criterion) {
    c.bench_function("circuit_breaker/burst_150_trip", |b| {
        b.iter(|| {
            let mut cb = CircuitBreaker::new(10, 100);
            let key = make_key(99);
            for i in 0..150 {
                cb.record_event(&key, i * 50_000);
            }
            assert!(cb.is_tripped(&key));
            black_box(());
        });
    });
}

/// Benchmark: many independent connections (measures HashMap scaling)
fn bench_many_connections(c: &mut Criterion) {
    let mut group = c.benchmark_group("circuit_breaker/scaling");

    for &conn_count in &[100, 1000, 10000] {
        group.bench_with_input(
            BenchmarkId::new("connections", conn_count),
            &conn_count,
            |b, &count| {
                b.iter(|| {
                    let mut cb = CircuitBreaker::new(10, 100);
                    for i in 0..count {
                        let key = make_key(i as u32);
                        cb.record_event(&key, 0);
                    }
                    black_box(cb.tracked_connections());
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: sliding window eviction under sustained load
fn bench_sustained_load_with_eviction(c: &mut Criterion) {
    c.bench_function("circuit_breaker/sustained_1000_with_eviction", |b| {
        b.iter(|| {
            let mut cb = CircuitBreaker::new(1, 50); // 1ms window
            let key = make_key(7);
            // Send 1000 events spread over 100ms — window eviction should keep count low
            for i in 0..1000 {
                cb.record_event(&key, i * 100_000); // 100μs apart
            }
            // Should NOT trip because events are spread out (only ~10 per 1ms window)
            assert!(!cb.is_tripped(&key));
            black_box(());
        });
    });
}

criterion_group!(
    benches,
    bench_single_event,
    bench_burst_100_no_trip,
    bench_burst_150_with_trip,
    bench_many_connections,
    bench_sustained_load_with_eviction,
);
criterion_main!(benches);
