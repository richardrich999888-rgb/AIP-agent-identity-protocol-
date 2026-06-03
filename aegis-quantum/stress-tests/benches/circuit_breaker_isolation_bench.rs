use std::net::Ipv4Addr;

use aegis_quantum_circuit_breaker::CircuitBreaker;
use aegis_quantum_common::ConnectionKey;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn key(src_host: u8, dst_port: u16) -> ConnectionKey {
    ConnectionKey {
        src_addr: u32::from(Ipv4Addr::new(10, 43, 0, src_host)),
        dst_addr: u32::from(Ipv4Addr::new(192, 168, 1, 10)),
        src_port: 40_000 + u16::from(src_host),
        dst_port,
    }
}

fn run_isolation_burst() -> usize {
    let mut breaker = CircuitBreaker::new(10, 100);
    let rogue = key(1, 8443);
    let legitimate = key(2, 443);
    let mut drops = 0;

    for call_idx in 0..10_000 {
        if breaker.record_event(&rogue, call_idx as u64 * 50_000) {
            drops += 1;
        }

        if call_idx % 10 == 0 {
            let legitimate_timestamp_ns = call_idx as u64 * 200_000;
            black_box(breaker.record_event(&legitimate, legitimate_timestamp_ns));
        }
    }

    drops
}

fn bench_circuit_breaker_isolation(c: &mut Criterion) {
    let mut group = c.benchmark_group("aegis_circuit_breaker_isolation");
    group.sample_size(40);
    group.bench_function("rogue_burst_plus_legitimate_flow", |b| {
        b.iter(|| black_box(run_isolation_burst()))
    });
    group.finish();
}

criterion_group!(benches, bench_circuit_breaker_isolation);
criterion_main!(benches);
