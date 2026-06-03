use std::net::Ipv4Addr;
use std::time::Instant;

use aegis_quantum_circuit_breaker::CircuitBreaker;
use aegis_quantum_common::ConnectionKey;
use aegis_quantum_stress_tests::percentile_micros;

fn key(src_host: u8, dst_port: u16) -> ConnectionKey {
    ConnectionKey {
        src_addr: u32::from(Ipv4Addr::new(10, 42, 0, src_host)),
        dst_addr: u32::from(Ipv4Addr::new(192, 168, 1, 10)),
        src_port: 50_000 + u16::from(src_host),
        dst_port,
    }
}

#[test]
fn circuit_breaker_isolates_legitimate_flow_during_rogue_burst() {
    let threshold_limit = 100;
    let burst_volume = 10_000;
    let mut breaker = CircuitBreaker::new(10, threshold_limit);
    let rogue = key(1, 8443);
    let legitimate = key(2, 443);
    let mut rogue_dropped = 0;
    let mut legitimate_latencies = Vec::with_capacity(burst_volume / 10);

    for call_idx in 0..burst_volume {
        let rogue_timestamp_ns = call_idx as u64 * 50_000;
        if breaker.record_event(&rogue, rogue_timestamp_ns) {
            rogue_dropped += 1;
        }

        if call_idx % 10 == 0 {
            let legitimate_timestamp_ns = call_idx as u64 * 200_000;
            let started_at = Instant::now();
            let legitimate_tripped = breaker.record_event(&legitimate, legitimate_timestamp_ns);
            legitimate_latencies.push(started_at.elapsed());
            assert!(
                !legitimate_tripped,
                "legitimate transaction stream must not inherit rogue block state"
            );
        }
    }

    assert_eq!(rogue_dropped, burst_volume - threshold_limit);
    assert!(breaker.is_tripped(&rogue));
    assert!(!breaker.is_tripped(&legitimate));

    let p99_legitimate_latency_us = percentile_micros(&legitimate_latencies, 99.0);
    assert!(
        p99_legitimate_latency_us < 5_000,
        "local isolation guard exceeded 5ms p99: {p99_legitimate_latency_us}us"
    );
}

#[test]
fn circuit_breaker_keeps_many_legitimate_connections_independent() {
    let threshold_limit = 100;
    let mut breaker = CircuitBreaker::new(10, threshold_limit);
    let rogue = key(1, 8443);

    for call_idx in 0..10_000 {
        breaker.record_event(&rogue, call_idx as u64 * 50_000);
    }

    assert!(breaker.is_tripped(&rogue));

    for host in 2..=250 {
        let legitimate = key(host, 443);
        assert!(
            !breaker.record_event(&legitimate, 1_000_000_000),
            "legitimate host {host} was incorrectly blocked"
        );
        assert!(!breaker.is_tripped(&legitimate));
    }
}
