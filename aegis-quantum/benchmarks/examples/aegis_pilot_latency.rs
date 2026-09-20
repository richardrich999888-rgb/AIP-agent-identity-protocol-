use std::time::Instant;

use aegis_quantum_circuit_breaker::CircuitBreaker;
use aegis_quantum_common::ConnectionKey;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::SharedSecret;
use serde_json::json;

fn parse_samples() -> usize {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--samples" {
            return args
                .next()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(200);
        }
    }
    200
}

fn make_key() -> ConnectionKey {
    ConnectionKey {
        src_addr: 0x0A000001,
        dst_addr: 0x0A000002,
        src_port: 55000,
        dst_port: 443,
    }
}

fn measure_ml_kem_ms() -> f64 {
    let start = Instant::now();
    let (pk, sk) = kyber768::keypair();
    let (client_secret, ciphertext) = kyber768::encapsulate(&pk);
    let server_secret = kyber768::decapsulate(&ciphertext, &sk);
    assert_eq!(client_secret.as_bytes(), server_secret.as_bytes());
    start.elapsed().as_secs_f64() * 1000.0
}

fn measure_circuit_breaker_detonation_us() -> f64 {
    let key = make_key();
    let mut breaker = CircuitBreaker::new(10, 100);
    for i in 0..100 {
        assert!(!breaker.record_event(&key, i * 50_000));
    }

    let start = Instant::now();
    assert!(breaker.record_event(&key, 100 * 50_000));
    start.elapsed().as_secs_f64() * 1_000_000.0
}

fn main() {
    let samples = parse_samples();
    for _ in 0..10 {
        let _ = measure_ml_kem_ms();
        let _ = measure_circuit_breaker_detonation_us();
    }

    let mut ml_kem = Vec::with_capacity(samples);
    let mut detonation = Vec::with_capacity(samples);
    for _ in 0..samples {
        ml_kem.push(measure_ml_kem_ms());
        detonation.push(measure_circuit_breaker_detonation_us());
    }

    println!(
        "{}",
        json!({
            "ml_kem_handshake_ms": ml_kem,
            "aegis_circuit_breaker_detonation_us": detonation
        })
    );
}
