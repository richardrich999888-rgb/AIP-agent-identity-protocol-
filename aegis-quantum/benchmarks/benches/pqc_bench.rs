//! TRL-4 Benchmark: Post-Quantum Cryptographic Engine (Kyber-768)
//!
//! Measures the exact microsecond-level latency of each PQC operation to
//! produce hard numbers for the TDB validation report and VC pitch.
//!
//! Target metrics:
//!   - Key Generation:   < 500 μs
//!   - Encapsulation:    < 500 μs
//!   - Decapsulation:    < 500 μs
//!   - Full Round-Trip:  < 5 ms (5000 μs)
//!
//! Run with:
//!   cargo bench --package aegis-quantum-benchmarks --bench pqc_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use sha2::{Digest, Sha256};

fn bench_kyber768_keygen(c: &mut Criterion) {
    c.bench_function("kyber768/keygen", |b| {
        b.iter(|| {
            let (pk, sk) = kyber768::keypair();
            black_box((pk, sk));
        });
    });
}

fn bench_kyber768_encapsulate(c: &mut Criterion) {
    let (pk, _sk) = kyber768::keypair();
    c.bench_function("kyber768/encapsulate", |b| {
        b.iter(|| {
            let (ss, ct) = kyber768::encapsulate(black_box(&pk));
            black_box((ss, ct));
        });
    });
}

fn bench_kyber768_decapsulate(c: &mut Criterion) {
    let (pk, sk) = kyber768::keypair();
    let (_ss, ct) = kyber768::encapsulate(&pk);
    c.bench_function("kyber768/decapsulate", |b| {
        b.iter(|| {
            let ss = kyber768::decapsulate(black_box(&ct), black_box(&sk));
            black_box(ss);
        });
    });
}

fn bench_kyber768_full_roundtrip(c: &mut Criterion) {
    c.bench_function("kyber768/full_roundtrip", |b| {
        b.iter(|| {
            let (pk, sk) = kyber768::keypair();
            let (ss_client, ct) = kyber768::encapsulate(&pk);
            let ss_server = kyber768::decapsulate(&ct, &sk);
            assert_eq!(ss_client.as_bytes(), ss_server.as_bytes());
            black_box(ss_client);
        });
    });
}

fn bench_kyber768_with_session_hash(c: &mut Criterion) {
    c.bench_function("kyber768/roundtrip_with_sha256", |b| {
        b.iter(|| {
            let (pk, sk) = kyber768::keypair();
            let (ss_client, ct) = kyber768::encapsulate(&pk);
            let ss_server = kyber768::decapsulate(&ct, &sk);

            // Compute SHA-256 session key (as stored in BPF session map)
            let mut hasher = Sha256::new();
            hasher.update(ss_server.as_bytes());
            let hash = hasher.finalize();
            black_box(hash);
        });
    });
}

/// Compare all three Kyber security levels (512, 768, 1024).
fn bench_kyber_security_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("kyber_security_levels");

    group.bench_function(BenchmarkId::new("full_roundtrip", "Kyber-512"), |b| {
        b.iter(|| {
            let (pk, sk) = kyber512::keypair();
            let (ss_c, ct) = kyber512::encapsulate(&pk);
            let ss_s = kyber512::decapsulate(&ct, &sk);
            assert_eq!(ss_c.as_bytes(), ss_s.as_bytes());
            black_box(ss_c);
        });
    });

    group.bench_function(BenchmarkId::new("full_roundtrip", "Kyber-768"), |b| {
        b.iter(|| {
            let (pk, sk) = kyber768::keypair();
            let (ss_c, ct) = kyber768::encapsulate(&pk);
            let ss_s = kyber768::decapsulate(&ct, &sk);
            assert_eq!(ss_c.as_bytes(), ss_s.as_bytes());
            black_box(ss_c);
        });
    });

    group.bench_function(BenchmarkId::new("full_roundtrip", "Kyber-1024"), |b| {
        b.iter(|| {
            let (pk, sk) = kyber1024::keypair();
            let (ss_c, ct) = kyber1024::encapsulate(&pk);
            let ss_s = kyber1024::decapsulate(&ct, &sk);
            assert_eq!(ss_c.as_bytes(), ss_s.as_bytes());
            black_box(ss_c);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_kyber768_keygen,
    bench_kyber768_encapsulate,
    bench_kyber768_decapsulate,
    bench_kyber768_full_roundtrip,
    bench_kyber768_with_session_hash,
    bench_kyber_security_levels,
);
criterion_main!(benches);
