#![allow(dead_code)]

use std::time::Instant;

use jsonwebtoken::{DecodingKey, EncodingKey};
use serde_json::json;

#[path = "../keys.rs"]
mod keys;
#[path = "../tokens.rs"]
mod tokens;

fn parse_samples() -> usize {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--samples" {
            return args
                .next()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(2_000);
        }
    }
    2_000
}

fn main() {
    let samples = parse_samples();
    let keypair = keys::KeyPair::generate();
    let encoding_key = EncodingKey::from_ed_pem(keypair.private_pem.as_bytes())
        .expect("generated private key PEM must be valid");
    let decoding_key = DecodingKey::from_ed_pem(keypair.public_pem.as_bytes())
        .expect("generated public key PEM must be valid");
    let token = tokens::issue(
        "550e8400-e29b-41d4-a716-446655440000",
        "ai_model",
        None,
        3600,
        &encoding_key,
    )
    .expect("token issuance must succeed")
    .token;

    for _ in 0..100 {
        assert!(tokens::verify(&token, &decoding_key).valid);
    }

    let mut verify_us = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        let result = tokens::verify(&token, &decoding_key);
        let elapsed_us = start.elapsed().as_secs_f64() * 1_000_000.0;
        assert!(result.valid, "pilot token must verify");
        verify_us.push(elapsed_us);
    }

    println!("{}", json!({ "signature_verification_us": verify_us }));
}
