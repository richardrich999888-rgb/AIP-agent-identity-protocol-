//! Cross-language interop: does Rust accept what the Python SDK signs?
//!
//! The parity vectors prove the two encoders agree on bytes. This proves the
//! whole loop: a Python agent loads a key, builds events through the
//! adapters, signs them, and a Rust verifier accepts the signatures and the
//! chain. If the SDK's preimage drifted by one byte, every signature here
//! would fail to verify — which is the failure mode we want, and is loud.
//!
//! The fixture is written by
//! `sdk/python/tests/test_adapters_e2e.py::test_events_serialise_for_the_rust_interop_fixture`.
//! When it is absent the test skips rather than fails: a Rust-only checkout
//! should not go red because Python was not run.

use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdk/python/tests/python_events.json")
}

/// Minimal reader — the fixture is a flat object and pulling in a JSON
/// dependency for four fields would not earn its place.
fn field<'a>(hay: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\": \"");
    let start = hay.find(&pat)? + pat.len();
    let rest = &hay[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn all_fields<'a>(hay: &'a str, key: &str) -> Vec<&'a str> {
    let pat = format!("\"{key}\": \"");
    let mut out = Vec::new();
    let mut cur = hay;
    while let Some(i) = cur.find(&pat) {
        let rest = &cur[i + pat.len()..];
        if let Some(end) = rest.find('"') {
            out.push(&rest[..end]);
            cur = &rest[end..];
        } else {
            break;
        }
    }
    out
}

#[test]
fn rust_verifies_signatures_produced_by_the_python_sdk() {
    let path = fixture_path();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        eprintln!(
            "skipping: {} not present (run the Python SDK tests to generate it)",
            path.display()
        );
        return;
    };

    let pk_hex = field(&raw, "public_key").expect("public_key in fixture");
    let public_key = hex::decode(pk_hex).expect("public key is hex");
    assert_eq!(public_key.len(), 32, "Ed25519 public keys are 32 bytes");

    let preimages = all_fields(&raw, "preimage");
    let signatures = all_fields(&raw, "signature");
    assert_eq!(
        preimages.len(),
        signatures.len(),
        "fixture is malformed: preimage/signature count mismatch"
    );
    assert!(!preimages.is_empty(), "fixture contains no events");

    let domain = aip_airi::AIRI_EVENT_DOMAIN.as_bytes();

    for (i, (pre_hex, sig_hex)) in preimages.iter().zip(signatures.iter()).enumerate() {
        let preimage = hex::decode(pre_hex).expect("preimage is hex");
        let sig_bytes = hex::decode(sig_hex).expect("signature is hex");
        let sig: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .expect("Ed25519 signatures are 64 bytes");

        // 1. The Python side used AIRI's domain tag, length-prefixed.
        assert_eq!(
            &preimage[..4],
            &(domain.len() as u32).to_le_bytes(),
            "event {i}: missing length prefix on the domain tag"
        );
        assert_eq!(
            &preimage[4..4 + domain.len()],
            domain,
            "event {i}: wrong or absent AIRI domain tag"
        );

        // 2. The signature verifies over exactly those bytes.
        assert!(
            aip_crypto::verify_ed25519_raw(&public_key, &preimage, &sig),
            "SECURITY: event {i} signed by the Python SDK does not verify in Rust. \
             The two canonical encoders have diverged."
        );

        // 3. A one-bit change must break it — proving the check is real and
        //    not vacuously passing on a malformed key.
        let mut tampered = preimage.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            !aip_crypto::verify_ed25519_raw(&public_key, &tampered, &sig),
            "event {i}: a tampered preimage still verified"
        );
    }

    eprintln!(
        "verified {} Python-signed AIRI events in Rust",
        preimages.len()
    );
}
