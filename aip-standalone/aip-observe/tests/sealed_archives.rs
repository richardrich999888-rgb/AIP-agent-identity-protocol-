//! Sealed evidence stays verifiable when the protocol moves on.
//!
//! These archives were attested by a real collector and committed as
//! results; tests elsewhere read them as evidence. A protocol bump that left
//! them unverifiable would destroy the property evidence exists to have
//! (ADR-019 §10), so every batch in each one must verify, at the version it
//! was sealed under, for as long as the archive is in the repository.

use aip_observe::{verify_attested_batch, AttestedBatch, ObserverTrustAnchors};

/// `(archive directory relative to the repository root, sealed version)`.
const SEALED: [(&str, u16); 2] = [
    ("validation/external/corroborate/results/sealed", 12),
    ("validation/external/spiffe/results/sealed-joint", 12),
];

fn repo() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn every_sealed_batch_verifies_at_the_version_it_was_sealed_under() {
    for (dir, version) in SEALED {
        let base = repo().join(dir);
        let key = hex_decode(
            std::fs::read_to_string(base.join("observer.pub"))
                .unwrap()
                .trim(),
        );
        let archive = std::fs::read_to_string(base.join("attested.archive.jsonl")).unwrap();
        let mut n = 0;
        for (i, line) in archive.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let b: AttestedBatch = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{dir} line {i}: does not parse: {e}"));
            assert_eq!(b.version, version, "{dir} line {i}");
            let anchors = ObserverTrustAnchors::new().trust(&b.observer_id, b.key_version, &key);
            verify_attested_batch(&b, &anchors).unwrap_or_else(|e| {
                panic!("{dir} line {i}: sealed batch no longer verifies: {e:?}")
            });
            n += 1;
        }
        assert!(n > 0, "{dir}: empty archive");
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
