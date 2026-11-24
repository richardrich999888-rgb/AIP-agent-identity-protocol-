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

/// The genuine LangGraph/local-model Linux capture is protocol 13. Verify
/// every original batch and health record after the retention-scope upgrade;
/// never rewrite old signed evidence to fit the new struct.
#[test]
fn genuine_local_model_v13_archive_and_health_remain_verifiable() {
    let base = repo().join("examples/local-evidence-agent/results/linux-observation/41508547378");
    let trust: serde_json::Value =
        serde_json::from_slice(&std::fs::read(base.join("trust/controller-trust.json")).unwrap())
            .unwrap();
    let key = hex_decode(trust["observer_anchor"]["public_key"].as_str().unwrap());
    let anchors = ObserverTrustAnchors::new().trust("collector.local.qa", 1, &key);
    let archive = std::fs::read_to_string(base.join("public/attested.archive.jsonl")).unwrap();
    let expected_hash = trust["public_files"]["attested.archive.jsonl"]
        .as_str()
        .unwrap();
    assert_eq!(
        aip_crypto::sha256(archive.as_bytes()).to_vec(),
        hex_decode(expected_hash)
    );
    let mut batches = 0;
    let mut previous_head = [0; 32];
    for line in archive.lines().filter(|s| !s.trim().is_empty()) {
        let batch: AttestedBatch = serde_json::from_str(line).unwrap();
        assert_eq!(batch.version, 13);
        assert!(batch.batch.filter_report.is_none());
        verify_attested_batch(&batch, &anchors).unwrap();
        assert_eq!(batch.sequence, batches + 1);
        assert_eq!(batch.prev_head, previous_head);
        previous_head = batch.head();
        batches += 1;
    }
    let archive = std::fs::read_to_string(base.join("public/health.archive.jsonl")).unwrap();
    let expected_hash = trust["public_files"]["health.archive.jsonl"]
        .as_str()
        .unwrap();
    assert_eq!(
        aip_crypto::sha256(archive.as_bytes()).to_vec(),
        hex_decode(expected_hash)
    );
    let mut health = 0;
    for line in archive.lines().filter(|s| !s.trim().is_empty()) {
        let record: aip_observe::SignedSensorHealth = serde_json::from_str(line).unwrap();
        assert_eq!(record.health.version, 13);
        aip_observe::verify_signed_health(&record, &anchors).unwrap();
        health += 1;
    }
    assert_eq!((batches, health), (93, 6));
}
