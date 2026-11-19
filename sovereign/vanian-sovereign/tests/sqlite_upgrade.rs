//! Read real pre-upgrade database bytes, then exercise the public corpus API.
//! The fixture was produced by rusqlite 0.32.1 / SQLite 3.46.0, not by the
//! engine under test. This is compatibility and ACL testing, not a CVE exploit.

use std::path::Path;

use serde_json::{json, Value};
use vanian_sovereign::adapters::sqlite_corpus::SqliteCorpus;
use vanian_sovereign::domain::corpus::{Classification, Document, Ident, Principal};
use vanian_sovereign::ports::CorpusStore;

fn fixture(path: &Path) -> Value {
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/sqlite-032/expected.json")).unwrap();
    let encoded: String = include_str!("fixtures/sqlite-032/corpus.hex")
        .split_whitespace()
        .collect();
    let bytes = hex::decode(encoded).unwrap();
    assert_eq!(
        hex::encode(aip_crypto::sha256(&bytes)),
        expected["corpus_sha256"].as_str().unwrap(),
        "legacy fixture bytes changed"
    );
    std::fs::write(path, bytes).unwrap();
    expected
}

fn principal(tenant: &str, clearance: Classification) -> Principal {
    Principal {
        tenant: Ident::new(tenant).unwrap(),
        clearance,
    }
}

#[test]
fn old_engine_database_preserves_tenant_clearance_quarantine_and_digests() {
    // Check the linked library, not only the version written in Cargo.lock.
    assert!(rusqlite::version_number() >= 3_054_000);
    println!("linked SQLite {}", rusqlite::version());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corpus.db");
    let expected = fixture(&path);
    let corpus = SqliteCorpus::open(&path).unwrap();
    for row in expected["principals"].as_array().unwrap() {
        let p = principal(
            row["tenant"].as_str().unwrap(),
            serde_json::from_value(row["clearance"].clone()).unwrap(),
        );
        let hits: Vec<_> = corpus
            .search(&p, "hydraulic pump", 20)
            .unwrap()
            .iter()
            .map(|h| json!({"id": h.doc_id.as_str(), "body": h.text, "classification": h.classification}))
            .collect();
        assert_eq!(json!(hits), row["hits"], "{p:?}");
        assert_eq!(
            hex::encode(corpus.snapshot_digest(&p).unwrap()),
            row["snapshot_digest"].as_str().unwrap(),
            "dependency commitment changed for {p:?}"
        );
        for doc in row["documents"].as_array().unwrap() {
            assert_eq!(
                json!(corpus
                    .document_digest(&p, doc["id"].as_str().unwrap())
                    .unwrap()
                    .map(hex::encode)),
                doc["digest"],
                "{p:?}: {doc}"
            );
        }
    }
    let low = principal("acme", Classification::Public);
    for attack in [
        "' OR 1=1 --",
        "NEAR(hydraulic key) OR tenant:globex",
        "\"; DROP TABLE documents; --",
        "hydraulic* OR body:restricted",
    ] {
        assert!(corpus
            .search(&low, attack, 20)
            .unwrap()
            .iter()
            .all(|h| h.doc_id.as_str() == "notice"));
    }
    assert_eq!(corpus.search(&low, "inspection", 20).unwrap().len(), 1);
}

#[test]
fn old_engine_database_updates_fts_versions_and_clearance_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corpus.db");
    fixture(&path);
    let own = principal("acme", Classification::Restricted);
    let low = principal("acme", Classification::Internal);
    let other = principal("globex", Classification::Restricted);
    let mut corpus = SqliteCorpus::open(&path).unwrap();
    let before = corpus.snapshot_digest(&own).unwrap();
    let other_before = corpus.snapshot_digest(&other).unwrap();
    let updated_body = "replacement valve torque limit 45 Nm";
    corpus
        .ingest(&Document {
            tenant: Ident::new("acme").unwrap(),
            doc_id: Ident::new("manual").unwrap(),
            title: "manual".into(),
            classification: Classification::Restricted,
            body: updated_body.into(),
        })
        .unwrap();
    let after = corpus.snapshot_digest(&own).unwrap();
    assert_ne!(
        before, after,
        "replacement must invalidate dependency binding"
    );
    drop(corpus);

    let corpus = SqliteCorpus::open(&path).unwrap();
    assert_eq!(corpus.snapshot_digest(&own).unwrap(), after);
    assert_eq!(corpus.snapshot_digest(&other).unwrap(), other_before);
    assert!(corpus.search(&own, "pressure", 20).unwrap().is_empty());
    assert!(corpus.search(&low, "torque", 20).unwrap().is_empty());
    assert!(corpus.document_digest(&low, "manual").unwrap().is_none());
    let hits = corpus.search(&own, "torque", 20).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].doc_id.as_str(), "manual");
    assert_eq!(hits[0].text, updated_body);
    assert!(corpus.search(&other, "torque", 20).unwrap().is_empty());
    drop(corpus);
    let conn = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = conn
        .query_row(
            "SELECT version FROM documents WHERE tenant='acme' AND doc_id='manual'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 3, "two old ingests, then one new ingest");
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
}
