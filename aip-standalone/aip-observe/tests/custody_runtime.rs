//! The production custody path: a collector whose signing key is wrapped at
//! rest (argon2 + XChaCha20-Poly1305) resumes through the runtime, attests a
//! batch, and that batch verifies — with the raw key never present as bytes in
//! the process's configuration. This is the composition the Phase 1 collector
//! daemon relies on (`CollectorRuntime::start_with_custodian`).

use aip_observe::{
    verify_attested_batch, CollectorKey, CollectorRuntime, CollectorStore, ContinuityPolicy,
    ObserverTrustAnchors, ProcfsProbe, Started,
};

/// A unique temp directory for one test run; no `tempfile` dependency.
fn scratch(tag: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "aip-custody-runtime-{tag}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_wrapped_key_collector_attests_a_verifiable_batch() {
    let dir = scratch("wrapped");
    let store = CollectorStore::open(&dir).unwrap();

    // Production key: created wrapped on first use, dev backend refused.
    let key =
        CollectorKey::production(dir.join("collector.key.wrapped"), b"correct horse").unwrap();
    let observer_id = "collector.pilot.example";
    let key_version = 1u32;
    let public_key = key.public_key().to_vec();
    let custodian = key.into_custodian();

    let started = CollectorRuntime::start_with_custodian(
        store,
        observer_id,
        key_version,
        custodian,
        ContinuityPolicy::Strict,
    )
    .unwrap();
    let mut rt = match started {
        Started::Running(rt, _) => rt,
        Started::Refused(brk) => panic!("fresh start must not refuse: {brk:?}"),
    };

    // Attest an empty batch (no host needed): the point is the signature under
    // the wrapped key, verified against the anchors a verifier supplies.
    let mut probe = ProcfsProbe::new("probe-pilot-1");
    let batch = probe.batch([1u8; 16], 100, 200, vec![]);
    let attested = rt.attest(batch).unwrap();

    let anchors = ObserverTrustAnchors::new().trust(observer_id, key_version, &public_key);
    assert_eq!(
        verify_attested_batch(&attested, &anchors),
        Ok(()),
        "a batch signed under the wrapped custodian must verify"
    );
    assert_eq!(attested.observer_id, observer_id);
    assert_eq!(attested.key_version, key_version);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_second_start_over_the_same_store_continues_one_chain() {
    let dir = scratch("resume");
    let key_path = dir.join("collector.key.wrapped");
    let observer_id = "collector.pilot.example";

    // First lifetime: attest one batch, then drop the runtime.
    let first_seq;
    {
        let store = CollectorStore::open(&dir).unwrap();
        let key = CollectorKey::production(&key_path, b"pw").unwrap();
        let custodian = key.into_custodian();
        let started = CollectorRuntime::start_with_custodian(
            store,
            observer_id,
            1,
            custodian,
            ContinuityPolicy::Strict,
        )
        .unwrap();
        let mut rt = match started {
            Started::Running(rt, _) => rt,
            Started::Refused(brk) => panic!("fresh start refused: {brk:?}"),
        };
        let mut probe = ProcfsProbe::new("probe-pilot-1");
        let attested = rt.attest(probe.batch([1u8; 16], 100, 200, vec![])).unwrap();
        first_seq = attested.sequence;
    }

    // Second lifetime over the same store + same wrapped key: opens (not
    // creates) the key, resumes the chain, and the next sequence advances.
    let store = CollectorStore::open(&dir).unwrap();
    let key = CollectorKey::production(&key_path, b"pw").unwrap();
    let custodian = key.into_custodian();
    let started = CollectorRuntime::start_with_custodian(
        store,
        observer_id,
        1,
        custodian,
        ContinuityPolicy::Strict,
    )
    .unwrap();
    let mut rt = match started {
        Started::Running(rt, _) => rt,
        Started::Refused(brk) => panic!("clean resume must not refuse: {brk:?}"),
    };
    let mut probe = ProcfsProbe::new("probe-pilot-1");
    let attested = rt.attest(probe.batch([2u8; 16], 200, 300, vec![])).unwrap();
    assert!(
        attested.sequence > first_seq,
        "resumed chain must advance the sequence ({} !> {first_seq})",
        attested.sequence
    );

    let _ = std::fs::remove_dir_all(&dir);
}
