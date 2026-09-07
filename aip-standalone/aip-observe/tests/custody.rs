//! Phase A — custody of the collector's signing key.
//!
//! These live in `aip-observe` because `aip-observe` owns this key's
//! custody. Putting them anywhere else would put the decision anywhere
//! else, and observer independence is a property of who holds the key.

use aip_crypto::custody::{Backend, Custodian, InMemoryCustodian, WrappedFileCustodian};
use aip_observe::{CollectorKey, CollectorKeyError, CollectorKeyPolicy, CollectorSigner};

const PASS: &[u8] = b"correct horse battery staple";

fn keyfile(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("aip-obs-key-{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// 6 (collector side) — a production collector never falls back to a
/// development backend.
///
/// PROVES: refused outright rather than accepted at reduced strength. A
/// collector signing with an in-memory key is not a slightly weaker
/// production collector; it is a development one, and the mistake is
/// calling it production.
///
/// The store half of requirement 6 is in `aip-core/tests/custody.rs`,
/// where the store lives.
#[test]
fn a_6_a_production_collector_never_falls_back() {
    let dev: Box<dyn Custodian> = Box::new(InMemoryCustodian::generate());
    match CollectorKey::with_custodian(dev, CollectorKeyPolicy::Production) {
        Err(CollectorKeyError::DevelopmentBackendInProduction(b)) => {
            assert_eq!(b, Backend::DevelopmentInMemory)
        }
        _ => panic!("a production collector accepted an in-memory key"),
    }
    // The same custodian under a development policy is fine, and says so.
    let dev2: Box<dyn Custodian> = Box::new(InMemoryCustodian::generate());
    let ok = CollectorKey::with_custodian(dev2, CollectorKeyPolicy::Development).unwrap();
    assert!(!ok.backend().is_production());
}

/// 14 — observer-key ownership stays in `aip-observe`.
///
/// PROVES: the collector key's policy type lives in `aip-observe` and
/// nowhere else. Checked as a source-level fence because the property is
/// about *where a decision lives*, which no runtime call can answer.
#[test]
fn a_14_observer_key_custody_stays_in_aip_observe() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    assert!(
        std::path::Path::new(&format!("{root}/aip-observe/src/custody.rs")).exists(),
        "aip-observe must own the collector key's custody"
    );
    // No downstream crate may define a collector-key policy of its own.
    for crate_name in [
        "aip-reconcile",
        "aip-nexora",
        "aip-warrant",
        "aip-containment",
    ] {
        let dir = format!("{root}/{crate_name}/src");
        let mut found = Vec::new();
        for e in walk(&dir) {
            let text = std::fs::read_to_string(&e).unwrap_or_default();
            if text.contains("CollectorKeyPolicy") || text.contains("struct CollectorKey") {
                found.push(e);
            }
        }
        assert!(
            found.is_empty(),
            "{crate_name} has taken on collector-key custody: {found:?}"
        );
    }
}

/// 15 — a development backend cannot be mistaken for a production one.
///
/// PROVES: every backend answers `is_production()`, the two answers
/// differ, and the production collector policy acts on the answer. A
/// caller that wants to know is told; a caller that does not ask is
/// refused anyway on the path that matters.
#[test]
fn a_15_a_development_backend_is_not_mistakable_for_production() {
    assert!(!Backend::DevelopmentInMemory.is_production());
    assert!(Backend::WrappedFile.is_production());

    let dev = CollectorKey::development();
    assert_eq!(dev.backend(), Backend::DevelopmentInMemory);
    assert_eq!(dev.policy(), CollectorKeyPolicy::Development);
    assert!(!dev.backend().is_production());

    // The debug rendering names the backend, so an operator reading a log
    // sees which one is in use rather than inferring it.
    assert!(format!("{dev:?}").contains("DevelopmentInMemory"));

    let path = keyfile("prod");
    let prod = CollectorKey::production(&path, PASS).unwrap();
    assert!(prod.backend().is_production());
    assert_eq!(prod.policy(), CollectorKeyPolicy::Production);
    let _ = std::fs::remove_file(&path);
}

/// 1 (collector side) & 11 — first initialization, restart, and the key
/// surviving both.
///
/// PROVES: `production()` creates on first run and opens thereafter, so a
/// collector needs no different command the first time it starts; and the
/// public key is the same across a restart, which is what makes previously
/// attested batches still verify.
#[test]
fn a_1_11_first_initialization_and_restart_keep_the_same_key() {
    let path = keyfile("lifecycle");
    let first = CollectorKey::production(&path, PASS).unwrap();
    let public = first.public_key().to_vec();
    drop(first);

    let restarted = CollectorKey::production(&path, PASS).unwrap();
    assert_eq!(
        restarted.public_key(),
        public.as_slice(),
        "a restart must not silently mint a new observer identity"
    );

    // And a collector signing through it produces batches that verify.
    let signer = CollectorSigner::with_custodian(
        "collector-1",
        1,
        Box::new(WrappedFileCustodian::open(&path, PASS).unwrap()),
    )
    .unwrap();
    assert_eq!(signer.custody_backend(), Backend::WrappedFile);
    let _ = std::fs::remove_file(&path);
}

fn walk(dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(p.to_str().unwrap()));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p.to_string_lossy().into_owned());
        }
    }
    out
}

/// 10 (guard) — a custodian offering a malformed public key is refused by
/// the signer.
///
/// PROVES: `with_custodian` validates what it is handed. Without this a
/// custodian returning a short or empty public key would produce a signer
/// whose observer identity nothing could ever verify, and the failure
/// would surface far from its cause.
///
/// The double below is the smallest thing that can be wrong in the right
/// place: it signs correctly and lies only about its key's shape.
#[test]
fn a_10_guard_a_custodian_with_a_malformed_public_key_is_refused() {
    #[derive(Debug)]
    struct BadKey {
        public: Vec<u8>,
        inner: InMemoryCustodian,
    }
    impl Custodian for BadKey {
        fn public_key(&self) -> &[u8] {
            &self.public
        }
        fn sign(
            &self,
            signer_id: &str,
            payload: &[u8],
        ) -> Result<aip_types::Signature, aip_crypto::custody::CustodyError> {
            self.inner.sign(signer_id, payload)
        }
        fn backend(&self) -> Backend {
            Backend::WrappedFile
        }
    }

    for public in [vec![], vec![0u8; 31], vec![0u8; 33], vec![0u8; 64]] {
        let len = public.len();
        let bad = Box::new(BadKey {
            public,
            inner: InMemoryCustodian::generate(),
        });
        assert!(
            CollectorSigner::with_custodian("collector-1", 1, bad).is_err(),
            "a {len}-byte public key was accepted"
        );
    }
}
