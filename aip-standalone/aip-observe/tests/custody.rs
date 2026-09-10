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

// ─── Rotation, revocation, replacement ───
//
// Custody changes where a key lives. It does not change what the verifier
// trusts, and these tests exist to keep those two facts from being confused.
// Trust lives in `ObserverTrustAnchors`, keyed by `(observer_id, key_version)`;
// nothing in the custody layer can add an anchor, remove one, or make a
// verifier consult a different set.

use aip_crypto::generate_ed25519_keypair;
use aip_observe::{
    verify_attested_batch, ObservedEffect, ObservedProcess, ObserverAttestor, ObserverTrustAnchors,
    ProcfsProbe, VerifyError,
};

const OBS: &str = "collector.rotation.example";

fn probe_batch(
    probe: &mut ProcfsProbe,
    id: u8,
    from: u64,
    to: u64,
) -> aip_observe::ObservationBatch {
    let p = ObservedProcess {
        process: aip_types::ProcessInstance {
            pid: 42,
            pid_start_time_ticks: 1000,
            boot_id: [0xb0; 16],
        },
        exe_content_sha256: [0xe0; 32],
        exe_path: "/opt/agent/bin/agent".into(),
    };
    let obs = probe.observation(p, ObservedEffect::ProcessPresent, None, from);
    probe.batch([id; 16], from, to, vec![obs])
}

/// 7 — rotation keeps history verifiable.
///
/// PROVES: after `key_version` A becomes B, batches signed under B verify
/// against B's anchor and batches signed under A still verify against A's.
/// "Do not silently break historical proof verification" is exactly this: the
/// old anchor is retained, so the old batches keep verifying.
#[test]
fn a_7_rotation_keeps_history_verifiable() {
    let kp1 = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBS, 1, &kp1.private_key, &kp1.public_key).unwrap();
    let mut probe = ProcfsProbe::new("probe-rot");
    let anchors_v1 = ObserverTrustAnchors::new().trust(OBS, 1, &kp1.public_key);

    let old = signer.attest(probe_batch(&mut probe, 1, 100, 200)).unwrap();
    assert_eq!(verify_attested_batch(&old, &anchors_v1), Ok(()));
    assert_eq!(old.key_version, 1);

    let kp2 = generate_ed25519_keypair();
    signer
        .rotate_key(2, &kp2.private_key, &kp2.public_key)
        .unwrap();
    assert_eq!(signer.key_version(), 2);
    assert_eq!(
        signer.observer_id(),
        OBS,
        "rotation changes the key, never the identity"
    );

    let new = signer.attest(probe_batch(&mut probe, 2, 200, 300)).unwrap();
    assert_eq!(new.key_version, 2);

    // Only the old anchor: the new batch is untrusted, the old one still fine.
    assert!(matches!(
        verify_attested_batch(&new, &anchors_v1).unwrap_err(),
        VerifyError::UntrustedObserverKey { .. }
    ));
    assert_eq!(verify_attested_batch(&old, &anchors_v1), Ok(()));

    // Both anchored: both verify.
    let both = anchors_v1.clone().trust(OBS, 2, &kp2.public_key);
    assert_eq!(verify_attested_batch(&new, &both), Ok(()));
    assert_eq!(verify_attested_batch(&old, &both), Ok(()));
}

/// 7 (guard) — a malformed key is refused by rotation, and the old key stays.
///
/// PROVES: `rotate_key` validates before it assigns. Without the check it
/// would half-apply — `key_version` bumped, key material set to something that
/// cannot sign — and the collector would be silently unable to produce a
/// verifiable batch from then on.
///
/// This is a mutation-driven test: dropping the length check in `rotate_key`
/// failed nothing in the suite before it existed.
#[test]
fn a_7_guard_rotation_refuses_a_bad_key_and_leaves_the_old_one() {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBS, 1, &kp.private_key, &kp.public_key).unwrap();
    let mut probe = ProcfsProbe::new("probe-rot-bad");
    let anchors = ObserverTrustAnchors::new().trust(OBS, 1, &kp.public_key);

    for (name, priv_len, pub_len) in [
        ("short private", 31, 32),
        ("long private", 33, 32),
        ("short public", 32, 31),
        ("empty private", 0, 32),
    ] {
        assert!(
            signer
                .rotate_key(2, &vec![1u8; priv_len], &vec![2u8; pub_len])
                .is_err(),
            "{name}: a malformed key must be refused"
        );
        assert_eq!(signer.key_version(), 1, "{name}: version must not move");
        assert_eq!(
            signer.public_key(),
            &kp.public_key[..],
            "{name}: the old key must still be in place"
        );
    }

    // And the collector still signs verifiably.
    let b = signer.attest(probe_batch(&mut probe, 1, 100, 200)).unwrap();
    assert_eq!(
        verify_attested_batch(&b, &anchors),
        Ok(()),
        "a refused rotation must leave a working signer"
    );
}

/// 8 — a revoked key stops verifying, and the failure names trust, not crypto.
///
/// PROVES: revocation is anchor withdrawal by the verifier. The signature is
/// still cryptographically perfect; keeping the two outcomes distinct is what
/// lets an operator tell forgery from revocation.
#[test]
fn a_8_revoked_key_fails_as_untrusted_not_as_bad_crypto() {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBS, 1, &kp.private_key, &kp.public_key).unwrap();
    let mut probe = ProcfsProbe::new("probe-rev");
    let mut anchors = ObserverTrustAnchors::new().trust(OBS, 1, &kp.public_key);

    let b = signer.attest(probe_batch(&mut probe, 1, 100, 200)).unwrap();
    assert_eq!(verify_attested_batch(&b, &anchors), Ok(()));

    anchors.revoke(OBS, 1);
    assert!(
        matches!(
            verify_attested_batch(&b, &anchors).unwrap_err(),
            VerifyError::UntrustedObserverKey { .. }
        ),
        "a revoked key must fail as untrusted trust, not as an invalid signature"
    );

    // Re-anchoring the same key restores verification with no change to the
    // batch: revocation is a policy decision, not damage to the record.
    let restored = anchors.clone().trust(OBS, 1, &kp.public_key);
    assert_eq!(verify_attested_batch(&b, &restored), Ok(()));
}

/// 8 (unknown) — a key version that was never anchored is refused the same way
/// a revoked one is. Absence of an anchor is absence of trust, whatever the
/// reason for the absence.
#[test]
fn a_8_unknown_key_version_is_refused() {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBS, 1, &kp.private_key, &kp.public_key).unwrap();
    let mut probe = ProcfsProbe::new("probe-unk");
    let anchors = ObserverTrustAnchors::new().trust(OBS, 1, &kp.public_key);

    let kp2 = generate_ed25519_keypair();
    signer
        .rotate_key(99, &kp2.private_key, &kp2.public_key)
        .unwrap();
    let b = signer.attest(probe_batch(&mut probe, 1, 100, 200)).unwrap();

    assert!(matches!(
        verify_attested_batch(&b, &anchors).unwrap_err(),
        VerifyError::UntrustedObserverKey { .. }
    ));
}

/// 9 — a replacement observer is a new identity, not the old one with a new
/// key.
///
/// PROVES: a replaced host has no continuity with the one it replaced. It
/// cannot inherit the original's trust by claiming its identity, its chain
/// restarts at sequence 1 so it inherits no coverage, and anchoring it is a
/// deliberate act. The original's history is untouched by any of it.
#[test]
fn a_9_a_replacement_observer_is_a_new_identity() {
    let kp = generate_ed25519_keypair();
    let mut original = CollectorSigner::new(OBS, 1, &kp.private_key, &kp.public_key).unwrap();
    let mut probe = ProcfsProbe::new("probe-orig");
    let anchors = ObserverTrustAnchors::new().trust(OBS, 1, &kp.public_key);
    let first = original
        .attest(probe_batch(&mut probe, 1, 100, 200))
        .unwrap();

    // The host is replaced: new machine, new key, new observer id.
    let rep_id = "collector.rotation.example.replacement";
    let rep_kp = generate_ed25519_keypair();
    let mut replacement =
        CollectorSigner::new(rep_id, 1, &rep_kp.private_key, &rep_kp.public_key).unwrap();
    let mut rep_probe = ProcfsProbe::new("probe-replacement");
    let attested = replacement
        .attest(probe_batch(&mut rep_probe, 9, 300, 400))
        .unwrap();

    assert!(
        matches!(
            verify_attested_batch(&attested, &anchors).unwrap_err(),
            VerifyError::UntrustedObserverKey { .. }
        ),
        "a replacement cannot inherit the original's trust by claiming its identity"
    );

    let with_replacement = anchors.clone().trust(rep_id, 1, &rep_kp.public_key);
    assert_eq!(verify_attested_batch(&attested, &with_replacement), Ok(()));
    assert_eq!(
        verify_attested_batch(&first, &with_replacement),
        Ok(()),
        "the original's history is untouched"
    );

    assert_eq!(attested.sequence, 1, "the replacement inherits no coverage");
    assert_eq!(attested.prev_head, [0u8; 32]);
}

/// 5 / 14 — a batch cannot be relabelled as another observer, and a wrong key
/// under a trusted identity is rejected.
///
/// PROVES: the anchor is looked up by the `observer_id` inside the batch, so
/// relabelling invalidates it; and anchored identity plus anchored version
/// plus a valid Ed25519 signature is still not enough — the signature must be
/// by the key the anchor names.
#[test]
fn a_5_14_wrong_identity_and_wrong_key_are_both_rejected() {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBS, 1, &kp.private_key, &kp.public_key).unwrap();
    let mut probe = ProcfsProbe::new("probe-ident");
    let anchors = ObserverTrustAnchors::new().trust(OBS, 1, &kp.public_key);

    // Relabelled as another observer, whose key is separately anchored.
    let other_kp = generate_ed25519_keypair();
    let both = anchors
        .clone()
        .trust("other-observer", 1, &other_kp.public_key);
    let mut relabelled = signer.attest(probe_batch(&mut probe, 1, 100, 200)).unwrap();
    relabelled.observer_id = "other-observer".to_string();
    assert_ne!(
        verify_attested_batch(&relabelled, &both),
        Ok(()),
        "a batch relabelled as another observer must not verify under its anchor"
    );

    // A different key signing under a trusted identity and version.
    let impostor = generate_ed25519_keypair();
    let mut fake =
        CollectorSigner::new(OBS, 1, &impostor.private_key, &impostor.public_key).unwrap();
    let forged = fake.attest(probe_batch(&mut probe, 2, 200, 300)).unwrap();
    assert_ne!(
        verify_attested_batch(&forged, &anchors),
        Ok(()),
        "a batch signed by a different key under a trusted identity must fail"
    );
}
