//! Observer key custody: rotation, revocation, replacement, and ownership.
//!
//! Mandated tests 5 (a wrong identity cannot use the signer), 7 (rotation),
//! 8 (revoked key), 9 (replacement key), 14 (wrong key identity) and 15
//! (observer-key ownership remains in `aip-observe`).
//!
//! The point of the whole file: **custody is not trust.** How the observer key
//! is stored has no bearing on whether a verifier accepts a batch signed with
//! it. Trust lives in [`ObserverTrustAnchors`], keyed by
//! `(observer_id, key_version)`, and nothing in the custody layer can add an
//! anchor, remove one, or make a verifier consult a different set.

use std::fs;
use std::path::PathBuf;

use aip_crypto::generate_ed25519_keypair;
use aip_custody::{CustodyClass, CustodyPolicy, KeyCustody};
use aip_observe::*;
use aip_types::KeyPair;

const OBSERVER: &str = "collector.custody.example";
const V1: u32 = 1;
const V2: u32 = 2;

struct Fx {
    signer: CollectorSigner,
    kp: KeyPair,
    anchors: ObserverTrustAnchors,
    probe: ProcfsProbe,
}

fn fixture() -> Fx {
    let kp = generate_ed25519_keypair();
    let signer = CollectorSigner::new(OBSERVER, V1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = ObserverTrustAnchors::new().trust(OBSERVER, V1, &kp.public_key);
    Fx {
        signer,
        kp,
        anchors,
        probe: ProcfsProbe::new("probe-custody-1"),
    }
}

fn process(pid: u32) -> ObservedProcess {
    ObservedProcess {
        process: aip_types::ProcessInstance {
            pid,
            pid_start_time_ticks: 1000,
            boot_id: [0xb0; 16],
        },
        exe_content_sha256: [0xe0; 32],
        exe_path: "/opt/agent/bin/agent".into(),
    }
}

fn batch(f: &mut Fx, id: u8, from: u64, to: u64) -> ObservationBatch {
    let obs = f
        .probe
        .observation(process(42), ObservedEffect::ProcessPresent, None, from);
    f.probe.batch([id; 16], from, to, vec![obs])
}

fn strip_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let (mut i, mut in_line, mut in_block) = (0usize, false, false);
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push('\n');
            }
            i += 1;
        } else if in_block {
            if c == '*' && next == Some('/') {
                in_block = false;
                i += 2;
            } else {
                if c == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
        } else if c == '/' && next == Some('/') {
            in_line = true;
            i += 2;
        } else if c == '/' && next == Some('*') {
            in_block = true;
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

// ─── 5 / 14. a wrong identity cannot use the signer ───

/// A batch signed by observer A is not accepted as observer B's, even when B's
/// key is anchored and the signature is cryptographically perfect.
///
/// The anchor is looked up by the `observer_id` *inside* the batch, so
/// relabelling a batch invalidates it. There is no path by which holding one
/// observer's key lets you speak as another.
#[test]
fn t05_a_batch_cannot_be_relabelled_as_another_observer() {
    let mut f = fixture();
    let b = batch(&mut f, 1, 100, 200);
    let mut a = f.signer.attest(b).unwrap();
    assert_eq!(verify_attested_batch(&a, &f.anchors), Ok(()));

    // Another observer, separately anchored.
    let other_kp = generate_ed25519_keypair();
    let anchors = f.anchors.clone().trust("other-observer", V1, &other_kp.public_key);

    a.observer_id = "other-observer".to_string();
    assert_ne!(
        verify_attested_batch(&a, &anchors),
        Ok(()),
        "a batch relabelled as another observer must not verify under that \
         observer's anchor"
    );
}

/// Signing with the wrong key under a trusted identity is rejected.
///
/// Anchored identity plus anchored version plus a valid Ed25519 signature is
/// not enough: the signature must be by the key the anchor names.
#[test]
fn t14_wrong_key_under_a_trusted_identity_is_rejected() {
    let mut f = fixture();
    let impostor = generate_ed25519_keypair();
    let mut fake =
        CollectorSigner::new(OBSERVER, V1, &impostor.private_key, &impostor.public_key).unwrap();

    let b = batch(&mut f, 1, 100, 200);
    let a = fake.attest(b).unwrap();

    // The anchors trust (OBSERVER, V1) — but with the real key.
    assert_ne!(
        verify_attested_batch(&a, &f.anchors),
        Ok(()),
        "a batch signed by a different key under a trusted identity must fail"
    );
}

// ─── 7. rotation ───

/// After rotation, new batches verify under the new version and history
/// verifies under the old one — as long as the verifier keeps both anchors.
#[test]
fn t07_rotation_keeps_history_verifiable() {
    let mut f = fixture();
    let old = batch(&mut f, 1, 100, 200);
    let attested_old = f.signer.attest(old).unwrap();
    assert_eq!(verify_attested_batch(&attested_old, &f.anchors), Ok(()));
    assert_eq!(attested_old.key_version, V1);

    let new_kp = generate_ed25519_keypair();
    f.signer
        .rotate_key(V2, &new_kp.private_key, &new_kp.public_key)
        .unwrap();
    assert_eq!(f.signer.key_version(), V2);
    assert_eq!(
        f.signer.observer_id(),
        OBSERVER,
        "rotation changes the key, never the identity"
    );

    let new = batch(&mut f, 2, 200, 300);
    let attested_new = f.signer.attest(new).unwrap();
    assert_eq!(attested_new.key_version, V2);

    // Only the old anchor: the new batch is untrusted, the old one still fine.
    assert_ne!(verify_attested_batch(&attested_new, &f.anchors), Ok(()));
    assert_eq!(verify_attested_batch(&attested_old, &f.anchors), Ok(()));

    // Both anchored: both verify. This is what "do not silently break
    // historical proof verification" means in practice.
    let both = f.anchors.clone().trust(OBSERVER, V2, &new_kp.public_key);
    assert_eq!(verify_attested_batch(&attested_new, &both), Ok(()));
    assert_eq!(verify_attested_batch(&attested_old, &both), Ok(()));
}

/// Rotation refuses a malformed key rather than half-applying one.
#[test]
fn t07_rotation_refuses_a_bad_key_and_leaves_the_old_one() {
    let mut f = fixture();
    let before_version = f.signer.key_version();
    let before_public = f.signer.public_key().to_vec();

    assert!(f.signer.rotate_key(V2, &[0u8; 31], &[0u8; 32]).is_err());
    assert_eq!(f.signer.key_version(), before_version);
    assert_eq!(f.signer.public_key(), &before_public[..]);

    let b = batch(&mut f, 1, 100, 200);
    let a = f.signer.attest(b).unwrap();
    assert_eq!(
        verify_attested_batch(&a, &f.anchors),
        Ok(()),
        "a refused rotation must leave a working signer"
    );
}

// ─── 8. revoked key ───

/// Revoking an anchor stops verification for that `(observer, version)` pair,
/// and the failure is a *trust* failure, distinct from a cryptographic one.
#[test]
fn t08_revoked_key_stops_verifying_and_says_why() {
    let mut f = fixture();
    let b = batch(&mut f, 1, 100, 200);
    let a = f.signer.attest(b).unwrap();
    assert_eq!(verify_attested_batch(&a, &f.anchors), Ok(()));

    f.anchors.revoke(OBSERVER, V1);
    let err = verify_attested_batch(&a, &f.anchors).unwrap_err();
    assert!(
        matches!(err, VerifyError::UntrustedObserverKey { .. }),
        "a revoked key must fail as unknown trust, not as a bad signature: {err:?}"
    );

    // The signature itself is still cryptographically valid — the verifier's
    // refusal is a policy decision, and keeping the two distinct is what lets
    // an operator tell forgery from revocation. Re-anchoring the same key
    // restores verification with no change to the batch.
    let restored = f.anchors.clone().trust(OBSERVER, V1, &f.kp.public_key);
    assert_eq!(
        verify_attested_batch(&a, &restored),
        Ok(()),
        "revocation is a trust decision, not damage to the batch"
    );
}

/// An unknown key version is refused the same way a revoked one is: absence of
/// an anchor is absence of trust, whatever the reason for the absence.
#[test]
fn t08_unknown_key_version_is_refused() {
    let mut f = fixture();
    let new_kp = generate_ed25519_keypair();
    f.signer
        .rotate_key(99, &new_kp.private_key, &new_kp.public_key)
        .unwrap();

    let b = batch(&mut f, 1, 100, 200);
    let a = f.signer.attest(b).unwrap();
    let err = verify_attested_batch(&a, &f.anchors).unwrap_err();
    assert!(
        matches!(err, VerifyError::UntrustedObserverKey { .. }),
        "{err:?}"
    );
}

// ─── 9. replacement key / host replacement ───

/// A replacement observer is a different observer, not the same one with a new
/// key.
///
/// A replaced host has no continuity with the one it replaced: it cannot
/// inherit the old observer's identity, and anchoring it is a deliberate act.
#[test]
fn t09_a_replacement_observer_is_a_new_identity() {
    let mut f = fixture();
    let b = batch(&mut f, 1, 100, 200);
    let original = f.signer.attest(b).unwrap();

    // The host is replaced: new machine, new key, new observer id.
    let replacement_kp = generate_ed25519_keypair();
    let mut replacement = CollectorSigner::new(
        "collector.custody.example.replacement",
        1,
        &replacement_kp.private_key,
        &replacement_kp.public_key,
    )
    .unwrap();
    let mut probe = ProcfsProbe::new("probe-custody-2");
    let obs = probe.observation(process(42), ObservedEffect::ProcessPresent, None, 300);
    let rb = probe.batch([9u8; 16], 300, 400, vec![obs]);
    let attested = replacement.attest(rb).unwrap();

    // Not trusted until the verifier anchors it — the replacement cannot
    // inherit the original's trust by claiming its identity.
    assert!(matches!(
        verify_attested_batch(&attested, &f.anchors).unwrap_err(),
        VerifyError::UntrustedObserverKey { .. }
    ));

    let anchors = f.anchors.clone().trust(
        "collector.custody.example.replacement",
        1,
        &replacement_kp.public_key,
    );
    assert_eq!(verify_attested_batch(&attested, &anchors), Ok(()));

    // The original's history is untouched by any of this.
    assert_eq!(verify_attested_batch(&original, &anchors), Ok(()));

    // And the replacement's chain starts at 1: it inherits no coverage.
    assert_eq!(attested.sequence, 1);
    assert_eq!(attested.prev_head, [0u8; 32]);
}

// ─── 15. observer-key ownership remains in aip-observe ───

/// The observer key is held by `CollectorSigner`, in this crate, and the
/// custody layer only describes it.
#[test]
fn t15_collector_reports_custody_without_surrendering_the_key() {
    let f = fixture();
    assert_eq!(f.signer.key_id(), OBSERVER);
    assert_eq!(f.signer.key_version(), V1);
    assert_eq!(f.signer.public_key(), &f.kp.public_key[..]);
    assert_eq!(f.signer.custody_class(), CustodyClass::Development);

    // Honest classification: an operator-supplied in-memory key is development
    // custody, and a production policy says so.
    let err = aip_custody::admits(CustodyPolicy::Production, &f.signer).unwrap_err();
    assert!(matches!(
        err,
        aip_custody::CustodyError::PolicyRefused { .. }
    ));
}

/// `CollectorSigner` implements `KeyCustody` and **not** `SigningCustodian`.
///
/// Deliberate. `SigningCustodian` would give the collector a general
/// `sign(&[u8])` — a raw-signing oracle over the observer key. A caller could
/// then obtain the observer's signature over bytes that are a valid preimage
/// for some other protocol in this workspace. The collector's only signing
/// surface stays `attest`, whose input it constructs itself.
///
/// Structural, because the defect is an `impl` somebody adds later.
#[test]
fn t15_structural_collector_has_no_general_signing_oracle() {
    let src = strip_comments(
        &fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/attest.rs"))
            .unwrap(),
    );

    assert!(
        src.contains("impl KeyCustody for CollectorSigner"),
        "the collector must report its custody"
    );
    assert!(
        !src.contains("impl SigningCustodian for CollectorSigner"),
        "the collector must not gain a general signing oracle over the observer key"
    );

    // And no accessor hands the key out.
    for l in src.lines().map(str::trim) {
        if l.starts_with("pub fn ") {
            assert!(
                !l.contains("private_key"),
                "attest.rs exposes the observer private key: {l}"
            );
        }
    }
}

/// The observer key does not leave this crate, and no other crate constructs a
/// custodian over it.
///
/// The brief's requirement, checked rather than asserted: the key is not moved
/// into reconciliation, into a platform layer, or into packaging.
#[test]
fn t15_structural_no_other_crate_holds_the_observer_key() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();

    let mut offenders = Vec::new();
    let mut stack = vec![workspace.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            if p.is_dir() {
                if name != "target" && !name.starts_with('.') {
                    stack.push(p);
                }
                continue;
            }
            if p.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            // The collector's own crate is where the key belongs.
            if p.starts_with(workspace.join("aip-observe")) {
                continue;
            }
            let Ok(src) = fs::read_to_string(&p) else {
                continue;
            };
            let code = strip_comments(&src);
            if code.contains("impl SigningCustodian for CollectorSigner")
                || code.contains("impl KeyCustody for CollectorSigner")
            {
                offenders.push(p.display().to_string());
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "the observer key's custody is implemented outside aip-observe: {offenders:?}"
    );
}
