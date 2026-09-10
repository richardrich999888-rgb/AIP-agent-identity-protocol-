//! Phase A — private-key custody, RED.
//!
//! The production blocker is that `IdentityStore` persists private keys as
//! plaintext JSON, and that nothing anywhere distinguishes a store that may
//! do so from one that may not. Two demonstrations against the current API.
//!
//! The second is the one that matters for the collector key: `aip-observe`
//! offers no custody path at all, so a deployer's only worked example is
//! the demo binary, which writes a hex private key with default
//! permissions. A key that anchors every attested observation deserves
//! better than being copied out of a demo.

use aip_core::create_identity;
use aip_core::store::{IdentityStore, Persistence, StoreError};
use aip_types::ProvenanceTriple;

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: aip_crypto::sha256(format!("m-{tag}").as_bytes()),
        environment_commitment: aip_crypto::sha256(format!("e-{tag}").as_bytes()),
        toolchain_commitment: aip_crypto::sha256(format!("t-{tag}").as_bytes()),
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("aip-custody-{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// PHASE A DEFECT — a store that persists private keys in the clear, and no
/// way to say it must not.
///
/// INVARIANT: a production deployment must not be able to write private key
/// material as plaintext, and must not be able to do so *by accident* —
/// which is what a single `with_file` constructor with no mode makes
/// inevitable.
///
/// MODELS: an operator persisting identities the documented way, on a host
/// whose filesystem is later read by anyone with a backup, a stray
/// container mount, or a support bundle.
///
/// DOES NOT PROVE: that the store is wrong to persist keys at all in
/// development, where it is a convenience with no secret worth taking.
#[test]
fn a1_a_production_store_must_refuse_to_write_a_private_key_in_the_clear() {
    let path = tmp("plaintext");
    let (aid, kp) = create_identity(provenance("agent"), None).unwrap();
    let secret = kp.private_key.clone();

    let mut store = IdentityStore::with_file(&path, Persistence::ProductionNoSecrets).unwrap();
    store.put_identity(aid, kp);

    // A production store refuses, and names how much it is refusing rather
    // than writing a quietly incomplete file.
    match store.save() {
        Err(aip_core::store::StoreError::SecretsRefused(n)) => assert_eq!(n, 1),
        other => panic!("a production store wrote private key material: {other:?}"),
    }
    assert!(
        !path.exists(),
        "a refused save must leave no file behind at all"
    );

    // The development store may write it — that is what it is for — but
    // never at mode 644, and the file must actually be readable back.
    let mut dev = IdentityStore::with_file(&path, Persistence::DevelopmentPlaintext).unwrap();
    let (aid2, kp2) = create_identity(provenance("agent"), None).unwrap();
    dev.put_identity(aid2, kp2);
    dev.save().unwrap();

    // Read the file back as data rather than as text: the JSON is
    // pretty-printed, so the key's bytes are one per line and a naive
    // substring search finds nothing while the secret sits there in full.
    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut found: Option<Vec<u8>> = None;
    if let Some(ids) = written.get("identities").and_then(|x| x.as_object()) {
        for (_, v) in ids {
            if let Some(bytes) = v.pointer("/keypair/private_key").and_then(|x| x.as_array()) {
                found = Some(
                    bytes
                        .iter()
                        .filter_map(|b| b.as_u64())
                        .map(|b| b as u8)
                        .collect(),
                );
            }
        }
    }
    // The first identity's key never reached the disk, because that save
    // was refused.
    assert_ne!(
        found.as_deref(),
        Some(secret.as_slice()),
        "the production store's private key reached {} anyway",
        path.display()
    );
    let _ = std::fs::remove_file(&path);
}

/// PHASE A DEFECT — the file carrying it is world-readable by default.
///
/// INVARIANT: whatever a development store writes, it must not be readable
/// by every account on the host. `aip-service` already sets 0600 on its
/// seed file; `aip-core` sets nothing.
///
/// DOES NOT PROVE: that 0600 is sufficient protection. It is not — it is
/// the floor below which nothing else matters, and the fix for the
/// production case is custody, not permissions.
#[test]
#[cfg(unix)]
fn a2_the_store_file_must_not_be_readable_by_everyone() {
    use std::os::unix::fs::PermissionsExt;

    let path = tmp("perms");
    let (aid, kp) = create_identity(provenance("agent"), None).unwrap();
    let mut store = IdentityStore::with_file(&path, Persistence::DevelopmentPlaintext).unwrap();
    store.put_identity(aid, kp);
    store.save().unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode & 0o077,
        0,
        "{} is mode {mode:o}; group and other can read a file holding key material",
        path.display()
    );
    let _ = std::fs::remove_file(&path);
}

/// PHASE A DEFECT — `aip-observe` offers no custody for the one key whose
/// compromise forges every attested observation.
///
/// INVARIANT: the collector's signing key must have a supported way to
/// exist at rest that is not "write the bytes to a file yourself". The
/// ownership of that path must sit in `aip-observe` and nowhere else.
///
/// MODELS: a deployer following the only worked example in the repository —
/// `ghost-demo-collector`, which writes a hex private key with default
/// permissions — because nothing better is offered.
///
/// DOES NOT PROVE: that a custodian makes the observation truthful. It does
/// not. A protected key says who signed; it says nothing about whether what
/// was signed is true.
#[test]
fn a3_aip_observe_must_own_a_custody_path_for_the_collector_key() {
    let observe_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../aip-observe/src/lib.rs"
    ))
    .unwrap();
    assert!(
        observe_src.contains("custody"),
        "aip-observe exposes no custody module, so the collector key has no \
         supported way to exist at rest"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Phase A matrix — the fifteen
//
// Numbering follows the mandate. Where a requirement is met by a mechanism
// that already existed, the test says so rather than pretending this work
// introduced it.
// ═══════════════════════════════════════════════════════════════════

use aip_crypto::custody::{
    Backend, Custodian, CustodyError, InMemoryCustodian, WrappedFileCustodian,
};

const PASS: &[u8] = b"correct horse battery staple";

fn keyfile(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("aip-key-{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// 2 & 3 — the secure backend signs, and what it signs verifies.
///
/// PROVES: custody changes where a key lives, not what a signature means.
/// A wrapped-file custodian's signature verifies under the same
/// `verify_ed25519` as any other, because there is one envelope.
#[test]
fn a_2_3_the_secure_backend_signs_and_verification_is_unchanged() {
    let path = keyfile("sign");
    let c = WrappedFileCustodian::create(&path, PASS).unwrap();
    assert_eq!(c.backend(), Backend::WrappedFile);
    assert!(c.backend().is_production());

    let sig = c.sign("collector-1", b"an attested batch").unwrap();
    assert!(aip_crypto::verify_ed25519(c.public_key(), &sig).unwrap());

    // Reopened in a fresh custodian, the same key still verifies — this is
    // the reboot/reload case (11).
    drop(c);
    let again = WrappedFileCustodian::open(&path, PASS).unwrap();
    let sig2 = again.sign("collector-1", b"another batch").unwrap();
    assert!(aip_crypto::verify_ed25519(again.public_key(), &sig2).unwrap());
    let _ = std::fs::remove_file(&path);
}

/// 4 & 5 — the private key is not obtainable through the custodian, by
/// anyone.
///
/// PROVES: structurally. `Custodian` has no method returning key material,
/// so there is no call an unauthorized caller could make. Checked against
/// the source because the property is the *absence* of an accessor and an
/// absence cannot be invoked.
///
/// DOES NOT PROVE: that the key is unreachable. A caller who can read this
/// process's memory has it. That is what a hardware backend addresses and
/// it is not implemented — `ADR-KEY-CUSTODY.md` says so.
#[test]
fn a_4_5_no_caller_can_obtain_the_private_key_through_the_custodian() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../aip-crypto/src/custody.rs"
    ))
    .unwrap();
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let trait_at = code.find("pub trait Custodian").unwrap();
    let trait_body = &code[trait_at..code[trait_at..].find('}').unwrap() + trait_at];
    assert!(
        !trait_body.contains("private_key") && !trait_body.contains("secret"),
        "the Custodian trait grew a way to hand back key material:\n{trait_body}"
    );
    // And no backend offers one on the side.
    assert!(
        !code.contains("pub fn private_key"),
        "a custody backend exposes the private key"
    );
}

/// 7 — the wrong identity cannot sign.
///
/// PROVES: the signer id is inside the signed envelope, so a signature
/// made as one collector does not verify as another. This is pre-existing
/// (`audit.rs::a04`) and is asserted here through the custody path to show
/// custody did not weaken it.
#[test]
fn a_7_the_wrong_identity_cannot_sign() {
    let path = keyfile("identity");
    let c = WrappedFileCustodian::create(&path, PASS).unwrap();
    let mut sig = c.sign("collector-1", b"payload").unwrap();
    assert!(aip_crypto::verify_ed25519(c.public_key(), &sig).unwrap());
    sig.signer_id = "collector-2".into();
    assert!(!aip_crypto::verify_ed25519(c.public_key(), &sig).unwrap());
    let _ = std::fs::remove_file(&path);
}

/// 8 — a revoked key is rejected.
///
/// PROVES: through the mechanism this system actually has. Revocation here
/// is withdrawal of a trust anchor by the verifier — a key is "revoked"
/// when no verifier anchors it. Custody deliberately does not add a second
/// revocation model, so this asserts the existing one still holds over a
/// custody-produced signature.
#[test]
fn a_8_a_key_no_verifier_anchors_is_rejected() {
    let path = keyfile("revoked");
    let c = WrappedFileCustodian::create(&path, PASS).unwrap();
    let sig = c.sign("collector-1", b"payload").unwrap();

    // The verifier's anchor set is somebody else's key: the signature is
    // perfectly valid and belongs to nobody this verifier trusts.
    let other = InMemoryCustodian::generate();
    assert!(!aip_crypto::verify_ed25519(other.public_key(), &sig).unwrap());
    let _ = std::fs::remove_file(&path);
}

/// 9 & 10 — rotation and replacement.
///
/// PROVES: rotation produces a different key, and history signed under the
/// old one stays verifiable for anyone holding the old public key —
/// verification never consults custody, so rotation is not retroactive.
#[test]
fn a_9_10_rotation_and_replacement() {
    let path = keyfile("rotate");
    let first = WrappedFileCustodian::create(&path, PASS).unwrap();
    let old_public = first.public_key().to_vec();
    let old_sig = first.sign("collector-1", b"before rotation").unwrap();
    drop(first);

    let second = WrappedFileCustodian::rotate(&path, PASS).unwrap();
    assert_ne!(
        second.public_key(),
        old_public.as_slice(),
        "rotation must change the key"
    );

    // History stays verifiable under the old anchor.
    assert!(aip_crypto::verify_ed25519(&old_public, &old_sig).unwrap());
    // And the old key cannot verify the new one's work.
    let new_sig = second.sign("collector-1", b"after rotation").unwrap();
    assert!(!aip_crypto::verify_ed25519(&old_public, &new_sig).unwrap());
    assert!(aip_crypto::verify_ed25519(second.public_key(), &new_sig).unwrap());
    let _ = std::fs::remove_file(&path);
}

/// 12 & 13 — corrupt and missing key material fail closed.
///
/// PROVES: every malformed shape is an error, never a fallback to a
/// generated key or an empty one. A wrong passphrase and a tampered file
/// are one error because an AEAD cannot tell them apart.
#[test]
fn a_12_13_corrupt_and_missing_material_fail_closed() {
    let path = keyfile("corrupt");

    // Missing.
    assert!(matches!(
        WrappedFileCustodian::open(&path, PASS),
        Err(CustodyError::Io(_))
    ));

    let c = WrappedFileCustodian::create(&path, PASS).unwrap();
    drop(c);
    let good = std::fs::read(&path).unwrap();

    // Wrong passphrase.
    assert!(matches!(
        WrappedFileCustodian::open(&path, b"wrong"),
        Err(CustodyError::CannotOpen)
    ));

    // A flipped ciphertext byte.
    let mut torn = good.clone();
    *torn.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &torn).unwrap();
    assert!(matches!(
        WrappedFileCustodian::open(&path, PASS),
        Err(CustodyError::CannotOpen)
    ));

    // A flipped header byte — the header is the AEAD's associated data, so
    // editing it fails to open rather than opening something else.
    let mut header = good.clone();
    header[10] ^= 1;
    std::fs::write(&path, &header).unwrap();
    assert!(WrappedFileCustodian::open(&path, PASS).is_err());

    // Wrong magic, at the *right length* — otherwise the length check
    // fires first and the magic check is never exercised, which is how a
    // removed magic check hides behind a passing test.
    let mut wrong_magic = good.clone();
    wrong_magic[0] ^= 0xff;
    std::fs::write(&path, &wrong_magic).unwrap();
    match WrappedFileCustodian::open(&path, PASS) {
        Err(CustodyError::Malformed(why)) => assert!(
            why.contains("magic"),
            "a full-length file with wrong magic must be refused for the magic, got {why:?}"
        ),
        other => panic!("wrong magic was not refused as malformed: {other:?}"),
    }

    // A version this build does not implement.
    let mut future = good.clone();
    future[8..10].copy_from_slice(&99u16.to_be_bytes());
    std::fs::write(&path, &future).unwrap();
    assert!(matches!(
        WrappedFileCustodian::open(&path, PASS),
        Err(CustodyError::UnsupportedVersion(99))
    ));

    // Truncated.
    std::fs::write(&path, &good[..10]).unwrap();
    assert!(matches!(
        WrappedFileCustodian::open(&path, PASS),
        Err(CustodyError::Malformed(_))
    ));
    let _ = std::fs::remove_file(&path);
}

/// 6 (store side) — a production store never falls back to plaintext.
///
/// PROVES: the refusal is total. No partial file, no stripped keys, no
/// downgrade to the development mode. The collector side of requirement 6
/// is in `aip-observe/tests/custody.rs`.
#[test]
fn a_6_a_production_store_never_falls_back() {
    let path = tmp("nofallback");
    let (aid, kp) = create_identity(provenance("x"), None).unwrap();
    let mut store = IdentityStore::with_file(&path, Persistence::ProductionNoSecrets).unwrap();
    store.put_identity(aid, kp);
    assert!(store.save().is_err());
    assert!(!path.exists(), "a refused save must leave nothing behind");
}

// ─── The key does not come back out ───
//
// `Persistence::ProductionNoSecrets` stops `save` from writing a private key.
// It cannot stop anything else in the process from reading one, and until the
// field was made private there were two ways around it: `pub keypair` handed
// the raw key to any caller, and `derive(Serialize)` on `StoredIdentity` put it
// into any JSON somebody serialized the struct into. Both are closed
// structurally, because both failure modes are future edits that would compile.

/// Comment-stripped source, so a guard reads code and not the prose describing
/// the thing it forbids.
fn store_code() -> String {
    let src = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/store.rs"),
    )
    .unwrap();
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn stored_identity_keypair_is_private_and_unserializable() {
    let code = store_code();

    let decl = code
        .split("pub struct StoredIdentity {")
        .nth(1)
        .expect("StoredIdentity must exist")
        .split('}')
        .next()
        .unwrap();
    assert!(
        !decl.contains("pub keypair"),
        "StoredIdentity::keypair must be private; a public field is a key \
         accessor by another name: {decl}"
    );
    assert!(decl.contains("keypair: KeyPair"), "{decl}");

    let derive = code
        .split("pub struct StoredIdentity {")
        .next()
        .unwrap()
        .lines()
        .rfind(|l| l.trim_start().starts_with("#[derive"))
        .unwrap_or("");
    assert!(
        !derive.contains("Serialize") && !derive.contains("Deserialize"),
        "StoredIdentity must carry no serialization derive: {derive}"
    );

    for l in code.lines().map(str::trim) {
        if l.starts_with("pub fn ") {
            let name = l.trim_start_matches("pub fn ").split('(').next().unwrap();
            assert!(
                !["private_key", "keypair", "secret", "export"].contains(&name),
                "store.rs exposes `pub fn {name}`, an export path for key material"
            );
        }
    }
}

/// Key material is written from exactly one place, and read from exactly one.
#[test]
fn key_material_crosses_the_boundary_in_one_place_each() {
    let code = store_code();

    let save = code
        .split("pub fn save(&self)")
        .nth(1)
        .expect("save must exist")
        .split("pub fn reload")
        .next()
        .unwrap();
    assert_eq!(
        save.matches("keypair: e.keypair.clone()").count(),
        1,
        "key material must leave the store from exactly one place in save()"
    );

    let sign = code
        .split("pub fn sign(&self, payload: &[u8])")
        .nth(1)
        .expect("StoredIdentity::sign must exist")
        .split("pub fn respond_to_challenge")
        .next()
        .unwrap();
    assert!(
        sign.contains("InMemoryCustodian::new"),
        "signing must go through the custody interface, not a private \
         arrangement of the store's own: {sign}"
    );
}

/// A `ProductionNoSecrets` round trip leaves an identity that verifies but
/// cannot sign, and says so rather than failing obscurely later.
#[test]
fn production_roundtrip_yields_a_verifiable_but_unsignable_identity() {
    let dir = std::env::temp_dir().join(format!("aip-store-nosec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");

    let (aid, kp) = create_identity(provenance("nosec"), None).unwrap();
    let id = aid.id.clone();
    let public = aid.primary_key.key_bytes.clone();

    // A production store refuses to write a private key rather than stripping
    // it: writing less than the caller asked for, silently, is its own defect.
    {
        let mut store = IdentityStore::with_file(&path, Persistence::ProductionNoSecrets).unwrap();
        store.put_identity(aid.clone(), kp.clone());
        assert!(matches!(
            store.save().unwrap_err(),
            StoreError::SecretsRefused(1)
        ));
    }

    // Stored public-only, it saves, reloads, verifies — and refuses to sign.
    {
        let mut store = IdentityStore::with_file(&path, Persistence::ProductionNoSecrets).unwrap();
        store.put_identity(
            aid,
            aip_types::KeyPair {
                algorithm: kp.algorithm,
                public_key: kp.public_key.clone(),
                private_key: Vec::new(),
            },
        );
        store.save().unwrap();
    }

    let store = IdentityStore::with_file(&path, Persistence::ProductionNoSecrets).unwrap();
    let entry = store.get_identity(&id).unwrap();
    assert_eq!(entry.public_key(), &public[..], "the public key survives");
    assert!(!entry.can_sign());
    assert!(
        matches!(entry.sign(b"x").unwrap_err(), StoreError::NoPrivateKey(ref who) if who == &id),
        "an entry with no private key must say so"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
