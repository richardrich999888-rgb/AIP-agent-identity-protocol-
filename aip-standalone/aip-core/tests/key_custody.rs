//! Store custody: what the identity store will and will not write.
//!
//! Mandated tests 1 (plaintext persistence rejected in production) and 17
//! (the production backend cannot silently fall back to plaintext JSON), plus
//! the structural guards that keep them true.

use std::fs;
use std::path::PathBuf;

use aip_core::store::{IdentityStore, KeyPersistence, StoreError};
use aip_core::{activate_identity, create_identity};
use aip_crypto::{sha256, verify_ed25519};
use aip_custody::CustodyPolicy;
use aip_types::ProvenanceTriple;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aip_store_t_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    aip_custody::ensure_secret_dir(&dir).unwrap();
    dir
}

fn prov(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model:{tag}").as_bytes()),
        environment_commitment: sha256(format!("env:{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("tool:{tag}").as_bytes()),
    }
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

fn store_src() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/store.rs");
    strip_comments(&fs::read_to_string(p).unwrap())
}

// ─── 1. plaintext private-key persistence is rejected under a production policy ───

/// Asking for plaintext key persistence under a production policy is an error,
/// and no file is created as a side effect.
#[test]
fn t01_plaintext_persistence_refused_under_production_policy() {
    let dir = scratch("t01");
    let path = dir.join("store.json");

    let err = IdentityStore::with_file_and_plaintext_keys(&path, CustodyPolicy::Production)
        .expect_err("a production policy must refuse plaintext key persistence");
    assert!(
        matches!(err, StoreError::CustodyRefused(_)),
        "expected CustodyRefused, got {err:?}"
    );
    assert!(!path.exists(), "a refused open must not create the file");
}

/// Under the default constructor, a saved store contains no key material at
/// all — checked against the bytes on disk, not against an API.
#[test]
fn t01_saved_file_contains_no_private_key_bytes() {
    let dir = scratch("t01b");
    let path = dir.join("store.json");

    let (mut aid, kp) = create_identity(prov("t01b"), None).unwrap();
    activate_identity(&mut aid).unwrap();
    let private = kp.private_key.clone();

    let mut store = IdentityStore::with_file(&path).unwrap();
    assert_eq!(store.key_persistence(), KeyPersistence::Never);
    store.put_identity(aid, kp);
    store.save().unwrap();

    let written = fs::read_to_string(&path).unwrap();
    assert!(
        !written.contains("keypair"),
        "the saved store names a keypair field: {written}"
    );
    assert!(
        !written.contains("private_key"),
        "the saved store names a private_key field"
    );

    // And the bytes themselves are absent, in the encoding serde_json would
    // have used for a Vec<u8> — a byte array, not hex or base64.
    let as_json_array = format!(
        "[{}]",
        private
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let compact: String = written.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        !compact.contains(&as_json_array),
        "the saved store contains the raw private key bytes"
    );
}

/// The store file is created at mode 0600, whichever persistence it uses.
#[test]
fn t01_store_file_is_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("t01c");
    let path = dir.join("store.json");

    let mut store = IdentityStore::with_file(&path).unwrap();
    store.update_reputation("agent", 1);
    store.save().unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600, "the store file must not be readable by others");
}

// ─── 17. no silent fallback from production to plaintext JSON ───

/// Opening a legacy plaintext store with the production constructor is an
/// error, not a load.
///
/// The alternative — loading it and dropping the keys on the next save — is
/// silent, irreversible destruction of every private key in the file. Refusing
/// forces the migration to be a decision somebody makes.
#[test]
fn t17_legacy_plaintext_store_is_refused_not_silently_stripped() {
    let dir = scratch("t17");
    let path = dir.join("store.json");

    // A store written by an older build: plaintext key material.
    let (mut aid, kp) = create_identity(prov("t17"), None).unwrap();
    activate_identity(&mut aid).unwrap();
    let id = aid.id.clone();
    {
        let mut legacy =
            IdentityStore::with_file_and_plaintext_keys(&path, CustodyPolicy::Development).unwrap();
        legacy.put_identity(aid, kp);
        legacy.save().unwrap();
    }
    let before = fs::read(&path).unwrap();
    assert!(
        String::from_utf8_lossy(&before).contains("keypair"),
        "the fixture must actually contain key material"
    );

    // The production constructor refuses it.
    let err = IdentityStore::with_file(&path).unwrap_err();
    match err {
        StoreError::PlaintextKeysPresent { count, .. } => assert_eq!(count, 1),
        other => panic!("expected PlaintextKeysPresent, got {other:?}"),
    }
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "a refused open must not rewrite the file"
    );

    // The development path still opens it, and the key still works. Historical
    // fixtures are not invalidated.
    let dev =
        IdentityStore::with_file_and_plaintext_keys(&path, CustodyPolicy::Development).unwrap();
    let entry = dev.get_identity(&id).unwrap();
    assert!(entry.can_sign());
    let sig = entry.sign(b"still works").unwrap();
    assert!(verify_ed25519(entry.public_key(), &sig).unwrap());
}

/// After a production round trip the identity is public-only: verifiable, not
/// signable. The absence of the key is explicit, not a surprise at signing time.
#[test]
fn t17_reload_without_keys_is_public_only_and_says_so() {
    let dir = scratch("t17b");
    let path = dir.join("store.json");

    let (mut aid, kp) = create_identity(prov("t17b"), None).unwrap();
    activate_identity(&mut aid).unwrap();
    let id = aid.id.clone();
    let public = aid.primary_key.key_bytes.clone();

    let mut store = IdentityStore::with_file(&path).unwrap();
    store.put_identity(aid, kp);
    store.save().unwrap();

    let reloaded = IdentityStore::with_file(&path).unwrap();
    let entry = reloaded.get_identity(&id).unwrap();
    assert!(!entry.can_sign());
    assert_eq!(entry.custody_class(), None);
    assert_eq!(entry.public_key(), &public[..], "the public key survives");

    let err = entry.sign(b"nope").unwrap_err();
    assert!(
        matches!(err, StoreError::NoPrivateKey(ref who) if who == &id),
        "expected NoPrivateKey, got {err:?}"
    );
}

/// An in-memory key held by the store is classified as development custody,
/// and a production policy refuses it.
#[test]
fn t17_in_memory_key_is_development_custody() {
    let (mut aid, kp) = create_identity(prov("t17c"), None).unwrap();
    activate_identity(&mut aid).unwrap();
    let id = aid.id.clone();

    let mut store = IdentityStore::new();
    store.put_identity(aid, kp);
    let entry = store.get_identity(&id).unwrap();

    assert_eq!(
        entry.custody_class(),
        Some(aip_custody::CustodyClass::Development),
        "a key pair in a HashMap on the heap is development custody, however it \
         arrived"
    );
    assert!(!CustodyPolicy::Production.admits(aip_custody::CustodyClass::Development));
}

// ─── structural guards ───

/// `StoredIdentity` has no key accessor and no serialization derive.
///
/// Structural, because the defect it prevents is a future edit: a `pub keypair`
/// field or a `derive(Serialize)` would compile, and would put a private key
/// into every JSON response the type reaches.
#[test]
fn t02_structural_stored_identity_has_no_key_accessor() {
    let src = store_src();

    let decl = src
        .split("pub struct StoredIdentity {")
        .nth(1)
        .expect("StoredIdentity must exist")
        .split('}')
        .next()
        .unwrap();
    assert!(
        decl.contains("keypair: Option<KeyPair>") && !decl.contains("pub keypair"),
        "StoredIdentity::keypair must be private: {decl}"
    );

    // The derive immediately above the declaration.
    let derive = src
        .split("pub struct StoredIdentity {")
        .next()
        .unwrap()
        .lines()
        .rfind(|l| l.trim_start().starts_with("#[derive"))
        .unwrap_or("")
        .to_string();
    assert!(
        !derive.contains("Serialize") && !derive.contains("Deserialize"),
        "StoredIdentity must not derive serialization: {derive}"
    );

    for l in src.lines().map(str::trim) {
        if l.starts_with("pub fn ") && l.contains("private_key") {
            panic!("store.rs exposes a private-key accessor: {l}");
        }
    }
}

/// `save()` writes key material from exactly one branch, guarded by
/// `KeyPersistence::DevelopmentPlaintext`.
#[test]
fn t17_structural_save_writes_keys_from_one_guarded_branch() {
    let src = store_src();
    let save = src
        .split("pub fn save(&self)")
        .nth(1)
        .expect("save must exist")
        .split("pub fn reload")
        .next()
        .unwrap();

    assert_eq!(
        save.matches("entry.keypair.clone()").count(),
        1,
        "key material must leave the store from exactly one place in save()"
    );
    assert!(
        save.contains("KeyPersistence::DevelopmentPlaintext => entry.keypair.clone()"),
        "the branch that writes key material must be the DevelopmentPlaintext one"
    );
    assert!(
        save.contains("KeyPersistence::Never => None"),
        "the Never branch must write no key material"
    );
}

/// `IdentityStore`'s `Debug` reports counts, never contents.
#[test]
fn t02_store_debug_reports_counts_not_contents() {
    let (mut aid, kp) = create_identity(prov("dbg"), None).unwrap();
    activate_identity(&mut aid).unwrap();
    let private = kp.private_key.clone();

    let mut store = IdentityStore::new();
    store.put_identity(aid, kp);

    let rendered = format!("{store:?}");
    let bytes = format!(
        "[{}]",
        private
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(!rendered.contains(&bytes), "store Debug leaked a key");
    assert!(rendered.contains("identities: 1"), "{rendered}");
}

/// Structural guard: `StoredIdentity::sign` routes through the custody
/// abstraction, and `store.rs` never signs with raw key material.
///
/// **Documented limitation.** Bypassing the abstraction here — signing with
/// `aip_crypto::sign_ed25519(&kp.private_key, ..)` directly — produces a
/// byte-identical signature, so no behavioural test can detect it. Verified by
/// mutation: replacing the custodian call with a direct one leaves the whole
/// suite green. The property is structural and is guarded structurally.
///
/// It matters because the bypass reintroduces the shape this work removed: key
/// material named, borrowed and passed as an argument at a call site. That is
/// how the field became public, how it reached `fs::write`, and how it would
/// again.
#[test]
fn t03_structural_sign_routes_through_the_custodian() {
    let src = store_src();

    let sign = src
        .split("pub fn sign(&self, payload: &[u8])")
        .nth(1)
        .expect("StoredIdentity::sign must exist")
        .split("pub fn ")
        .next()
        .unwrap();
    assert!(
        sign.contains("aip_custody::sign_envelope"),
        "StoredIdentity::sign must sign through a custodian: {sign}"
    );
    assert!(
        !sign.contains("private_key"),
        "StoredIdentity::sign must not name key material: {sign}"
    );

    // Nowhere in the store does key material reach a signing call directly.
    for l in src.lines().map(str::trim) {
        assert!(
            !(l.contains("sign_ed25519") && l.contains("private_key")),
            "store.rs signs with raw key material: {l}"
        );
    }

    // The one place key material is read at all is the private custodian
    // adapter, which does not return it.
    let uses: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|l| l.contains("kp.private_key"))
        .collect();
    assert_eq!(
        uses.len(),
        1,
        "key material must be read from exactly one place in store.rs: {uses:?}"
    );
}
