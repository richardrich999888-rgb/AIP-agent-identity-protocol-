//! Service key custody: the `load_or_generate` defect, closed.
//!
//! The behaviour under test is the one that made the old entry point a
//! production hazard: on *any* load failure it generated a new key, silently
//! rotating the service identity and invalidating every token and bundle ever
//! signed. `ServiceKey::load_or_create` reaches generation from exactly one
//! condition — the file does not exist.

use std::fs;
use std::path::PathBuf;

use airon_aip::keys::ServiceKey;
use aip_custody::{CustodyClass, CustodyError, CustodyPolicy, KeyCustody, SigningCustodian};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aip_svc_key_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    aip_custody::ensure_secret_dir(&dir).unwrap();
    dir
}

fn chmod(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// First boot creates the key at mode 0600; a restart loads the same one.
#[test]
fn first_boot_creates_and_restart_reloads_the_same_key() {
    let dir = scratch("boot");
    let path = dir.join("service.key");
    let p = path.to_str().unwrap();

    let first = ServiceKey::load_or_create(p).unwrap();
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(first.custody_class(), CustodyClass::OsProtectedFile);
    let fingerprint = first.fingerprint.clone();
    let public = first.verifying_key_bytes();
    let sig = first.sign(b"issued before restart").unwrap();
    drop(first);

    let second = ServiceKey::load_or_create(p).unwrap();
    assert_eq!(
        second.fingerprint, fingerprint,
        "a restart must not rotate the service identity"
    );
    assert_eq!(second.verifying_key_bytes(), public);
    assert!(
        aip_crypto::verify_ed25519_raw(&public, b"issued before restart", &sig),
        "signatures made before the restart must still verify"
    );
}

/// A corrupt key file is fatal. It is never treated as "no key".
///
/// This is the regression test for the defect: `load_or_generate` would have
/// logged a warning here and minted a replacement identity.
#[test]
fn corrupt_key_file_is_fatal_and_never_regenerated() {
    for (name, contents) in [
        ("garbage", "not base64 at all !!!".to_string()),
        ("wrong length", base64_of(&[7u8; 16])),
        ("too long", base64_of(&[7u8; 64])),
        ("empty", String::new()),
    ] {
        let dir = scratch(&format!("corrupt_{}", name.replace(' ', "_")));
        let path = dir.join("service.key");
        aip_custody::create_secret_file(&path, contents.as_bytes()).unwrap();
        let before = fs::read(&path).unwrap();

        let err = ServiceKey::load_or_create(path.to_str().unwrap()).unwrap_err();
        assert!(
            matches!(err, CustodyError::Malformed { .. }),
            "{name}: expected Malformed, got {err:?}"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "{name}: a refused load must not replace the key"
        );
    }
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    B64.encode(bytes)
}

/// A key file readable by group or other is refused, not loaded.
#[test]
fn permissive_key_file_fails_closed() {
    let dir = scratch("perm");
    let path = dir.join("service.key");
    let p = path.to_str().unwrap();

    let original = ServiceKey::load_or_create(p).unwrap().fingerprint.clone();
    chmod(&path, 0o644);

    let err = ServiceKey::load_or_create(p).unwrap_err();
    assert!(
        matches!(err, CustodyError::Permissions { .. }),
        "expected Permissions, got {err:?}"
    );

    chmod(&path, 0o600);
    assert_eq!(
        ServiceKey::load_or_create(p).unwrap().fingerprint,
        original,
        "once the mode is fixed the original key is still there"
    );
}

/// An ephemeral in-memory key is classified as development custody and is
/// refused under a production policy.
///
/// The startup path applies exactly this check, which is why a service can no
/// longer come up on a key it failed to persist.
#[test]
fn ephemeral_key_is_development_custody_and_refused_in_production() {
    let key = ServiceKey::generate();
    assert_eq!(key.custody_class(), CustodyClass::Development);
    assert!(aip_custody::admits(CustodyPolicy::Development, &key).is_ok());
    assert!(aip_custody::admits(CustodyPolicy::Production, &key).is_err());
}

/// The key material never appears in `Debug` output.
#[test]
fn debug_redacts_the_seed_and_the_private_pem() {
    let key = ServiceKey::generate();
    let rendered = format!("{key:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(
        !rendered.contains("BEGIN PRIVATE KEY"),
        "the private PEM leaked through Debug: {rendered}"
    );
}

/// Structural guard: no accessor returns the seed or the private PEM.
///
/// `signing_seed()` used to exist and was called from `main.rs` to populate a
/// raw key into shared HTTP state. Its absence is the property; a runtime test
/// cannot assert the absence of an API.
#[test]
fn structural_no_private_key_accessor_remains() {
    let src = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/keys.rs"))
        .unwrap();
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");

    for l in code.lines().map(str::trim) {
        if !l.starts_with("pub fn ") {
            continue;
        }
        let name = l.trim_start_matches("pub fn ").split('(').next().unwrap();
        assert!(
            !["signing_seed", "seed", "private_pem", "export"].contains(&name),
            "keys.rs exposes `pub fn {name}`, an export path for the service key"
        );
    }
    assert!(
        !code.contains("pub private_pem"),
        "the private PEM must not be a public field"
    );
    assert!(
        !code.contains("pub seed"),
        "the seed must not be a public field"
    );

    // And the removed entry point must stay removed.
    assert!(
        !code.contains("fn load_or_generate"),
        "load_or_generate regenerates the service identity on any load error"
    );
}

/// Structural guard: `AppState` carries a signer, not a key.
#[test]
fn structural_app_state_holds_no_raw_key() {
    let src =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let state = code
        .split("pub struct AppState {")
        .nth(1)
        .expect("AppState must exist")
        .split("\n}")
        .next()
        .unwrap();

    assert!(
        !state.contains("signer_seed"),
        "AppState still holds the raw signing seed, readable from every handler"
    );
    assert!(
        !state.contains("[u8; 32]"),
        "AppState holds raw 32-byte key material: {state}"
    );
    assert!(
        state.contains("Arc<dyn aip_custody::SigningCustodian>"),
        "AppState must hold a signer, not a key"
    );
}
