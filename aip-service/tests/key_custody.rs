//! Service key custody: the `load_or_generate` defect, closed.
//!
//! The behaviour under test is the one that made the old entry point a
//! production hazard: on *any* load failure it generated a new key, silently
//! rotating the service identity and invalidating every token and bundle ever
//! signed. `ServiceKey::load_or_create` reaches generation from exactly one
//! condition — the file does not exist.

use std::fs;
use std::path::{Path, PathBuf};

use aip_crypto::custody::{Backend, CustodyError, RawSigner};
use airon_aip::keys::ServiceKey;

const PP: &[u8] = b"a test passphrase";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aip_svc_key_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    chmod(&dir, 0o700);
    dir
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

// ─── 10 / reboot-reload lifecycle ───

/// First boot creates the wrapped key at mode 0600; a restart loads the same
/// one and signatures made before the restart still verify.
#[test]
fn wrapped_first_boot_creates_and_restart_reloads_the_same_key() {
    let dir = scratch("wrapped_boot");
    let path = dir.join("service.key");
    let p = path.to_str().unwrap();

    let first = ServiceKey::load_or_create(p, Some(PP)).unwrap();
    assert_eq!(mode_of(&path), 0o600, "the key file must be owner-only");
    assert_eq!(first.backend(), Backend::WrappedFile);
    assert!(first.backend().is_production());

    let fingerprint = first.fingerprint.clone();
    let public = first.verifying_key_bytes();
    let sig = first.sign_raw(b"issued before restart").unwrap();
    drop(first);

    let second = ServiceKey::load_or_create(p, Some(PP)).unwrap();
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

/// The plaintext path behaves the same way, and says what it is.
#[test]
fn plaintext_first_boot_creates_and_restart_reloads_the_same_key() {
    let dir = scratch("plain_boot");
    let path = dir.join("service.key");
    let p = path.to_str().unwrap();

    let first = ServiceKey::load_or_create(p, None).unwrap();
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(first.backend(), Backend::PlaintextFile);
    assert!(
        !first.backend().is_production(),
        "a plaintext key on disk must not claim to be a production backend"
    );
    let fingerprint = first.fingerprint.clone();
    drop(first);

    let second = ServiceKey::load_or_create(p, None).unwrap();
    assert_eq!(second.fingerprint, fingerprint);
}

// ─── 12 / corrupt storage ───

/// A corrupt key file is fatal. It is never treated as "no key".
///
/// This is the regression test for the defect: `load_or_generate` would have
/// logged a warning here and minted a replacement identity.
#[test]
fn corrupt_plaintext_key_is_fatal_and_never_regenerated() {
    for (name, contents) in [
        ("garbage", "not base64 at all !!!".to_string()),
        ("wrong length", base64_of(&[7u8; 16])),
        ("too long", base64_of(&[7u8; 64])),
        ("empty", String::new()),
    ] {
        let dir = scratch(&format!("corrupt_{}", name.replace(' ', "_")));
        let path = dir.join("service.key");
        aip_crypto::custody::create_owner_only(&path, contents.as_bytes()).unwrap();
        let before = fs::read(&path).unwrap();

        let err = ServiceKey::load_or_create(path.to_str().unwrap(), None).unwrap_err();
        assert!(
            matches!(err, CustodyError::Malformed(_)),
            "{name}: expected Malformed, got {err:?}"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "{name}: a refused load must not replace the key"
        );
    }
}

/// A corrupt or truncated wrapped file is fatal, and so is a wrong passphrase.
#[test]
fn corrupt_or_unopenable_wrapped_key_is_fatal_and_never_regenerated() {
    let dir = scratch("wrapped_corrupt");
    let path = dir.join("service.key");
    let p = path.to_str().unwrap();

    let original = ServiceKey::load_or_create(p, Some(PP)).unwrap().fingerprint;
    let good = fs::read(&path).unwrap();

    // Wrong passphrase → refused, file untouched, no new key.
    let err = ServiceKey::load_or_create(p, Some(b"the wrong passphrase")).unwrap_err();
    assert!(
        matches!(err, CustodyError::CannotOpen),
        "expected CannotOpen, got {err:?}"
    );
    assert_eq!(fs::read(&path).unwrap(), good);

    // A flipped ciphertext byte is indistinguishable from a wrong passphrase,
    // and is refused the same way rather than opening something else.
    let mut tampered = good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    fs::write(&path, &tampered).unwrap();
    chmod(&path, 0o600);
    let err = ServiceKey::load_or_create(p, Some(PP)).unwrap_err();
    assert!(matches!(err, CustodyError::CannotOpen), "{err:?}");

    // Truncated → malformed, not absent.
    fs::write(&path, &good[..10]).unwrap();
    chmod(&path, 0o600);
    let err = ServiceKey::load_or_create(p, Some(PP)).unwrap_err();
    assert!(matches!(err, CustodyError::Malformed(_)), "{err:?}");

    // Restored → the original key is still the original key. Nothing minted a
    // replacement behind the operator's back.
    fs::write(&path, &good).unwrap();
    chmod(&path, 0o600);
    assert_eq!(
        ServiceKey::load_or_create(p, Some(PP)).unwrap().fingerprint,
        original
    );
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    B64.encode(bytes)
}

// ─── 18 / fail closed ───

/// A key file readable by group or other is refused, not loaded — on either
/// backend.
#[test]
fn permissive_key_file_fails_closed() {
    for (name, pp) in [("wrapped", Some(PP)), ("plaintext", None)] {
        let dir = scratch(&format!("perm_{name}"));
        let path = dir.join("service.key");
        let p = path.to_str().unwrap();

        let original = ServiceKey::load_or_create(p, pp).unwrap().fingerprint;
        chmod(&path, 0o644);

        let err = ServiceKey::load_or_create(p, pp).unwrap_err();
        assert!(
            matches!(err, CustodyError::Malformed(ref m) if m.contains("mode")),
            "{name}: expected a mode refusal, got {err:?}"
        );

        chmod(&path, 0o600);
        assert_eq!(
            ServiceKey::load_or_create(p, pp).unwrap().fingerprint,
            original,
            "{name}: once the mode is fixed the original key is still there"
        );
    }
}

/// A key in a directory another user can write to is refused: they could
/// unlink it and leave their own.
#[test]
fn group_writable_directory_fails_closed() {
    let dir = scratch("dirperm");
    let path = dir.join("service.key");
    let p = path.to_str().unwrap();
    ServiceKey::load_or_create(p, Some(PP)).unwrap();

    chmod(&dir, 0o770);
    let err = ServiceKey::load_or_create(p, Some(PP)).unwrap_err();
    assert!(
        matches!(err, CustodyError::Malformed(ref m) if m.contains("replace")),
        "expected a directory refusal, got {err:?}"
    );
    chmod(&dir, 0o700);
}

/// A symlink where the key should be is refused.
#[test]
fn symlink_fails_closed() {
    let dir = scratch("symlink");
    let real = dir.join("real.key");
    let link = dir.join("link.key");
    ServiceKey::load_or_create(real.to_str().unwrap(), Some(PP)).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let err = ServiceKey::load_or_create(link.to_str().unwrap(), Some(PP)).unwrap_err();
    assert!(
        matches!(err, CustodyError::Malformed(ref m) if m.contains("regular file")),
        "a symlink cannot carry enforceable key permissions: {err:?}"
    );
}

// ─── 16 / dev backend is clearly non-production ───

#[test]
fn ephemeral_key_is_development_backend() {
    let key = ServiceKey::generate();
    assert_eq!(key.backend(), Backend::DevelopmentInMemory);
    assert!(!key.backend().is_production());
}

#[test]
fn plaintext_backend_is_not_production_and_wrapped_is() {
    assert!(!Backend::PlaintextFile.is_production());
    assert!(!Backend::DevelopmentInMemory.is_production());
    assert!(Backend::WrappedFile.is_production());
}

// ─── 2 / 4 / the key does not come back out ───

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

/// Signing through the custody interface produces a signature the ordinary
/// verifier accepts, knowing nothing about custody.
#[test]
fn signing_through_the_interface_verifies_normally() {
    let dir = scratch("sign");
    let key =
        ServiceKey::load_or_create(dir.join("service.key").to_str().unwrap(), Some(PP)).unwrap();

    let sig = key.sign_raw(b"manifest bytes").unwrap();
    assert!(aip_crypto::verify_ed25519_raw(
        key.public_key(),
        b"manifest bytes",
        &sig
    ));
    assert!(!aip_crypto::verify_ed25519_raw(
        key.public_key(),
        b"other bytes",
        &sig
    ));
}

// ─── 6 / structural guards ───

/// No accessor returns the seed or the private PEM.
///
/// `signing_seed()` used to exist and was called from `main.rs` to populate a
/// raw key into shared HTTP state. Its absence is the property, and a runtime
/// test cannot assert the absence of an API.
#[test]
fn structural_no_private_key_accessor_remains() {
    let code = code_of("src/keys.rs");

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
    assert!(
        !code.contains("fn load_or_generate"),
        "load_or_generate regenerates the service identity on any load error"
    );
}

/// `AppState` carries a signer, not a key.
#[test]
fn structural_app_state_holds_no_raw_key() {
    let code = code_of("src/lib.rs");
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
        state.contains("Arc<dyn aip_crypto::custody::RawSigner>"),
        "AppState must hold a signer, not a key"
    );
}

/// Generation is reachable from exactly one condition on each path: the file
/// does not exist.
///
/// Structural because the failure mode is a future edit that adds a second
/// path — the `load_or_generate` shape returning. Verified by mutation: adding
/// one makes `corrupt_plaintext_key_is_fatal_and_never_regenerated` fail.
#[test]
fn structural_generation_is_guarded_by_absence_only() {
    let code = code_of("src/keys.rs");

    for (f, end) in [
        ("fn load_or_create_wrapped", "fn load_or_create_plaintext"),
        ("fn load_or_create_plaintext", "impl RawSigner"),
    ] {
        let body = code.split(f).nth(1).unwrap().split(end).next().unwrap();
        let generates = body.matches("SigningKey::generate").count()
            + body.matches("WrappedFileCustodian::create").count();
        assert_eq!(
            generates, 1,
            "{f} must have exactly one path that mints a key, got {generates}"
        );
        assert!(
            body.contains("path.exists()") || body.contains("!path.exists()"),
            "{f} must gate generation on the file's absence"
        );
    }
}

/// Comment-stripped source, so a guard reads code rather than the prose
/// describing the thing it forbids.
fn code_of(rel: &str) -> String {
    let src = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap();
    src.lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("///") && !t.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n")
}
