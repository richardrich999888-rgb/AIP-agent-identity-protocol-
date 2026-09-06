//! B-5 / B-6 — custody of the service's signing identity.
//!
//! # The findings
//!
//! **B-6.** `load_or_generate` treated any load failure as licence to
//! generate a fresh keypair. A corrupt, truncated, or unreadable seed file
//! therefore produced a *running service with a different identity*, warned
//! about once at WARN level. Every token and audit bundle signed under the
//! previous key became unverifiable, and nothing distinguished that from
//! forgery.
//!
//! **B-5.** `save_to_file` wrote the seed with `fs::write` and chmod'd it
//! afterwards. Between the two calls the private key sat on disk at whatever
//! the umask allowed. The same function would also happily overwrite an
//! existing key.
//!
//! # What these tests establish
//!
//! That the *only* condition under which a key is created is the absence of
//! one, and that a created key is never observable at wider than 0600.
//!
//! # What they do not establish
//!
//! That `main` exits on failure. That is one `match` in `main.rs` and testing
//! it would mean spawning the binary; the property tested here is the one
//! that decides it — `load_or_create` returns `Err` rather than a substitute
//! keypair. The corresponding risk is recorded in the evidence report.

use airon_aip::keys::{KeyError, KeyPair};
use std::fs;
use std::path::{Path, PathBuf};

/// A directory that removes itself, so a failing test leaves no key material
/// behind in the temp dir.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("aip_key_custody_{tag}_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&p).expect("temp dir");
        TempDir(p)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().expect("utf-8 path").to_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn mode_of(path: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

#[cfg(unix)]
fn chmod(path: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(Path::new(path), fs::Permissions::from_mode(mode)).expect("chmod");
}

// ═══ B-6: a key that exists but cannot be used is an error, not a prompt ═══

#[test]
fn a_corrupt_seed_file_refuses_rather_than_rotating_the_identity() {
    let dir = TempDir::new("corrupt");
    let path = dir.path("signing.key");
    fs::write(&path, "this is not base64 !!!").expect("write");
    #[cfg(unix)]
    chmod(&path, 0o600);

    match KeyPair::load_or_create(&path) {
        Err(KeyError::Malformed { .. }) => {}
        Ok(kp) => panic!(
            "SECURITY (B-6): a corrupt seed file produced a working keypair \
             (fingerprint {}). The service's identity was silently rotated.",
            kp.fingerprint
        ),
        Err(other) => panic!("expected Malformed, got {other}"),
    }
}

#[test]
fn a_truncated_seed_file_refuses() {
    // The realistic corruption: a partial write, or a 16-byte seed pasted in
    // by hand. It decodes cleanly as base64 and is the wrong length.
    let dir = TempDir::new("short");
    let path = dir.path("signing.key");
    fs::write(
        &path,
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 16]),
    )
    .expect("write");
    #[cfg(unix)]
    chmod(&path, 0o600);

    let err = KeyPair::load_or_create(&path)
        .err()
        .expect("SECURITY (B-6): a 16-byte seed was accepted or silently replaced");
    assert!(matches!(err, KeyError::Malformed { .. }), "got {err}");
    assert!(
        err.to_string().contains("32 bytes"),
        "the message must say what was wrong: {err}"
    );
}

#[test]
#[cfg(unix)]
fn an_unreadable_seed_file_refuses() {
    // Running as root defeats permission-based unreadability, so the test
    // states its precondition rather than passing vacuously.
    let dir = TempDir::new("unreadable");
    let path = dir.path("signing.key");
    let kp = KeyPair::create_new(&path).expect("create");
    chmod(&path, 0o000);

    match KeyPair::load_or_create(&path) {
        Err(KeyError::Unreadable { .. }) => {}
        Err(KeyError::Permissions { .. }) => {}
        Ok(loaded) if fs::read_to_string(&path).is_ok() => {
            // The process can read a 000 file, i.e. it is root. The property
            // under test cannot be observed here; assert the weaker one that
            // still holds: the identity was not rotated.
            assert_eq!(
                loaded.fingerprint, kp.fingerprint,
                "the key on disk must be the key that loaded"
            );
        }
        Ok(other) => panic!(
            "SECURITY (B-6): an unreadable seed file produced a new identity \
             ({} rather than {})",
            other.fingerprint, kp.fingerprint
        ),
        Err(other) => panic!("unexpected error {other}"),
    }
}

#[test]
#[cfg(unix)]
fn a_group_readable_seed_file_refuses() {
    // A key other local accounts can read does not identify this service.
    let dir = TempDir::new("perms");
    let path = dir.path("signing.key");
    KeyPair::create_new(&path).expect("create");
    chmod(&path, 0o644);

    let err = KeyPair::load_or_create(&path)
        .err()
        .expect("SECURITY (B-5): a world-readable signing key was accepted");
    match err {
        KeyError::Permissions { mode, .. } => assert_eq!(mode, 0o644),
        other => panic!("expected Permissions, got {other}"),
    }
    assert!(
        err.to_string().contains("chmod 600"),
        "the message must name the remedy: {err}"
    );
}

#[test]
fn a_valid_key_loads_as_the_same_identity_every_time() {
    // The counterweight to every refusal above: the normal path must work,
    // and must be stable. If this failed, the tests above would be measuring
    // a broken loader rather than a fail-closed one.
    let dir = TempDir::new("stable");
    let path = dir.path("signing.key");

    let first = KeyPair::load_or_create(&path).expect("first start creates");
    let second = KeyPair::load_or_create(&path).expect("second start loads");
    let third = KeyPair::load_or_create(&path).expect("third start loads");

    assert_eq!(first.fingerprint, second.fingerprint);
    assert_eq!(second.fingerprint, third.fingerprint);
    assert_eq!(first.signing_seed(), third.signing_seed());
}

#[test]
fn absence_is_the_only_condition_that_creates_a_key() {
    // Stated directly, because it is the whole of B-6. Every other outcome of
    // `load` must propagate.
    let dir = TempDir::new("absence");
    let missing = dir.path("not-there.key");
    assert!(
        KeyPair::load_or_create(&missing).is_ok(),
        "a first start must create a key"
    );
    assert!(Path::new(&missing).exists());

    // And `load` alone never creates one.
    let never = dir.path("never.key");
    assert!(matches!(
        KeyPair::load(&never),
        Err(KeyError::Absent { .. })
    ));
    assert!(
        !Path::new(&never).exists(),
        "load must not have side effects on the filesystem"
    );
}

// ═══ B-5: a created key is never observable at wider than 0600 ═══

#[test]
#[cfg(unix)]
fn a_created_key_is_mode_600() {
    let dir = TempDir::new("mode");
    let path = dir.path("signing.key");
    KeyPair::create_new(&path).expect("create");
    assert_eq!(
        mode_of(&path),
        0o600,
        "SECURITY (B-5): the seed file was created with permissions other \
         than 0600"
    );
}

#[test]
#[cfg(unix)]
fn the_final_mode_is_600_even_under_a_permissive_umask() {
    // `fs::write` applies the umask, so the original code's window between
    // write and chmod was widest exactly here. This asserts the end state is
    // 0600 whatever the umask.
    //
    // # What this test cannot prove
    //
    // It does not discriminate against the defect. Verified by mutation: with
    // `write_new_seed_file` reverted to write-then-chmod, this test still
    // passes, because the chmod lands before the assertion runs. The window
    // is transient and a single-threaded test cannot observe it; a test that
    // raced a reader thread against it would be non-deterministic, which the
    // engineering standard here forbids more strongly than it demands this
    // coverage.
    //
    // The closure evidence for the *race* is therefore CODE-PROVEN, not
    // TEST-PROVEN: `write_new_seed_file` passes the mode to
    // `OpenOptions::mode` and never calls `set_permissions`, so no state
    // exists in which the file is present at wider permissions. The
    // discriminating test for that function's shape is
    // `creating_a_key_never_overwrites_an_existing_one`, which pins the
    // `O_EXCL` half of the same open call and does fail under the mutation.
    let previous = unsafe { libc_umask(0o000) };
    let dir = TempDir::new("umask");
    let path = dir.path("signing.key");
    let created = KeyPair::create_new(&path);
    let mode = created.as_ref().ok().map(|_| mode_of(&path));
    unsafe { libc_umask(previous) };

    created.expect("create");
    assert_eq!(
        mode,
        Some(0o600),
        "SECURITY (B-5): with umask 000 the seed file ended up wider than 0600"
    );
}

/// `umask(2)`. Declared here rather than adding a `libc` dependency for one
/// call: the signature is fixed by POSIX and the crate has a standing rule to
/// minimise dependencies.
#[cfg(unix)]
unsafe fn libc_umask(mask: u32) -> u32 {
    extern "C" {
        fn umask(mask: u32) -> u32;
    }
    umask(mask)
}

#[test]
fn creating_a_key_never_overwrites_an_existing_one() {
    let dir = TempDir::new("noclobber");
    let path = dir.path("signing.key");
    let original = KeyPair::create_new(&path).expect("create");

    let err = KeyPair::create_new(&path)
        .err()
        .expect("SECURITY (B-5): create_new overwrote an existing signing key");
    assert!(matches!(err, KeyError::AlreadyExists { .. }), "got {err}");

    let still = KeyPair::load(&path).expect("the original key must survive");
    assert_eq!(still.fingerprint, original.fingerprint);
}

#[test]
fn the_seed_file_contains_only_the_seed() {
    // Nothing derived, nothing extra: the PEMs are recomputed on load. A file
    // carrying more than the seed would be a second place for the private key
    // to leak from.
    let dir = TempDir::new("contents");
    let path = dir.path("signing.key");
    let kp = KeyPair::create_new(&path).expect("create");
    let raw = fs::read_to_string(&path).expect("read");

    assert!(!raw.contains("PRIVATE KEY"), "no PEM in the seed file");
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw.trim())
        .expect("base64");
    assert_eq!(decoded, kp.signing_seed().to_vec());
}
