//! Custody invariants: the tests that make the private-key boundary real.
//!
//! Numbering follows the mandated test list. Tests that need the identity
//! store live in `aip-core/tests/key_custody.rs` and tests that need the
//! observer live in `aip-observe/tests/key_custody.rs`, because those crates
//! depend on this one and the dependency cannot run backwards.

use std::fs;
use std::path::PathBuf;

use aip_custody::{
    admits, sign_envelope, CustodyClass, CustodyError, CustodyPolicy, DevCustodian, FileCustodian,
    KeyCustody, SigningCustodian,
};

// ─── helpers ───

/// A private directory unique to one test.
///
/// Unique per test *name*, not per process: the test harness runs these in
/// parallel threads inside one process, so a process-id-only name would have
/// two tests fighting over one directory and failing intermittently.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aip_custody_t_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    aip_custody::ensure_secret_dir(&dir).expect("scratch directory must be creatable");
    dir
}

fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Rust source with `//` and `/* */` comments removed.
///
/// Source-scanning guards must look at code, not at prose. A guard that reads
/// comments fires on the documentation describing the thing it forbids — and
/// the tempting fix, rewording the comment, deletes the explanation instead of
/// the defect.
fn strip_comments(src: &str) -> String {
    // Operates on `char`s, not bytes: this source contains non-ASCII (box
    // drawing, arrows) and byte-slicing it would split a multi-byte character.
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

fn custody_src(file: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(file);
    strip_comments(&fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
}

// ─── 2. private key not returned through normal API ───

/// The `Debug` of every custodian redacts its key.
///
/// `{:?}` is how key material reaches a log line: a struct printed in an error
/// path, a `dbg!` left behind, a tracing field. The derived `Debug` would print
/// the bytes; both custodians implement it by hand.
#[test]
fn t02_debug_never_prints_key_material() {
    let dir = scratch("t02");
    let path = dir.join("k.key");
    let kp = aip_crypto::generate_ed25519_keypair();

    let dev = DevCustodian::from_bytes("dev", 0, &kp.private_key, &kp.public_key);
    let file = FileCustodian::create(&path, "file", 0, &kp.private_key, &kp.public_key).unwrap();

    let needle: Vec<String> = kp
        .private_key
        .iter()
        .map(|b| format!("{b}"))
        .collect::<Vec<_>>();
    for rendered in [format!("{dev:?}"), format!("{file:?}")] {
        assert!(
            rendered.contains("redacted"),
            "custodian Debug must say it redacted something: {rendered}"
        );
        // The full byte sequence, in the shape a derived Debug would print it.
        let joined = format!("[{}]", needle.join(", "));
        assert!(
            !rendered.contains(&joined),
            "custodian Debug leaked the private key: {rendered}"
        );
        assert!(
            !rendered.contains(&hex(&kp.private_key)),
            "custodian Debug leaked the private key in hex: {rendered}"
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// No custodian type can be serialized. Structural guard.
///
/// The invariant "never casually serialized" cannot be expressed as a runtime
/// assertion: the failure mode is a `derive(Serialize)` somebody adds later,
/// which would compile and quietly put a private key into every JSON response
/// the type appears in. This test reads the source and refuses the derive.
#[test]
fn t02_structural_no_serialize_derive_on_custodians() {
    for file in ["dev.rs", "file.rs"] {
        let src = custody_src(file);
        assert!(
            !src.contains("Serialize"),
            "{file} mentions Serialize in code; a custodian must never be serializable"
        );
        assert!(
            !src.contains("Deserialize"),
            "{file} mentions Deserialize in code; a custodian must never be deserializable"
        );
    }
}

// ─── 3. signing works through the custody abstraction ───

#[test]
fn t03_signing_works_through_the_abstraction() {
    let dir = scratch("t03");
    let path = dir.join("k.key");
    let file = FileCustodian::generate(&path, "svc", 3).unwrap();

    let sig = file.sign(b"payload").unwrap();
    assert!(aip_crypto::verify_ed25519_raw(
        file.public_key(),
        b"payload",
        &sig
    ));
    assert_eq!(file.key_id(), "svc");
    assert_eq!(file.key_version(), 3);
}

// ─── 4. verification still works, and does not depend on custody ───

/// The same key produces the same signature through either path, and a
/// verifier cannot tell which was used.
///
/// This is the property that makes migrating a call site to a custodian safe:
/// custody is a property of the signer, never evidence. Ed25519 is
/// deterministic (RFC 8032 §5.1.6), so "the same signature" is exact equality,
/// not a re-verification.
#[test]
fn t04_verification_is_independent_of_custody() {
    let dir = scratch("t04");
    let kp = aip_crypto::generate_ed25519_keypair();

    let dev = DevCustodian::from_bytes("same", 0, &kp.private_key, &kp.public_key);
    let file = FileCustodian::create(
        &dir.join("k.key"),
        "same",
        0,
        &kp.private_key,
        &kp.public_key,
    )
    .unwrap();

    let msg = b"identical bytes";
    let a = dev.sign(msg).unwrap();
    let b = file.sign(msg).unwrap();
    let c = aip_crypto::sign_ed25519_raw(&kp.private_key, msg).unwrap();

    assert_eq!(a, b, "custody backend must not change the signature");
    assert_eq!(a, c, "the custodian must not change the signature");
    assert!(aip_crypto::verify_ed25519_raw(&kp.public_key, msg, &a));
}

/// A full AIP signature envelope produced through a custodian verifies with
/// the ordinary verifier, which knows nothing about custody.
#[test]
fn t04_envelope_through_custodian_verifies_normally() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let dev = DevCustodian::from_bytes("signer-1", 0, &kp.private_key, &kp.public_key);

    let sig = sign_envelope(&dev, "signer-1", b"the payload").unwrap();
    assert!(aip_crypto::verify_ed25519(&kp.public_key, &sig).unwrap());
    assert_eq!(sig.signer_id, "signer-1");
}

// ─── 6. an unauthorized caller cannot export the key ───

/// There is no export path, and that is enforced structurally.
///
/// A runtime test cannot demonstrate the absence of an API. This reads the
/// trait definition and asserts that its method set is exactly the four
/// reporting methods plus `sign` — so a `fn private_key`, `fn export`, `fn
/// seed` or `fn to_bytes` added later fails here rather than shipping.
#[test]
fn t06_structural_trait_exposes_no_key_accessor() {
    let src = custody_src("custodian.rs");
    let methods: Vec<String> = src
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("fn "))
        .map(|l| {
            l.trim_start_matches("fn ")
                .split(['(', '<'])
                .next()
                .unwrap()
                .to_string()
        })
        .collect();

    let mut expected = vec!["key_id", "key_version", "public_key", "custody_class", "sign"];
    expected.sort();
    let mut got = methods.clone();
    got.sort();
    assert_eq!(
        got, expected,
        "the custodian traits gained or lost a method. Every addition is a new \
         way out for key material and must be reviewed deliberately."
    );

    for forbidden in [
        "private_key",
        "secret",
        "seed",
        "export",
        "to_bytes",
        "into_bytes",
        "as_bytes",
        "reveal",
    ] {
        assert!(
            !methods.iter().any(|m| m == forbidden),
            "the custodian trait exposes `{forbidden}`, which returns key material"
        );
    }
}

/// The concrete backends expose no accessor either.
#[test]
fn t06_structural_backends_expose_no_key_accessor() {
    for file in ["dev.rs", "file.rs"] {
        let src = custody_src(file);
        for l in src.lines().map(str::trim) {
            if !l.starts_with("pub fn ") {
                continue;
            }
            let name = l.trim_start_matches("pub fn ").split('(').next().unwrap();
            assert!(
                !["private_key", "seed", "export", "secret", "key_bytes"].contains(&name),
                "{file} exposes `pub fn {name}`, an export path for key material"
            );
            // A public method returning the private field is the same defect
            // under a different name.
            assert!(
                !l.contains("self.private_key"),
                "{file}: `{l}` returns the private key from a public method"
            );
        }
    }
}

// ─── 10. reboot / reload lifecycle ───

/// A process restart re-loads the same key. It does not mint a new identity.
#[test]
fn t10_reload_after_restart_keeps_the_same_key() {
    let dir = scratch("t10");
    let path = dir.join("k.key");

    let first = FileCustodian::load_or_create(&path, "node-a", 1).unwrap();
    let public_before = first.public_key().to_vec();
    let sig_before = first.sign(b"before restart").unwrap();
    drop(first); // the process ends

    let second = FileCustodian::load_or_create(&path, "node-a", 1).unwrap();
    assert_eq!(
        second.public_key(),
        &public_before[..],
        "a restart must not rotate the key"
    );
    assert_eq!(second.key_id(), "node-a");
    assert_eq!(second.key_version(), 1);

    // The signature made before the restart still verifies against the key
    // the restarted process holds.
    assert!(aip_crypto::verify_ed25519_raw(
        second.public_key(),
        b"before restart",
        &sig_before
    ));
}

/// `create` refuses to overwrite. First boot happens once.
#[test]
fn t10_create_refuses_to_replace_an_existing_key() {
    let dir = scratch("t10b");
    let path = dir.join("k.key");
    FileCustodian::generate(&path, "node-b", 0).unwrap();
    let before = fs::read(&path).unwrap();

    let err = FileCustodian::generate(&path, "node-b", 0).unwrap_err();
    assert!(
        matches!(err, CustodyError::AlreadyExists { .. }),
        "expected AlreadyExists, got {err:?}"
    );
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "a refused create must leave the existing key byte-identical"
    );
}

// ─── 11. missing key ───

#[test]
fn t11_missing_key_is_absent_and_load_never_creates() {
    let dir = scratch("t11");
    let path = dir.join("nothing-here.key");

    let err = FileCustodian::load(&path).unwrap_err();
    assert!(
        matches!(err, CustodyError::Absent { .. }),
        "expected Absent, got {err:?}"
    );
    assert!(
        !path.exists(),
        "load() must never create a key file as a side effect"
    );
}

// ─── 12. corrupt key storage ───

/// Every shape of corruption is refused, and none of them produces a key.
///
/// The failure this guards against is the `load_or_generate` shape: a damaged
/// file treated as "no file", so the process generates a replacement identity
/// and reports success while every prior signature becomes unverifiable.
#[test]
fn t12_corrupt_storage_is_refused_and_never_regenerated() {
    let kp = aip_crypto::generate_ed25519_keypair();

    let cases: Vec<(&str, Vec<u8>)> = {
        let dir = scratch("t12_seed");
        let good_path = dir.join("good.key");
        FileCustodian::create(&good_path, "id", 7, &kp.private_key, &kp.public_key).unwrap();
        let good = fs::read(&good_path).unwrap();

        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';

        let mut bad_version = good.clone();
        bad_version[6] = 0x09;

        let truncated = good[..good.len() - 1].to_vec();

        let mut trailing = good.clone();
        trailing.push(0x00);

        // A public key that is valid but belongs to a different private key:
        // signatures would be produced that no verifier anchored on it accepts.
        let other = aip_crypto::generate_ed25519_keypair();
        let mut mismatched = good.clone();
        let at = mismatched.len() - 32;
        mismatched[at..].copy_from_slice(&other.public_key);

        vec![
            ("empty", Vec::new()),
            ("header only", good[..10].to_vec()),
            ("bad magic", bad_magic),
            ("unknown format version", bad_version),
            ("truncated", truncated),
            ("trailing byte", trailing),
            ("mismatched public key", mismatched),
            ("random bytes", vec![0xAB; 78]),
        ]
    };

    for (name, bytes) in cases {
        let dir = scratch(&format!("t12_{}", name.replace(' ', "_")));
        let path = dir.join("k.key");
        aip_custody::create_secret_file(&path, &bytes).unwrap();

        let err = FileCustodian::load(&path).unwrap_err();
        assert!(
            matches!(err, CustodyError::Malformed { .. }),
            "{name}: expected Malformed, got {err:?}"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            bytes,
            "{name}: a refused load must not rewrite the file"
        );
    }
}

/// `load_or_create` creates from `Absent` and from nothing else.
///
/// The single most important behaviour in this crate. Every non-`Absent`
/// failure must propagate, because generating a key in response to any of them
/// destroys an identity that still exists.
#[test]
fn t12_load_or_create_generates_only_when_absent() {
    let dir = scratch("t12_loc");
    let path = dir.join("k.key");

    // Absent → creates.
    let created = FileCustodian::load_or_create(&path, "id", 0).unwrap();
    let public = created.public_key().to_vec();

    // Corrupt → refuses, and does not replace.
    fs::remove_file(&path).unwrap();
    aip_custody::create_secret_file(&path, b"not a key file").unwrap();
    let err = FileCustodian::load_or_create(&path, "id", 0).unwrap_err();
    assert!(
        matches!(err, CustodyError::Malformed { .. }),
        "corrupt storage must not be treated as absent: {err:?}"
    );
    assert_eq!(fs::read(&path).unwrap(), b"not a key file");

    // Bad permissions → refuses, and does not replace.
    let dir2 = scratch("t12_loc2");
    let path2 = dir2.join("k.key");
    let untouched = FileCustodian::generate(&path2, "id", 0).unwrap();
    let public2 = untouched.public_key().to_vec();
    chmod(&path2, 0o644);
    let err = FileCustodian::load_or_create(&path2, "id", 0).unwrap_err();
    assert!(
        matches!(err, CustodyError::Permissions { .. }),
        "a bad mode must not be treated as absent: {err:?}"
    );

    // Once the operator fixes the mode, the original key is still there —
    // nothing generated a replacement behind their back.
    chmod(&path2, 0o600);
    let recovered = FileCustodian::load_or_create(&path2, "id", 0).unwrap();
    assert_eq!(recovered.public_key(), &public2[..]);
    let _ = public;
}

fn chmod(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

// ─── 13. wrong key type / wrong key length ───

#[test]
fn t13_wrong_key_length_is_refused_at_creation() {
    let dir = scratch("t13");
    for (name, priv_len, pub_len) in [
        ("short private", 31, 32),
        ("long private", 33, 32),
        ("short public", 32, 31),
        ("empty private", 0, 32),
    ] {
        let path = dir.join(format!("{}.key", name.replace(' ', "_")));
        let err = FileCustodian::create(&path, "id", 0, &vec![1u8; priv_len], &vec![2u8; pub_len])
            .unwrap_err();
        assert!(
            matches!(err, CustodyError::Malformed { .. }),
            "{name}: expected Malformed, got {err:?}"
        );
        assert!(!path.exists(), "{name}: a refused create must write nothing");
    }
}

#[test]
fn t13_empty_key_id_is_refused() {
    let dir = scratch("t13b");
    let kp = aip_crypto::generate_ed25519_keypair();
    let err = FileCustodian::create(
        &dir.join("k.key"),
        "",
        0,
        &kp.private_key,
        &kp.public_key,
    )
    .unwrap_err();
    assert!(matches!(err, CustodyError::Malformed { .. }), "{err:?}");
}

// ─── 16. the development backend is clearly non-production ───

#[test]
fn t16_dev_backend_is_classified_development_and_refused_in_production() {
    let dev = DevCustodian::generate("dev", 0);
    assert_eq!(dev.custody_class(), CustodyClass::Development);
    assert!(
        CustodyClass::Development.is_exportable(),
        "the development class must admit that its key is exportable"
    );

    assert!(admits(CustodyPolicy::Development, &dev).is_ok());
    let err = admits(CustodyPolicy::Production, &dev).unwrap_err();
    assert!(
        matches!(
            err,
            CustodyError::PolicyRefused {
                policy: CustodyPolicy::Production,
                class: CustodyClass::Development
            }
        ),
        "{err:?}"
    );
}

#[test]
fn t16_file_backend_is_admitted_in_production() {
    let dir = scratch("t16");
    let file = FileCustodian::generate(&dir.join("k.key"), "svc", 0).unwrap();
    assert_eq!(file.custody_class(), CustodyClass::OsProtectedFile);
    assert!(admits(CustodyPolicy::Production, &file).is_ok());
    assert!(
        !CustodyClass::OsProtectedFile.is_exportable(),
        "the file backend does not hand the key back through any API"
    );
}

/// `HardwareBacked` is reserved, not implemented, and refused by both policies.
///
/// It exists so that its absence is visible in the model rather than silently
/// missing. Implementing it requires ADR-002 to be decided; ADR-002 is
/// PROPOSED, so nothing may report this class.
#[test]
fn t16_hardware_backed_is_reserved_and_unimplemented() {
    assert!(!CustodyClass::HardwareBacked.is_implemented());
    assert!(!CustodyPolicy::Production.admits(CustodyClass::HardwareBacked));
    assert!(!CustodyPolicy::Development.admits(CustodyClass::HardwareBacked));

    // No backend in this crate reports it.
    for file in ["dev.rs", "file.rs"] {
        let src = custody_src(file);
        assert!(
            !src.contains("CustodyClass::HardwareBacked"),
            "{file} reports HardwareBacked custody, which no backend establishes"
        );
    }
}

// ─── 18. failure to access secure custody fails closed ───

/// A key file reachable by group or other is refused, not used.
#[test]
fn t18_permissive_mode_fails_closed() {
    for mode in [0o644, 0o640, 0o604, 0o666, 0o601, 0o610] {
        let dir = scratch(&format!("t18_{mode:o}"));
        let path = dir.join("k.key");
        FileCustodian::generate(&path, "id", 0).unwrap();
        chmod(&path, mode);

        let err = FileCustodian::load(&path).unwrap_err();
        match err {
            CustodyError::Permissions { mode: got, .. } => assert_eq!(got, mode),
            other => panic!("mode {mode:o}: expected Permissions, got {other:?}"),
        }
    }
}

/// A key created by this crate is 0600 from the moment it exists.
#[test]
fn t18_created_key_is_0600() {
    let dir = scratch("t18_mode");
    let path = dir.join("k.key");
    FileCustodian::generate(&path, "id", 0).unwrap();
    assert_eq!(mode_of(&path), 0o600);
    FileCustodian::load(&path).expect("a key this crate created must load");
}

/// A key in a directory another user can write to is refused.
///
/// Mode 0600 on the file is not enough: a writable directory lets another user
/// unlink the key and leave their own, and the process then signs with the
/// attacker's key while every permission check passes.
#[test]
fn t18_group_writable_directory_fails_closed() {
    let dir = scratch("t18_dir");
    let path = dir.join("k.key");
    FileCustodian::generate(&path, "id", 0).unwrap();

    chmod(&dir, 0o770);
    let err = FileCustodian::load(&path).unwrap_err();
    assert!(
        matches!(err, CustodyError::Permissions { .. }),
        "a group-writable key directory must be refused: {err:?}"
    );

    // The sticky bit is the kernel's own exception and is accepted.
    chmod(&dir, 0o1777);
    FileCustodian::load(&path).expect("a sticky world-writable directory is safe against unlink");

    chmod(&dir, 0o700);
}

/// A symlink where a key file should be is refused.
#[test]
fn t18_symlink_fails_closed() {
    let dir = scratch("t18_link");
    let real = dir.join("real.key");
    let link = dir.join("link.key");
    FileCustodian::generate(&real, "id", 0).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let err = FileCustodian::load(&link).unwrap_err();
    assert!(
        matches!(err, CustodyError::Malformed { .. }),
        "a symlink cannot carry enforceable key permissions: {err:?}"
    );
}

/// The default policy, with nothing configured, is Production.
///
/// A security posture must not weaken because an environment variable was
/// missing. Only an explicit development opt-in relaxes it.
#[test]
fn t18_unset_policy_defaults_to_production() {
    // Read the parser's own table rather than mutating the process
    // environment, which is global and would race the other tests in this
    // binary. The values are the ones `from_env` matches on.
    let src = custody_src("policy.rs");
    assert!(
        src.contains("_ => Self::Production"),
        "the catch-all arm of CustodyPolicy::from_env must be Production, so an \
         unset, empty or unparseable value is a production policy"
    );
    assert!(
        src.contains(r#"Ok("development")"#) && src.contains(r#"Ok("dev")"#),
        "only an explicit development opt-in may relax the policy"
    );
}
