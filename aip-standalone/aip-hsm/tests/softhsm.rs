//! R16 — the PKCS#11 custodian against a real token.
//!
//! SoftHSM2 presents the same interface a hardware module does, so every
//! property below is exercised through `C_Login`, `C_FindObjects`,
//! `C_GetAttributeValue`, `C_GenerateRandom` and `C_Sign` — not through a
//! mock that would prove only that the mock agrees with the code.
//!
//! **These tests do not skip.** If the module is absent they fail and say
//! how to install it. A custody test that passes on a machine without the
//! module is one that has never run, and the CI workflow installs it.
//!
//! One module, one token, one process: a PKCS#11 library initialises once
//! per process and SoftHSM reads its configuration at that moment, so the
//! token directory is created once (`OnceLock`).
//!
//! # Provision first, then operate — which is also how production works
//!
//! Every key the tests need is generated **serially, in the one-time
//! setup**, and the tests then open and sign against those keys in
//! parallel. SoftHSM2's file-backed object store is not safe for object
//! creation concurrent with other operations on the same token (it fails
//! with `CKR_GENERAL_ERROR`, intermittently); its SQLite store would be,
//! but the distribution build here has none. A hardware module does not
//! have the limitation. Commissioning is a serial, once-per-key step in
//! any real deployment, and structuring the tests the same way tests the
//! deployment rather than the harness. Concurrent *signing* is exercised
//! deliberately, because that is what a daemon does.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use aip_crypto::custody::{Backend, Custodian};
use aip_hsm::{provision_ed25519, HsmError, PinSource, Pkcs11Config, Pkcs11Custodian};

const TOKEN: &str = "aip-test";
/// A second token that nothing logs into correctly, for the wrong-PIN
/// test. PKCS#11 login state is per token per application, so on the
/// shared token a wrong PIN after a right one is not checked at all — see
/// `session::login_user` — and the test would depend on ordering.
const PIN_ONLY_TOKEN: &str = "aip-test-pin";
const PIN: &str = "1234";
const SO_PIN: &str = "5678";
const PIN_ENV: &str = "AIP_HSM_TEST_PIN";

struct Token {
    module: PathBuf,
}

fn module_path() -> PathBuf {
    if let Ok(p) = std::env::var("AIP_PKCS11_MODULE") {
        return PathBuf::from(p);
    }
    for candidate in [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return p;
        }
    }
    panic!(
        "SoftHSM2 is required for the aip-hsm tests and was not found.\n\
         Install it (Debian/Ubuntu: `sudo apt-get install -y softhsm2`) or set \
         AIP_PKCS11_MODULE to a PKCS#11 module path.\n\
         These tests deliberately do not skip: a custody test that passes without the \
         module has not run."
    );
}

/// One token for the whole test binary.
fn token() -> &'static Token {
    static TOKEN_ONCE: OnceLock<Token> = OnceLock::new();
    TOKEN_ONCE.get_or_init(|| {
        let module = module_path();
        let dir = std::env::temp_dir().join(format!("aip-hsm-test-{}", std::process::id()));
        let tokens = dir.join("tokens");
        std::fs::create_dir_all(&tokens).expect("token dir");
        let conf = dir.join("softhsm2.conf");
        std::fs::write(
            &conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                tokens.display()
            ),
        )
        .expect("write conf");
        // Read by SoftHSM at C_Initialize, which has not happened yet.
        std::env::set_var("SOFTHSM2_CONF", &conf);
        std::env::set_var(PIN_ENV, PIN);

        let util = which_softhsm2_util();
        for label in [TOKEN, PIN_ONLY_TOKEN] {
            let status = std::process::Command::new(&util)
                .env("SOFTHSM2_CONF", &conf)
                .args([
                    "--init-token",
                    "--free",
                    "--label",
                    label,
                    "--pin",
                    PIN,
                    "--so-pin",
                    SO_PIN,
                ])
                .status()
                .expect("run softhsm2-util");
            assert!(
                status.success(),
                "softhsm2-util --init-token {label} failed"
            );
        }
        let token = Token { module };

        // Commissioning: every key, serially, before any test operates.
        for label in HARDENED_LABELS {
            provision_ed25519(&config_on(&token, label)).expect(label);
        }
        aip_hsm::provision::provision_ed25519_with_weak_policy(
            &config_on(&token, EXTRACTABLE_LABEL),
            true,
            true,
        )
        .expect(EXTRACTABLE_LABEL);
        aip_hsm::provision::provision_ed25519_with_weak_policy(
            &config_on(&token, INSENSITIVE_LABEL),
            false,
            false,
        )
        .expect(INSENSITIVE_LABEL);
        let dup = config_on(&token, DUPLICATE_LABEL);
        provision_ed25519(&dup).expect(DUPLICATE_LABEL);
        aip_hsm::provision::provision_duplicate_label(&dup).expect("second under the label");
        token
    })
}

fn which_softhsm2_util() -> PathBuf {
    for candidate in ["/usr/bin/softhsm2-util", "/usr/local/bin/softhsm2-util"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("softhsm2-util")
}

/// Keys provisioned with the hardened policy at setup, one per test that
/// needs its own.
const HARDENED_LABELS: [&str; 10] = [
    "k-basic",
    "k-envelope",
    "k-nonce",
    "k-reconciler",
    "k-threads",
    "k-unexportable",
    "k-second-a",
    "k-second-b",
    "k-debug",
    "k-twice",
];
const EXTRACTABLE_LABEL: &str = "k-extractable";
const INSENSITIVE_LABEL: &str = "k-insensitive";
const DUPLICATE_LABEL: &str = "k-duplicate";

fn config_on(token: &Token, key_label: &str) -> Pkcs11Config {
    Pkcs11Config {
        module: token.module.clone(),
        token_label: TOKEN.into(),
        key_label: key_label.into(),
        pin: PinSource::Env(PIN_ENV.into()),
    }
}

fn config(key_label: &str) -> Pkcs11Config {
    config_on(token(), key_label)
}

/// An open custodian on a key provisioned at setup, and its public key as
/// the custodian reports it.
fn opened(key_label: &str) -> ([u8; 32], Pkcs11Custodian) {
    assert!(
        HARDENED_LABELS.contains(&key_label),
        "{key_label} is not provisioned at setup"
    );
    let c = Pkcs11Custodian::open(&config(key_label)).expect("open");
    let pk: [u8; 32] = c.public_key().try_into().unwrap();
    (pk, c)
}

// ─── The positive path ───

/// A key made inside the module signs an envelope that the workspace's
/// ordinary verifier accepts under the public key the module reports.
#[test]
fn a_key_provisioned_on_the_token_signs_and_the_standard_verifier_accepts_it() {
    let (pk, c) = opened("k-basic");
    assert_eq!(c.public_key(), &pk);
    assert_eq!(c.backend(), Backend::Pkcs11);
    assert!(c.backend().is_production());

    let sig = c.sign("reconciler-1", b"payload").unwrap();
    assert!(aip_crypto::verify_ed25519(&pk, &sig).unwrap());
    assert_eq!(sig.signature_bytes.len(), 64);
    assert_eq!(sig.payload_hash, aip_crypto::sha256(b"payload"));

    // And not under another key.
    let other = aip_crypto::generate_ed25519_keypair();
    assert!(!aip_crypto::verify_ed25519(&other.public_key, &sig).unwrap());
}

/// The envelope is byte-for-byte the software signer's construction: a
/// verifier cannot tell which backend signed and does not need to.
#[test]
fn the_envelope_is_indistinguishable_from_the_software_signer_s() {
    let (pk, c) = opened("k-envelope");
    let sig = c.sign("id", b"x").unwrap();
    let recomputed = aip_crypto::signature_signed_bytes(
        sig.algorithm,
        &sig.signer_id,
        sig.timestamp,
        &sig.nonce,
        &sig.payload_hash,
    );
    let raw: [u8; 64] = sig.signature_bytes.clone().try_into().unwrap();
    assert!(aip_crypto::verify_ed25519_raw(&pk, &recomputed, &raw));
}

/// Nonces come from the module and differ per signature, so two
/// signatures over one payload are two envelopes.
#[test]
fn each_signature_carries_a_fresh_nonce_from_the_module() {
    let (_, c) = opened("k-nonce");
    let a = c.sign("id", b"same").unwrap();
    let b = c.sign("id", b"same").unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.nonce, [0u8; 16]);
}

/// The consumer that matters: `ReconcilerSigner` takes the custodian and
/// the verdict verifies under anchors holding the module's public key.
#[test]
fn the_reconciler_signer_signs_a_verdict_through_the_module() {
    use aip_reconcile::{ReconcilerSigner, ReconcilerTrustAnchors, Reconciliation};
    let (pk, c) = opened("k-reconciler");
    let signer = ReconcilerSigner::with_custodian("reconciler-hsm", 1, Box::new(c));
    let verdict = signer.sign(&Reconciliation::fixture_default()).unwrap();
    let anchors = ReconcilerTrustAnchors::new().trust("reconciler-hsm", 1, &pk);
    verdict
        .verify(&anchors)
        .expect("verifies under the module's key");
    // And an impostor anchor fails.
    let other = aip_crypto::generate_ed25519_keypair();
    let wrong = ReconcilerTrustAnchors::new().trust("reconciler-hsm", 1, &other.public_key);
    assert!(verdict.verify(&wrong).is_err());
}

/// Concurrency: the session is serialised behind a mutex, and every
/// signature made from several threads verifies.
#[test]
fn signing_from_several_threads_is_serialised_and_every_signature_verifies() {
    let (pk, c) = opened("k-threads");
    let c = Arc::new(c);
    let handles: Vec<_> = (0..4)
        .map(|t| {
            let c = Arc::clone(&c);
            std::thread::spawn(move || {
                (0..25)
                    .map(|i| c.sign("id", format!("{t}-{i}").as_bytes()).unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    for h in handles {
        for sig in h.join().unwrap() {
            assert!(aip_crypto::verify_ed25519(&pk, &sig).unwrap());
        }
    }
}

// ─── What the module, and the custodian, refuse ───

/// **The property this backend exists for.** The module refuses to hand
/// over the private key. Asked for `CKA_VALUE` on the private object, a
/// sensitive key returns `CKR_ATTRIBUTE_SENSITIVE`; asked to wrap it, a
/// non-extractable key returns `CKR_KEY_UNEXTRACTABLE`. There is no
/// custodian method to test here because there is no method: the trait
/// has `public_key`, `sign` and `backend`, and that is the structural half
/// of the guarantee. This is the other half, from the module itself.
#[test]
fn the_private_key_cannot_be_read_out_of_the_module() {
    use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;

    let label = "k-unexportable";
    let (_, _c) = opened(label);

    // A second, independent session with the same PIN — the strongest
    // position an attacker who has the PIN can be in.
    let pkcs11 = aip_hsm::module::load(&token().module).unwrap();
    let slot = pkcs11
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| pkcs11.get_token_info(*s).unwrap().label().trim_end() == TOKEN)
        .unwrap();
    let session = pkcs11.open_ro_session(slot).unwrap();
    // The attacker's session. Login state is per token per application,
    // so if the custodian's session already logged in, this one already
    // is too — which only strengthens the attacker's position here.
    match session.login(UserType::User, Some(&AuthPin::from(PIN))) {
        Ok(()) => {}
        Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => panic!("{e}"),
    }
    let handles = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .unwrap();
    assert_eq!(handles.len(), 1);

    let attempt = session.get_attributes(handles[0], &[AttributeType::Value]);
    let leaked = match &attempt {
        Ok(attrs) => attrs
            .iter()
            .any(|a| matches!(a, Attribute::Value(v) if !v.is_empty())),
        Err(_) => false,
    };
    assert!(
        !leaked,
        "the module returned private key material: {attempt:?}"
    );
}

/// A key that could leave the module is refused at open, with the policy
/// read back from the module rather than assumed.
#[test]
fn an_extractable_key_is_refused_at_open() {
    let cfg = config(EXTRACTABLE_LABEL);
    let err = Pkcs11Custodian::open(&cfg).unwrap_err();
    match &err {
        HsmError::KeyPolicy { label, detail } => {
            assert_eq!(label, EXTRACTABLE_LABEL);
            assert!(detail.contains("CKA_EXTRACTABLE=true"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
    assert!(err.to_string().contains("slow file"), "{err}");
}

/// A key that is not sensitive is refused for the same reason.
#[test]
fn a_non_sensitive_key_is_refused_at_open() {
    assert!(matches!(
        Pkcs11Custodian::open(&config(INSENSITIVE_LABEL)),
        Err(HsmError::KeyPolicy { .. })
    ));
}

/// Two keys under one label: the custodian will not pick one, and
/// provisioning will not add a third.
#[test]
fn two_keys_under_one_label_are_refused_not_guessed() {
    let cfg = config(DUPLICATE_LABEL);
    match Pkcs11Custodian::open(&cfg).unwrap_err() {
        HsmError::AmbiguousKey { count, .. } => assert_eq!(count, 2),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        provision_ed25519(&cfg),
        Err(HsmError::AmbiguousKey { .. })
    ));
}

#[test]
fn a_missing_key_is_refused_by_name() {
    let cfg = config("k-does-not-exist");
    match Pkcs11Custodian::open(&cfg).unwrap_err() {
        HsmError::KeyNotFound { label } => assert_eq!(label, "k-does-not-exist"),
        other => panic!("{other:?}"),
    }
}

/// A wrong PIN opens nothing. The error names the login, not the key, so
/// an operator looks in the right place. On a token this process has not
/// yet logged into — which is the only case in which PKCS#11 checks the
/// PIN at all.
#[test]
fn a_wrong_pin_is_refused() {
    std::env::set_var("AIP_HSM_TEST_WRONG_PIN", "0000");
    let mut cfg = config("k-pin");
    cfg.token_label = PIN_ONLY_TOKEN.into();
    cfg.pin = PinSource::Env("AIP_HSM_TEST_WRONG_PIN".into());
    match Pkcs11Custodian::open(&cfg).unwrap_err() {
        HsmError::Login(_) => {}
        other => panic!("{other:?}"),
    }
}

/// A second custodian on a token the process is already logged into opens
/// without a second PIN check: PKCS#11 login state is per token per
/// application. Stated and tested rather than discovered in production
/// when a daemon holds two keys on one token.
#[test]
fn a_second_custodian_on_the_same_token_opens_while_logged_in() {
    let (_, first) = opened("k-second-a");
    let (_, second) = opened("k-second-b");
    assert_ne!(first.public_key(), second.public_key());
    let sig = second.sign("id", b"x").unwrap();
    assert!(aip_crypto::verify_ed25519(second.public_key(), &sig).unwrap());
}

/// A wrong token label is refused and the error lists what is present, so
/// a typo is diagnosable from the message alone.
#[test]
fn a_missing_token_is_refused_and_the_present_ones_are_listed() {
    let mut cfg = config("k-any");
    cfg.token_label = "no-such-token".into();
    match Pkcs11Custodian::open(&cfg).unwrap_err() {
        HsmError::TokenNotFound { label, present } => {
            assert_eq!(label, "no-such-token");
            assert!(present.iter().any(|p| p == TOKEN), "{present:?}");
        }
        other => panic!("{other:?}"),
    }
}

/// Debug output — what lands in a log — names the token and key and never
/// the PIN.
#[test]
fn debug_output_never_contains_the_pin() {
    let (_, c) = opened("k-debug");
    let d = format!("{c:?}");
    assert!(d.contains("k-debug") && d.contains("Pkcs11"), "{d}");
    assert!(!d.contains(PIN), "{d}");
    let d = format!("{:?}", config("k-debug"));
    assert!(!d.contains(PIN), "{d}");
}

/// Provisioning into a label that already holds a key is refused: the
/// state it would create is one the custodian refuses to open. The label
/// was provisioned once at setup; this is the second attempt.
#[test]
fn provisioning_over_an_existing_label_is_refused() {
    let (_, c) = opened("k-twice");
    drop(c);
    assert!(matches!(
        provision_ed25519(&config("k-twice")),
        Err(HsmError::AmbiguousKey { count: 2, .. })
    ));
}
