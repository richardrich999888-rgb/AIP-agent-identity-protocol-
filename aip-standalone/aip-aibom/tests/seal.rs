//! The detached seal: authorship, never truth.

mod common;

use aip_aibom::seal::{verify_seal, Publisher, SealError};
use common::*;
use std::collections::BTreeMap;

fn setup() -> (Publisher, BTreeMap<String, Vec<u8>>) {
    let kp = aip_crypto::generate_ed25519_keypair();
    let p = Publisher::new("platform-team", &kp.private_key, &kp.public_key).unwrap();
    let mut anchors = BTreeMap::new();
    anchors.insert("platform-team".to_string(), kp.public_key.clone());
    (p, anchors)
}

#[test]
fn a_seal_verifies_over_the_manifest_it_was_made_for() {
    let (p, anchors) = setup();
    let m = manifest("agent");
    let s = p.seal(&m, 10).unwrap();
    assert_eq!(verify_seal(&s, &m, &anchors), Ok(()));
}

#[test]
fn a_seal_over_a_different_manifest_is_refused() {
    let (p, anchors) = setup();
    let m = manifest("agent");
    let s = p.seal(&m, 10).unwrap();
    let mut changed = m.clone();
    changed.permissions.allowed.push(custom("wire_transfer"));
    assert_eq!(
        verify_seal(&s, &changed, &anchors),
        Err(SealError::DigestMismatch)
    );
}

/// The key comes from the assessor's anchors. A seal cannot name its own.
#[test]
fn a_seal_from_an_unanchored_publisher_is_refused() {
    let (p, _) = setup();
    let m = manifest("agent");
    let s = p.seal(&m, 10).unwrap();
    assert_eq!(
        verify_seal(&s, &m, &BTreeMap::new()),
        Err(SealError::PublisherNotAnchored("platform-team".into()))
    );
}

#[test]
fn a_seal_under_the_wrong_key_is_refused() {
    let (p, _) = setup();
    let other = aip_crypto::generate_ed25519_keypair();
    let mut anchors = BTreeMap::new();
    anchors.insert("platform-team".to_string(), other.public_key);
    let m = manifest("agent");
    let s = p.seal(&m, 10).unwrap();
    assert_eq!(
        verify_seal(&s, &m, &anchors),
        Err(SealError::SignatureInvalid)
    );
}

#[test]
fn every_sealed_field_is_covered_by_the_signature() {
    let (p, anchors) = setup();
    let m = manifest("agent");
    let s = p.seal(&m, 10).unwrap();

    let mut t = s.clone();
    t.sealed_at_ms += 1;
    assert_eq!(
        verify_seal(&t, &m, &anchors),
        Err(SealError::PayloadHashMismatch)
    );

    let mut t = s.clone();
    t.publisher_id = "someone-else".into();
    let mut a2 = anchors.clone();
    a2.insert("someone-else".into(), anchors["platform-team"].clone());
    assert_eq!(verify_seal(&t, &m, &a2), Err(SealError::SignerMismatch));

    let mut t = s.clone();
    t.version = 2;
    assert_eq!(
        verify_seal(&t, &m, &anchors),
        Err(SealError::UnsupportedVersion(2))
    );
}

#[test]
fn a_publisher_with_a_mismatched_key_pair_is_refused_at_construction() {
    let a = aip_crypto::generate_ed25519_keypair();
    let b = aip_crypto::generate_ed25519_keypair();
    assert_eq!(
        Publisher::new("x", &a.private_key, &b.public_key).unwrap_err(),
        SealError::KeyPairMismatch
    );
}

#[test]
fn a_publishers_debug_output_never_contains_its_key() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let p = Publisher::new("platform-team", &kp.private_key, &kp.public_key).unwrap();
    let shown = format!("{p:?}");
    assert!(!shown.contains(&format!("{:?}", kp.private_key)));
    assert!(!shown.contains(&hex::encode(&kp.private_key)));
}

// ─── Custodian-backed publisher tests ───

#[test]
fn custodian_backed_publisher_seals_and_verifies() {
    use aip_crypto::custody::{Custodian, InMemoryCustodian};
    use std::sync::Arc;

    let custodian = Arc::new(InMemoryCustodian::generate());
    let public_key = custodian.public_key().to_vec();

    let publisher = Publisher::from_custodian("platform-team", custodian).unwrap();

    let manifest = manifest("agent");
    let seal = publisher.seal(&manifest, 20).unwrap();

    let mut anchors = BTreeMap::new();
    anchors.insert("platform-team".to_string(), public_key);

    assert_eq!(verify_seal(&seal, &manifest, &anchors), Ok(()));
}

#[test]
fn custodian_backed_publisher_reports_its_backend() {
    use aip_crypto::custody::{Backend, InMemoryCustodian};
    use std::sync::Arc;

    let custodian = Arc::new(InMemoryCustodian::generate());
    let publisher = Publisher::from_custodian("platform-team", custodian).unwrap();

    assert_eq!(publisher.backend(), Backend::DevelopmentInMemory);
}

#[test]
fn publisher_rejects_custodian_with_wrong_signer_envelope() {
    use aip_crypto::custody::{Backend, Custodian, CustodyError, InMemoryCustodian};
    use aip_types::Signature;
    use std::sync::Arc;

    #[derive(Debug)]
    struct WrongSignerCustodian(InMemoryCustodian);

    impl Custodian for WrongSignerCustodian {
        fn public_key(&self) -> &[u8] {
            self.0.public_key()
        }

        fn sign(&self, signer_id: &str, payload: &[u8]) -> Result<Signature, CustodyError> {
            let mut signature = self.0.sign(signer_id, payload)?;
            signature.signer_id = "forged-signer".to_string();
            Ok(signature)
        }

        fn backend(&self) -> Backend {
            self.0.backend()
        }
    }

    let custodian = Arc::new(WrongSignerCustodian(InMemoryCustodian::generate()));

    assert!(matches!(
        Publisher::from_custodian("platform-team", custodian),
        Err(SealError::SignerMismatch)
    ));
}

// ─── Wrapped-file custody integration test ───

#[test]
fn wrapped_file_custodian_can_publish_and_reopen() {
    use aip_crypto::custody::{Custodian, WrappedFileCustodian};
    use std::sync::Arc;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let path = std::env::temp_dir().join(format!(
        "aibom-wrapped-seal-{}-{unique}.key",
        std::process::id()
    ));

    let passphrase = b"aibom-integration-test-passphrase";

    {
        let custodian = WrappedFileCustodian::create(&path, passphrase).unwrap();
        let public_key = custodian.public_key().to_vec();

        assert_eq!(
            custodian.backend(),
            aip_crypto::custody::Backend::WrappedFile
        );

        let publisher = Publisher::from_custodian("platform-team", Arc::new(custodian)).unwrap();

        let m = manifest("agent");
        let seal = publisher.seal(&m, 30).unwrap();

        let mut anchors = BTreeMap::new();
        anchors.insert("platform-team".to_string(), public_key.clone());

        assert_eq!(verify_seal(&seal, &m, &anchors), Ok(()));

        // Reopen the persisted key and publish another manifest.
        let reopened = WrappedFileCustodian::open(&path, passphrase).unwrap();

        assert_eq!(reopened.public_key(), public_key.as_slice());

        let reopened_publisher =
            Publisher::from_custodian("platform-team", Arc::new(reopened)).unwrap();

        let reopened_seal = reopened_publisher.seal(&m, 31).unwrap();

        assert_eq!(verify_seal(&reopened_seal, &m, &anchors), Ok(()));
    }

    let _ = std::fs::remove_file(&path);
}

// Cleans up process environment and isolated SoftHSM files, even on panic.
struct SoftHsmTestCleanup {
    root: std::path::PathBuf,
    pin_env: String,
    previous_conf: Option<std::ffi::OsString>,
}

impl Drop for SoftHsmTestCleanup {
    fn drop(&mut self) {
        std::env::remove_var(&self.pin_env);

        match self.previous_conf.take() {
            Some(value) => std::env::set_var("SOFTHSM2_CONF", value),
            None => std::env::remove_var("SOFTHSM2_CONF"),
        }

        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ─── PKCS#11 / SoftHSM publisher integration ───

#[test]
fn pkcs11_custodian_can_publish_and_verify_aibom_seal() {
    use aip_crypto::custody::Custodian;
    use aip_hsm::{provision_ed25519, PinSource, Pkcs11Config, Pkcs11Custodian};
    use std::path::PathBuf;
    use std::sync::Arc;

    let pid = std::process::id();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let root = std::env::temp_dir().join(format!("aibom-pkcs11-{pid}-{unique}"));
    let tokens = root.join("tokens");
    std::fs::create_dir_all(&tokens).unwrap();

    let conf = root.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .unwrap();

    let module = std::env::var_os("AIP_PKCS11_MODULE")
        .map(PathBuf::from)
        .or_else(|| {
            [
                "/usr/lib/softhsm/libsofthsm2.so",
                "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
                "/usr/lib64/pkcs11/libsofthsm2.so",
            ]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
        })
        .expect("SoftHSM2 module not found");

    let token_label = format!("aibom-{pid}");
    let key_label = format!("aibom-key-{pid}");
    let pin_env = format!("AIBOM_HSM_TEST_PIN_{pid}");
    let cleanup = SoftHsmTestCleanup {
        root: root.clone(),
        pin_env: pin_env.clone(),
        previous_conf: std::env::var_os("SOFTHSM2_CONF"),
    };
    let pin = "1234";
    let so_pin = "5678";

    // Initialize the isolated token before the PKCS#11 module is loaded.
    let status = std::process::Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", &conf)
        .args([
            "--init-token",
            "--free",
            "--label",
            &token_label,
            "--pin",
            pin,
            "--so-pin",
            so_pin,
        ])
        .status()
        .expect("could not execute softhsm2-util");

    assert!(status.success(), "SoftHSM token initialization failed");

    std::env::set_var("SOFTHSM2_CONF", &conf);
    std::env::set_var(&pin_env, pin);

    let config = Pkcs11Config {
        module,
        token_label,
        key_label,
        pin: PinSource::Env(pin_env.clone()),
    };

    // Commission the key inside the token, then open the hardened custodian.
    let provisioned = provision_ed25519(&config).unwrap();
    let custodian = Pkcs11Custodian::open(&config).unwrap();

    assert_eq!(custodian.backend(), aip_crypto::custody::Backend::Pkcs11);
    assert_eq!(custodian.public_key(), provisioned.public_key.as_slice());

    let public_key = custodian.public_key().to_vec();

    let publisher = Publisher::from_custodian("platform-team", Arc::new(custodian)).unwrap();

    let m = manifest("agent");
    let seal = publisher.seal(&m, 60).unwrap();

    let mut anchors = BTreeMap::new();
    anchors.insert("platform-team".to_string(), public_key);

    assert_eq!(verify_seal(&seal, &m, &anchors), Ok(()));

    drop(publisher);
    drop(cleanup);
}
