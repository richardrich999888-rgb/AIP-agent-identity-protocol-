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
use aip_core::store::IdentityStore;
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

    let mut store = IdentityStore::with_file(&path).unwrap();
    store.put_identity(aid, kp);
    store.save().unwrap();

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
    assert_ne!(
        found.as_deref(),
        Some(secret.as_slice()),
        "the private key was written to {} in the clear",
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
    let mut store = IdentityStore::with_file(&path).unwrap();
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
