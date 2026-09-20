//! Generating a key pair inside the module.
//!
//! The only place this crate creates a key, and it creates one kind: a
//! token-resident Ed25519 pair whose private half is sensitive and not
//! extractable. There is no import path. A key that was ever outside the
//! module cannot be shown never to have been copied, and the property this
//! backend exists to provide is exactly that.

use std::sync::Mutex;

use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::session::Session;

use crate::config::Pkcs11Config;
use crate::custodian::Pkcs11Custodian;
use crate::ec_point::{self, ED25519_OID_DER};
use crate::error::HsmError;
use crate::session::{open_logged_in, Access};

/// The outcome of provisioning: the public half, which is what a verifier
/// anchors on. The private half is on the token and nowhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    pub public_key: [u8; 32],
}

/// The private-key policy a key is created with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyPolicy {
    pub sensitive: bool,
    pub extractable: bool,
}

impl KeyPolicy {
    /// The only policy production code uses.
    pub(crate) const HARDENED: KeyPolicy = KeyPolicy {
        sensitive: true,
        extractable: false,
    };
}

/// Generate an Ed25519 pair on the token under `config.key_label`, with
/// the hardened policy, and return the public key.
///
/// Refuses to proceed if a key of that label already exists: a second key
/// under one label would make the custodian refuse to open, and silently
/// producing that state is worse than reporting it.
pub fn provision_ed25519(config: &Pkcs11Config) -> Result<Provisioned, HsmError> {
    provision_with_policy(config, KeyPolicy::HARDENED)
}

/// **Not production.** As [`provision_ed25519`] but with any policy, so a
/// test can prove the custodian refuses a key that could leave the module.
/// Gated behind the `test-fixtures` feature, which no production build
/// enables.
#[cfg(feature = "test-fixtures")]
pub fn provision_ed25519_with_weak_policy(
    config: &Pkcs11Config,
    sensitive: bool,
    extractable: bool,
) -> Result<Provisioned, HsmError> {
    provision_with_policy(
        config,
        KeyPolicy {
            sensitive,
            extractable,
        },
    )
}

/// **Not production.** Create a second key under an existing label, to
/// prove the custodian refuses ambiguity rather than guessing.
#[cfg(feature = "test-fixtures")]
pub fn provision_duplicate_label(config: &Pkcs11Config) -> Result<Provisioned, HsmError> {
    let session = open_rw_logged_in(config)?;
    generate(&session, &config.key_label, KeyPolicy::HARDENED)
}

fn provision_with_policy(
    config: &Pkcs11Config,
    policy: KeyPolicy,
) -> Result<Provisioned, HsmError> {
    let session = open_rw_logged_in(config)?;
    let existing = session
        .find_objects(&[Attribute::Label(config.key_label.as_bytes().to_vec())])
        .map_err(|e| HsmError::from_cryptoki("C_FindObjects", e))?;
    if !existing.is_empty() {
        return Err(HsmError::AmbiguousKey {
            label: config.key_label.clone(),
            count: existing.len(),
        });
    }
    generate(&session, &config.key_label, policy)
}

/// Token objects can only be created in a read-write session.
fn open_rw_logged_in(config: &Pkcs11Config) -> Result<Session, HsmError> {
    open_logged_in(config, Access::ReadWrite)
}

/// One key generation at a time, per process.
///
/// PKCS#11 permits concurrent object creation and hardware modules
/// generally honour it. SoftHSM2's file-backed object store does not:
/// `C_GenerateKeyPair` concurrent with *any* other operation on the same
/// token — another generation, a search, a signature — intermittently
/// fails with `CKR_GENERAL_ERROR`, the standard's "some horrible,
/// unrecoverable error". This lock removes the generation-against-
/// generation case, which is the one a multi-threaded commissioning tool
/// could otherwise produce on its own. It cannot remove the
/// generation-against-signing case, which crosses processes on a file
/// store, and does not pretend to: commissioning is a serial step done
/// when nothing else is using the token, and `deploy/pilot/HSM_CUSTODY.md`
/// says so.
static GENERATE: Mutex<()> = Mutex::new(());

fn generate(session: &Session, label: &str, policy: KeyPolicy) -> Result<Provisioned, HsmError> {
    // A poisoned lock means a generation panicked mid-flight on another
    // thread. The token may be in the inconsistent state the standard
    // warns about; refuse rather than add to it.
    let _serialised = GENERATE.lock().map_err(|_| HsmError::SessionPoisoned)?;

    let label_bytes = label.as_bytes().to_vec();
    let public_template = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        Attribute::Label(label_bytes.clone()),
        Attribute::EcParams(ED25519_OID_DER.to_vec()),
    ];
    let private_template = [
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Sensitive(policy.sensitive),
        Attribute::Extractable(policy.extractable),
        Attribute::Label(label_bytes),
    ];
    let (public_object, _private_object) = session
        .generate_key_pair(
            &Mechanism::EccEdwardsKeyPairGen,
            &public_template,
            &private_template,
        )
        .map_err(|e| HsmError::from_cryptoki("C_GenerateKeyPair", e))?;

    let attrs = session
        .get_attributes(public_object, &[cryptoki::object::AttributeType::EcPoint])
        .map_err(|e| HsmError::from_cryptoki("C_GetAttributeValue", e))?;
    let point = attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(p) => Some(p),
            _ => None,
        })
        .ok_or_else(|| HsmError::EcPoint("generated public object has no CKA_EC_POINT".into()))?;
    Ok(Provisioned {
        public_key: ec_point::ed25519_public_key(&point)?,
    })
}

/// Open a custodian on a freshly provisioned key: what a deployment does
/// once, at commissioning, to confirm the token works end to end.
pub fn provision_and_open(
    config: &Pkcs11Config,
) -> Result<(Provisioned, Pkcs11Custodian), HsmError> {
    let p = provision_ed25519(config)?;
    let c = Pkcs11Custodian::open(config)?;
    Ok((p, c))
}
