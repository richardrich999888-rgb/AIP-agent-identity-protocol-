//! The custodian: finds the key, proves the pair, refuses weak policy,
//! and signs.

use std::sync::Mutex;

use aip_crypto::custody::{Backend, Custodian, CustodyError};
use aip_crypto::{sha256, signature_signed_bytes, verify_ed25519_raw};
use aip_types::{AlgorithmId, Signature};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

use crate::config::Pkcs11Config;
use crate::ec_point;
use crate::error::HsmError;
use crate::session::{open_logged_in, Access};

/// Length of the envelope nonce, fixed by `aip_types::Signature`.
const NONCE_LEN: usize = 16;
/// Length of an Ed25519 signature.
const ED25519_SIGNATURE_LEN: usize = 64;
/// What the pair is proven with at open. Any fixed bytes will do; naming
/// them keeps the probe recognisable in a module's audit log.
const PAIR_PROBE_MESSAGE: &[u8] = b"aip-hsm pair probe";

/// A signing key held inside a PKCS#11 module.
///
/// The private key is never in this struct, never in this process. The
/// session is behind a mutex because PKCS#11 forbids concurrent operations
/// on one session; a poisoned mutex makes every subsequent sign fail rather
/// than proceed on a session whose state is unknown.
pub struct Pkcs11Custodian {
    session: Mutex<Session>,
    private_key: ObjectHandle,
    public_key: Vec<u8>,
    token_label: String,
    key_label: String,
}

impl std::fmt::Debug for Pkcs11Custodian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Custodian")
            .field("backend", &Backend::Pkcs11)
            .field("token_label", &self.token_label)
            .field("key_label", &self.key_label)
            .field("public_key_prefix", &hex_prefix(&self.public_key))
            .finish()
    }
}

impl Pkcs11Custodian {
    /// Open the module, find the token, log in, find the key, and prove it.
    ///
    /// Everything that can be wrong with a deployment is discovered here,
    /// once, rather than at the first signature an audit depends on.
    pub fn open(config: &Pkcs11Config) -> Result<Self, HsmError> {
        // Read-only is enough to sign. A read-write session would let a
        // bug here modify token objects; least privilege costs nothing.
        let session = open_logged_in(config, Access::ReadOnly)?;

        let private_key = find_exactly_one(&session, ObjectClass::PRIVATE_KEY, &config.key_label)?;
        refuse_weak_policy(&session, private_key, &config.key_label)?;

        let public_object = find_exactly_one(&session, ObjectClass::PUBLIC_KEY, &config.key_label)?;
        let public_key = read_public_key(&session, public_object)?;

        // Prove the pair. A public object under the right label is only a
        // claim; a signature that verifies under it is a fact.
        let probe = sign_raw(&session, private_key, PAIR_PROBE_MESSAGE)?;
        if !verify_ed25519_raw(&public_key, PAIR_PROBE_MESSAGE, &probe) {
            return Err(HsmError::KeyPairMismatch {
                label: config.key_label.clone(),
            });
        }

        Ok(Self {
            session: Mutex::new(session),
            private_key,
            public_key: public_key.to_vec(),
            token_label: config.token_label.clone(),
            key_label: config.key_label.clone(),
        })
    }

    pub fn token_label(&self) -> &str {
        &self.token_label
    }

    pub fn key_label(&self) -> &str {
        &self.key_label
    }
}

impl Custodian for Pkcs11Custodian {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign the AIP envelope. The construction is
    /// `aip_crypto::signature_signed_bytes`, the one function the software
    /// signer and the verifier already share, so a verifier cannot tell —
    /// and does not need to know — that a module signed.
    fn sign(&self, signer_id: &str, payload: &[u8]) -> Result<Signature, CustodyError> {
        let session = self
            .session
            .lock()
            .map_err(|_| custody_io(HsmError::SessionPoisoned))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CustodyError::Io(format!("system clock before the epoch: {e}")))?
            .as_millis() as u64;

        // The nonce from the module's RNG, not the host's. The envelope
        // requires one (FIX-1); the module is already the trust anchor.
        let mut nonce = [0u8; NONCE_LEN];
        session
            .generate_random_slice(&mut nonce)
            .map_err(|e| custody_io(HsmError::from_cryptoki("C_GenerateRandom", e)))?;

        let payload_hash = sha256(payload);
        let signed_bytes = signature_signed_bytes(
            AlgorithmId::Ed25519,
            signer_id,
            timestamp,
            &nonce,
            &payload_hash,
        );
        let sig = sign_raw(&session, self.private_key, &signed_bytes).map_err(custody_io)?;

        Ok(Signature {
            algorithm: AlgorithmId::Ed25519,
            signer_id: signer_id.to_string(),
            timestamp,
            nonce,
            payload_hash,
            signature_bytes: sig.to_vec(),
        })
    }

    fn backend(&self) -> Backend {
        Backend::Pkcs11
    }
}

// ─── Pieces ───

/// Exactly one Ed25519 object of `class` under `label`. Zero and many are
/// both errors, with different names.
fn find_exactly_one(
    session: &Session,
    class: ObjectClass,
    label: &str,
) -> Result<ObjectHandle, HsmError> {
    let found = session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .map_err(|e| HsmError::from_cryptoki("C_FindObjects", e))?;
    match found.len() {
        1 => Ok(found[0]),
        0 => Err(HsmError::KeyNotFound {
            label: label.to_string(),
        }),
        n => Err(HsmError::AmbiguousKey {
            label: label.to_string(),
            count: n,
        }),
    }
}

/// Read the policy back from the module and refuse a key that could leave
/// it. The attributes are read, not assumed from how the key was
/// provisioned: a key imported by a different tool has whatever policy
/// that tool gave it.
fn refuse_weak_policy(session: &Session, key: ObjectHandle, label: &str) -> Result<(), HsmError> {
    let attrs = session
        .get_attributes(key, &[AttributeType::Sensitive, AttributeType::Extractable])
        .map_err(|e| HsmError::from_cryptoki("C_GetAttributeValue", e))?;
    let mut sensitive = None;
    let mut extractable = None;
    for a in attrs {
        match a {
            Attribute::Sensitive(v) => sensitive = Some(v),
            Attribute::Extractable(v) => extractable = Some(v),
            _ => {}
        }
    }
    // A module that will not say is a module whose policy cannot be
    // established, and an unestablished policy is not a safe one.
    match (sensitive, extractable) {
        (Some(true), Some(false)) => Ok(()),
        (s, e) => Err(HsmError::KeyPolicy {
            label: label.to_string(),
            detail: format!(
                "CKA_SENSITIVE={} CKA_EXTRACTABLE={}; required true/false",
                s.map(|v| v.to_string())
                    .unwrap_or_else(|| "unreported".into()),
                e.map(|v| v.to_string())
                    .unwrap_or_else(|| "unreported".into()),
            ),
        }),
    }
}

fn read_public_key(session: &Session, object: ObjectHandle) -> Result<[u8; 32], HsmError> {
    let attrs = session
        .get_attributes(object, &[AttributeType::EcPoint])
        .map_err(|e| HsmError::from_cryptoki("C_GetAttributeValue", e))?;
    let point = attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(p) => Some(p),
            _ => None,
        })
        .ok_or_else(|| HsmError::EcPoint("the public object has no CKA_EC_POINT".into()))?;
    ec_point::ed25519_public_key(&point)
}

/// One raw Ed25519 signature over `data`, pure mode (no pre-hash, no
/// context), which is what RFC 8032 Ed25519 is and what
/// `verify_ed25519_raw` checks.
fn sign_raw(
    session: &Session,
    key: ObjectHandle,
    data: &[u8],
) -> Result<[u8; ED25519_SIGNATURE_LEN], HsmError> {
    let mech = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
    let sig = session
        .sign(&mech, key, data)
        .map_err(|e| HsmError::from_cryptoki("C_Sign", e))?;
    sig.try_into()
        .map_err(|v: Vec<u8>| HsmError::SignatureLength(v.len()))
}

fn custody_io(e: HsmError) -> CustodyError {
    CustodyError::Io(e.to_string())
}

fn hex_prefix(b: &[u8]) -> String {
    b.iter()
        .take(4)
        .map(|x| format!("{x:02x}"))
        .collect::<String>()
        + "…"
}
