//! The development custodian: a key in memory, and honest about it.
//!
//! # Why this exists and why it is safe to exist
//!
//! Tests need a signer, and so does anyone running the CLI locally. Pretending
//! otherwise produces a worse outcome than providing one: people reach for the
//! raw key bytes instead, and the interface is bypassed entirely.
//!
//! It is safe to exist because [`CustodyPolicy::Production`] refuses it, by
//! class, with no downgrade path. The honesty is the mechanism: this backend
//! reports [`CustodyClass::Development`], that class is `is_exportable()`, and
//! a production policy will not admit it.
//!
//! # What it does not protect against
//!
//! Anything. The key is in this process's memory and, for
//! [`DevCustodian::from_bytes`], came from wherever the caller had it. That is
//! not a limitation to work around; it is the classification.

use crate::custodian::{KeyCustody, SigningCustodian};
use crate::error::CustodyError;
use crate::policy::CustodyClass;

/// An in-memory signer for development and tests.
pub struct DevCustodian {
    key_id: String,
    key_version: u32,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl DevCustodian {
    /// Wrap key bytes the caller already holds.
    ///
    /// Named `from_bytes` rather than `new` so that a reader of a call site
    /// can see raw key material entering the process, which is exactly the
    /// thing a production deployment must not be doing.
    pub fn from_bytes(
        key_id: &str,
        key_version: u32,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Self {
        Self {
            key_id: key_id.to_owned(),
            key_version,
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
        }
    }

    /// Generate a fresh ephemeral key.
    pub fn generate(key_id: &str, key_version: u32) -> Self {
        let kp = aip_crypto::generate_ed25519_keypair();
        Self::from_bytes(key_id, key_version, &kp.private_key, &kp.public_key)
    }
}

impl KeyCustody for DevCustodian {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn key_version(&self) -> u32 {
        self.key_version
    }
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn custody_class(&self) -> CustodyClass {
        // Honest, and load-bearing: this is what a production policy refuses.
        CustodyClass::Development
    }
}

impl SigningCustodian for DevCustodian {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], CustodyError> {
        aip_crypto::sign_ed25519_raw(&self.private_key, message)
            .map_err(|e| CustodyError::SigningFailed(format!("{e:?}")))
    }
}

/// Redacted: a custodian must not print what it holds, in any format.
impl std::fmt::Debug for DevCustodian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevCustodian")
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("custody_class", &CustodyClass::Development)
            .field(
                "private_key",
                &format_args!("<redacted {} bytes>", self.private_key.len()),
            )
            .finish()
    }
}
