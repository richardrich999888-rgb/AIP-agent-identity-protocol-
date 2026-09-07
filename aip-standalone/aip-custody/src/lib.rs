//! Private key custody: one signing interface, pluggable backends, no key
//! accessor.
//!
//! # The problem this crate exists to solve
//!
//! Seven kinds of private key are held across this workspace — an agent
//! identity key, a collector signing key, a service key, decision-point,
//! warrant, containment and NEXORA keys. Six of the seven already implemented
//! the right shape independently: a private field, a `sign()` method, and no
//! accessor. Each was correct; none was named. An unnamed convention followed
//! six times is a convention the seventh implementer will break, and one of the
//! seven had already broken it — `aip_core::store` wrote a key pair to disk as
//! plaintext JSON with no mode and no exclusive create.
//!
//! This crate is the name. The invariant becomes a property of the type system
//! rather than a habit:
//!
//! ```text
//! private key
//!     ↓  never casually serialized   (no Serialize on any custodian)
//!     ↓  never returned to a caller  (no accessor on the trait)
//!     ↓  used through a controlled signing operation
//! signature returned
//!     ↓
//! verification remains independent   (public key only; custody is not evidence)
//! ```
//!
//! # The architecture in twelve answers
//!
//! Set out in full in `docs/architecture/KEY_CUSTODY_INVENTORY.md`; in brief:
//!
//! 1. **Generated where it lives.** [`FileCustodian::generate`] creates the key
//!    and its file in one operation; the bytes never travel.
//! 2. **Lives** in an OS-protected file (mode 0600, `O_EXCL`, permission-checked
//!    parent) or, for tests only, in process memory.
//! 3. **Plaintext exists** in this process's memory during a signing operation,
//!    and on disk for the file backend — stated plainly, because that is what
//!    [`CustodyClass::OsProtectedFile`] classifies and no more.
//! 4. **Used by** the process that owns the file's uid. Enforced by the kernel,
//!    not by this crate.
//! 5. **Export: no API.** [`SigningCustodian`] has no method returning key
//!    material. A holder of `&dyn SigningCustodian` can obtain a public key and
//!    a signature and nothing else.
//! 6. **Rotation** is `(key_id, key_version)` — the same scheme the observer
//!    trust anchors already use, deliberately not a second one.
//! 7. **Backup and recovery** are the operator's, over the key file; this crate
//!    refuses to paper over a lost key by minting a new one.
//! 8. **After compromise**, the key version is revoked at the verifier's anchor
//!    set. Custody has no say in that: revocation is a verifier property.
//! 9. **On reboot**, the file is re-loaded. No re-provisioning, no new identity.
//! 10. **On host replacement**, there is no key to carry over: a new host is a
//!     new key version, anchored deliberately.
//! 11. **Observer continuity** is unchanged and stays owned by `aip-observe`.
//!     Custody moves no key between crates and grants no trust.
//! 12. **Deployment classes** are the [`CustodyClass`] values, and
//!     [`CustodyPolicy`] decides which a deployment will accept.
//!
//! # What this crate deliberately does not claim
//!
//! Not hardware-secured, not tamper-proof, not non-exportable *at the storage
//! layer*. The file backend writes key bytes to a disk in the clear; `root`,
//! anyone with the same uid, and anyone holding the volume can read them.
//! Non-exportability here is a property of the **interface** — no code path in
//! this workspace hands the key to a caller — and that is a narrower and more
//! honest claim than the words a hardware backend would earn.
//!
//! [`CustodyClass::HardwareBacked`] is reserved and unconstructible, and
//! `is_implemented()` returns `false` for it. Implementing it requires ADR-002
//! (hardware attestation, currently **PROPOSED**) to be decided, because a
//! hardware root of trust is a new trust anchor and not a storage detail. A
//! hardware-held key is also not hardware-attested execution and neither is a
//! proof of physical effect; this crate does not conflate the three and its
//! existence is not evidence for any of them.
//!
//! # Fail closed
//!
//! [`CustodyPolicy::Production`] is the default when unconfigured, and refuses
//! [`CustodyClass::Development`] with an error rather than a downgrade. There
//! is no code path from a production policy to a development backend.

pub mod custodian;
pub mod dev;
pub mod error;
pub mod file;
pub mod policy;

pub use custodian::{admits, sign_envelope, KeyCustody, SigningCustodian};
pub use dev::DevCustodian;
pub use error::CustodyError;
pub use file::{
    check_secret_file_permissions, create_secret_file, ensure_secret_dir, write_secret_file,
    FileCustodian,
};
pub use policy::{CustodyClass, CustodyPolicy};
