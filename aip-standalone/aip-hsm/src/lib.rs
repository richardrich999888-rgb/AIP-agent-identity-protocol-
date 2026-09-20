//! `aip-hsm` — a [`Custodian`](aip_crypto::custody::Custodian) backed by a
//! PKCS#11 module (R16 of `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`).
//!
//! # What this changes and what it does not
//!
//! With [`WrappedFileCustodian`](aip_crypto::custody::WrappedFileCustodian)
//! the signing key is decrypted into this process's memory for the life
//! of the custodian. Anyone who can read that memory — a core dump, a
//! debugger, a compromised sibling thread — has the key. A PKCS#11 module
//! removes that: the key is generated *inside* the module with
//! `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`, and the module's own
//! firmware refuses to return it. This process sends 32 bytes and receives
//! a signature. There is no code path here that could return the key,
//! because there is no API on the far side that would give it one.
//!
//! What this does **not** change is what a signature means. A
//! hardware-held key establishes who signed. It says nothing about whether
//! what was signed is true — the observation, the verdict, the ledger —
//! and no evidence-strength decision anywhere in the workspace consults
//! which backend signed. `aip_crypto::custody` says the same thing at more
//! length; this crate inherits it.
//!
//! # What the custodian refuses
//!
//! * A key that is extractable, or not sensitive. Such a key can be
//!   wrapped out of the module by anyone with the PIN, which makes the
//!   module a slow file. Checked at [`Pkcs11Custodian::open`], and the
//!   check reads the attributes back from the module rather than trusting
//!   how the key was said to be created.
//! * Two keys under one label. The custodian will not pick the first; a
//!   label that resolves ambiguously is an operational fault to surface,
//!   not a choice to make silently.
//! * A key whose public half does not verify a signature its private half
//!   just made. The pair is proven at open, so a mislabelled public object
//!   is caught once, at start-up, rather than in an audit.
//! * A PIN on the command line, or in a file another user can read.
//!
//! # The nonce comes from the module
//!
//! The AIP signature envelope carries a 16-byte nonce. Here it is drawn
//! from the module's own RNG (`C_GenerateRandom`) rather than the host's:
//! the module is already the trust anchor for the operation, and this
//! keeps a host with a broken `getrandom` from producing a signature whose
//! envelope is more predictable than its key.
//!
//! # Tested against a real token
//!
//! `tests/softhsm.rs` runs every property above against SoftHSM2 through
//! the same PKCS#11 interface a hardware module presents. The tests do not
//! skip when the module is absent — they fail with the install command —
//! because a custody test that quietly passes on a machine without the
//! module is a custody test that has never run.

pub mod config;
pub mod custodian;
pub mod ec_point;
pub mod error;
pub mod module;
pub mod provision;
pub(crate) mod session;

pub use config::{PinSource, Pkcs11Config};
pub use custodian::Pkcs11Custodian;
pub use error::HsmError;
pub use provision::{provision_ed25519, Provisioned};
