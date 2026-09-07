//! Custody of the collector's signing key — owned here, and nowhere else.
//!
//! The collector's key anchors every attested observation. If it is
//! forged, every batch, every health record and every continuity report
//! this system produces can be forged with it — and the reconciler, the
//! warrant engine and the proof layer all rest on those. It is the most
//! sensitive key in the repository, and until Phase A it had no supported
//! way to exist at rest at all: the only worked example was a demo binary
//! writing hex to a file at mode 644.
//!
//! # Why this module is in `aip-observe`
//!
//! Observer trust is independent of the observed subject. That
//! independence is not a property of any one check — it is a property of
//! *who holds the key*, and it survives only as long as nobody else owns
//! that decision. So the collector key's custody lives in the crate that
//! signs with it, and not in a platform layer, a reconciler, a proof layer
//! or a system model. `aip-crypto` supplies the mechanism; the policy for
//! this key is here.
//!
//! # What a protected key does and does not buy
//!
//! ```text
//! protected key  →  "this collector signed it"
//! protected key  ↛  "what it signed is true"
//! ```
//!
//! Custody raises the cost of forging the *signature*. It says nothing
//! about the truthfulness of the observation, and nothing in this crate
//! reads a stronger meaning out of which backend signed. A collector whose
//! key is in an HSM and whose probe is lying produces impeccably signed
//! lies.

use aip_crypto::custody::{
    Backend, Custodian, CustodyError, InMemoryCustodian, WrappedFileCustodian,
};

/// How a deployment is expected to hold the collector key.
///
/// Named rather than inferred, so that a development collector cannot be
/// mistaken for a production one by reading its configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorKeyPolicy {
    /// A production deployment: the custodian's backend must be one that
    /// survives the process, and a development backend is refused.
    Production,
    /// Tests, demos and development. Says so.
    Development,
}

/// Why a collector key was refused.
#[derive(Debug)]
pub enum CollectorKeyError {
    /// A production collector was handed a development backend. Refused
    /// rather than downgraded: a collector that signs with an
    /// in-memory key is not a slightly weaker production collector, it is
    /// a development one, and calling it production is the mistake.
    DevelopmentBackendInProduction(Backend),
    Custody(CustodyError),
}

impl std::fmt::Display for CollectorKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollectorKeyError::DevelopmentBackendInProduction(b) => write!(
                f,
                "a production collector cannot use the {b:?} backend: its key would not \
                 survive the process, and nothing would be protecting it while it did"
            ),
            CollectorKeyError::Custody(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CollectorKeyError {}

impl From<CustodyError> for CollectorKeyError {
    fn from(e: CustodyError) -> Self {
        CollectorKeyError::Custody(e)
    }
}

/// The collector's key, held by a custodian this crate chose.
///
/// The private key is not reachable through this type. It signs.
#[derive(Debug)]
pub struct CollectorKey {
    custodian: Box<dyn Custodian>,
    policy: CollectorKeyPolicy,
}

impl CollectorKey {
    /// Open — or on first run, create — a production collector key wrapped
    /// under `passphrase` at `path`.
    ///
    /// First initialization and every subsequent start are the same call,
    /// because a collector that needs a different command the first time
    /// it runs is a collector somebody will get wrong at three in the
    /// morning.
    pub fn production(
        path: impl AsRef<std::path::Path>,
        passphrase: &[u8],
    ) -> Result<Self, CollectorKeyError> {
        let path = path.as_ref();
        let custodian = if path.exists() {
            WrappedFileCustodian::open(path, passphrase)?
        } else {
            WrappedFileCustodian::create(path, passphrase)?
        };
        Self::with_custodian(Box::new(custodian), CollectorKeyPolicy::Production)
    }

    /// Replace the key at `path`. The previous key is gone; signatures it
    /// made stay verifiable for anyone holding its public key, because
    /// verification does not consult custody.
    pub fn rotate(
        path: impl AsRef<std::path::Path>,
        passphrase: &[u8],
    ) -> Result<Self, CollectorKeyError> {
        let custodian = WrappedFileCustodian::rotate(path, passphrase)?;
        Self::with_custodian(Box::new(custodian), CollectorKeyPolicy::Production)
    }

    /// A key that exists only for this process. Development and tests.
    pub fn development() -> Self {
        Self {
            custodian: Box::new(InMemoryCustodian::generate()),
            policy: CollectorKeyPolicy::Development,
        }
    }

    /// Adopt any custodian under a stated policy. The production policy
    /// refuses a development backend; there is no fallback, silent or
    /// otherwise.
    pub fn with_custodian(
        custodian: Box<dyn Custodian>,
        policy: CollectorKeyPolicy,
    ) -> Result<Self, CollectorKeyError> {
        if policy == CollectorKeyPolicy::Production && !custodian.backend().is_production() {
            return Err(CollectorKeyError::DevelopmentBackendInProduction(
                custodian.backend(),
            ));
        }
        Ok(Self { custodian, policy })
    }

    pub fn public_key(&self) -> &[u8] {
        self.custodian.public_key()
    }

    pub fn backend(&self) -> Backend {
        self.custodian.backend()
    }

    pub fn policy(&self) -> CollectorKeyPolicy {
        self.policy
    }

    /// Sign as `observer_id`. The only thing this type does with the key.
    pub fn sign(
        &self,
        observer_id: &str,
        payload: &[u8],
    ) -> Result<aip_types::Signature, CollectorKeyError> {
        Ok(self.custodian.sign(observer_id, payload)?)
    }
}
