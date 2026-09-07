//! What this verifier is prepared to establish — Defect #5.
//!
//! A package declares the parameters its reconciliation ran under. Those
//! declarations are inputs to the verdict, and re-derivation alone cannot
//! object to them: widening the staleness allowance from a minute to a
//! century leaves a record that is still derivable from the same evidence
//! and still true *under those parameters*. Whether those parameters are
//! acceptable is a different question, and it belongs to the verifier.
//!
//! ```text
//!   what the package declares        DeclaredParameters   (in the package)
//!   what this verifier will accept   VerifierCapability   (never in a package)
//!   what it actually established     VerifiedProof        (the output)
//!   what it refuses to claim         InvalidReason::DeclaredParameterRefused
//!                                    InvalidReason::UnsupportedVersion
//! ```
//!
//! # Why there is no "unbounded" default
//!
//! The previous shape was `Option<u64>`, where `None` meant *accept
//! whatever the package declares*. That put the most permissive setting
//! behind the least deliberate act: `VerifierAnchors::default()` produced
//! it, `import_anchors` produced it, and an operator who provisioned keys
//! correctly and simply never thought about declared parameters got a
//! verifier with no bounds at all.
//!
//! So there is no `Default` here, and no variant meaning "anything". Every
//! bound is a value somebody had to write down. A verifier that genuinely
//! wants to accept a century of staleness says `u64::MAX` and that choice
//! is visible in its source, which is the whole difference between a policy
//! and an accident.
//!
//! # Why a package cannot widen it
//!
//! Three independent reasons, in increasing order of how much they would
//! survive a refactor:
//!
//! 1. No package type has a field for it. `NexoraProof` carries
//!    `DeclaredParameters`, which says what the *original run* used, never
//!    what a verifier should accept.
//! 2. `import_anchors` cannot produce a [`VerifierCapability`] — it takes
//!    one from its caller, because there is nothing in an anchor file to
//!    build one from.
//! 3. [`VerifierCapability`] has private fields, no public constructor that
//!    takes untrusted input, and **deliberately does not implement
//!    `Deserialize`**. There is no sequence of bytes that becomes one. That
//!    is the guard that holds even if somebody later adds a field to a
//!    package by mistake.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::proof::NEXORA_PROOF_VERSION;

/// How old a reconciliation this verifier will accept, measured against its
/// own present time.
///
/// Both variants are deliberate statements. There is no third variant
/// meaning "I did not think about it".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ReconciliationAge {
    /// Refuse a package whose reconciliation is older than this. Requires
    /// the verifier to supply a present time; without one the age cannot be
    /// computed and the package is refused rather than waved through.
    AtMost(u64),
    /// This verifier deliberately does not bound how old a reconciliation
    /// may be, because it is checking history rather than currency. An
    /// air-gapped verifier reading a package from three years ago is doing
    /// its job, not failing at it.
    ///
    /// Named, so that choosing it is an act. It is not what you get by
    /// saying nothing.
    Unbounded,
}

/// What this verifier is prepared to establish.
///
/// Constructed only by the verifier's own code — see the module docs for
/// why nothing else can build one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifierCapability {
    /// Proof format versions this build implements. Never empty.
    understood_versions: BTreeSet<u16>,
    /// The largest `health_max_age_ms` a package may declare.
    max_health_age_ms: u64,
    /// The largest `window_tolerance_ms` a package may declare.
    max_window_tolerance_ms: u64,
    /// How old a reconciliation may be.
    max_reconciliation_age: ReconciliationAge,
}

impl VerifierCapability {
    /// A conservative starting point, with every number visible here rather
    /// than spread across call sites:
    ///
    /// - understands exactly the proof version this build implements;
    /// - a package may declare at most **one hour** of health staleness;
    /// - a package may declare **no** window tolerance;
    /// - the reconciliation's age is not bounded, because bounding it would
    ///   require a present time and would break the offline and historical
    ///   cases this verifier exists for. That is the one permissive choice
    ///   in here, and it is named rather than defaulted.
    ///
    /// Adopting this is a decision a verifier makes by naming it. Narrow it
    /// or widen it explicitly with the methods below.
    pub fn strict() -> Self {
        Self {
            understood_versions: BTreeSet::from([NEXORA_PROOF_VERSION]),
            max_health_age_ms: 3_600_000,
            max_window_tolerance_ms: 0,
            max_reconciliation_age: ReconciliationAge::Unbounded,
        }
    }

    /// The proof format versions this build actually implements. A
    /// capability can name a subset of these and nothing else.
    pub const IMPLEMENTED_VERSIONS: &'static [u16] = &[NEXORA_PROOF_VERSION];

    /// Narrow the set of proof versions this verifier will read.
    ///
    /// Two configuration mistakes are refused outright rather than stored.
    ///
    /// An **empty** set would produce a verifier that refuses every package
    /// for a reason nobody could find.
    ///
    /// A version this build does **not implement** would be worse: there is
    /// one parser and one set of verification rules here, so a package
    /// labelled with an unimplemented version would be read under this
    /// build's rules while the report claimed the version was understood.
    /// A declaration is not an implementation, and this is the one place
    /// where the two could be confused, so it is the place that refuses.
    pub fn understanding(mut self, versions: impl IntoIterator<Item = u16>) -> Self {
        let set: BTreeSet<u16> = versions.into_iter().collect();
        assert!(
            !set.is_empty(),
            "a verifier must understand at least one proof version"
        );
        for v in &set {
            assert!(
                Self::IMPLEMENTED_VERSIONS.contains(v),
                "this build does not implement proof version {v}; a verifier \
                 cannot declare a capability it does not have"
            );
        }
        self.understood_versions = set;
        self
    }

    pub fn max_health_age_ms(mut self, ms: u64) -> Self {
        self.max_health_age_ms = ms;
        self
    }

    pub fn max_window_tolerance_ms(mut self, ms: u64) -> Self {
        self.max_window_tolerance_ms = ms;
        self
    }

    pub fn max_reconciliation_age(mut self, age: ReconciliationAge) -> Self {
        self.max_reconciliation_age = age;
        self
    }

    // ─── What it will answer, for the verifier to ask ───

    pub fn understands(&self, version: u16) -> bool {
        self.understood_versions.contains(&version)
    }

    pub fn understood_versions(&self) -> impl Iterator<Item = u16> + '_ {
        self.understood_versions.iter().copied()
    }

    pub fn health_age_bound(&self) -> u64 {
        self.max_health_age_ms
    }

    pub fn window_tolerance_bound(&self) -> u64 {
        self.max_window_tolerance_ms
    }

    pub fn reconciliation_age_bound(&self) -> ReconciliationAge {
        self.max_reconciliation_age
    }
}
