//! `ObservationProfile` — what a deployment is provisioned to observe.
//!
//! # The gap this fills
//!
//! `SignedSensorHealth.covered_by` says what an observer **did** cover over a
//! window. Nothing said what a deployment **can** cover, so a class nobody is
//! able to observe was silently absent — indistinguishable, to a reader, from
//! a class that was observable and simply quiet.
//!
//! A profile makes the difference explicit. It is what lets a later UAS
//! profile state honestly that physical-effect observation is unavailable on
//! this airframe, and have that be a recorded fact.
//!
//! # A profile grants nothing
//!
//! It carries no key, no signature and no trust decision. It is a declaration,
//! consumed by a verifier, in the same shape as Skill 19's platform registry.
//! In particular a profile **cannot raise a ceiling**: the construction point
//! takes the minimum of the declared value and the class's own, so a
//! deployment can be more conservative than the architecture and never less.

use std::collections::BTreeMap;

use aip_observe::SourceMechanism;
use aip_types::canonical::{put_domain, put_str, put_u16, put_u32, put_u8};
use serde::{Deserialize, Serialize};

use crate::class::{class_of, EvidenceCeiling, ObservationClass};
use crate::completeness::Completeness;
use crate::error::ObservationError;

/// Domain tag leading every `ObservationProfile` canonical encoding.
pub const OBSERVATION_PROFILE_DOMAIN: &str = "SYNTRIASS/AUTONOMY/OBSERVATION_PROFILE/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const OBSERVATION_PROFILE_VERSION: u16 = 1;

/// What a deployment can observe for one class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassCapability {
    /// The strongest evidence this deployment could contribute for the class.
    ///
    /// Never above [`ObservationClass::ceiling`] — the constructor takes the
    /// minimum, so a malformed or over-optimistic declaration is lowered
    /// rather than accepted.
    ceiling: EvidenceCeiling,
    /// Whether any mechanism here can produce the class at all.
    observable: bool,
}

impl ClassCapability {
    pub fn ceiling(&self) -> EvidenceCeiling {
        self.ceiling
    }
    pub fn is_observable(&self) -> bool {
        self.observable
    }
}

/// A deployment's declared observation capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationProfile {
    pub version: u16,
    /// The observer this profile describes. A reference the existing anchor
    /// model resolves; naming an observer here grants it nothing.
    observer_id: String,
    /// Class → capability. `BTreeMap` so the encoding is order-independent.
    classes: BTreeMap<u8, ClassCapability>,
}

impl ObservationProfile {
    /// A profile that observes nothing.
    ///
    /// The honest default: every class is `NotObservable` until a mechanism is
    /// declared for it. A profile that started out claiming capability would
    /// make silence look like coverage.
    pub fn new(observer_id: &str) -> Result<Self, ObservationError> {
        if observer_id.is_empty() || observer_id.len() > 128 {
            return Err(ObservationError::Malformed {
                reason: "observer id must be 1-128 bytes",
            });
        }
        Ok(Self {
            version: OBSERVATION_PROFILE_VERSION,
            observer_id: observer_id.to_owned(),
            classes: BTreeMap::new(),
        })
    }

    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }

    /// Declare that this deployment provisions `mechanism`.
    ///
    /// The class follows from the mechanism — a caller does not get to choose
    /// it, because a caller that could choose would eventually choose a class
    /// with a higher ceiling than the mechanism deserves. The ceiling is the
    /// class's own.
    pub fn with_mechanism(mut self, mechanism: SourceMechanism) -> Self {
        let class = class_of(mechanism);
        let cap = ClassCapability {
            ceiling: class.ceiling(),
            observable: true,
        };
        // A class provisioned twice keeps the same capability; mechanisms
        // within a class do not accumulate into a stronger claim.
        self.classes.insert(class.code(), cap);
        self
    }

    /// Declare a class observable at a ceiling **no higher** than its own.
    ///
    /// For a deployment that is deliberately more conservative than the
    /// architecture allows — a mirror-port collector that will not vouch for
    /// process identity, say. Raising a ceiling is refused rather than
    /// silently lowered, because a caller attempting it has misunderstood
    /// something and should be told.
    pub fn with_class_at(
        mut self,
        class: ObservationClass,
        ceiling: EvidenceCeiling,
    ) -> Result<Self, ObservationError> {
        if ceiling > class.ceiling() {
            return Err(ObservationError::CeilingRaised { class });
        }
        self.classes.insert(
            class.code(),
            ClassCapability {
                ceiling,
                observable: true,
            },
        );
        Ok(self)
    }

    /// What this deployment can do for `class`.
    ///
    /// An undeclared class is `NotObservable` with the lowest ceiling — never
    /// an optimistic default.
    pub fn capability(&self, class: ObservationClass) -> ClassCapability {
        self.classes
            .get(&class.code())
            .copied()
            .unwrap_or(ClassCapability {
                ceiling: EvidenceCeiling::Corroborative,
                observable: false,
            })
    }

    /// How a class with no evidence should be recorded for this deployment.
    ///
    /// The distinction the whole module exists for: a class this deployment
    /// cannot observe is `NotObservable`; one it can observe but did not is
    /// `NotObserved`. Neither says the event did not happen.
    pub fn completeness_without_evidence(&self, class: ObservationClass) -> Completeness {
        if self.capability(class).is_observable() {
            Completeness::NotObserved
        } else {
            Completeness::NotObservable
        }
    }

    pub fn check_version(&self) -> Result<(), ObservationError> {
        if self.version != OBSERVATION_PROFILE_VERSION {
            return Err(ObservationError::UnsupportedVersion {
                found: self.version,
                supported: OBSERVATION_PROFILE_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    ///
    /// Classes are key-sorted by the `BTreeMap` and counted, so two profiles
    /// declaring the same capability encode identically whatever order they
    /// were built in, and a truncated list is not a valid prefix of a longer
    /// one.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, OBSERVATION_PROFILE_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.observer_id);
        put_u32(&mut buf, self.classes.len() as u32);
        for (code, cap) in &self.classes {
            put_u8(&mut buf, *code);
            put_u8(&mut buf, cap.ceiling.code());
            put_u8(&mut buf, u8::from(cap.observable));
        }
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        aip_crypto::sha256(&self.canonical_bytes())
    }
}
