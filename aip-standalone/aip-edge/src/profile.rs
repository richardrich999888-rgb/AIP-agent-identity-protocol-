//! Projecting the observer's one capability declaration into a profile.
//!
//! # The duplication this closes (Skill 22 Phase 7)
//!
//! At baseline there were two unrelated statements of the same fact. The probe
//! told the collector which mechanisms it was provisioned for
//! (`ProcfsProbe::declare_source`, `CollectorSigner::register_probe`), and a
//! verifier separately built an `ObservationProfile` by calling
//! `with_mechanism` for whatever it believed was deployed. Nothing connected
//! them, so a deployment could lose a mechanism and keep a profile that said
//! it had one — and a profile that overstates capability turns
//! `NotObservable` into `NotObserved`, which is the exact inversion the
//! observation model exists to prevent.
//!
//! Here there is **one authoritative declaration**: the mechanism set the
//! observer provisions its probe with, published in its announcement. The
//! verifier projects that set and nothing else.
//!
//! # Why the projection cannot inflate
//!
//! `ObservationProfile::with_mechanism` derives the class from the mechanism
//! and takes the class's own ceiling; a caller cannot choose either. So the
//! strongest thing this projection can produce is what the mechanism already
//! deserved. Lowering stays available to a deliberately conservative
//! deployment through `with_class_at`, which refuses to raise.
//!
//! # Why codes rather than values on the wire
//!
//! `aip-edge-contract` must not link `aip-observe` — see its module docs — so
//! the observer publishes `SourceMechanism::code()` values. Mapping back is
//! [`mechanism_from_code`], which searches `SourceMechanism::ALL` and **fails
//! closed** on a code this build does not implement. Guessing a neighbouring
//! mechanism would assign a class, and therefore a ceiling, to something whose
//! meaning is unknown.

use aip_observation::ObservationProfile;
use aip_observe::SourceMechanism;

use crate::error::EdgeError;

/// The `SourceMechanism` a wire code denotes.
///
/// Derived by sweeping `SourceMechanism::ALL` rather than by a hand-written
/// match, so a mechanism added to `aip-observe` is mapped here automatically
/// and a code removed there stops resolving here — the table cannot drift.
pub fn mechanism_from_code(code: u8) -> Result<SourceMechanism, EdgeError> {
    SourceMechanism::ALL
        .iter()
        .copied()
        .find(|m| m.code() == code)
        .ok_or(EdgeError::UnknownMechanismCode(code))
}

/// Project a declared mechanism set into the deployment's profile.
///
/// The profile starts observing nothing — `ObservationProfile::new`'s honest
/// default — and gains exactly the classes the declared mechanisms imply.
/// Every other class, `PhysicalEffect` among them, stays `NotObservable`,
/// which is what lets the reference state that it cannot see physical effect
/// rather than leaving the question blank.
pub fn profile_from_mechanisms(
    observer_id: &str,
    mechanisms: &[SourceMechanism],
) -> Result<ObservationProfile, EdgeError> {
    let mut profile = ObservationProfile::new(observer_id)?;
    for m in mechanisms {
        profile = profile.with_mechanism(*m);
    }
    Ok(profile)
}

/// As [`profile_from_mechanisms`], from the wire codes an observer published.
///
/// Fails closed on any unknown code: a profile built from a partially
/// understood declaration would silently understate or overstate capability,
/// and both are worse than a refusal the operator can see.
pub fn profile_from_codes(observer_id: &str, codes: &[u8]) -> Result<ObservationProfile, EdgeError> {
    let mechanisms = codes
        .iter()
        .map(|c| mechanism_from_code(*c))
        .collect::<Result<Vec<_>, _>>()?;
    profile_from_mechanisms(observer_id, &mechanisms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observation::{Completeness, EvidenceCeiling, ObservationClass};

    #[test]
    fn every_mechanism_code_round_trips() {
        for m in SourceMechanism::ALL {
            assert_eq!(mechanism_from_code(m.code()).unwrap(), m);
        }
    }

    #[test]
    fn an_unknown_code_is_refused_not_guessed() {
        // 0xFF is not assigned and must never resolve to a neighbour.
        assert_eq!(
            mechanism_from_code(0xFF),
            Err(EdgeError::UnknownMechanismCode(0xFF))
        );
    }

    #[test]
    fn a_profile_declares_only_what_was_projected() {
        let p = profile_from_mechanisms(
            "obs",
            &[SourceMechanism::PidFdAnchored, SourceMechanism::ProcNetTable],
        )
        .unwrap();
        assert!(p.capability(ObservationClass::ProcessIdentity).is_observable());
        assert!(p.capability(ObservationClass::NetworkSocket).is_observable());
        // Nothing was declared for these, so they stay unobservable.
        assert!(!p.capability(ObservationClass::FilesystemEffect).is_observable());
        assert!(!p.capability(ObservationClass::PhysicalEffect).is_observable());
    }

    #[test]
    fn an_undeclared_class_is_not_observable_rather_than_not_observed() {
        let p = profile_from_mechanisms("obs", &[SourceMechanism::PidFdAnchored]).unwrap();
        assert_eq!(
            p.completeness_without_evidence(ObservationClass::PhysicalEffect),
            Completeness::NotObservable,
        );
        assert_eq!(
            p.completeness_without_evidence(ObservationClass::ProcessIdentity),
            Completeness::NotObserved,
        );
    }

    #[test]
    fn the_projection_cannot_raise_a_ceiling() {
        // WireTapAfPacket's class is capped at Corroborative by the class
        // table; projecting the mechanism must not produce anything higher.
        let p = profile_from_mechanisms("obs", &[SourceMechanism::WireTapAfPacket]).unwrap();
        assert_eq!(
            p.capability(ObservationClass::NetworkWire).ceiling(),
            EvidenceCeiling::Corroborative,
        );
    }

    #[test]
    fn an_empty_declaration_observes_nothing() {
        let p = profile_from_mechanisms("obs", &[]).unwrap();
        for class in ObservationClass::ALL {
            assert!(
                !p.capability(class).is_observable(),
                "{class:?} must not be observable under an empty declaration"
            );
        }
    }
}
