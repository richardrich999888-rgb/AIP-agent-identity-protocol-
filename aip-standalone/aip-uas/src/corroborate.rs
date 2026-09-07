//! Agreement between sensors, and why it is not truth.
//!
//! # The intuition this module refuses
//!
//! GNSS, IMU and barometer all say 100 m. Surely that is 100 m?
//!
//! No, and the reason is not statistical. All three are inside the aircraft.
//! An attacker at the bus writes all three; a compromised autopilot publishes
//! all three; a spoofer that captures GNSS drags the fused solution the other
//! two are aligned to. Three agreeing reports from inside one trust boundary
//! are **one** report with three names on it, and counting them as three is
//! how a fusion filter becomes an amplifier for whoever owns the bus.
//!
//! Agreement is still worth recording — it is the difference between a
//! consistent picture and a contradictory one, and an operator needs both. So
//! this module counts agreement and refuses to promote it.
//!
//! # Two rules, stated as code
//!
//! 1. [`SensorAgreement::ceiling_after_agreement`] returns the base ceiling
//!    **unchanged**, for any number of agreeing sources. There is no arithmetic
//!    in it, deliberately: a function that computed a ceiling from a count
//!    would eventually compute a higher one.
//! 2. A conflict is reported as a conflict. It is never resolved by majority,
//!    by recency, by a source that looks stronger, or by a self-reported
//!    confidence value — the same rule `EffectFinding::Conflicting` states one
//!    layer down, applied to sensors.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::navigation::NavigationQuantity;
use crate::telemetry::TelemetrySource;

/// What a set of sources said about one quantity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Agreement {
    /// Every reporting source agreed.
    ///
    /// A count, not a score. `independent` is the number of agreeing sources
    /// that are actually outside the subject, and it is reported separately
    /// because it is the only part of the count that adds anything.
    Corroborated { agreeing: u32, independent: u32 },
    /// Sources disagreed. **Never resolved here**, by any rule.
    Conflicting { agreeing: u32, disagreeing: u32 },
    /// Fewer than two sources reported, so there was nothing to agree about.
    Insufficient { reporting: u32 },
}

impl Agreement {
    pub fn code(&self) -> u8 {
        match self {
            Self::Corroborated { .. } => 0x01,
            Self::Conflicting { .. } => 0x02,
            Self::Insufficient { .. } => 0x03,
        }
    }

    /// Whether this agreement supports treating the quantity as established.
    ///
    /// **False for every variant, including `Corroborated`.** Agreement is
    /// consistency, and consistency is not observation. What establishes a
    /// quantity is `NavigationEvidence::establishes`, which asks whether
    /// anything outside the subject measured it.
    pub fn establishes(&self) -> bool {
        false
    }
}

/// A set of sources reporting on one quantity, and what may be said about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorAgreement {
    pub quantity: NavigationQuantity,
    /// Sources that reported a value consistent with the others.
    pub agreeing: Vec<TelemetrySource>,
    /// Sources that reported an inconsistent value.
    pub disagreeing: Vec<TelemetrySource>,
}

impl SensorAgreement {
    /// Classify the set.
    ///
    /// Conflict wins over agreement: a set with any disagreement is
    /// `Conflicting` however many sources agree, because the interesting fact
    /// is that something is wrong and the count of agreeing sources is exactly
    /// the number that would tempt someone to overrule it.
    pub fn classify(&self) -> Agreement {
        let agreeing = self.agreeing.len() as u32;
        let disagreeing = self.disagreeing.len() as u32;
        if disagreeing > 0 {
            return Agreement::Conflicting {
                agreeing,
                disagreeing,
            };
        }
        if agreeing < 2 {
            return Agreement::Insufficient {
                reporting: agreeing,
            };
        }
        Agreement::Corroborated {
            agreeing,
            independent: self
                .agreeing
                .iter()
                .filter(|s| s.is_independent() && s.can_produce_observation_record())
                .count() as u32,
        }
    }

    /// The ceiling after taking agreement into account.
    ///
    /// Returns `base`. Unchanged. For any number of agreeing sources.
    ///
    /// The parameters are consumed so the signature reads like the question a
    /// caller is asking, and the body answers it honestly rather than by
    /// arithmetic that could drift upward.
    pub fn ceiling_after_agreement(&self, base: EvidenceCeiling) -> EvidenceCeiling {
        let _ = self.classify();
        base
    }

    /// Whether this set may be reduced to a single value.
    ///
    /// False whenever anything disagrees. There is deliberately no method that
    /// *performs* such a reduction: resolving a sensor conflict is a domain
    /// decision with safety consequences, and a generic profile that picked a
    /// winner would be making it on a deployment's behalf.
    pub fn is_resolvable(&self) -> bool {
        self.disagreeing.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_agreeing_onboard_sensors_establish_nothing() {
        let a = SensorAgreement {
            quantity: NavigationQuantity::Altitude,
            agreeing: vec![
                TelemetrySource::GnssReceiverOnboard,
                TelemetrySource::ImuOnboard,
                TelemetrySource::BarometerOnboard,
            ],
            disagreeing: vec![],
        };
        match a.classify() {
            Agreement::Corroborated {
                agreeing,
                independent,
            } => {
                assert_eq!(agreeing, 3);
                assert_eq!(
                    independent, 0,
                    "three sensors inside one trust boundary are one report with three names"
                );
            }
            other => panic!("expected corroboration, got {other:?}"),
        }
        assert!(!a.classify().establishes());
    }

    #[test]
    fn agreement_never_raises_the_ceiling() {
        for n in 1..=8usize {
            let a = SensorAgreement {
                quantity: NavigationQuantity::Position,
                agreeing: vec![TelemetrySource::GnssReceiverOnboard; n],
                disagreeing: vec![],
            };
            for base in [
                EvidenceCeiling::Corroborative,
                EvidenceCeiling::Attested,
                EvidenceCeiling::Proven,
            ] {
                assert_eq!(
                    a.ceiling_after_agreement(base),
                    base,
                    "{n} agreeing sources moved the ceiling from {base:?}"
                );
            }
        }
    }

    #[test]
    fn a_conflict_is_never_resolved_by_a_majority() {
        let a = SensorAgreement {
            quantity: NavigationQuantity::Altitude,
            agreeing: vec![
                TelemetrySource::GnssReceiverOnboard,
                TelemetrySource::ImuOnboard,
                TelemetrySource::FlightControllerTelemetry,
            ],
            disagreeing: vec![TelemetrySource::BarometerOnboard],
        };
        match a.classify() {
            Agreement::Conflicting {
                agreeing,
                disagreeing,
            } => {
                assert_eq!(agreeing, 3);
                assert_eq!(disagreeing, 1);
            }
            other => panic!("three-to-one must stay a conflict, got {other:?}"),
        }
        assert!(!a.is_resolvable());
        assert!(!a.classify().establishes());
    }

    #[test]
    fn a_conflict_does_not_raise_the_ceiling_either() {
        let a = SensorAgreement {
            quantity: NavigationQuantity::Position,
            agreeing: vec![TelemetrySource::GnssReceiverOnboard],
            disagreeing: vec![TelemetrySource::ImuOnboard],
        };
        assert_eq!(
            a.ceiling_after_agreement(EvidenceCeiling::Corroborative),
            EvidenceCeiling::Corroborative
        );
    }

    #[test]
    fn one_source_is_not_corroboration() {
        let a = SensorAgreement {
            quantity: NavigationQuantity::Heading,
            agreeing: vec![TelemetrySource::ImuOnboard],
            disagreeing: vec![],
        };
        assert_eq!(a.classify(), Agreement::Insufficient { reporting: 1 });
    }

    #[test]
    fn independent_agreement_is_counted_separately() {
        let a = SensorAgreement {
            quantity: NavigationQuantity::LinkState,
            agreeing: vec![
                TelemetrySource::CompanionNetworkObservation,
                TelemetrySource::FlightControllerTelemetry,
            ],
            disagreeing: vec![],
        };
        match a.classify() {
            Agreement::Corroborated {
                agreeing,
                independent,
            } => {
                assert_eq!(agreeing, 2);
                assert_eq!(independent, 1, "only one of the two is outside the subject");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn no_agreement_variant_establishes_anything() {
        for a in [
            Agreement::Corroborated {
                agreeing: 9,
                independent: 9,
            },
            Agreement::Conflicting {
                agreeing: 1,
                disagreeing: 1,
            },
            Agreement::Insufficient { reporting: 0 },
        ] {
            assert!(!a.establishes(), "{a:?}");
        }
    }
}
