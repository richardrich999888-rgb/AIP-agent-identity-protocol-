//! Sensor agreement, and why it is not proof.
//!
//! # The robotics version of the intuition
//!
//! Camera, lidar and encoder all say the robot moved two metres. Surely it
//! moved two metres?
//!
//! No. All three are inside the robot. An attacker at the bus writes all three;
//! a compromised autonomy stack publishes all three; and — the failure mode
//! with no attacker in it at all — a robot whose wheels are spinning on a
//! polished floor reports encoder motion, an odometry integral, and a
//! localisation estimate that has been dragged along by both. Three agreeing
//! sensors inside one trust boundary are **one** report with three names on
//! it.
//!
//! # Two rules, as code
//!
//! 1. [`SensorAgreement::ceiling_after_agreement`] returns the base ceiling
//!    unchanged, for any number of agreeing sources, and contains no arithmetic
//!    — a function that computed a ceiling from a count would eventually
//!    compute a higher one.
//! 2. A conflict is reported as a conflict, never resolved by majority, by
//!    recency, by an apparently stronger source, or by a self-reported
//!    confidence. The last is worth naming for robotics specifically: an
//!    estimator's covariance is an output of its own model, so "the filter was
//!    confident" is the subject reporting on itself twice.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::sensing::SensingSource;

/// What a set of sources said about one quantity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Agreement {
    /// Every reporting source agreed. `independent` counts those actually
    /// outside the subject and backed by a mechanism — the only part of the
    /// count that adds anything.
    Corroborated { agreeing: u32, independent: u32 },
    /// Sources disagreed. Never resolved here, by any rule.
    Conflicting { agreeing: u32, disagreeing: u32 },
    /// Fewer than two sources reported.
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

    /// Whether this agreement supports treating a quantity as established.
    ///
    /// **False for every variant, including `Corroborated`.** Agreement is
    /// consistency; consistency is not observation.
    pub fn establishes(&self) -> bool {
        false
    }
}

/// A set of sources reporting on one thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorAgreement {
    pub agreeing: Vec<SensingSource>,
    pub disagreeing: Vec<SensingSource>,
}

impl SensorAgreement {
    /// Classify the set. Conflict wins over agreement: a set with any
    /// disagreement is `Conflicting` however many sources agree, because the
    /// count of agreeing sources is exactly the number that would tempt someone
    /// to overrule the one that does not.
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

    /// The ceiling after taking agreement into account. Returns `base`.
    /// Unchanged. For any number of agreeing sources.
    pub fn ceiling_after_agreement(&self, base: EvidenceCeiling) -> EvidenceCeiling {
        let _ = self.classify();
        base
    }

    /// Whether the set may be reduced to a single value.
    ///
    /// False whenever anything disagrees. There is deliberately no method that
    /// performs such a reduction: resolving a sensor conflict on a machine that
    /// moves near people is a domain decision with safety consequences, and a
    /// generic profile that picked a winner would be making it on a
    /// deployment's behalf.
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
            agreeing: vec![
                SensingSource::EncoderOnboard,
                SensingSource::OdometryOnboard,
                SensingSource::LocalizationEstimateOnboard,
            ],
            disagreeing: vec![],
        };
        match a.classify() {
            Agreement::Corroborated {
                agreeing,
                independent,
            } => {
                assert_eq!(agreeing, 3);
                assert_eq!(independent, 0, "all three are inside the robot");
            }
            other => panic!("{other:?}"),
        }
        assert!(!a.classify().establishes());
    }

    #[test]
    fn agreement_never_raises_the_ceiling() {
        for n in 1..=8usize {
            let a = SensorAgreement {
                agreeing: vec![SensingSource::EncoderOnboard; n],
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
                    "{n} sources, {base:?}"
                );
            }
        }
    }

    #[test]
    fn a_conflict_is_never_resolved_by_a_majority() {
        let a = SensorAgreement {
            agreeing: vec![
                SensingSource::EncoderOnboard,
                SensingSource::OdometryOnboard,
                SensingSource::ImuOnboard,
            ],
            disagreeing: vec![SensingSource::LidarOnboard],
        };
        match a.classify() {
            Agreement::Conflicting {
                agreeing,
                disagreeing,
            } => {
                assert_eq!(agreeing, 3);
                assert_eq!(disagreeing, 1);
            }
            other => panic!("three-to-one must stay a conflict: {other:?}"),
        }
        assert!(!a.is_resolvable());
        assert!(!a.classify().establishes());
    }

    #[test]
    fn one_source_is_not_corroboration() {
        let a = SensorAgreement {
            agreeing: vec![SensingSource::ImuOnboard],
            disagreeing: vec![],
        };
        assert_eq!(a.classify(), Agreement::Insufficient { reporting: 1 });
    }

    #[test]
    fn independent_agreement_is_counted_separately() {
        let a = SensorAgreement {
            agreeing: vec![
                SensingSource::CompanionNetworkObservation,
                SensingSource::ControllerTelemetry,
            ],
            disagreeing: vec![],
        };
        match a.classify() {
            Agreement::Corroborated {
                agreeing,
                independent,
            } => {
                assert_eq!(agreeing, 2);
                assert_eq!(independent, 1);
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
