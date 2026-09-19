//! Instrument agreement, and why it is not proof.
//!
//! # The industrial version of the intuition
//!
//! The transmitter, the historian and the HMI all say the pressure was 4.2 bar.
//! Surely it was 4.2 bar?
//!
//! No. The transmitter reported to the control system; the historian archived
//! what the control system reported; the HMI displayed what the control system
//! reported. Three agreeing sources inside one trust boundary are **one** report
//! with three names on it — and the failure mode with no attacker in it at all
//! is a blocked impulse line, whose steady wrong value propagates identically
//! to all three.
//!
//! Redundant transmitters do not fix this. Two-out-of-three voting is excellent
//! against random transmitter failure and is useless against a common-cause
//! failure — a shared tapping, a shared impulse line, a shared power supply, a
//! shared engineering error — and useless against anyone who can write the
//! controller's memory, which is where the vote is counted.
//!
//! # Two rules, as code
//!
//! 1. [`InstrumentAgreement::ceiling_after_agreement`] returns the base ceiling
//!    unchanged, for any number of agreeing sources, and contains no arithmetic
//!    — a function that computed a ceiling from a count would eventually
//!    compute a higher one.
//! 2. A conflict is reported as a conflict, never resolved by majority, by
//!    recency, by an apparently better instrument, or by a voting scheme. The
//!    last is worth naming for industrial specifically: a two-out-of-three vote
//!    is computed *by the controller*, so "the vote agreed" is the subject
//!    reporting on itself once more.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::sensing::ProcessSensingSource;

/// What a set of sources said about one quantity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Agreement {
    /// Every reporting source agreed. `independent` counts those actually
    /// outside the control system and backed by a mechanism — the only part of
    /// the count that adds anything.
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
pub struct InstrumentAgreement {
    pub agreeing: Vec<ProcessSensingSource>,
    pub disagreeing: Vec<ProcessSensingSource>,
}

impl InstrumentAgreement {
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
    /// performs such a reduction: resolving an instrument conflict on a plant
    /// with stored energy in it is a domain decision with safety consequences,
    /// and a generic profile that picked a winner would be making it on a
    /// deployment's behalf.
    pub fn is_resolvable(&self) -> bool {
        self.disagreeing.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_agreeing_control_system_sources_establish_nothing() {
        let a = InstrumentAgreement {
            agreeing: vec![
                ProcessSensingSource::ProcessTransmitter,
                ProcessSensingSource::HistorianArchive,
                ProcessSensingSource::HmiOperatorLog,
            ],
            disagreeing: vec![],
        };
        match a.classify() {
            Agreement::Corroborated {
                agreeing,
                independent,
            } => {
                assert_eq!(agreeing, 3);
                assert_eq!(independent, 0, "all three are inside the control system");
            }
            other => panic!("{other:?}"),
        }
        assert!(!a.classify().establishes());
    }

    #[test]
    fn agreement_never_raises_the_ceiling() {
        for n in 1..=8usize {
            let a = InstrumentAgreement {
                agreeing: vec![ProcessSensingSource::ProcessTransmitter; n],
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
    fn a_two_out_of_three_vote_is_still_a_conflict() {
        let a = InstrumentAgreement {
            agreeing: vec![
                ProcessSensingSource::ProcessTransmitter,
                ProcessSensingSource::HistorianArchive,
            ],
            disagreeing: vec![ProcessSensingSource::IndependentPlantSensor],
        };
        match a.classify() {
            Agreement::Conflicting {
                agreeing,
                disagreeing,
            } => {
                assert_eq!(agreeing, 2);
                assert_eq!(disagreeing, 1);
            }
            other => panic!("two-to-one must stay a conflict: {other:?}"),
        }
        assert!(!a.is_resolvable());
        assert!(!a.classify().establishes());
    }

    #[test]
    fn one_source_is_not_corroboration() {
        let a = InstrumentAgreement {
            agreeing: vec![ProcessSensingSource::ProcessTransmitter],
            disagreeing: vec![],
        };
        assert_eq!(a.classify(), Agreement::Insufficient { reporting: 1 });
    }

    #[test]
    fn independent_agreement_is_counted_separately() {
        let a = InstrumentAgreement {
            agreeing: vec![
                ProcessSensingSource::EdgeNetworkObservation,
                ProcessSensingSource::ControllerStatusReport,
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
