//! Agreement between external sources, and why it is not truth.
//!
//! # No consensus semantics
//!
//! Three ROS 2 topics agreeing is one node's world model published three times.
//! Three telemetry streams from one platform is one platform. Three onboard
//! sensors agreeing is one report with three names on it. A majority vote
//! computed by the subject is the subject voting on itself.
//!
//! So: [`SourceAgreement::ceiling_after_agreement`] returns the base ceiling
//! unchanged, for any number of agreeing sources, and contains no arithmetic. A
//! conflict is reported as a conflict and is never resolved by majority, by
//! recency, by an apparently better source, or by a confidence score.
//!
//! This mirrors `aip-uas`, `aip-robotics` and `aip-industrial` exactly, and for
//! the same reason: three verticals and a validation adapter answering the same
//! question differently would be four accountability models.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::provenance::ProvenanceClass;

/// What a set of sources said about one quantity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Agreement {
    /// Every reporting source agreed. `independent_anchored` counts those
    /// actually outside the subject *and* anchored — the only part of the count
    /// that adds anything.
    Corroborated {
        agreeing: u32,
        independent_anchored: u32,
    },
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
pub struct SourceAgreement {
    pub agreeing: Vec<ProvenanceClass>,
    pub disagreeing: Vec<ProvenanceClass>,
}

impl SourceAgreement {
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
            independent_anchored: self
                .agreeing
                .iter()
                .filter(|c| c.is_external_to_subject() && c.is_anchored())
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
    /// performs such a reduction: resolving a disagreement between a robot's
    /// account of itself and an external observation is the entire question the
    /// experiment exists to ask, and an adapter that picked a winner would be
    /// answering it in advance.
    pub fn is_resolvable(&self) -> bool {
        self.disagreeing.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_agreeing_subject_sources_establish_nothing() {
        let a = SourceAgreement {
            agreeing: vec![
                ProvenanceClass::SubjectSelfReport,
                ProvenanceClass::SubjectControlledRecording,
                ProvenanceClass::SubjectMiddlewareInstrumentation,
            ],
            disagreeing: vec![],
        };
        match a.classify() {
            Agreement::Corroborated {
                agreeing,
                independent_anchored,
            } => {
                assert_eq!(agreeing, 3);
                assert_eq!(
                    independent_anchored, 0,
                    "a topic, its recording and its trace are one report"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(!a.classify().establishes());
    }

    #[test]
    fn agreement_never_raises_the_ceiling() {
        for n in 1..=8usize {
            let a = SourceAgreement {
                agreeing: vec![ProvenanceClass::ExternalSensorAnchored; n],
                disagreeing: vec![],
            };
            for base in [
                EvidenceCeiling::Corroborative,
                EvidenceCeiling::Attested,
                EvidenceCeiling::Proven,
            ] {
                assert_eq!(a.ceiling_after_agreement(base), base, "{n}, {base:?}");
            }
        }
    }

    #[test]
    fn the_robot_disagreeing_with_the_camera_stays_a_conflict() {
        // The experiment's whole point. Two subject-side sources agreeing
        // against one external observation is still a conflict.
        let a = SourceAgreement {
            agreeing: vec![
                ProvenanceClass::SubjectSelfReport,
                ProvenanceClass::ControllerAcknowledgement,
            ],
            disagreeing: vec![ProvenanceClass::ExternalSensorAnchored],
        };
        assert!(matches!(a.classify(), Agreement::Conflicting { .. }));
        assert!(!a.is_resolvable());
        assert!(!a.classify().establishes());
    }

    #[test]
    fn one_source_is_not_corroboration() {
        let a = SourceAgreement {
            agreeing: vec![ProvenanceClass::ExternalSensorAnchored],
            disagreeing: vec![],
        };
        assert_eq!(a.classify(), Agreement::Insufficient { reporting: 1 });
    }

    #[test]
    fn anchored_independence_is_counted_separately() {
        let a = SourceAgreement {
            agreeing: vec![
                ProvenanceClass::ExternalSensorAnchored,
                ProvenanceClass::ExternalSensorUnanchored,
                ProvenanceClass::SimulatorGroundTruth,
            ],
            disagreeing: vec![],
        };
        match a.classify() {
            Agreement::Corroborated {
                agreeing,
                independent_anchored,
            } => {
                assert_eq!(agreeing, 3);
                assert_eq!(
                    independent_anchored, 1,
                    "external and unanchored is nobody observing; so is a simulator"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn no_agreement_variant_establishes_anything() {
        for a in [
            Agreement::Corroborated {
                agreeing: 9,
                independent_anchored: 9,
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
