//! Agreement between enterprise evidence sources, and why it is not proof.
//!
//! # The enterprise version of the intuition
//!
//! The agent's log, the framework's trace and the APM span all say the tool
//! call succeeded. Surely it did?
//!
//! No. All three are emitted by the same process. The framework traces what the
//! workload told it, the APM agent is instrumented into the workload's own
//! build, and the log is a line the workload chose to write. Three agreeing
//! sources inside one trust boundary are **one** report with three names on it.
//!
//! # Two rules, as code
//!
//! 1. [`SourceAgreement::ceiling_after_agreement`] returns the base ceiling
//!    unchanged, for any number of agreeing sources, and contains no
//!    arithmetic.
//! 2. A conflict is reported as a conflict, never resolved by majority, by
//!    recency, by an apparently better source, or by a confidence score. The
//!    last is worth naming for enterprise specifically: a model's own
//!    self-reported confidence is an output of the thing being asked.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

use crate::source::EnterpriseSource;

/// What a set of sources said about one quantity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Agreement {
    Corroborated { agreeing: u32, independent: u32 },
    Conflicting { agreeing: u32, disagreeing: u32 },
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
    /// **False for every variant, including `Corroborated`.**
    pub fn establishes(&self) -> bool {
        false
    }
}

/// A set of sources reporting on one thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAgreement {
    pub agreeing: Vec<EnterpriseSource>,
    pub disagreeing: Vec<EnterpriseSource>,
}

impl SourceAgreement {
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
    pub fn ceiling_after_agreement(&self, base: EvidenceCeiling) -> EvidenceCeiling {
        let _ = self.classify();
        base
    }

    /// Whether the set may be reduced to a single value.
    ///
    /// False whenever anything disagrees. There is deliberately no method that
    /// performs such a reduction: when the agent says it called the API and the
    /// host observer saw no socket, which one is wrong is the entire question,
    /// and a profile that picked a winner would be answering it in advance.
    pub fn is_resolvable(&self) -> bool {
        self.disagreeing.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_agreeing_in_process_sources_establish_nothing() {
        let a = SourceAgreement {
            agreeing: vec![
                EnterpriseSource::AgentSelfReport,
                EnterpriseSource::FrameworkTrace,
                EnterpriseSource::ApmTelemetry,
            ],
            disagreeing: vec![],
        };
        match a.classify() {
            Agreement::Corroborated {
                agreeing,
                independent,
            } => {
                assert_eq!(agreeing, 3);
                assert_eq!(independent, 0, "all three come out of one process");
            }
            other => panic!("{other:?}"),
        }
        assert!(!a.classify().establishes());
    }

    #[test]
    fn agreement_never_raises_the_ceiling() {
        for n in 1..=8usize {
            let a = SourceAgreement {
                agreeing: vec![EnterpriseSource::AgentSelfReport; n],
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
    fn a_host_observer_disagreeing_with_the_workload_stays_a_conflict() {
        let a = SourceAgreement {
            agreeing: vec![
                EnterpriseSource::AgentSelfReport,
                EnterpriseSource::FrameworkTrace,
                EnterpriseSource::ApplicationLog,
            ],
            disagreeing: vec![EnterpriseSource::HostSocketObservation],
        };
        assert!(matches!(a.classify(), Agreement::Conflicting { .. }));
        assert!(!a.is_resolvable());
        assert!(!a.classify().establishes());
    }

    #[test]
    fn one_source_is_not_corroboration_and_no_variant_establishes() {
        let a = SourceAgreement {
            agreeing: vec![EnterpriseSource::AgentSelfReport],
            disagreeing: vec![],
        };
        assert_eq!(a.classify(), Agreement::Insufficient { reporting: 1 });
        for v in [
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
            assert!(!v.establishes(), "{v:?}");
        }
    }
}
