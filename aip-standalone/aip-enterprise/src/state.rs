//! Workload state, and the evidence ladder that differs from the embodied
//! verticals'.
//!
//! # Why the top tier is not called `PhysicallyObserved`
//!
//! UAS, robotics, industrial and space all top out at `PhysicallyObserved`, a
//! tier no mechanism implements. Enterprise does not. A file write is
//! `Fanotify`; a socket is `ProcNetTable`. The top tier here is
//! [`EnterpriseEvidence::LocalEffectObserved`] and it is **reachable**.
//!
//! Naming it `PhysicallyObserved` would have made the five ladders look
//! identical and would have made one of them lie. What remains unreachable is
//! the *remote* effect, and that is a property of the resource rather than of
//! the ladder — see [`crate::resource::EffectLocality`].
//!
//! This is the point ADR-011 records: three rules generalise across all five
//! verticals, and "the top tier is unreachable" is not one of them. It is
//! embodiment-specific.

use serde::{Deserialize, Serialize};

/// What evidence a workload state claim would need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EnterpriseEvidence {
    Declared,
    DecisionSigned,
    ExecutionObserved,
    /// An anchored observer measured an effect **on the observed host** — a
    /// marked path written, a socket held. Reachable, unlike every other
    /// vertical's top tier.
    LocalEffectObserved,
}

impl EnterpriseEvidence {
    pub fn code(self) -> u8 {
        match self {
            Self::Declared => 0x01,
            Self::DecisionSigned => 0x02,
            Self::ExecutionObserved => 0x03,
            Self::LocalEffectObserved => 0x04,
        }
    }

    /// Whether this tier is reachable in this build.
    ///
    /// **True for all four**, and computed rather than asserted: the local
    /// effect tier is reachable exactly when the filesystem-effect class is
    /// implemented, which it is.
    pub fn is_reachable(self) -> bool {
        match self {
            Self::LocalEffectObserved => {
                aip_observation::ObservationClass::FilesystemEffect.is_implemented()
            }
            _ => true,
        }
    }

    /// Whether a **remote** effect is reachable at any tier.
    ///
    /// `false`. A socket to a database is not a row; a call to an API is not a
    /// consequence at the far end. Computed from the class table, so a future
    /// mechanism has to change the table.
    pub fn remote_effect_reachable() -> bool {
        aip_observation::ObservationClass::PhysicalEffect.is_implemented()
    }
}

/// The state of an enterprise workload's activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkloadState {
    Planned,
    Authorized,
    Started,
    Executing,
    Degraded,
    Suspended,
    AbortRequested,
    /// A file was written or a socket held on the observed host.
    LocalEffectApplied,
    /// The far end acted. **Unreachable**: nothing here observes another host.
    RemoteEffectApplied,
    /// The activity finished as intended. A judgement over remote effects.
    Completed,
    Unknown,
}

impl WorkloadState {
    pub const ALL: [WorkloadState; 11] = [
        Self::Planned,
        Self::Authorized,
        Self::Started,
        Self::Executing,
        Self::Degraded,
        Self::Suspended,
        Self::AbortRequested,
        Self::LocalEffectApplied,
        Self::RemoteEffectApplied,
        Self::Completed,
        Self::Unknown,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Planned => 0x01,
            Self::Authorized => 0x02,
            Self::Started => 0x03,
            Self::Executing => 0x04,
            Self::Degraded => 0x05,
            Self::Suspended => 0x06,
            Self::AbortRequested => 0x07,
            Self::LocalEffectApplied => 0x08,
            Self::RemoteEffectApplied => 0x09,
            Self::Completed => 0x0A,
            Self::Unknown => 0xFF,
        }
    }

    pub fn evidence_required(self) -> EnterpriseEvidence {
        match self {
            Self::Planned | Self::Unknown => EnterpriseEvidence::Declared,
            Self::Authorized | Self::AbortRequested => EnterpriseEvidence::DecisionSigned,
            Self::Started | Self::Executing | Self::Degraded | Self::Suspended => {
                EnterpriseEvidence::ExecutionObserved
            }
            Self::LocalEffectApplied => EnterpriseEvidence::LocalEffectObserved,
            // Both of these are about another host. There is no tier for them,
            // and inventing one would be a claim in the type system.
            Self::RemoteEffectApplied | Self::Completed => EnterpriseEvidence::LocalEffectObserved,
        }
    }

    /// Whether this state is a claim about a host nobody here observes.
    pub fn is_remote_claim(self) -> bool {
        matches!(self, Self::RemoteEffectApplied | Self::Completed)
    }

    /// What may be asserted, given a claim and the available evidence.
    ///
    /// Echo or weaken; never strengthen, never substitute. A remote claim
    /// resolves to `Unknown` at every tier, because no tier covers another
    /// host.
    pub fn assertable(claimed: WorkloadState, available: EnterpriseEvidence) -> WorkloadState {
        if claimed.is_remote_claim() {
            return WorkloadState::Unknown;
        }
        if available >= claimed.evidence_required() && claimed.evidence_required().is_reachable() {
            claimed
        } else {
            WorkloadState::Unknown
        }
    }

    pub fn reachable_in_this_build(self) -> bool {
        !self.is_remote_claim() && self.evidence_required().is_reachable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_effect_is_assertable_and_a_remote_one_never_is() {
        // The enterprise difference, stated as a test.
        assert_eq!(
            WorkloadState::assertable(
                WorkloadState::LocalEffectApplied,
                EnterpriseEvidence::LocalEffectObserved
            ),
            WorkloadState::LocalEffectApplied
        );
        for tier in [
            EnterpriseEvidence::Declared,
            EnterpriseEvidence::DecisionSigned,
            EnterpriseEvidence::ExecutionObserved,
            EnterpriseEvidence::LocalEffectObserved,
        ] {
            assert_eq!(
                WorkloadState::assertable(WorkloadState::RemoteEffectApplied, tier),
                WorkloadState::Unknown,
                "{tier:?}"
            );
            assert_eq!(
                WorkloadState::assertable(WorkloadState::Completed, tier),
                WorkloadState::Unknown,
                "{tier:?}"
            );
        }
    }

    #[test]
    fn every_tier_is_reachable_and_remote_effect_is_not() {
        for t in [
            EnterpriseEvidence::Declared,
            EnterpriseEvidence::DecisionSigned,
            EnterpriseEvidence::ExecutionObserved,
            EnterpriseEvidence::LocalEffectObserved,
        ] {
            assert!(t.is_reachable(), "{t:?}");
        }
        assert!(!EnterpriseEvidence::remote_effect_reachable());
    }

    #[test]
    fn assertable_never_strengthens_or_substitutes() {
        for claimed in WorkloadState::ALL {
            for tier in [
                EnterpriseEvidence::Declared,
                EnterpriseEvidence::DecisionSigned,
                EnterpriseEvidence::ExecutionObserved,
                EnterpriseEvidence::LocalEffectObserved,
            ] {
                let out = WorkloadState::assertable(claimed, tier);
                assert!(
                    out == claimed || out == WorkloadState::Unknown,
                    "{claimed:?}/{tier:?}"
                );
            }
        }
    }

    #[test]
    fn execution_states_still_need_an_observation() {
        for s in [
            WorkloadState::Started,
            WorkloadState::Executing,
            WorkloadState::Degraded,
            WorkloadState::Suspended,
        ] {
            assert_eq!(
                WorkloadState::assertable(s, EnterpriseEvidence::ExecutionObserved),
                s,
                "{s:?}"
            );
            assert_eq!(
                WorkloadState::assertable(s, EnterpriseEvidence::DecisionSigned),
                WorkloadState::Unknown,
                "{s:?}"
            );
        }
    }

    #[test]
    fn remote_states_are_unreachable_and_the_rest_are_not() {
        for s in [WorkloadState::RemoteEffectApplied, WorkloadState::Completed] {
            assert!(s.is_remote_claim(), "{s:?}");
            assert!(!s.reachable_in_this_build(), "{s:?}");
        }
        assert!(WorkloadState::LocalEffectApplied.reachable_in_this_build());
        let mut codes: Vec<u8> = WorkloadState::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), WorkloadState::ALL.len());
    }
}
