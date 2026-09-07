//! Containment, and the sentence that has to be said out loud.
//!
//! # Compute containment is not process containment
//!
//! `aip-containment` can freeze a process on a Linux host. On a critical-edge
//! node that means the supervisory software stops issuing commands. It does
//! **not** mean the plant is safe:
//!
//! - a controller keeps executing the program it already has;
//! - outputs hold their last commanded state;
//! - a valve stays where it was, and a pump keeps running;
//! - a process with stored energy keeps converting it.
//!
//! Freezing the thing that gives orders is not the same as stopping the thing
//! that carries them out, and a deployment that reads "contained" as "safe" has
//! made the most expensive category error available in this domain.
//!
//! # This module contains nothing
//!
//! It defines no actuator, holds no key, produces no warrant and has no runtime
//! dependency on `aip-warrant` or `aip-containment`. It states two facts per
//! scope — whether a mechanism exists, and what the fail-safe direction actually
//! is — so that a deployment's own containment design has to confront them.
//!
//! [`ContainmentScope::requires_warrant`] is `true` for both scopes. There is
//! no scope this profile marks as needing less authority, and no method that
//! could produce one.

use serde::{Deserialize, Serialize};

use crate::state::ProcessEvidence;

/// What a containment action would act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ContainmentScope {
    /// The supervisory workload on the edge node: freeze the process.
    EdgeCompute,
    /// The process itself: trip it, isolate it, put it in a safe state.
    ProcessActuation,
}

impl ContainmentScope {
    pub const ALL: [ContainmentScope; 2] = [Self::EdgeCompute, Self::ProcessActuation];

    pub fn code(self) -> u8 {
        match self {
            Self::EdgeCompute => 0x01,
            Self::ProcessActuation => 0x02,
        }
    }

    /// Whether a mechanism exists in this workspace for this scope.
    ///
    /// True for compute alone: the cgroup v2 freezer is real, implemented and
    /// tested. False for process actuation, and it must stay false until an
    /// ADR says otherwise — a profile that claimed to be able to trip a plant
    /// would be claiming an actuator nobody built.
    pub fn mechanism_exists(self) -> bool {
        matches!(self, Self::EdgeCompute)
    }

    /// Whether an action in this scope requires a signed warrant.
    ///
    /// True for both, unconditionally. Containment is the one thing this
    /// architecture does *to* a system rather than *about* it, and the warrant
    /// path is the only path.
    pub fn requires_warrant(self) -> bool {
        true
    }

    /// Whether acting in this scope leaves the plant in a safe state.
    ///
    /// **False for both.** Freezing the supervisory process removes the source
    /// of new commands and moves nothing; and there is no mechanism for the
    /// other scope at all. Written as `false` for both rather than as a
    /// judgement per scope, because the honest answer to "does containment make
    /// the plant safe?" is "this system does not know, and nothing it can do
    /// establishes it".
    pub fn restores_process_safe_state(self) -> bool {
        false
    }

    /// The evidence tier that would be needed to establish that containment
    /// achieved a safe process state.
    pub fn safe_state_evidence_required(self) -> ProcessEvidence {
        ProcessEvidence::PhysicallyObserved
    }

    /// What actually happens when this scope is acted on.
    pub fn fail_safe_direction(self) -> &'static str {
        match self {
            Self::EdgeCompute => {
                "new commands stop; the controller keeps running the program it has, outputs hold \
                 their last commanded state, and the process continues from wherever it was"
            }
            Self::ProcessActuation => {
                "nothing: no actuator in this workspace acts on a plant, and a design that \
                 assumes one is assuming a component that does not exist"
            }
        }
    }

    /// What the scope must not be reported as achieving.
    pub fn must_not_be_read_as(self) -> &'static str {
        match self {
            Self::EdgeCompute => "the process having been made safe",
            Self::ProcessActuation => "an available capability",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containment_never_establishes_a_safe_process_state() {
        for s in ContainmentScope::ALL {
            assert!(!s.restores_process_safe_state(), "{s:?}");
            assert_eq!(
                s.safe_state_evidence_required(),
                ProcessEvidence::PhysicallyObserved
            );
            assert!(!s.safe_state_evidence_required().is_reachable(), "{s:?}");
        }
    }

    #[test]
    fn every_scope_requires_a_warrant() {
        for s in ContainmentScope::ALL {
            assert!(s.requires_warrant(), "{s:?}");
        }
    }

    #[test]
    fn only_compute_containment_has_a_mechanism() {
        assert!(ContainmentScope::EdgeCompute.mechanism_exists());
        assert!(!ContainmentScope::ProcessActuation.mechanism_exists());
        assert!(ContainmentScope::ProcessActuation
            .fail_safe_direction()
            .contains("does not exist"));
    }

    #[test]
    fn freezing_the_supervisor_leaves_the_outputs_where_they_were() {
        let d = ContainmentScope::EdgeCompute.fail_safe_direction();
        assert!(d.contains("outputs hold"));
        assert_eq!(
            ContainmentScope::EdgeCompute.must_not_be_read_as(),
            "the process having been made safe"
        );
    }

    #[test]
    fn scope_codes_are_unique() {
        let mut codes: Vec<u8> = ContainmentScope::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), ContainmentScope::ALL.len());
    }
}
