//! What may honestly be said about whether an effect occurred.

use aip_observation::EvidenceCeiling;
use serde::{Deserialize, Serialize};

/// Why no independent evidence bears on an effect.
///
/// # Five reasons, and why they are not one reason
///
/// Every variant here means "this assessment establishes nothing positive".
/// None of them means "the effect did not happen". Collapsing them into a
/// single `Unknown` would be technically true and operationally useless: an
/// operator who cannot tell "my collector is down" from "the class is not
/// observable in this deployment" from "the observation was too old" cannot
/// fix any of them, and will eventually read all three as "fine".
///
/// This mirrors `aip_observation::Completeness`, which draws the same line
/// between *nothing recorded* and *nothing recordable*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotObservedReason {
    /// No observation records were supplied at all.
    ///
    /// Nobody looked. The honest answer for a tool call with a 200 and nothing
    /// else, and the default this crate returns rather than anything warmer.
    NoObserverConsulted,
    /// Records were supplied and none is about this system, execution and
    /// measured boot.
    ///
    /// Distinct from the previous case: an observer ran, and what it saw was
    /// about something else. That is a correlation failure, which is worth
    /// telling apart from a coverage failure.
    NoneCorrelated,
    /// The deployment declares it cannot observe any class that could bear on
    /// this effect.
    ///
    /// A stated capability gap, read from the `ObservationProfile`. The
    /// canonical case is `ObservationClass::PhysicalEffect`, for which this
    /// workspace has no mechanism at all.
    NotObservable,
    /// Correlated records exist, but every one of them is of a class whose
    /// ceiling cannot support a positive finding on its own.
    ///
    /// `NetworkWire` is the standing example: the device layer knows no
    /// process, so a frame is never bound to an instance.
    ClassCannotEstablish,
    /// Correlated records exist and all of them fall outside the window in
    /// which the effect could have occurred.
    ///
    /// Staleness, in the only form a verifier can check: the collector's own
    /// signed clock, not the agent's.
    OutsideWindow,
}

impl NotObservedReason {
    /// Stable wire code.
    pub fn code(self) -> u8 {
        match self {
            Self::NoObserverConsulted => 0x01,
            Self::NoneCorrelated => 0x02,
            Self::NotObservable => 0x03,
            Self::ClassCannotEstablish => 0x04,
            Self::OutsideWindow => 0x05,
        }
    }
}

/// What independent observation established about one requested effect.
///
/// **Not a verdict.** This is a structural fact about the evidence, and it is
/// an input to `aip-reconcile`, which owns every judgement in this system.
///
/// # No variant asserts non-occurrence
///
/// There is deliberately no `DidNotHappen`. The strongest negative available
/// is [`Self::Contradicted`], which says an anchored observer's finding
/// disagrees with the request — a statement about an observation, still
/// bounded by that observation's ceiling. Absence of evidence never becomes
/// evidence of absence anywhere in this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectFinding {
    /// Correlated, anchored observation supports the requested effect.
    ///
    /// The ceiling is the strongest thing this could contribute and is
    /// computed, never chosen: `min(class ceiling, profile capability)`. It is
    /// reported so a consumer knows what it is holding; this crate does not
    /// gate on it, because gating is the reconciler's job.
    Corroborated {
        ceiling: EvidenceCeiling,
        /// How many admitted records support it. A count, not a score: two
        /// observations from one collector are not twice the evidence.
        supporting: u32,
    },
    /// Correlated, anchored observation disagrees with the requested effect.
    Contradicted {
        ceiling: EvidenceCeiling,
        opposing: u32,
    },
    /// Admitted observations disagree with each other.
    ///
    /// **Never resolved here.** Not by count, not by recency, not by ceiling,
    /// and above all not in whichever direction the requester would prefer. A
    /// system that picks a winner among conflicting independent observers has
    /// replaced observation with preference; the conflict itself is the
    /// finding, and what to do about it belongs to the reconciler and
    /// ultimately to a human.
    Conflicting { supporting: u32, opposing: u32 },
    /// Admitted, in-window observations exist and establish neither direction.
    ///
    /// A verifier looked, with adequate coverage, and found nothing bearing on
    /// this effect. Distinct from [`Self::NotObserved`]: the difference
    /// between *searched and found nothing* and *did not search*.
    Inconclusive { records_examined: u32 },
    /// Nothing independent bears on this effect. See [`NotObservedReason`].
    NotObserved(NotObservedReason),
}

impl EffectFinding {
    /// Stable wire code.
    pub fn code(&self) -> u8 {
        match self {
            Self::Corroborated { .. } => 0x01,
            Self::Contradicted { .. } => 0x02,
            Self::Conflicting { .. } => 0x03,
            Self::Inconclusive { .. } => 0x04,
            Self::NotObserved(_) => 0x05,
        }
    }

    /// Whether this finding asserts the effect occurred.
    ///
    /// True for `Corroborated` alone. `Conflicting` is false in both
    /// directions on purpose: a conflict is not a weak yes.
    pub fn asserts_occurrence(&self) -> bool {
        matches!(self, Self::Corroborated { .. })
    }

    /// Whether this finding asserts the effect did **not** occur.
    ///
    /// Always `false`. It is a method rather than a constant so that a caller
    /// asking the question gets an answer in the same shape as the positive
    /// one, and so that a future variant claiming otherwise has to change this
    /// function and fail its test.
    pub fn asserts_non_occurrence(&self) -> bool {
        false
    }

    /// The strongest evidence this finding could contribute, when it
    /// contributes any.
    ///
    /// `None` for every state that establishes nothing — including
    /// `Conflicting`, which has evidence on both sides and therefore no
    /// direction to contribute in.
    pub fn ceiling(&self) -> Option<EvidenceCeiling> {
        match self {
            Self::Corroborated { ceiling, .. } | Self::Contradicted { ceiling, .. } => {
                Some(*ceiling)
            }
            Self::Conflicting { .. } | Self::Inconclusive { .. } | Self::NotObserved(_) => None,
        }
    }
}
