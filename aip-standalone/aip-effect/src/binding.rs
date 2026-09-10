//! How tightly an observation is bound to *one* effect.

use serde::{Deserialize, Serialize};

/// The granularity at which independent evidence attaches to an effect.
///
/// # The limitation this type exists to state
///
/// `ObservationCorrelation` binds an observation to a `(system, execution,
/// boot)` triple. It does **not** carry a parameter commitment, because no
/// mechanism in this workspace produces one: a `fanotify` close-write knows a
/// path, a socket tracepoint knows a five-tuple, and neither knows which of an
/// execution's requested effects it corresponds to.
///
/// So when an execution requests one effect, an admitted observation is about
/// that effect and nothing else. When it requests several, the observation is
/// about the execution and the assessment cannot say which effect — and must
/// say *that*, rather than silently attributing it to whichever effect is
/// being assessed.
///
/// Recorded in ADR-004. It is a real gap, not a modelling nicety: an execution
/// that requests "open valve A" and "open valve B" and is observed to have
/// written to one device file has one observation and two candidate effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectBinding {
    /// The observation can only be about this effect: it is correlated to the
    /// execution, and the execution requested exactly one effect.
    Exact,
    /// The observation is bound to the execution, which requested more than
    /// one effect, and carries nothing that names which.
    ///
    /// A consumer must not treat this as effect-specific evidence. It is
    /// evidence that *something* the execution asked for was observed.
    ExecutionOnly {
        /// How many effects the execution requested, and hence how many this
        /// observation could equally be about. Always ≥ 2.
        candidate_effects: u32,
    },
}

impl EffectBinding {
    /// Derive the binding from how many effects the execution requested.
    ///
    /// Zero requested effects is not a legal input to an assessment — there is
    /// nothing to assess — and is treated as the ambiguous case rather than
    /// the exact one, because the conservative reading of a nonsensical count
    /// is the weaker binding.
    pub fn for_request_count(requested_effects: u32) -> Self {
        if requested_effects == 1 {
            Self::Exact
        } else {
            Self::ExecutionOnly {
                candidate_effects: requested_effects,
            }
        }
    }

    /// Whether this binding identifies a single effect.
    ///
    /// The question a consumer asks before treating a finding as being about
    /// the effect it names.
    pub fn is_effect_specific(self) -> bool {
        matches!(self, Self::Exact)
    }

    /// Stable wire code.
    pub fn code(self) -> u8 {
        match self {
            Self::Exact => 0x01,
            Self::ExecutionOnly { .. } => 0x02,
        }
    }
}
