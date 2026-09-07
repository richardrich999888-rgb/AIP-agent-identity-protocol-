//! Refusals. Every variant here is a path the reference declined to take.
//!
//! There is no `Warning` and no recoverable variant: a correlation that does
//! not hold, a batch that does not verify and a profile that cannot see a
//! class are all reasons to produce *less*, never reasons to produce a
//! weakened positive.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeError {
    /// The attested batch did not verify against the verifier's own observer
    /// anchors. No observation is derived from it — not a weaker one, none.
    BatchNotTrusted { observer_id: String },
    /// The batch verified but carries no observation at that index.
    NoObservationAtIndex { index: usize, len: usize },
    /// The observation at that index describes a **different process
    /// instance** than the one the decision point bound its authorization to.
    ///
    /// This is the cross-execution injection refusal. The comparison is over
    /// the full instance tuple (pid, start ticks, boot id) and the executable
    /// content digest, so an equal pid alone can never satisfy it.
    ProcessInstanceMismatch,
    /// `ObservationRecord::from_attested` refused. Carries its own reason.
    RecordRefused(aip_observation::ObservationError),
    /// The effect layer refused. Carries its own reason.
    EffectRefused(aip_effect::EffectError),
    /// A mechanism code arrived that this build does not implement. Refused
    /// rather than mapped to a neighbour: an unknown mechanism is an unknown
    /// class, and an unknown class has no defensible ceiling.
    UnknownMechanismCode(u8),
    /// The decision point's signature over the expectation did not verify, so
    /// nothing inside it — including the execution binding the correlation
    /// rests on — may be read as authorized.
    ExpectationNotTrusted,
    /// A file, line or field the reference transport requires was absent or
    /// unparseable.
    Transport(String),
}

impl fmt::Display for EdgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BatchNotTrusted { observer_id } => write!(
                f,
                "the batch claiming observer {observer_id:?} did not verify against this \
                 verifier's anchors; no observation is derived from it"
            ),
            Self::NoObservationAtIndex { index, len } => write!(
                f,
                "no observation at index {index}: the batch carries {len}"
            ),
            Self::ProcessInstanceMismatch => write!(
                f,
                "the observation describes a different process instance than the one the \
                 decision point bound; it is evidence about another execution and is \
                 excluded rather than downgraded"
            ),
            Self::RecordRefused(e) => write!(f, "observation record refused: {e}"),
            Self::EffectRefused(e) => write!(f, "effect assessment refused: {e}"),
            Self::UnknownMechanismCode(c) => write!(
                f,
                "mechanism code 0x{c:02x} is not implemented by this build; refusing rather \
                 than guessing which class it belongs to"
            ),
            Self::ExpectationNotTrusted => write!(
                f,
                "the expectation's decision-point signature did not verify; its execution \
                 binding must not be used as the correlation subject"
            ),
            Self::Transport(m) => write!(f, "reference transport: {m}"),
        }
    }
}

impl std::error::Error for EdgeError {}

impl From<aip_observation::ObservationError> for EdgeError {
    fn from(e: aip_observation::ObservationError) -> Self {
        Self::RecordRefused(e)
    }
}

impl From<aip_effect::EffectError> for EdgeError {
    fn from(e: aip_effect::EffectError) -> Self {
        Self::EffectRefused(e)
    }
}
