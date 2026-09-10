//! Turning verified observations into a finding about one requested effect.

use aip_execution::RequestedEffect;
use aip_observation::{Completeness, EvidenceCeiling, ObservationProfile, ObservationRecord};
use serde::{Deserialize, Serialize};

use crate::{EffectBinding, EffectCorrelation, EffectFinding, NotObservedReason};

/// Which way an admitted observation bears on the requested effect.
///
/// # Where this comes from, and where it must not
///
/// An `ObservationRecord` says *that* a mechanism observed a class for an
/// execution. Whether a particular close-write or socket state **supports**
/// "open valve A" is a domain question, and this crate is domain-neutral by
/// design — a generic core that guessed would guess wrong for every vertical.
///
/// So the stance is supplied by the caller, and the caller is a verifier
/// holding records that already passed `ObservationRecord::from_attested`.
/// What this crate enforces is everything the caller could otherwise get
/// wrong: that the record is correlated, that its class can bear weight, that
/// its ceiling is not exceeded, that a conflict is not resolved, and — see
/// [`EffectObservation::new`] — that a record which recorded *nothing* cannot
/// be made to support anything.
///
/// The agent is never the caller. An agent holds no verified records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservedStance {
    /// The observation's content is consistent with the effect having occurred.
    Supports,
    /// The observation's content is inconsistent with it.
    Opposes,
    /// The observation is about this execution but says nothing either way.
    Neither,
}

/// A verified observation, with the stance a verifier read from it.
#[derive(Debug, Clone)]
pub struct EffectObservation {
    record: ObservationRecord,
    stance: ObservedStance,
}

impl EffectObservation {
    /// Pair a verified record with the stance read from its content.
    ///
    /// Refuses to let a record that observed nothing carry a stance. A record
    /// whose [`Completeness`] is `NotObserved` or `NotObservable` is a
    /// statement that the observer has no content here; attaching `Supports`
    /// to it would manufacture evidence out of a stated absence, which is the
    /// exact inversion this whole model exists to prevent. Such a record is
    /// admissible only as `Neither`.
    pub fn new(record: ObservationRecord, stance: ObservedStance) -> Result<Self, EffectError> {
        if !matches!(record.completeness(), Completeness::Observed)
            && !matches!(stance, ObservedStance::Neither)
        {
            return Err(EffectError::StanceWithoutObservation {
                completeness: record.completeness(),
            });
        }
        Ok(Self { record, stance })
    }

    pub fn record(&self) -> &ObservationRecord {
        &self.record
    }
    pub fn stance(&self) -> ObservedStance {
        self.stance
    }
}

/// Why an assessment could not be formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectError {
    /// A stance other than `Neither` was attached to a record that recorded
    /// nothing.
    StanceWithoutObservation { completeness: Completeness },
    /// The assessment was given no effect to assess.
    NoEffectRequested,
}

impl std::fmt::Display for EffectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StanceWithoutObservation { completeness } => write!(
                f,
                "a record with completeness {completeness:?} recorded no content and cannot \
                 support or oppose an effect; absence of observation is not evidence"
            ),
            Self::NoEffectRequested => {
                write!(f, "no effect was requested, so none can be assessed")
            }
        }
    }
}

impl std::error::Error for EffectError {}

/// The time window in which an effect could have occurred.
///
/// Bounds are the **collector's** signed clock, never the agent's. An agent
/// that could move the window could admit an observation from another moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectWindow {
    pub from_ms: u64,
    pub to_ms: u64,
}

impl EffectWindow {
    pub fn contains(&self, attested_at_ms: u64) -> bool {
        attested_at_ms >= self.from_ms && attested_at_ms <= self.to_ms
    }
}

/// An assessment of one requested effect against independent observation.
#[derive(Debug, Clone)]
pub struct EffectAssessment {
    correlation: EffectCorrelation,
    binding: EffectBinding,
    finding: EffectFinding,
}

impl EffectAssessment {
    /// Assess `requested` against `observations`.
    ///
    /// # What is deliberately not a parameter
    ///
    /// There is no `EffectOutcome` and no `EffectDisposition` here. The
    /// agent's own account of whether its effect landed is not an input, so no
    /// amount of self-report can move this result. `requested` is taken to
    /// name the effect and for its parameter commitment; its `target` and the
    /// runtime's transport status are never read.
    ///
    /// # Order of decision
    ///
    /// 1. Nothing supplied → `NoObserverConsulted`. Nobody looked.
    /// 2. Nothing correlated → `NoneCorrelated`. Someone looked elsewhere.
    /// 3. Everything correlated is out of window → `OutsideWindow`.
    /// 4. The profile says no admitted class is observable → `NotObservable`.
    /// 5. No admitted class can carry a positive finding → `ClassCannotEstablish`.
    /// 6. Support and opposition both present → `Conflicting`, unresolved.
    /// 7. One direction → `Corroborated` / `Contradicted` at the computed ceiling.
    /// 8. Otherwise → `Inconclusive`.
    ///
    /// Each earlier step is a stronger statement about *why* nothing was
    /// established, and they are ordered so the most specific true reason
    /// wins.
    pub fn assess(
        requested: &RequestedEffect,
        correlation: &EffectCorrelation,
        window: EffectWindow,
        observations: &[EffectObservation],
        profile: &ObservationProfile,
        requested_effects_in_execution: u32,
    ) -> Result<Self, EffectError> {
        if requested_effects_in_execution == 0 {
            return Err(EffectError::NoEffectRequested);
        }
        let _ = requested; // named for the caller's benefit; never read for the finding.

        let binding = EffectBinding::for_request_count(requested_effects_in_execution);
        let finding = Self::derive(correlation, window, observations, profile);
        Ok(Self {
            correlation: correlation.clone(),
            binding,
            finding,
        })
    }

    fn derive(
        correlation: &EffectCorrelation,
        window: EffectWindow,
        observations: &[EffectObservation],
        profile: &ObservationProfile,
    ) -> EffectFinding {
        if observations.is_empty() {
            return EffectFinding::NotObserved(NotObservedReason::NoObserverConsulted);
        }

        // Correlation is an exclusion, not a discount: a record about another
        // execution is evidence about another execution.
        let correlated: Vec<&EffectObservation> = observations
            .iter()
            .filter(|o| correlation.admits(o.record()))
            .collect();
        if correlated.is_empty() {
            return EffectFinding::NotObserved(NotObservedReason::NoneCorrelated);
        }

        let in_window: Vec<&&EffectObservation> = correlated
            .iter()
            .filter(|o| window.contains(o.record().attested_at_ms()))
            .collect();
        if in_window.is_empty() {
            return EffectFinding::NotObserved(NotObservedReason::OutsideWindow);
        }

        // The deployment's own declaration. A class it says it cannot observe
        // contributes nothing, however many records claim it.
        let observable: Vec<&&&EffectObservation> = in_window
            .iter()
            .filter(|o| profile.capability(o.record().class()).is_observable())
            .collect();
        if observable.is_empty() {
            return EffectFinding::NotObserved(NotObservedReason::NotObservable);
        }

        // A class whose ceiling is `Corroborative` cannot carry a positive
        // finding alone. If nothing better is present, say so rather than
        // reporting a corroboration the ceiling forbids.
        let can_establish: Vec<&&&&EffectObservation> = observable
            .iter()
            .filter(|o| o.record().ceiling_under(profile) > EvidenceCeiling::Corroborative)
            .collect();
        if can_establish.is_empty() {
            return EffectFinding::NotObserved(NotObservedReason::ClassCannotEstablish);
        }

        let supporting = can_establish
            .iter()
            .filter(|o| matches!(o.stance(), ObservedStance::Supports))
            .count() as u32;
        let opposing = can_establish
            .iter()
            .filter(|o| matches!(o.stance(), ObservedStance::Opposes))
            .count() as u32;

        // The ceiling is the strongest any *contributing* record could reach,
        // and it is computed from the class and the profile. Nothing in this
        // function can raise it; `min` inside `ceiling_under` is what caps it.
        let ceiling = |stance: ObservedStance| -> EvidenceCeiling {
            can_establish
                .iter()
                .filter(|o| o.stance() == stance)
                .map(|o| o.record().ceiling_under(profile))
                .max()
                .unwrap_or(EvidenceCeiling::Corroborative)
        };

        match (supporting, opposing) {
            // Both directions present. Not resolved, in either direction, by
            // any rule. See `EffectFinding::Conflicting`.
            (s, o) if s > 0 && o > 0 => EffectFinding::Conflicting {
                supporting: s,
                opposing: o,
            },
            (s, 0) if s > 0 => EffectFinding::Corroborated {
                ceiling: ceiling(ObservedStance::Supports),
                supporting: s,
            },
            (0, o) if o > 0 => EffectFinding::Contradicted {
                ceiling: ceiling(ObservedStance::Opposes),
                opposing: o,
            },
            _ => EffectFinding::Inconclusive {
                records_examined: can_establish.len() as u32,
            },
        }
    }

    pub fn correlation(&self) -> &EffectCorrelation {
        &self.correlation
    }

    /// How tightly this finding attaches to the named effect.
    pub fn binding(&self) -> EffectBinding {
        self.binding
    }

    /// Read-only. There is no setter: the finding is a consequence of the
    /// evidence supplied, never an independent choice.
    pub fn finding(&self) -> &EffectFinding {
        &self.finding
    }

    /// Whether this assessment supports treating the named effect as having
    /// occurred.
    ///
    /// Requires **both** a corroborating finding and an effect-specific
    /// binding. A corroboration that could equally be about a sibling effect
    /// is not evidence about this one, and the conjunction is where that is
    /// enforced rather than left to each caller to remember.
    pub fn establishes_named_effect(&self) -> bool {
        self.finding.asserts_occurrence() && self.binding.is_effect_specific()
    }
}
