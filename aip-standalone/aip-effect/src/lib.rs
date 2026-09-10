//! The effect boundary: what independent observation establishes about an
//! actuation, and where the claim stops.
//!
//! # What this crate is for
//!
//! Skill 18 (`aip-execution`) models what the *agent* says: it asked for an
//! effect, it made a call, the call returned. Skill 20 (`aip-observation`)
//! models what an *observer* saw, with a class and a ceiling. The two were
//! never joined, and the join is the whole of the effect boundary:
//!
//! ```text
//!   aip-execution            aip-effect              aip-observation
//!   ─────────────            ──────────              ───────────────
//!   RequestedEffect  ──┐                        ┌──  ObservationRecord
//!   RuntimeAction    ──┼──►  EffectAssessment  ◄┤    (verified, correlated,
//!   (agent-authored)   │          │             │     classed, ceilinged)
//!                      │          ▼             │
//!                      │     EffectFinding      │
//!                      │   + EvidenceCeiling    │
//!                      │   + EffectBinding      │
//! ```
//!
//! # The one rule everything else follows from
//!
//! **The agent's own account is not an input to the finding.**
//!
//! [`EffectAssessment::assess`] takes the agent's [`RequestedEffect`] to know
//! *what to look for*, and never reads
//! [`aip_execution::EffectDisposition`] at all. An agent that hands over
//! `Confirmed(...)` with fabricated evidence gets exactly the finding its
//! observations earn, which is usually [`EffectFinding::NotObserved`].
//!
//! That is why this crate exists rather than a method on `EffectOutcome`: a
//! method there would take `&self`, and `&self` contains the agent's
//! disposition. Separating the types separates the trust boundary.
//!
//! # The layers this crate keeps apart
//!
//! ```text
//! intent              the agent's mind             SelfReported
//! expected execution  the decision point           authority, not effect
//! actuation request   the agent called something   SelfReported
//! actuation execution the call returned            SelfReported
//! observed actuation  an anchored observer saw it  Attested (ceiling)
//! observed state      a device reported state      Attested (ceiling)
//! physical effect     a physical variable moved    no mechanism → CANNOT_PROVE
//! mission outcome     the objective was met        out of scope entirely
//! ```
//!
//! A transport status of 200 lives three rows above the first row anything
//! independent appears in. This crate cannot move it up, because it never
//! reads it.
//!
//! # What this crate does not do
//!
//! It produces **no verdict**. [`EffectFinding`] is a structural statement
//! about which independent evidence exists for one requested effect. It is an
//! input to the single reconciliation engine in `aip-reconcile`, which is
//! untouched by this crate. There is no second reconciler, no second verifier,
//! no second evidence vocabulary: [`aip_observation::EvidenceCeiling`] is
//! reused as-is and never widened.
//!
//! It also never asserts that an effect did **not** happen. Every negative
//! state here is a statement about the observer, not about the world.

#![forbid(unsafe_code)]

mod assess;
mod binding;
mod correlation;
mod finding;

pub use assess::{EffectAssessment, EffectError, EffectObservation, EffectWindow, ObservedStance};
pub use binding::EffectBinding;
pub use correlation::EffectCorrelation;
pub use finding::{EffectFinding, NotObservedReason};

/// Wire version for every serialized security object in this crate.
///
/// Bumped as a deliberate act. A reader that does not recognise it refuses
/// rather than guessing, which is the same rule `ObservationRecord` follows.
pub const EFFECT_ASSESSMENT_VERSION: u16 = 1;

/// Domain tag for this crate's canonical encodings.
///
/// Distinct from every other tag in the workspace so bytes produced here can
/// never be reinterpreted as an observation record, an evidence packet or a
/// proof component.
pub const EFFECT_ASSESSMENT_DOMAIN: &str = "aip.effect.assessment.v1";
