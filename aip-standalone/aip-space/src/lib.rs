//! `aip-space` — the disconnected and space autonomy accountability profile
//! (Skill 26).
//!
//! # The claim, in one sentence
//!
//! Vanian can account for a disconnected vehicle's **onboard software
//! execution**, collect that evidence with no link, package it, move it at a
//! later contact and verify it offline — and it cannot account for what the
//! vehicle did in orbit, nor for when anything happened beyond an upper bound
//! the onboard collector signed.
//!
//! # Offline is a deployment mode, not a bypass
//!
//! A spacecraft out of contact is operating normally. It is collecting evidence
//! it cannot yet send. So [`link::LinkState::changes_evidential_standing`] is
//! `false` for every state, and
//! [`profile::SpaceExecutionProfile::link_state_changes_capability`] is `false`
//! for every state: being visible does not make a subject more accountable, and
//! an outage does not become covered by ending.
//!
//! # The three refusals this profile exists for
//!
//! **Delayed arrival is not non-occurrence.**
//! [`delayed::DelayedEvidence::event_time_established`] is `false`, and
//! `receipt_time_is_event_time` is `false`. Latency is reported and decides
//! nothing: evidence that arrives in a second says exactly as much about event
//! time as evidence that arrives in a month.
//!
//! **A gap is never papered over by later evidence.**
//! `aip-observe`'s `ContinuityStatus::GapObserved` is already sticky — a later
//! contiguous batch does not restore `Verified` — and
//! [`segment::SegmentLedger`] records the *exact missing sequences* rather than
//! a count, because "three segments missing" cannot be checked off later and
//! "segments 7, 8 and 9 missing" can. `non_occurrence_admissible()` is `false`
//! whatever the gap state.
//!
//! **A previously seen bundle does not become fresh after a reconnection.**
//! [`bundle::BundleLedger`] keys on the bundle digest, the same discipline
//! `aip-nexora::ProofLedger` applies to proofs.
//!
//! # What this crate does not contain
//!
//! **No second continuity ledger.** `aip-observe::ObserverLedger` is the
//! authority: it decides replay, fork, rollback and gap, and once it proves a
//! fork it stays quarantined. This crate stages bundles and offers segments to
//! it *in order* — which is what a store-and-forward mission needs and a live
//! link does not — and never repairs a fault it returns.
//!
//! **No second proof tree.** NEXORA's nine leaf kinds are frozen. A bundle is a
//! *container*, and containers are not evidence: its contents are already
//! committable as existing leaves, and offline reconstruction flows through the
//! existing verifier.
//!
//! **No identifier, no key, no signer, no reconciler, no verifier, no evidence
//! vocabulary.** `tests/no_second_architecture.rs` asserts that over this
//! crate's source.
//!
//! # Time
//!
//! Four clocks, and only one of them bounds an event:
//!
//! ```text
//!   event time          nobody signs it        NOT ESTABLISHED
//!   observation time    onboard collector      upper bound on event time
//!   receipt time        ground station         about the verifier
//!   verification time   ground station         about the verifier
//! ```
//!
//! [`delayed::CommandTiming`] carries six distinct moments for a delayed
//! command and computes no causal order between the onboard and ground clocks,
//! because the vehicle's clock is set by the vehicle.
//!
//! # Composition
//!
//! ```text
//!   generic accountability core      unchanged
//!            ↓
//!   generic observation (Skill 20)   unchanged
//!            ↓
//!   aip-space                        this crate
//!            ↓
//!   mission adapters                 the deployment's
//! ```

#![forbid(unsafe_code)]

pub mod bundle;
pub mod corroborate;
pub mod delayed;
pub mod error;
pub mod ground;
pub mod link;
pub mod mode;
pub mod profile;
pub mod segment;
pub mod sensing;
pub mod state;

pub use bundle::{BundleLedger, BundleSegment, StoreAndForwardBundle};
pub use corroborate::{Agreement, SourceAgreement};
pub use delayed::{CommandTiming, DelayedEvidence, TimeBasis};
pub use error::SpaceError;
pub use ground::{GroundConclusion, GroundVerificationContext};
pub use link::{ContactWindow, LinkState};
pub use mode::{AutonomyMode, AutonomyModeTransition, MODE_TRANSITION_PARAMETER_KEY};
pub use profile::{SpaceExecutionProfile, SPACE_PROFILE_ID};
pub use segment::{SegmentLedger, SegmentOutcome};
pub use sensing::SpaceSensingSource;
pub use state::{MissionState, SpaceEvidence};

/// Domain tag leading every canonical encoding this crate produces.
///
/// One tag for the crate, with a structure discriminant inside each preimage,
/// so three profile structures can never collide and none can collide with a
/// core structure or with another vertical's.
pub const SPACE_PROFILE_DOMAIN: &str = "SYNTRIASS/AUTONOMY/SPACE_PROFILE/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const SPACE_PROFILE_VERSION: u16 = 1;
