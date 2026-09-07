//! `aip-industrial` — the industrial and critical-edge accountability profile
//! (Skill 25).
//!
//! # The claim, in one sentence
//!
//! Vanian can account for what a **critical-edge node's software** did — which
//! binary ran, on which host-boot, which sockets it held, how many bytes the
//! kernel accepted for them, which configuration files it wrote. It cannot
//! account for what the plant did, and every claim about a valve, a breaker, a
//! flow, a pressure or a completed shutdown resolves to `CANNOT_PROVE` unless a
//! deployment supplies an independent physical mechanism, which this build does
//! not have.
//!
//! # Why this is a different problem from the robotics case
//!
//! A robot's controller sits on a bus the robot owns. An industrial controller
//! is a separate certified device, on a separate network, running a program
//! written by a separate party, executing on a scan cycle nobody outside it can
//! see — and it answers every command with the same positive response code
//! whether or not anything happened.
//!
//! So the chain has eight rungs and each is a real boundary:
//!
//! ```text
//!   supervisory decision        software      observable here
//!   command issued              software      observable here
//!   protocol accepted           a message     not observed
//!   controller logic executed   a device      not observed
//!   output energised            a device      not observed
//!   actuator response           the plant     not observed
//!   process variable change     an instrument not observed
//!   physical process effect     the plant     not observed
//! ```
//!
//! Two of eight, and six boundaries between the last observable rung and a
//! changed plant.
//!
//! # The three rules the specification calls non-negotiable
//!
//! **Safety boundaries and process effects are distinct commitments and
//! observations.** [`safety::SafetyBoundary`] is a document a decision point
//! signs, under its own parameter key and its own structure discriminant.
//! [`process::PhysicalProcessEffect`] is what a deployment's sources could
//! establish about what happened. There is no method turning one into the other,
//! and `SafetyBoundary::enforcement_establishable()` is `false`.
//!
//! **Industrial protocol messages are not automatically proof of physical
//! process change.** [`protocol::ProtocolInteraction::establishes_process_change`]
//! is `false` for every protocol, response and authentication state, computed
//! from the source table. `evidence_ceiling` is a function of the observation
//! mechanism and of nothing about the protocol, so no adapter can make its own
//! protocol worth more than another's — and there is deliberately no
//! `is_trusted` method for anyone to reach for.
//!
//! **Containment actions remain warrant-controlled and fail-safe.**
//! [`containment::ContainmentScope`] holds the sentence that has to be said out
//! loud: freezing the supervisory process on the edge node stops new commands
//! and moves nothing. Outputs hold their last state. `requires_warrant()` is
//! `true` for both scopes and `restores_process_safe_state()` is `false` for
//! both. This crate contains nothing itself; `aip-warrant` and `aip-containment`
//! remain the only enforcement path and are not runtime dependencies here.
//!
//! # What this crate does not contain
//!
//! No identifier — `SystemId`, `PlatformId`, `HardwareId` and `MissionId`
//! already exist and are reused, with a control loop expressed as a `MissionId`
//! and an edge node as a `PlatformId`. No observation record, no platform
//! binding, no execution model, no effect assessment, no reconciler, no
//! verifier, no trust anchor, no signing key, no leaf kind and no
//! evidence-strength vocabulary. `tests/no_second_architecture.rs` asserts that
//! over this crate's source.
//!
//! Command authority is not a new authorization engine: a
//! [`controlloop::ControlLoopExecution`] and a [`safety::SafetyBoundary`] each
//! commit their digest into `ActionParameters` under distinct keys, which a
//! decision point signs as `ExpectedExecution.parameter_digest` — the mechanism
//! Skills 18, 23 and 24 already use.
//!
//! # Composition
//!
//! ```text
//!   generic accountability core      unchanged
//!            ↓
//!   generic observation (Skill 20)   unchanged
//!            ↓
//!   aip-industrial                   this crate
//!            ↓
//!   industrial adapters              the deployment's (Modbus, DNP3, OPC UA)
//! ```
//!
//! No protocol stack is assumed and no protocol is trusted. Adding space or
//! enterprise later requires no change here and none below.
//!
//! # The third vertical, and the extraction ADR-007 anticipated
//!
//! ADR-007 deferred extracting the three generic profile rules until a third
//! vertical existed, and named this one. ADR-008 records what the third
//! vertical actually showed: industrial is a third *embodied* vertical, so the
//! shape it reveals is still an embodiment-shaped one, and the extraction is
//! deferred again on the evidence rather than on the same argument. The
//! two-vertical consistency guard is replaced by a three-vertical one in
//! `tests/cross_vertical.rs`.

#![forbid(unsafe_code)]

pub mod command;
pub mod containment;
pub mod controlloop;
pub mod corroborate;
pub mod coverage;
pub mod error;
pub mod operator;
pub mod process;
pub mod profile;
pub mod protocol;
pub mod safety;
pub mod sensing;
pub mod state;

pub use command::{
    device_parameters, ics_action, point_parameters, IndustrialCommand, ICS_ACTION_PREFIX,
};
pub use containment::ContainmentScope;
pub use controlloop::{
    CommandFreshness, CommandWindow, ControlLoopChain, ControlLoopExecution, ControlRung,
    CONTROL_LOOP_PARAMETER_KEY,
};
pub use corroborate::{Agreement, InstrumentAgreement};
pub use coverage::{class_domain, CoverageDomain, DomainCoverage, ObservationCoverage};
pub use error::IndustrialError;
pub use operator::{OverrideClaim, OverrideKind};
pub use process::{
    support_for, ClaimSupport, PhysicalProcessEffect, ProcessClaim, ProcessMeasurement,
    ProcessVariable,
};
pub use profile::{IndustrialProfile, INDUSTRIAL_PROFILE_ID};
pub use protocol::{
    Dnp3Adapter, IndustrialProtocol, MessageAuthentication, ModbusTcpAdapter, OpcUaAdapter,
    ProtocolAdapter, ProtocolInteraction, ProtocolTransport, ReplayDefence,
};
pub use safety::{
    LimitBound, ProcessLimit, SafetyBoundary, SafetyEvidence, SafetyFunction,
    SAFETY_BOUNDARY_PARAMETER_KEY,
};
pub use sensing::ProcessSensingSource;
pub use state::{LoopState, ProcessEvidence};

/// Domain tag leading every canonical encoding this crate produces.
///
/// One tag for the crate, with a structure discriminant inside each preimage,
/// so three profile structures can never collide and none can collide with a
/// core structure or with the UAS or robotics profiles'.
pub const INDUSTRIAL_PROFILE_DOMAIN: &str = "SYNTRIASS/AUTONOMY/INDUSTRIAL_PROFILE/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const INDUSTRIAL_PROFILE_VERSION: u16 = 1;
