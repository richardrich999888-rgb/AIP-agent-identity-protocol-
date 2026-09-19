//! The interlock tier of Sniffer Dog 3.0: a hardware dead-man's switch,
//! specified as a protocol and a state machine.
//!
//! # What this crate is
//!
//! The observation tier (`aip-observe`) can say when it has gone blind
//! (`ObserverState::IntegrityUnknown`). The reconciler turns that into
//! `CANNOT_PROVE`. Neither of them can stop a motor. This crate is the piece
//! that can, and it does so by **inverting the burden**: instead of proving
//! that something bad happened — which needs `Proven`, which the engine
//! deliberately cannot emit — the host must continuously prove that it is in
//! a condition where actuation is permitted. Silence, a stale counter, a
//! wrong epoch, or a signed "I cannot vouch" all trip the interlock.
//!
//! ```text
//!   Linux host                             interlock controller (STM32)
//!   ──────────                             ────────────────────────────
//!   ObserverState ─┐                        ┌─ verify signature (anchor)
//!   enforcement   ─┼─► HostSignal           ├─ counter strictly increases
//!   operator hold ─┘        │               ├─ epoch matches armed epoch
//!                           ▼               ├─ condition == Nominal
//!                    HeartbeatSender ──────►│  Watchdog::on_heartbeat
//!                     (signed, counted)     │  Watchdog::on_tick
//!                                           └─ actuator_permitted() ─► relay
//! ```
//!
//! # What this crate is not
//!
//! - **Not a Vanian verdict.** A tripped interlock produces no
//!   `Reconciliation`, raises no `EvidenceStrength`, and does not make
//!   `ResponseClass::Contain` reachable. Audit blocker B-3 stays
//!   ACCEPTED/JUSTIFIED. This is an out-of-band safety function whose trigger
//!   condition happens to include Vanian signals.
//! - **Not an observer.** [`measurement::InterlockMeasurement`] is a signed
//!   reading from an off-machine board with its own key, and it is exactly
//!   one step short of an `ObservationRecord`: no `SourceMechanism` exists for
//!   it, and `aip-observation` is deliberately not a dependency here. Closing
//!   that gap is Stage 4 of the physical validation roadmap and belongs in
//!   `aip-observation`, not in this crate.
//! - **Not proof of a safe state.** [`safe_state::SafeState`] is a
//!   *declaration* the operator makes per actuator after their own hazard
//!   analysis. De-energising is unsafe for a multirotor in flight and for a
//!   loaded gripper; this crate refuses to arm without a declaration and
//!   never chooses one.
//!
//! # Fail-closed by construction
//!
//! - [`watchdog::WatchdogState::Tripped`] is absorbing. No heartbeat, however
//!   valid, re-arms it; only [`watchdog::Watchdog::operator_reset`] does.
//! - A heartbeat that does not verify is not "invalid"; it is *absent*, and
//!   absence counts toward the miss budget.
//! - A heartbeat whose condition is [`heartbeat::HostCondition::Withheld`]
//!   trips immediately even though it verifies. A signed "I am blind" is
//!   stronger than silence, because it cannot be mistaken for a link fault.
//! - Arming is refused when the worst-case trip time exceeds the actuator's
//!   declared stopping budget. A watchdog that cannot stop the actuator in
//!   time is not a watchdog.
//!
//! # The counter
//!
//! A signature alone is replayable. The heartbeat carries a strictly
//! increasing counter and names its source. Only a hardware monotonic counter
//! (ATECC608B) makes the replay bound survive a host compromise; the
//! software counter shipped here is for the host-side protocol and for
//! tests, and every heartbeat says which it used, so a verifier is never
//! left guessing.

pub mod heartbeat;
pub mod measurement;
pub mod safe_state;
pub mod sender;
pub mod watchdog;

pub use heartbeat::{
    verify_heartbeat, CounterSource, Heartbeat, HeartbeatError, HostCondition, InterlockAnchors,
    SignedHeartbeat, VerifiedHeartbeat, WithholdReason, INTERLOCK_HEARTBEAT_DOMAIN,
    INTERLOCK_HEARTBEAT_VERSION,
};
pub use measurement::{
    verify_measurement, InterlockMeasurement, MeasurementError, SenseChannel,
    SignedInterlockMeasurement, INTERLOCK_MEASUREMENT_DOMAIN, INTERLOCK_MEASUREMENT_VERSION,
};
pub use safe_state::{ActuatorProfile, SafeState, StoppingBudget};
pub use sender::{
    CounterError, HeartbeatSender, HostSignal, MonotonicCounter, SenderError, SoftwareCounter,
};
pub use watchdog::{
    ArmError, HeartbeatOutcome, TripReason, Watchdog, WatchdogConfig, WatchdogState,
};
