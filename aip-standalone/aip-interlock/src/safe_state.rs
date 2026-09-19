//! The safe-state contract: what an interlock must be told about an actuator
//! before it is allowed to arm.
//!
//! Fail-closed is not fail-safe. De-energising a stationary manipulator
//! engages its brakes; de-energising a multirotor in flight drops it. This
//! module makes the operator's declaration a *type-level precondition* of
//! arming, so "we forgot to decide what safe means for this actuator" is a
//! compile error rather than an incident.

use serde::{Deserialize, Serialize};

/// What the interlock does to this actuator when it trips.
///
/// The variants are the three shapes a hazard analysis produces. This crate
/// never chooses between them; it refuses to arm until someone has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeState {
    /// Open the relay. Correct for actuators whose de-energised state is
    /// mechanically safe (brakes engage, valve closes, arming circuit opens).
    DeEnergise,
    /// Hold the last commanded position and refuse new commands. For
    /// actuators where loss of power is itself the hazard (a loaded gripper).
    HoldPosition,
    /// Assert a dedicated failsafe line into a controller that owns its own
    /// safe behaviour (a flight controller's return-to-launch or land).
    /// The interlock does not know what the controller will do; it knows
    /// only that cutting power would be worse.
    CommandFailsafe { channel: String },
}

/// The longest the actuator may keep moving after the host stops vouching
/// for it, as the operator's hazard analysis determined it. A watchdog whose
/// worst-case trip time exceeds this is not protecting anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoppingBudget {
    pub max_trip_ms: u64,
}

/// Everything the interlock must know about one actuator before arming.
///
/// `safe_state` is not `Option`. There is no way to build a profile that has
/// not declared one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActuatorProfile {
    pub actuator_id: String,
    pub safe_state: SafeState,
    /// Who made the declaration, for the record. Not verified here; the
    /// interlock has no anchors for operators and does not pretend to.
    pub declared_by: String,
    pub stopping_budget: StoppingBudget,
}
