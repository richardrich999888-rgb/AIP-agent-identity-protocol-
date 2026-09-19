//! The watchdog state machine that runs on the interlock controller.
//!
//! Pure and deterministic: time is injected, no allocation happens on the
//! hot path, and the only inputs are [`VerifiedHeartbeat`] values (which
//! nothing but verification can produce) and ticks. It is written so the
//! same logic can be compiled for a Cortex-M4 later; it is tested here on the
//! host, where the tests are cheaper to run and impossible to skip.
//!
//! ```text
//!   Disarmed ──arm(profile, epoch, first heartbeat)──► Armed
//!      ▲                                                 │
//!      │                                                 │ silence past budget
//!      │ operator_reset()                                │ counter not increasing
//!      │                                                 │ epoch mismatch
//!      │                                                 │ condition Withheld
//!      └──────────────────────── Tripped ◄───────────────┘
//!                                (absorbing)
//! ```

use crate::heartbeat::{HostCondition, VerifiedHeartbeat, WithholdReason};
use crate::safe_state::ActuatorProfile;

/// Timing parameters. Safety parameters, not tuning knobs: they must be
/// justified against the actuator's stopping budget, and [`Watchdog::arm`]
/// enforces that justification arithmetically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogConfig {
    /// Expected heartbeat interval.
    pub period_ms: u32,
    /// How many consecutive periods may pass with no accepted heartbeat
    /// before the interlock trips. Zero means one missed period trips.
    pub tolerated_misses: u8,
}

impl WatchdogConfig {
    /// The longest the actuator can remain permitted after the last accepted
    /// heartbeat: `period × (tolerated_misses + 1)`. Compared against the
    /// actuator's stopping budget at arm time.
    pub fn worst_case_trip_ms(&self) -> u64 {
        u64::from(self.period_ms) * (u64::from(self.tolerated_misses) + 1)
    }
}

/// Why the interlock tripped. Forensic; every variant has the same effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripReason {
    /// No accepted heartbeat for longer than the miss budget allows.
    Silence { periods_missed: u64 },
    /// A verified heartbeat carried a counter that did not increase — a
    /// replay, or a sender that lost its counter.
    CounterNotIncreasing { last: u64, got: u64 },
    /// A verified heartbeat for an epoch other than the armed one.
    EpochMismatch,
    /// The host signed a statement that it will not vouch for actuation.
    Withheld(WithholdReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogState {
    Disarmed,
    Armed {
        epoch: [u8; 16],
        last_counter: u64,
        last_accepted_ms: u64,
    },
    /// Absorbing. Only [`Watchdog::operator_reset`] leaves it.
    Tripped {
        reason: TripReason,
        at_ms: u64,
    },
}

/// Why [`Watchdog::arm`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmError {
    /// The watchdog is tripped. A heartbeat does not clear a trip; an
    /// operator does.
    TrippedRequiresOperatorReset,
    /// Already armed. Re-arming with a new epoch requires disarming first,
    /// which is a deliberate act rather than a side effect of a heartbeat.
    AlreadyArmed,
    /// `period × (misses + 1)` exceeds the actuator's declared stopping
    /// budget. The configuration would let the actuator run past the point
    /// the hazard analysis said it must have stopped.
    TripTimeExceedsStoppingBudget { worst_case_ms: u64, budget_ms: u64 },
    /// The first heartbeat is not `Nominal`; the host is not vouching, so
    /// there is nothing to arm on.
    FirstHeartbeatNotNominal,
    /// A period of zero would make every tick a miss.
    ZeroPeriod,
}

/// What a heartbeat or a tick did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatOutcome {
    /// Accepted; the actuator remains permitted.
    Accepted,
    /// The watchdog tripped on this input.
    Tripped(TripReason),
    /// The watchdog is not armed; the input changed nothing.
    Ignored,
}

/// The interlock's decision state for one actuator.
#[derive(Debug, Clone)]
pub struct Watchdog {
    config: WatchdogConfig,
    profile: ActuatorProfile,
    state: WatchdogState,
}

impl Watchdog {
    /// A disarmed watchdog for `profile`. Nothing is permitted until
    /// [`Watchdog::arm`] succeeds.
    pub fn new(config: WatchdogConfig, profile: ActuatorProfile) -> Self {
        Self {
            config,
            profile,
            state: WatchdogState::Disarmed,
        }
    }

    pub fn state(&self) -> WatchdogState {
        self.state
    }

    pub fn config(&self) -> WatchdogConfig {
        self.config
    }

    pub fn profile(&self) -> &ActuatorProfile {
        &self.profile
    }

    /// The single question the relay driver asks. True only while armed.
    pub fn actuator_permitted(&self) -> bool {
        matches!(self.state, WatchdogState::Armed { .. })
    }

    /// Arm on a first heartbeat. Refuses if tripped, if already armed, if the
    /// timing budget cannot stop the actuator in time, or if the host is not
    /// vouching.
    pub fn arm(&mut self, first: &VerifiedHeartbeat, now_ms: u64) -> Result<(), ArmError> {
        match self.state {
            WatchdogState::Tripped { .. } => return Err(ArmError::TrippedRequiresOperatorReset),
            WatchdogState::Armed { .. } => return Err(ArmError::AlreadyArmed),
            WatchdogState::Disarmed => {}
        }
        if self.config.period_ms == 0 {
            return Err(ArmError::ZeroPeriod);
        }
        let worst_case_ms = self.config.worst_case_trip_ms();
        let budget_ms = self.profile.stopping_budget.max_trip_ms;
        if worst_case_ms > budget_ms {
            return Err(ArmError::TripTimeExceedsStoppingBudget {
                worst_case_ms,
                budget_ms,
            });
        }
        let hb = first.heartbeat();
        if hb.condition != HostCondition::Nominal {
            return Err(ArmError::FirstHeartbeatNotNominal);
        }
        self.state = WatchdogState::Armed {
            epoch: hb.epoch,
            last_counter: hb.counter,
            last_accepted_ms: now_ms,
        };
        Ok(())
    }

    /// Feed a verified heartbeat. Unverified heartbeats never reach here —
    /// they are silence, and silence is handled by [`Watchdog::on_tick`].
    pub fn on_heartbeat(&mut self, hb: &VerifiedHeartbeat, now_ms: u64) -> HeartbeatOutcome {
        let (epoch, last_counter) = match self.state {
            WatchdogState::Armed {
                epoch,
                last_counter,
                ..
            } => (epoch, last_counter),
            _ => return HeartbeatOutcome::Ignored,
        };
        let h = hb.heartbeat();
        if h.epoch != epoch {
            return self.trip(TripReason::EpochMismatch, now_ms);
        }
        if h.counter <= last_counter {
            return self.trip(
                TripReason::CounterNotIncreasing {
                    last: last_counter,
                    got: h.counter,
                },
                now_ms,
            );
        }
        if let HostCondition::Withheld(reason) = h.condition {
            return self.trip(TripReason::Withheld(reason), now_ms);
        }
        self.state = WatchdogState::Armed {
            epoch,
            last_counter: h.counter,
            last_accepted_ms: now_ms,
        };
        HeartbeatOutcome::Accepted
    }

    /// Advance time. Trips on silence once more than `tolerated_misses`
    /// periods have elapsed since the last accepted heartbeat.
    pub fn on_tick(&mut self, now_ms: u64) -> HeartbeatOutcome {
        let last_accepted_ms = match self.state {
            WatchdogState::Armed {
                last_accepted_ms, ..
            } => last_accepted_ms,
            _ => return HeartbeatOutcome::Ignored,
        };
        // A clock that went backwards is not "no time passed"; treat it as
        // the full budget having elapsed, because the alternative is an
        // armed actuator whose timeout can be reset by adjusting a clock.
        let elapsed = now_ms.checked_sub(last_accepted_ms).unwrap_or(u64::MAX);
        let periods_missed = elapsed / u64::from(self.config.period_ms);
        if periods_missed > u64::from(self.config.tolerated_misses) {
            return self.trip(TripReason::Silence { periods_missed }, now_ms);
        }
        HeartbeatOutcome::Accepted
    }

    /// Leave `Tripped`. Deliberately not reachable from any heartbeat.
    pub fn operator_reset(&mut self) {
        if matches!(self.state, WatchdogState::Tripped { .. }) {
            self.state = WatchdogState::Disarmed;
        }
    }

    /// Disarm from `Armed`. A no-op otherwise; a trip is not cleared by
    /// disarming.
    pub fn disarm(&mut self) {
        if matches!(self.state, WatchdogState::Armed { .. }) {
            self.state = WatchdogState::Disarmed;
        }
    }

    fn trip(&mut self, reason: TripReason, now_ms: u64) -> HeartbeatOutcome {
        self.state = WatchdogState::Tripped {
            reason,
            at_ms: now_ms,
        };
        HeartbeatOutcome::Tripped(reason)
    }
}
