//! The host side: turning Vanian signals into a signed heartbeat, or into a
//! signed refusal to vouch.

use aip_observe::ObserverState;
use aip_types::AipError;

use crate::heartbeat::{
    CounterSource, Heartbeat, HostCondition, SignedHeartbeat, WithholdReason,
    INTERLOCK_HEARTBEAT_VERSION,
};

/// The signals the host folds into one condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSignal {
    pub observer: ObserverState,
    /// The enforcement tier's own health (ADR-008 §5.4). `true` withholds.
    pub enforcement_degraded: bool,
    pub operator_hold: bool,
}

impl HostSignal {
    /// The order of precedence is forensic only — every non-`Nominal` result
    /// trips the interlock the same way. Operator hold is reported first
    /// because it is the one a human will look for.
    pub fn condition(&self) -> HostCondition {
        if self.operator_hold {
            return HostCondition::Withheld(WithholdReason::OperatorHold);
        }
        // Exhaustive: a state added to `aip-observe` that nobody classified
        // here is a build failure, not an armed actuator.
        let state_code = match self.observer {
            ObserverState::Active => None,
            ObserverState::Degraded => Some(0x02),
            ObserverState::Recovering => Some(0x03),
            ObserverState::ContinuityUnverified => Some(0x04),
            ObserverState::Quarantined => Some(0x05),
            ObserverState::IntegrityUnknown => Some(0x06),
        };
        if let Some(state_code) = state_code {
            return HostCondition::Withheld(WithholdReason::ObserverNotActive { state_code });
        }
        if self.enforcement_degraded {
            return HostCondition::Withheld(WithholdReason::EnforcementDegraded);
        }
        HostCondition::Nominal
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CounterError {
    /// The counter cannot advance. A sender that cannot count cannot
    /// heartbeat; the caller must withhold, not reuse.
    Exhausted,
}

/// A strictly increasing counter. The interlock trips on any value that
/// does not exceed the last one it accepted, so an implementation that can
/// repeat a value after restart has already failed.
pub trait MonotonicCounter {
    fn source(&self) -> CounterSource;
    fn next(&mut self) -> Result<u64, CounterError>;
}

/// A process-local counter. It restarts at the value it was constructed
/// with, which is the honest reason it is [`CounterSource::Software`]: a
/// restarted host that reuses a value will trip the interlock, and should.
#[derive(Debug, Clone)]
pub struct SoftwareCounter {
    next: u64,
}

impl SoftwareCounter {
    pub fn starting_at(next: u64) -> Self {
        Self { next }
    }
}

impl MonotonicCounter for SoftwareCounter {
    fn source(&self) -> CounterSource {
        CounterSource::Software
    }
    fn next(&mut self) -> Result<u64, CounterError> {
        let v = self.next;
        self.next = self.next.checked_add(1).ok_or(CounterError::Exhausted)?;
        Ok(v)
    }
}

/// Produces signed heartbeats for one interlock under one epoch.
pub struct HeartbeatSender<C: MonotonicCounter> {
    interlock_id: String,
    sender_id: String,
    epoch: [u8; 16],
    counter: C,
    private_key: Vec<u8>,
}

impl<C: MonotonicCounter> HeartbeatSender<C> {
    pub fn new(
        interlock_id: &str,
        sender_id: &str,
        epoch: [u8; 16],
        counter: C,
        private_key: &[u8],
    ) -> Self {
        Self {
            interlock_id: interlock_id.to_string(),
            sender_id: sender_id.to_string(),
            epoch,
            counter,
            private_key: private_key.to_vec(),
        }
    }

    /// The next heartbeat for `signal`. A withheld condition is still sent —
    /// signed — because a positive "I cannot vouch" is more useful to the
    /// interlock than silence it cannot tell from a cut cable.
    pub fn next(
        &mut self,
        signal: HostSignal,
        now_ms: u64,
    ) -> Result<SignedHeartbeat, SenderError> {
        let counter = self.counter.next().map_err(SenderError::Counter)?;
        let heartbeat = Heartbeat {
            version: INTERLOCK_HEARTBEAT_VERSION,
            interlock_id: self.interlock_id.clone(),
            sender_id: self.sender_id.clone(),
            epoch: self.epoch,
            counter,
            counter_source: self.counter.source(),
            condition: signal.condition(),
            emitted_at_ms: now_ms,
        };
        SignedHeartbeat::sign(heartbeat, &self.private_key).map_err(SenderError::Crypto)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SenderError {
    Counter(CounterError),
    Crypto(AipError),
}
