//! The admitted epoch: verified once, consulted per syscall.

use crate::epoch::{verify_epoch, EpochAnchors, EpochError, SignedCapabilityEpoch, VerifiedEpoch};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitError {
    Verify(EpochError),
    /// The counter did not exceed the highest one admitted. A replayed or
    /// stale epoch never becomes active.
    CounterNotIncreasing {
        last: u64,
        got: u64,
    },
    /// The epoch names a different agent from the one this enforcer
    /// supervises.
    AgentMismatch {
        expected: String,
        got: String,
    },
}

/// The current epoch's standing at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochStatus<'a> {
    Active(&'a VerifiedEpoch),
    None,
    NotYetValid,
    Expired,
}

/// Holds at most one active epoch and the highest counter ever admitted.
#[derive(Debug, Clone)]
pub struct EpochCache {
    anchors: EpochAnchors,
    agent_id: String,
    active: Option<VerifiedEpoch>,
    highest_counter: Option<u64>,
}

impl EpochCache {
    pub fn new(anchors: EpochAnchors, agent_id: &str) -> Self {
        Self {
            anchors,
            agent_id: agent_id.to_string(),
            active: None,
            highest_counter: None,
        }
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Verify and admit. On success the epoch replaces any previous one.
    /// On failure nothing changes — a bad epoch does not evict a good one,
    /// and it does not advance the counter either.
    pub fn admit(&mut self, signed: &SignedCapabilityEpoch) -> Result<&VerifiedEpoch, AdmitError> {
        let verified = verify_epoch(signed, &self.anchors).map_err(AdmitError::Verify)?;
        let e = verified.epoch();
        if e.agent_id != self.agent_id {
            return Err(AdmitError::AgentMismatch {
                expected: self.agent_id.clone(),
                got: e.agent_id.clone(),
            });
        }
        if let Some(last) = self.highest_counter {
            if e.counter <= last {
                return Err(AdmitError::CounterNotIncreasing {
                    last,
                    got: e.counter,
                });
            }
        }
        self.highest_counter = Some(e.counter);
        self.active = Some(verified);
        Ok(self.active.as_ref().expect("just set"))
    }

    pub fn status(&self, now_ms: u64) -> EpochStatus<'_> {
        match &self.active {
            None => EpochStatus::None,
            Some(v) => {
                let e = v.epoch();
                if now_ms < e.issued_at {
                    EpochStatus::NotYetValid
                } else if now_ms > e.valid_until {
                    EpochStatus::Expired
                } else {
                    EpochStatus::Active(v)
                }
            }
        }
    }

    pub fn highest_counter(&self) -> Option<u64> {
        self.highest_counter
    }
}
