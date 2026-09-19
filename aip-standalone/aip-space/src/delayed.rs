//! Delayed evidence, and the four clocks that must not be confused.
//!
//! # The rule
//!
//! > An observation arriving at T2 does not imply the event occurred at T2.
//!
//! Obvious written down, and routinely violated in practice, because the
//! arrival timestamp is the one the ground system has to hand and the event
//! timestamp is the one it wants. On a link with a twenty-minute one-way time
//! and a three-day store-and-forward backlog, the difference is not a rounding
//! error.
//!
//! # What each clock is worth
//!
//! | clock | who signs it | what it bounds |
//! |---|---|---|
//! | event time | nobody | **not established** |
//! | observation time | the onboard collector | an upper bound on event time |
//! | receipt time | the ground station | when the *verifier* first held the bytes |
//! | verification time | the ground station | when the verifier checked them |
//!
//! Observation time is the only one that bounds the event, and it bounds it
//! from one side: `ObservationRecord::attested_at_ms` is the collector's clock
//! when it signed, so an event inside the batch cannot have happened after it.
//! It says nothing about how long before.
//!
//! Receipt and verification times are facts about the **ground station**. The
//! vehicle cannot sign them and does not know them. They are carried here
//! precisely so nobody has to smuggle them into the record.
//!
//! # Latency is reported and decides nothing
//!
//! [`DelayedEvidence::latency_ms`] exists because operators need it. It feeds
//! no admission decision, no ceiling and no verdict, and
//! [`DelayedEvidence::event_time_established`] is `false` however small it is.
//! Evidence that arrives in a second is exactly as silent about event time as
//! evidence that arrives in a month.

use serde::{Deserialize, Serialize};

use crate::error::SpaceError;

/// Which clock a timestamp came from.
///
/// Named rather than implied, because the whole failure mode is a number
/// arriving in a field whose clock nobody wrote down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TimeBasis {
    /// The onboard collector's clock, signed by it.
    OnboardAttested,
    /// The ground station's clock. Unsigned by the vehicle.
    GroundReceipt,
    /// The ground station's clock at verification.
    GroundVerification,
    /// A time the subject asserted with no signature behind it.
    SubjectAsserted,
}

impl TimeBasis {
    pub const ALL: [TimeBasis; 4] = [
        Self::OnboardAttested,
        Self::GroundReceipt,
        Self::GroundVerification,
        Self::SubjectAsserted,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::OnboardAttested => 0x01,
            Self::GroundReceipt => 0x02,
            Self::GroundVerification => 0x03,
            Self::SubjectAsserted => 0x04,
        }
    }

    /// Whether a timestamp on this basis bounds when the event happened.
    ///
    /// True for `OnboardAttested` alone, and only as an **upper** bound.
    pub fn bounds_event_time(self) -> bool {
        matches!(self, Self::OnboardAttested)
    }

    /// Whether this basis is a fact about the verifier rather than the subject.
    pub fn is_about_the_verifier(self) -> bool {
        matches!(self, Self::GroundReceipt | Self::GroundVerification)
    }

    pub fn statement(self) -> &'static str {
        match self {
            Self::OnboardAttested => {
                "the collector's clock when it signed; an event in the batch cannot have happened \
                 after it, and nothing is established about how long before"
            }
            Self::GroundReceipt => {
                "when the ground station first held the bytes; a fact about the ground station"
            }
            Self::GroundVerification => {
                "when the ground station checked them; a fact about the ground station"
            }
            Self::SubjectAsserted => {
                "a time the subject stated with nothing behind it; context, never a bound"
            }
        }
    }
}

/// Evidence that arrived later than it was produced.
///
/// Generic over the payload so the same wrapper carries an attested batch, a
/// signed health record or a reconciliation without this crate needing to know
/// which. The payload is never inspected here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedEvidence<T> {
    /// The evidence itself, untouched.
    pub payload: T,
    /// The onboard collector's clock when it attested. The only clock that
    /// bounds the event.
    pub attested_at_ms: u64,
    /// The ground station's clock when it first held the bytes.
    pub received_at_ms: u64,
    /// The ground station's clock when it verified them, once it has.
    pub verified_at_ms: Option<u64>,
}

impl<T> DelayedEvidence<T> {
    pub fn new(payload: T, attested_at_ms: u64, received_at_ms: u64) -> Result<Self, SpaceError> {
        if received_at_ms < attested_at_ms {
            return Err(SpaceError::UnestablishableOrdering {
                reason: "evidence received before it was attested; the two clocks disagree and \
                         this crate will not pick a winner",
            });
        }
        Ok(Self {
            payload,
            attested_at_ms,
            received_at_ms,
            verified_at_ms: None,
        })
    }

    /// Record that the ground station verified this at `t_ms`.
    pub fn verified_at(mut self, t_ms: u64) -> Result<Self, SpaceError> {
        if t_ms < self.received_at_ms {
            return Err(SpaceError::UnestablishableOrdering {
                reason: "verified before received; the ground station's own clock ran backwards",
            });
        }
        self.verified_at_ms = Some(t_ms);
        Ok(self)
    }

    /// How long the evidence took to arrive. Reported, and decides nothing.
    pub fn latency_ms(&self) -> u64 {
        self.received_at_ms - self.attested_at_ms
    }

    /// Whether the time the event occurred is established.
    ///
    /// **`false`, unconditionally.** The attestation time is an upper bound and
    /// nothing supplies a lower one. A caller that needs an event time needs a
    /// mechanism this build does not have.
    pub fn event_time_established(&self) -> bool {
        false
    }

    /// The upper bound on event time, and the basis it rests on.
    pub fn event_time_upper_bound(&self) -> (u64, TimeBasis) {
        (self.attested_at_ms, TimeBasis::OnboardAttested)
    }

    /// Whether this evidence may be treated as describing something that
    /// happened at `t_ms`.
    ///
    /// **`false` for every `t_ms`.** The method exists so a caller reaching for
    /// "did this happen at the moment it arrived?" meets a `false` and a
    /// reason rather than an accessor it can misuse.
    pub fn describes_event_at(&self, _t_ms: u64) -> bool {
        false
    }

    /// Whether the receipt time may be used as the event time.
    ///
    /// `false`. Named explicitly because it is the single most likely mistake
    /// in a delayed-evidence pipeline, and a named `false` can be tested and
    /// mutated.
    pub fn receipt_time_is_event_time(&self) -> bool {
        false
    }
}

/// The distinct moments in the life of a delayed ground command.
///
/// Six clocks, no ordering asserted between the ones that cannot be ordered.
/// A command authorized on Monday, radiated on Tuesday, received on Wednesday
/// and executed on Thursday is four facts, and a system that stores one
/// timestamp has lost three of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandTiming {
    /// When a decision point signed the expectation. Ground clock, signed.
    pub authorized_at_ms: u64,
    /// When the command left the ground station. Ground clock.
    pub transmitted_at_ms: Option<u64>,
    /// When the vehicle says it received it. Onboard clock, self-reported.
    pub received_onboard_at_ms: Option<u64>,
    /// When the vehicle says it executed it. Onboard clock, self-reported.
    pub executed_at_ms: Option<u64>,
    /// When an onboard collector attested something about the execution.
    pub observed_at_ms: Option<u64>,
    /// When ground verified the resulting evidence. Ground clock.
    pub ground_verified_at_ms: Option<u64>,
}

impl CommandTiming {
    pub fn authorized(authorized_at_ms: u64) -> Self {
        Self {
            authorized_at_ms,
            transmitted_at_ms: None,
            received_onboard_at_ms: None,
            executed_at_ms: None,
            observed_at_ms: None,
            ground_verified_at_ms: None,
        }
    }

    /// Whether a causal order between the onboard and ground clocks is
    /// established.
    ///
    /// **`false`.** The two clocks are disciplined separately and the vehicle's
    /// is set by the vehicle. Comparing an onboard execution time with a ground
    /// authorization time and concluding an ordering is a claim about clock
    /// synchronisation that nothing here supports.
    pub fn cross_clock_order_established(&self) -> bool {
        false
    }

    /// Whether the command is known to have executed *after* it was
    /// authorized.
    ///
    /// `false`: it requires exactly the cross-clock ordering above. This is not
    /// pedantry — a vehicle whose clock is wrong, or which has been made to
    /// report a wrong clock, produces an execution timestamp that precedes the
    /// authorization, and a system that "corrects" that has erased the finding.
    pub fn execution_follows_authorization(&self) -> bool {
        false
    }

    /// The number of distinct moments actually recorded. Reported for
    /// completeness auditing.
    pub fn recorded_moments(&self) -> usize {
        1 + [
            self.transmitted_at_ms,
            self.received_onboard_at_ms,
            self.executed_at_ms,
            self.observed_at_ms,
            self.ground_verified_at_ms,
        ]
        .iter()
        .filter(|t| t.is_some())
        .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> DelayedEvidence<&'static str> {
        DelayedEvidence::new("batch", 1_000, 900_000).unwrap()
    }

    #[test]
    fn arrival_time_is_never_event_time() {
        let e = evidence();
        assert!(!e.event_time_established());
        assert!(!e.receipt_time_is_event_time());
        for t in [0u64, 1_000, 900_000, u64::MAX] {
            assert!(!e.describes_event_at(t), "{t}");
        }
    }

    #[test]
    fn latency_is_reported_and_establishes_nothing() {
        let fast = DelayedEvidence::new("b", 1_000, 1_001).unwrap();
        let slow = DelayedEvidence::new("b", 1_000, 1_000 + 30 * 86_400_000).unwrap();
        assert_eq!(fast.latency_ms(), 1);
        assert_eq!(slow.latency_ms(), 30 * 86_400_000);
        // A second and a month say exactly the same thing about the event.
        assert_eq!(fast.event_time_established(), slow.event_time_established());
        assert_eq!(
            fast.event_time_upper_bound().0,
            slow.event_time_upper_bound().0
        );
    }

    #[test]
    fn only_the_onboard_attestation_bounds_the_event() {
        assert!(TimeBasis::OnboardAttested.bounds_event_time());
        for b in [
            TimeBasis::GroundReceipt,
            TimeBasis::GroundVerification,
            TimeBasis::SubjectAsserted,
        ] {
            assert!(!b.bounds_event_time(), "{b:?}");
        }
        assert!(TimeBasis::GroundReceipt.is_about_the_verifier());
        assert!(TimeBasis::GroundVerification.is_about_the_verifier());
        assert!(!TimeBasis::OnboardAttested.is_about_the_verifier());
    }

    #[test]
    fn evidence_received_before_it_was_attested_is_refused() {
        assert!(matches!(
            DelayedEvidence::new("b", 1_000, 999),
            Err(SpaceError::UnestablishableOrdering { .. })
        ));
        // And a verification before receipt.
        assert!(matches!(
            evidence().verified_at(1),
            Err(SpaceError::UnestablishableOrdering { .. })
        ));
        assert!(evidence().verified_at(900_001).is_ok());
    }

    #[test]
    fn the_six_command_moments_stay_distinct_and_unordered_across_clocks() {
        let t = CommandTiming {
            authorized_at_ms: 1_000,
            transmitted_at_ms: Some(2_000),
            received_onboard_at_ms: Some(500), // an onboard clock that disagrees
            executed_at_ms: Some(600),
            observed_at_ms: Some(700),
            ground_verified_at_ms: Some(900_000),
        };
        assert_eq!(t.recorded_moments(), 6);
        // The onboard clock says the command was received before ground
        // authorized it. That is a finding, not something to correct.
        assert!(!t.cross_clock_order_established());
        assert!(!t.execution_follows_authorization());
    }

    #[test]
    fn a_bare_authorization_records_one_moment() {
        let t = CommandTiming::authorized(1_000);
        assert_eq!(t.recorded_moments(), 1);
        assert!(!t.execution_follows_authorization());
    }

    #[test]
    fn every_basis_states_itself_and_codes_are_unique() {
        let mut codes: Vec<u8> = TimeBasis::ALL.iter().map(|b| b.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), TimeBasis::ALL.len());
        for b in TimeBasis::ALL {
            assert!(!b.statement().is_empty(), "{b:?}");
        }
    }
}
