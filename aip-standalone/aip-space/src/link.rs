//! The link, and why its state grants nothing.
//!
//! # Offline is a deployment mode, not a bypass
//!
//! A spacecraft out of contact is operating normally. It is not degraded, not
//! suspect, and not exempt from accountability — it is collecting evidence it
//! cannot yet send. The link state therefore describes *the verifier's reach*,
//! never the subject's standing.
//!
//! # Reconnection grants nothing
//!
//! The temptation this module exists to refuse: a vehicle comes back into
//! contact, everything it sends verifies, and the natural reading is that the
//! outage is now closed. It is not. Whatever was unobserved during the outage
//! stays unobserved, and [`LinkState::Reconnected`] carries exactly as much
//! evidential weight as [`LinkState::Disconnected`] — none.

use serde::{Deserialize, Serialize};

/// Where the link stood over an interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LinkState {
    /// A contact is open; evidence can flow now.
    Connected,
    /// No contact. The subject continues; the verifier cannot see it.
    Disconnected,
    /// A contact has just opened after an outage. A transition, not a repair.
    Reconnected,
    /// The link is up but unusable for evidence — insufficient margin, a
    /// one-way beacon, a relay that carries commands and not telemetry.
    /// Distinguished from `Disconnected` because "we could talk and could not
    /// send evidence" is a different operational fact.
    DegradedCarrier,
}

impl LinkState {
    pub const ALL: [LinkState; 4] = [
        Self::Connected,
        Self::Disconnected,
        Self::Reconnected,
        Self::DegradedCarrier,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Connected => 0x01,
            Self::Disconnected => 0x02,
            Self::Reconnected => 0x03,
            Self::DegradedCarrier => 0x04,
        }
    }

    /// Whether evidence can be transferred while the link is in this state.
    pub fn permits_transfer(self) -> bool {
        matches!(self, Self::Connected | Self::Reconnected)
    }

    /// Whether reaching this state changes what may be concluded about any
    /// interval.
    ///
    /// **`false` for every state, unconditionally.** The link is the
    /// verifier's reach. A subject does not become more or less accountable by
    /// being visible, and an outage does not become covered by ending.
    pub fn changes_evidential_standing(self) -> bool {
        false
    }

    pub fn statement(self) -> &'static str {
        match self {
            Self::Connected => "evidence can flow; nothing is thereby established about the past",
            Self::Disconnected => {
                "the subject continues and the verifier cannot see it; this is normal operation, \
                 not a fault"
            }
            Self::Reconnected => {
                "a contact opened after an outage; whatever was unobserved during the outage \
                 remains unobserved"
            }
            Self::DegradedCarrier => {
                "the link is up and cannot carry evidence; commands may still flow, which is the \
                 asymmetry worth recording"
            }
        }
    }
}

/// A contact opportunity, as the deployment plans or records one.
///
/// Half-open `[from, until)`, matching every other window in the codebase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactWindow {
    pub from_ms: u64,
    pub until_ms: u64,
}

impl ContactWindow {
    pub fn contains(&self, t_ms: u64) -> bool {
        t_ms >= self.from_ms && t_ms < self.until_ms
    }

    pub fn is_valid(&self) -> bool {
        self.until_ms > self.from_ms
    }

    pub fn duration_ms(&self) -> u64 {
        self.until_ms.saturating_sub(self.from_ms)
    }

    /// The interval between this contact and the next one.
    ///
    /// Returns `None` when the windows overlap or run backwards, rather than
    /// producing a negative-turned-huge number.
    pub fn outage_before(&self, next: &ContactWindow) -> Option<u64> {
        next.from_ms.checked_sub(self.until_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_link_state_changes_evidential_standing() {
        for s in LinkState::ALL {
            assert!(!s.changes_evidential_standing(), "{s:?}");
            assert!(!s.statement().is_empty(), "{s:?}");
        }
    }

    #[test]
    fn reconnection_is_a_transition_and_not_a_repair() {
        assert!(LinkState::Reconnected.permits_transfer());
        assert!(!LinkState::Reconnected.changes_evidential_standing());
        assert!(LinkState::Reconnected
            .statement()
            .contains("remains unobserved"));
    }

    #[test]
    fn a_degraded_carrier_is_distinct_from_no_link() {
        assert_ne!(LinkState::DegradedCarrier, LinkState::Disconnected);
        assert!(!LinkState::DegradedCarrier.permits_transfer());
        // The asymmetry: commands may flow when evidence cannot.
        assert!(LinkState::DegradedCarrier.statement().contains("commands"));
    }

    #[test]
    fn the_window_is_half_open_and_outages_are_computed_safely() {
        let w = ContactWindow {
            from_ms: 1_000,
            until_ms: 2_000,
        };
        assert!(!w.contains(999));
        assert!(w.contains(1_000));
        assert!(!w.contains(2_000));
        assert_eq!(w.duration_ms(), 1_000);
        let next = ContactWindow {
            from_ms: 5_000,
            until_ms: 6_000,
        };
        assert_eq!(w.outage_before(&next), Some(3_000));
        // Overlapping windows yield None rather than an enormous unsigned gap.
        let overlapping = ContactWindow {
            from_ms: 1_500,
            until_ms: 3_000,
        };
        assert_eq!(w.outage_before(&overlapping), None);
    }

    #[test]
    fn link_codes_are_unique() {
        let mut codes: Vec<u8> = LinkState::ALL.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), LinkState::ALL.len());
    }
}
