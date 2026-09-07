//! The observer's own condition — three states, never two.
//!
//! # Why "no observation" and "no observer" must not collapse
//!
//! This is the observation-integrity finding (`12767ea`) carried into the
//! physical-validation layer. Three situations look identical in a log file and
//! mean completely different things:
//!
//! | situation | what it means | what may be concluded |
//! |---|---|---|
//! | no observation | the observer looked and saw nothing | nothing about the world, but the looking is established |
//! | observer unavailable | nobody looked | nothing at all |
//! | observer integrity unknown | somebody looked and may have been blind | nothing at all, and the silence carries no information |
//!
//! Collapsing the second or third into the first turns absence of evidence into
//! evidence of absence, which is the error the whole architecture exists to
//! prevent. A camera that was unplugged, a camera whose view was occluded, and
//! a camera that returned an empty frame are three different facts.

use serde::{Deserialize, Serialize};

/// What is known about the observer over the window in question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObserverPosture {
    /// The observer was present, capable, and vouches for the window.
    Present,
    /// The observer was present and capable, and reported nothing in the
    /// window. The *looking* is established; the silence is a real datum.
    PresentAndSilent,
    /// Nobody looked: the observer was down, unreachable, or never deployed.
    Unavailable,
    /// The observer was live and may have been blind — an occluded view, a
    /// foreign program gating its mechanism, a calibration it cannot vouch
    /// for. Absence over this window carries no information.
    IntegrityUnknown,
}

impl ObserverPosture {
    pub const ALL: [ObserverPosture; 4] = [
        Self::Present,
        Self::PresentAndSilent,
        Self::Unavailable,
        Self::IntegrityUnknown,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Present => 0x01,
            Self::PresentAndSilent => 0x02,
            Self::Unavailable => 0x03,
            Self::IntegrityUnknown => 0x04,
        }
    }

    /// Whether an observation delivered under this posture may be used at all.
    ///
    /// True for `Present` alone. `PresentAndSilent` carries no observation by
    /// definition; the other two carry nothing usable.
    pub fn permits_use(self) -> bool {
        matches!(self, Self::Present)
    }

    /// Whether silence under this posture may be read as "it did not happen".
    ///
    /// **False for all four.** `PresentAndSilent` is the closest any posture
    /// comes, and it still is not enough on its own: a non-occurrence claim in
    /// the production architecture additionally requires a gate-independent
    /// kernel-pushed mechanism, and no optical observer has one. This method
    /// exists so that a caller looking for the shortcut finds a `false` and a
    /// reason.
    pub fn silence_establishes_non_occurrence(self) -> bool {
        false
    }

    pub fn statement(self) -> &'static str {
        match self {
            Self::Present => "the observer vouches for this window",
            Self::PresentAndSilent => {
                "the observer was capable and reported nothing; that it looked is established, \
                 that nothing happened is not"
            }
            Self::Unavailable => "nobody looked; nothing follows about the subject",
            Self::IntegrityUnknown => {
                "the observer was live and may have been blind; absence over this window carries \
                 no information"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_posture_lets_silence_become_non_occurrence() {
        for p in ObserverPosture::ALL {
            assert!(!p.silence_establishes_non_occurrence(), "{p:?}");
        }
    }

    #[test]
    fn only_a_present_observer_permits_use() {
        assert!(ObserverPosture::Present.permits_use());
        for p in [
            ObserverPosture::PresentAndSilent,
            ObserverPosture::Unavailable,
            ObserverPosture::IntegrityUnknown,
        ] {
            assert!(!p.permits_use(), "{p:?}");
        }
    }

    #[test]
    fn the_three_absences_are_distinguishable_and_say_different_things() {
        let s: Vec<&str> = [
            ObserverPosture::PresentAndSilent,
            ObserverPosture::Unavailable,
            ObserverPosture::IntegrityUnknown,
        ]
        .iter()
        .map(|p| p.statement())
        .collect();
        assert_eq!(s.len(), 3);
        assert_ne!(s[0], s[1]);
        assert_ne!(s[1], s[2]);
        assert_ne!(s[0], s[2]);
        assert!(s[2].contains("carries no information"));
    }

    #[test]
    fn posture_codes_are_unique() {
        let mut codes: Vec<u8> = ObserverPosture::ALL.iter().map(|p| p.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), ObserverPosture::ALL.len());
    }
}
