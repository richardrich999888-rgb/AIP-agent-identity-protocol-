//! What a verifier may say about whether something was observed.
//!
//! # Three states, and why none of them says "it did not happen"
//!
//! The failure this module exists to prevent is the one the audit names
//! repeatedly: reading absence of observation as evidence of non-occurrence.
//! Three distinct states keep it out of reach:
//!
//! | State | Means |
//! |---|---|
//! | `Observed` | an anchored observer recorded it |
//! | `NotObserved` | the class is observable here and nothing was recorded |
//! | `NotObservable` | this deployment cannot observe this class at all |
//!
//! `NotObserved` and `NotObservable` are separated for the same reason
//! `CANNOT_PROVE` exists, and for the same reason Skill 18 separates
//! `Unconfirmed` from `NotEvaluated`: "we can look and did not see it" and
//! "we cannot look" are different claims, and summing them turns a blind spot
//! into a clean bill of health.
//!
//! **None of the three asserts non-occurrence**, and there is no API that
//! does. That is checked by test rather than left to discipline.

use aip_types::canonical::put_u8;
use serde::{Deserialize, Serialize};

/// Whether a class was observed, and if not, why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Completeness {
    /// An anchored observer recorded evidence of this class.
    Observed,
    /// The class is observable in this deployment and nothing was recorded.
    ///
    /// This is *not* "the event did not happen". A probe samples; a kernel
    /// queue overflows; a collector restarts. The honest reading is that the
    /// verifier does not know.
    NotObserved,
    /// This deployment has no mechanism for this class.
    ///
    /// A stated fact, so a missing capability is recorded rather than
    /// appearing as a gap that might have been a clean result.
    NotObservable,
}

impl Completeness {
    pub fn code(self) -> u8 {
        match self {
            Self::Observed => 0x01,
            Self::NotObserved => 0x02,
            Self::NotObservable => 0x03,
        }
    }

    /// Whether this state records that something was seen.
    ///
    /// `true` only for `Observed`. Deliberately no `asserts_absence`
    /// counterpart: nothing in this crate may assert that an event did not
    /// occur, so there is no method to return it.
    pub fn asserts_observation(self) -> bool {
        matches!(self, Self::Observed)
    }

    pub fn encode(self, buf: &mut Vec<u8>) {
        put_u8(buf, self.code());
    }
}
