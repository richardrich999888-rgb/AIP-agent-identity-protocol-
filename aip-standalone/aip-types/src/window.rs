//! A closed time interval, shared by the observer side (an observation's
//! coverage) and the decision-point side (a completeness statement). Both
//! ends are inclusive, matching the R10 convention used since Stage 0; a
//! half-open form is avoided deliberately so that "covers" and "intersects"
//! compose without off-by-one rules.

use serde::{Deserialize, Serialize};

/// The interval a statement or observation covers, Unix ms, both ends
/// inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageWindow {
    pub from_ms: u64,
    pub to_ms: u64,
}

impl CoverageWindow {
    /// `from_ms <= t_ms <= to_ms`.
    pub fn contains(&self, t_ms: u64) -> bool {
        t_ms >= self.from_ms && t_ms <= self.to_ms
    }

    /// `other` lies entirely inside `self`.
    pub fn covers(&self, other: &CoverageWindow) -> bool {
        other.from_ms >= self.from_ms && other.to_ms <= self.to_ms
    }

    /// `to_ms >= from_ms`. A window with `to_ms < from_ms` is malformed
    /// and is refused by every producer and verifier that takes one.
    pub fn is_well_formed(&self) -> bool {
        self.to_ms >= self.from_ms
    }

    /// The closed intervals `[a_from, a_to]` and `[b_from, b_to]` share at
    /// least one instant. Both ends inclusive, so windows that touch at a
    /// single millisecond intersect.
    pub fn intersects(&self, other: &CoverageWindow) -> bool {
        self.from_ms <= other.to_ms && other.from_ms <= self.to_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: CoverageWindow = CoverageWindow {
        from_ms: 100,
        to_ms: 200,
    };

    #[test]
    fn contains_is_inclusive_at_both_ends() {
        assert!(W.contains(100));
        assert!(W.contains(200));
        assert!(!W.contains(99));
        assert!(!W.contains(201));
    }

    #[test]
    fn covers_requires_full_containment() {
        let inner = CoverageWindow {
            from_ms: 100,
            to_ms: 200,
        };
        assert!(W.covers(&inner));
        let shifted = CoverageWindow {
            from_ms: 99,
            to_ms: 200,
        };
        assert!(!W.covers(&shifted));
    }

    #[test]
    fn intersects_is_symmetric_and_inclusive() {
        let touching = CoverageWindow {
            from_ms: 200,
            to_ms: 300,
        };
        assert!(W.intersects(&touching));
        assert!(touching.intersects(&W));
        let apart = CoverageWindow {
            from_ms: 201,
            to_ms: 300,
        };
        assert!(!W.intersects(&apart));
        assert!(!apart.intersects(&W));
        let before = CoverageWindow {
            from_ms: 0,
            to_ms: 99,
        };
        assert!(!W.intersects(&before));
    }

    #[test]
    fn well_formedness() {
        assert!(W.is_well_formed());
        assert!(CoverageWindow {
            from_ms: 5,
            to_ms: 5
        }
        .is_well_formed());
        assert!(!CoverageWindow {
            from_ms: 6,
            to_ms: 5
        }
        .is_well_formed());
    }
}
