//! Exact maintenance-priority policy (Strategy A's decision table).
//!
//! Port of `research/system-one/datasets/maintenance_priority.py` (`METRICS`,
//! `priority`, and the min-over-readings decision). Interpreters (rules,
//! classifiers, a language model) only produce readings; this table alone
//! turns readings into a priority, so the decision never depends on which
//! interpreter ran. Parity with the Python reference is tested on every
//! labelled item in `tests/parity.rs`.

use serde::{Deserialize, Serialize};

/// Priority 1 (most urgent) … 4 (routine).
pub type Priority = u8;

/// One SOP band list: `(upper_bound_exclusive, priority)`; the last bound is +∞.
struct Metric {
    key: &'static str,
    bands: &'static [(f64, Priority)],
}

/// Bands are `[previous bound, bound)`; values copied verbatim from the
/// Python reference (including the `+0.0001` inclusive-boundary encodings).
const METRICS: &[Metric] = &[
    Metric {
        key: "p7_vib",
        bands: &[(4.5, 4), (7.1, 3), (f64::INFINITY, 1)],
    },
    Metric {
        key: "p7_bear",
        bands: &[(85.0001, 4), (f64::INFINITY, 1)],
    },
    Metric {
        key: "p7_seal",
        bands: &[(20.0001, 4), (f64::INFINITY, 2)],
    },
    Metric {
        key: "t3_oil",
        bands: &[(95.0, 4), (105.0, 2), (f64::INFINITY, 1)],
    },
    Metric {
        key: "v12_stroke",
        bands: &[(12.0001, 4), (f64::INFINITY, 3)],
    },
    Metric {
        key: "g2_tank",
        bands: &[(50.0, 1), (80.0, 2), (f64::INFINITY, 4)],
    },
    Metric {
        key: "ch5_app",
        bands: &[(3.0, 4), (f64::INFINITY, 3)],
    },
    Metric {
        key: "fp1_press",
        bands: &[(65.0, 1), (f64::INFINITY, 4)],
    },
];

/// One interpreted reading.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reading {
    pub key: String,
    pub value: f64,
}

/// Policy outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Priority(Priority),
    /// No reading, or an unknown metric key, or a non-finite value.
    Abstain,
}

impl Decision {
    /// Label spelling used by the evaluation sets ("1".."4", "ABSTAIN").
    pub fn label(&self) -> String {
        match self {
            Decision::Priority(p) => p.to_string(),
            Decision::Abstain => "ABSTAIN".into(),
        }
    }
}

/// Priority of one reading; `None` for an unknown key or non-finite value.
pub fn priority(key: &str, value: f64) -> Option<Priority> {
    if !value.is_finite() {
        return None;
    }
    let m = METRICS.iter().find(|m| m.key == key)?;
    m.bands.iter().find(|(b, _)| value < *b).map(|(_, p)| *p)
}

/// Decision over all readings: the most urgent (lowest) priority. Any unknown
/// key makes the whole decision abstain (fail closed: an interpreter that
/// invents a metric does not get a partial answer released).
pub fn decide(readings: &[Reading]) -> Decision {
    if readings.is_empty() {
        return Decision::Abstain;
    }
    let mut best: Option<Priority> = None;
    for r in readings {
        match priority(&r.key, r.value) {
            None => return Decision::Abstain,
            Some(p) => best = Some(best.map_or(p, |b| b.min(p))),
        }
    }
    best.map_or(Decision::Abstain, Decision::Priority)
}

/// Is `key` a metric the policy knows?
pub fn known_metric(key: &str) -> bool {
    METRICS.iter().any(|m| m.key == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(k: &str, v: f64) -> Reading {
        Reading {
            key: k.into(),
            value: v,
        }
    }

    #[test]
    fn band_edges_are_half_open() {
        assert_eq!(priority("p7_vib", 4.499), Some(4));
        assert_eq!(priority("p7_vib", 4.5), Some(3));
        assert_eq!(priority("p7_vib", 7.1), Some(1));
        assert_eq!(priority("p7_bear", 85.0), Some(4)); // inclusive via +0.0001
        assert_eq!(priority("t3_oil", 105.0), Some(1));
        assert_eq!(priority("g2_tank", 49.9), Some(1));
    }

    #[test]
    fn decision_is_most_urgent_reading() {
        assert_eq!(
            decide(&[r("p7_vib", 3.0), r("t3_oil", 106.0)]),
            Decision::Priority(1)
        );
        assert_eq!(decide(&[r("v12_stroke", 13.0)]).label(), "3");
    }

    #[test]
    fn fails_closed() {
        assert_eq!(decide(&[]), Decision::Abstain);
        assert_eq!(
            decide(&[r("p7_vib", 3.0), r("p9_vib", 9.0)]),
            Decision::Abstain
        );
        assert_eq!(decide(&[r("p7_vib", f64::NAN)]), Decision::Abstain);
        assert!(!known_metric("p9_vib"));
    }
}
