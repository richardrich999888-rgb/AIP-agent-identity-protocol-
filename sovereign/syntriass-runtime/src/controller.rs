//! Strategy selection. Pure: features in, strategy out.
//!
//! The order below was fixed before the controller was run on the fresh
//! held-out set (hard-reports-v5). Steps 3–5 are the "R3" order from
//! research/compute-memory/ADAPTIVE_ROUTING.md, which was derived on
//! already-inspected data (v3/v4); v5 is its first unseen test.
//!
//! 1. Exactly one ACTIVE, authorized, dependency-current capability applies
//!    → Strategy E. More than one → ask for clarification. One that applies
//!    but is stale (knowledge, policy or model changed) → refuse and flag
//!    for re-validation; never fall back to an unvalidated answer.
//! 2. An unregistered equipment code is named → refuse (registry gate).
//! 3. Exact equipment-code + unit rules produced readings → Strategy A.
//! 4. Two or more registered assets are named → Strategy C (SLM extraction).
//! 5. The compact interpreter produced a reading → Strategy B.
//! 6. The text is a question → grounded QA over authorized documents
//!    (Strategy C; escalation to D only if a larger model is configured).
//! 7. Otherwise → refuse.
//!
//! A model's output never reaches this function: features come from the
//! capability registry, deterministic interpreters and the request text.

use serde::{Deserialize, Serialize};

use crate::ports::Interpretation;

/// Why the runtime declined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    UnregisteredEquipment(Vec<String>),
    AmbiguousCapability(Vec<String>),
    CapabilityStale {
        id: String,
        reason: String,
    },
    /// The required model tier is not configured or failed to load.
    ModelUnavailable,
    NoApplicableStrategy,
    /// Explicitly requested capability is not ACTIVE, not trusted, or not
    /// authorized for the caller.
    NotPermitted {
        id: String,
        reason: String,
    },
}

/// Which generative tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// Strategy C.
    Small,
    /// Strategy D.
    Large,
}

/// Selected strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Strategy {
    /// A — exact rules + exact policy.
    Exact,
    /// B — compact interpreter + exact policy.
    Interpreter,
    /// C/D — model extracts readings; exact policy decides.
    ModelExtraction(Tier),
    /// C/D — grounded answer over authorized documents.
    GroundedQa(Tier),
    /// E — validated capability (id, content hash).
    Capability {
        id: String,
        hash: String,
    },
    Refuse(Refusal),
}

/// A capability candidate as seen by the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub hash: String,
    /// `Some(reason)` when it applies but must not run (stale dependency).
    pub stale: Option<String>,
}

/// Everything the controller may look at.
#[derive(Debug, Clone, Default)]
pub struct Features {
    /// Capabilities that are ACTIVE, authorized for the caller and apply to the text.
    pub capabilities: Vec<Candidate>,
    pub interpretation: Option<Interpretation>,
    pub is_question: bool,
    pub small_model: bool,
    pub large_model: bool,
}

/// Interrogative / imperative openers that mark a document question.
const QUESTION_OPENERS: &[&str] = &[
    "what",
    "which",
    "who",
    "whom",
    "when",
    "where",
    "why",
    "how",
    "is",
    "are",
    "can",
    "could",
    "should",
    "does",
    "do",
    "explain",
    "summarise",
    "summarize",
    "describe",
    "list",
    "tell",
];

/// Deterministic question test: ends with '?' or opens with an interrogative.
pub fn is_question(text: &str) -> bool {
    let t = text.trim();
    t.ends_with('?')
        || t.split_whitespace()
            .next()
            .map(|w| {
                w.trim_matches(|c: char| !c.is_alphanumeric())
                    .to_lowercase()
            })
            .is_some_and(|w| QUESTION_OPENERS.contains(&w.as_str()))
}

fn tier(f: &Features) -> Option<Tier> {
    if f.small_model {
        Some(Tier::Small)
    } else if f.large_model {
        Some(Tier::Large)
    } else {
        None
    }
}

/// Select a strategy.
pub fn route(f: &Features) -> Strategy {
    let fresh: Vec<&Candidate> = f
        .capabilities
        .iter()
        .filter(|c| c.stale.is_none())
        .collect();
    match fresh.len() {
        1 => {
            return Strategy::Capability {
                id: fresh[0].id.clone(),
                hash: fresh[0].hash.clone(),
            }
        }
        n if n > 1 => {
            return Strategy::Refuse(Refusal::AmbiguousCapability(
                fresh.iter().map(|c| c.id.clone()).collect(),
            ))
        }
        _ => {}
    }
    if let Some(c) = f.capabilities.iter().find(|c| c.stale.is_some()) {
        return Strategy::Refuse(Refusal::CapabilityStale {
            id: c.id.clone(),
            reason: c.stale.clone().unwrap_or_default(),
        });
    }
    if let Some(i) = &f.interpretation {
        if !i.unregistered.is_empty() {
            return Strategy::Refuse(Refusal::UnregisteredEquipment(i.unregistered.clone()));
        }
        if !i.rules.is_empty() {
            return Strategy::Exact;
        }
        if i.registered_codes >= 2 {
            return tier(f).map_or(
                Strategy::Refuse(Refusal::ModelUnavailable),
                Strategy::ModelExtraction,
            );
        }
        if !i.interp.is_empty() {
            return Strategy::Interpreter;
        }
    }
    if f.is_question {
        return tier(f).map_or(
            Strategy::Refuse(Refusal::ModelUnavailable),
            Strategy::GroundedQa,
        );
    }
    Strategy::Refuse(Refusal::NoApplicableStrategy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::maintenance::Reading;

    fn interp(rules: usize, interp: usize, codes: usize, unreg: &[&str]) -> Interpretation {
        let r = || Reading {
            key: "p7_vib".into(),
            value: 3.0,
        };
        Interpretation {
            rules: (0..rules).map(|_| r()).collect(),
            interp: (0..interp).map(|_| r()).collect(),
            interp_top_prob: 0.9,
            unregistered: unreg.iter().map(|s| s.to_string()).collect(),
            registered_codes: codes,
        }
    }

    fn cand(id: &str, stale: Option<&str>) -> Candidate {
        Candidate {
            id: id.into(),
            hash: format!("h-{id}"),
            stale: stale.map(String::from),
        }
    }

    fn f(i: Option<Interpretation>) -> Features {
        Features {
            interpretation: i,
            small_model: true,
            ..Default::default()
        }
    }

    #[test]
    fn order_is_capability_gate_rules_multi_interp_question() {
        let mut x = f(Some(interp(1, 1, 2, &["P-9"])));
        x.capabilities = vec![cand("c", None)];
        assert!(matches!(route(&x), Strategy::Capability { .. }));
        x.capabilities.clear();
        assert!(matches!(
            route(&x),
            Strategy::Refuse(Refusal::UnregisteredEquipment(_))
        ));
        assert_eq!(route(&f(Some(interp(1, 1, 2, &[])))), Strategy::Exact);
        assert_eq!(
            route(&f(Some(interp(0, 1, 2, &[])))),
            Strategy::ModelExtraction(Tier::Small)
        );
        assert_eq!(route(&f(Some(interp(0, 1, 1, &[])))), Strategy::Interpreter);
        let mut q = f(Some(interp(0, 0, 1, &[])));
        q.is_question = true;
        assert_eq!(route(&q), Strategy::GroundedQa(Tier::Small));
        assert_eq!(
            route(&f(Some(interp(0, 0, 1, &[])))),
            Strategy::Refuse(Refusal::NoApplicableStrategy)
        );
    }

    #[test]
    fn capability_conflicts_and_staleness_fail_closed() {
        let mut x = f(None);
        x.capabilities = vec![cand("a", None), cand("b", None)];
        assert!(matches!(
            route(&x),
            Strategy::Refuse(Refusal::AmbiguousCapability(_))
        ));
        x.capabilities = vec![cand("a", Some("knowledge changed"))];
        x.is_question = true;
        assert!(
            matches!(route(&x), Strategy::Refuse(Refusal::CapabilityStale { .. })),
            "never falls back to an unvalidated answer"
        );
    }

    #[test]
    fn missing_models_refuse_instead_of_guessing() {
        let mut x = f(Some(interp(0, 1, 2, &[])));
        x.small_model = false;
        assert_eq!(route(&x), Strategy::Refuse(Refusal::ModelUnavailable));
        x.large_model = true;
        assert_eq!(route(&x), Strategy::ModelExtraction(Tier::Large));
    }

    #[test]
    fn question_detection() {
        for q in [
            "What is the P-7 vibration limit?",
            "Explain what polarization index means.",
            "summarise EP-090",
            "Can we restart it",
        ] {
            assert!(is_question(q), "{q}");
        }
        for r in [
            "P-7 vibration 7.3 mm/s.",
            "Motor M-101 rated 6.6 kV: IR 220 megohms",
            "Isolation valve V-12 took 10.4 s",
        ] {
            assert!(!is_question(r), "{r}");
        }
    }
}
