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
//! 3. Exact equipment-code + unit rules produced readings *for every
//!    registered asset named* → Strategy A. (Fix after the v5 held-out run:
//!    rules that read one of two assets used to decide on partial evidence —
//!    hold-020, hold-024.)
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
    /// Strength of match (`Capability::fit`); routing picks the unique maximum.
    pub fit: u32,
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

/// Distinct assets covered by a set of readings. Reading keys are
/// `<asset>_<quantity>` (e.g. `p7_vib`), so the asset is the key's prefix.
fn assets_covered(readings: &[crate::domain::maintenance::Reading]) -> usize {
    let mut a: Vec<&str> = readings
        .iter()
        .map(|r| r.key.split('_').next().unwrap_or(""))
        .collect();
    a.sort_unstable();
    a.dedup();
    a.len()
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
    // S2 strongest-fit routing: the unique best-matching capability runs;
    // a tie at the top is refused as ambiguous; if the best match is stale
    // it is refused rather than falling back to a weaker match.
    if let Some(best) = f.capabilities.iter().map(|c| c.fit).max() {
        let top: Vec<&Candidate> = f.capabilities.iter().filter(|c| c.fit == best).collect();
        if top.len() > 1 {
            return Strategy::Refuse(Refusal::AmbiguousCapability(
                top.iter().map(|c| c.id.clone()).collect(),
            ));
        }
        let c = top[0];
        return match &c.stale {
            None => Strategy::Capability {
                id: c.id.clone(),
                hash: c.hash.clone(),
            },
            Some(reason) => Strategy::Refuse(Refusal::CapabilityStale {
                id: c.id.clone(),
                reason: reason.clone(),
            }),
        };
    }
    if let Some(i) = &f.interpretation {
        if !i.unregistered.is_empty() {
            return Strategy::Refuse(Refusal::UnregisteredEquipment(i.unregistered.clone()));
        }
        if !i.rules.is_empty() && assets_covered(&i.rules) >= i.registered_codes {
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

/// Why a model strategy's output was withheld (input to [`escalate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withhold {
    /// The model's output did not parse or failed validation, or a grounded
    /// answer restated a rule instead of computing the value: a stronger
    /// model may succeed.
    ModelQuality,
    /// No authorized source / nothing a model could fix: never escalated.
    NotModelFixable,
}

/// One-step escalation after a small-tier model strategy was withheld for a
/// model-quality reason: retry the same strategy on the large tier, if one
/// is configured. Never escalates a decision, an answer, a refusal, a
/// capability or exact strategy, or a large-tier attempt (at most one retry,
/// so cost is bounded at two model attempts per request).
pub fn escalate(s: &Strategy, withheld: Option<Withhold>, large_model: bool) -> Option<Strategy> {
    if !large_model || withheld != Some(Withhold::ModelQuality) {
        return None;
    }
    match s {
        Strategy::ModelExtraction(Tier::Small) => Some(Strategy::ModelExtraction(Tier::Large)),
        Strategy::GroundedQa(Tier::Small) => Some(Strategy::GroundedQa(Tier::Large)),
        _ => None,
    }
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
            fit: 3,
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
        assert_eq!(route(&f(Some(interp(1, 1, 1, &[])))), Strategy::Exact);
        // One rule reading cannot decide a report naming two assets.
        assert_eq!(
            route(&f(Some(interp(1, 1, 2, &[])))),
            Strategy::ModelExtraction(Tier::Small)
        );
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
    fn partial_rule_coverage_of_a_multi_asset_report_is_not_exact() {
        let rd = |k: &str| Reading {
            key: k.into(),
            value: 1.0,
        };
        let mut i = interp(0, 1, 2, &[]);
        i.rules = vec![rd("p7_vib")]; // one of two named assets read
        assert_eq!(
            route(&f(Some(i.clone()))),
            Strategy::ModelExtraction(Tier::Small)
        );
        i.rules = vec![rd("p7_vib"), rd("v12_stroke")]; // both assets read
        assert_eq!(route(&f(Some(i.clone()))), Strategy::Exact);
        i.rules = vec![rd("p7_vib"), rd("p7_temp")]; // two readings, one asset
        assert_eq!(
            route(&f(Some(i.clone()))),
            Strategy::ModelExtraction(Tier::Small)
        );
        let mut no_model = f(Some(i));
        no_model.small_model = false;
        assert_eq!(
            route(&no_model),
            Strategy::Refuse(Refusal::ModelUnavailable)
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
    fn strongest_fit_wins_ties_refuse_and_a_stale_best_is_never_bypassed() {
        let mut x = f(None);
        let mut strong = cand("tx", None);
        strong.fit = 5;
        x.capabilities = vec![cand("ir", None), strong.clone(), cand("bt", None)];
        assert_eq!(
            route(&x),
            Strategy::Capability {
                id: "tx".into(),
                hash: "h-tx".into()
            }
        );
        let mut rival = cand("other", None);
        rival.fit = 5;
        x.capabilities = vec![strong.clone(), rival];
        assert!(
            matches!(route(&x), Strategy::Refuse(Refusal::AmbiguousCapability(ids)) if ids.len() == 2)
        );
        let mut stale_best = cand("tx", Some("policy changed"));
        stale_best.fit = 5;
        x.capabilities = vec![stale_best, cand("ir", None)];
        assert!(
            matches!(route(&x), Strategy::Refuse(Refusal::CapabilityStale { .. })),
            "a weaker match is not used when the best one is stale"
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

    #[test]
    fn escalation_is_one_bounded_step_and_only_for_model_quality() {
        use super::{escalate, Withhold};
        let q = Some(Withhold::ModelQuality);
        assert_eq!(
            escalate(&Strategy::ModelExtraction(Tier::Small), q, true),
            Some(Strategy::ModelExtraction(Tier::Large))
        );
        assert_eq!(
            escalate(&Strategy::GroundedQa(Tier::Small), q, true),
            Some(Strategy::GroundedQa(Tier::Large))
        );
        // no large model, not withheld, not model-fixable, already large, non-model strategies
        assert_eq!(escalate(&Strategy::GroundedQa(Tier::Small), q, false), None);
        assert_eq!(
            escalate(&Strategy::GroundedQa(Tier::Small), None, true),
            None
        );
        assert_eq!(
            escalate(
                &Strategy::GroundedQa(Tier::Small),
                Some(Withhold::NotModelFixable),
                true
            ),
            None
        );
        assert_eq!(escalate(&Strategy::GroundedQa(Tier::Large), q, true), None);
        assert_eq!(escalate(&Strategy::Exact, q, true), None);
        assert_eq!(escalate(&Strategy::Interpreter, q, true), None);
    }
}
