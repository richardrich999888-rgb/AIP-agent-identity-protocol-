//! What happens to what the sentinel catches — and what constrains the
//! sentinel itself.
//!
//! # The warrant standard
//!
//! Automatic containment is gated on [`Strength::Proof`]. Nothing weaker can
//! quarantine or terminate an agent, no matter how severe the finding, and
//! [`ResponsePolicy::decide`] enforces that in code rather than leaving it to
//! configuration.
//!
//! This is not caution for its own sake. A watchdog that revokes agents on
//! statistical suspicion is a denial-of-service weapon pointed at its own
//! fleet: the cheapest attack on a governed system becomes generating traffic
//! that looks anomalous until the watchdog disables the agents doing the
//! real work. Requiring arithmetic — a chain that branched, a digest that
//! does not recompute, an effect matching no sealed packet — means an
//! attacker cannot manufacture a sanction without manufacturing a hash
//! collision.
//!
//! # The watchdog is itself accountable
//!
//! Every action the sentinel takes is sealed into the same hash-chained
//! ledger it polices, under the sentinel's own DID, citing the evidence that
//! justified it. An enforcement action with no citations is not a valid
//! record. So "who watches the watchmen" has a concrete answer here: the same
//! chain, the same verifier, the same offline audit. A sentinel that
//! quarantines an agent has to say what it saw, in a record it cannot later
//! edit without breaking its own chain.

use serde_json::{json, Value};

use crate::finding::{Finding, Severity, Strength};

/// Graduated containment, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Response {
    /// Record it; change nothing.
    Observe,
    /// Raise it for a human.
    Alert,
    /// Narrow the agent's authority without stopping it.
    Constrain,
    /// Revoke the delegation edge. Authority cascades away from the whole
    /// subtree at the next resolution.
    Quarantine,
    /// Terminal revocation: the lifecycle chain closes for good.
    Terminate,
}

impl Response {
    /// The wire vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "OBSERVE",
            Self::Alert => "ALERT",
            Self::Constrain => "CONSTRAIN",
            Self::Quarantine => "QUARANTINE",
            Self::Terminate => "TERMINATE",
        }
    }

    /// True when this response takes authority away from a running agent.
    pub fn is_containment(self) -> bool {
        self >= Self::Constrain
    }
}

/// The lowest response that may never be reached without proof.
pub const WARRANT_THRESHOLD: Response = Response::Quarantine;

/// How findings become actions.
///
/// The derived default is `autonomous: false` with nothing protected — an
/// advisory sentinel that reports and never acts. That is deliberate: a
/// deployment that forgets to configure a policy gets one that cannot disable
/// its own fleet, and turning enforcement on has to be a decision somebody
/// made on purpose.
#[derive(Debug, Clone, Default)]
pub struct ResponsePolicy {
    /// When false, the sentinel never acts on its own: everything is capped
    /// at [`Response::Alert`] and a human decides. The right default for a
    /// new deployment, and for any fleet where a wrongly-contained agent is
    /// more costly than a briefly-uncontained one.
    pub autonomous: bool,
    /// Agents that are never contained automatically regardless of findings.
    /// For the ones whose sudden loss of authority would itself be the
    /// incident.
    pub protected_dids: Vec<String>,
}

impl ResponsePolicy {
    /// A policy that may contain agents on its own, subject to the warrant
    /// standard.
    pub fn autonomous() -> Self {
        Self {
            autonomous: true,
            protected_dids: Vec::new(),
        }
    }

    /// Exempts an agent from automatic containment.
    pub fn protecting(mut self, did: impl Into<String>) -> Self {
        self.protected_dids.push(did.into());
        self
    }

    /// The response a finding warrants.
    ///
    /// Three gates, in order: severity proposes, the warrant standard
    /// disposes, and the operator's settings cap the result. A finding can
    /// only ever be de-escalated on its way through, never promoted.
    pub fn decide(&self, finding: &Finding) -> Response {
        // What the severity would justify if the finding were certain.
        let proposed = match finding.severity {
            Severity::Critical => Response::Quarantine,
            Severity::High => Response::Constrain,
            Severity::Medium => Response::Alert,
            Severity::Low => Response::Observe,
        };

        // The warrant standard: containment needs arithmetic, not a hunch.
        let warranted = if proposed >= WARRANT_THRESHOLD && finding.strength < Strength::Proof {
            Response::Alert
        } else if proposed.is_containment() && finding.strength == Strength::Indicator {
            // Even the mildest containment needs better than a lead.
            Response::Alert
        } else {
            proposed
        };

        // A finding that cites nothing cannot be checked, so it cannot be
        // acted on however it was tiered.
        let evidenced = if finding.evidence.is_empty() {
            warranted.min(Response::Alert)
        } else {
            warranted
        };

        // Operator settings.
        if !self.autonomous {
            return evidenced.min(Response::Alert);
        }
        let protected = finding
            .subject_did
            .as_deref()
            .is_some_and(|did| self.protected_dids.iter().any(|p| p == did));
        if protected {
            return evidenced.min(Response::Alert);
        }
        evidenced
    }
}

/// One action the sentinel took, and why.
///
/// Sealed into the ledger as a `SENTINEL_ENFORCEMENT` anchor so the
/// watchdog's own conduct is auditable by the same tooling as the fleet's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementAction {
    /// The sentinel that acted.
    pub sentinel_did: String,
    /// The agent acted upon, when the finding named one.
    pub subject_did: Option<String>,
    /// What was done.
    pub response: Response,
    /// The finding that justified it.
    pub finding: Finding,
    /// ISO-8601 UTC.
    pub decided_at_utc: String,
}

impl EnforcementAction {
    /// The canonical JSON payload for the sealing anchor.
    pub fn to_payload(&self) -> Value {
        let mut payload = json!({
            "sentinelDid": self.sentinel_did,
            "response": self.response.as_str(),
            "decidedAtUtc": self.decided_at_utc,
            "finding": self.finding.to_json(),
        });
        if let Some(did) = &self.subject_did {
            payload["subjectDid"] = json!(did);
        }
        payload
    }

    /// True when this action took authority away from an agent.
    pub fn is_containment(&self) -> bool {
        self.response.is_containment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::FindingKind;

    fn finding(severity: Severity, strength: Strength) -> Finding {
        Finding::new(
            FindingKind::UnattributedEffect,
            strength,
            severity,
            "test",
            "2026-08-27T00:00:00.000Z",
            "summary",
        )
        .about("did:syntriass:agent:AGT-1")
        .citing(["observation:o1".to_string()])
    }

    #[test]
    fn proof_of_a_critical_finding_warrants_containment() {
        let policy = ResponsePolicy::autonomous();
        assert_eq!(
            policy.decide(&finding(Severity::Critical, Strength::Proof)),
            Response::Quarantine
        );
        assert_eq!(
            policy.decide(&finding(Severity::High, Strength::Proof)),
            Response::Constrain
        );
    }

    #[test]
    fn severity_alone_never_reaches_containment_without_proof() {
        let policy = ResponsePolicy::autonomous();
        // The most alarming possible finding, on merely corroborated
        // evidence, still only raises an alert.
        assert_eq!(
            policy.decide(&finding(Severity::Critical, Strength::Corroborated)),
            Response::Alert
        );
        assert_eq!(
            policy.decide(&finding(Severity::Critical, Strength::Indicator)),
            Response::Alert
        );
        // And a mere indicator cannot even constrain.
        assert_eq!(
            policy.decide(&finding(Severity::High, Strength::Indicator)),
            Response::Alert
        );
    }

    #[test]
    fn a_finding_that_cites_nothing_cannot_be_acted_on() {
        let policy = ResponsePolicy::autonomous();
        let uncited = Finding::new(
            FindingKind::IdentityFork,
            Strength::Proof,
            Severity::Critical,
            "test",
            "t",
            "no citations",
        )
        .about("did:syntriass:agent:AGT-1");
        assert_eq!(policy.decide(&uncited), Response::Alert);
    }

    #[test]
    fn a_non_autonomous_policy_is_advisory_no_matter_what_it_finds() {
        let policy = ResponsePolicy::default();
        assert!(!policy.autonomous, "advisory is the default");
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            for strength in [Strength::Indicator, Strength::Corroborated, Strength::Proof] {
                let decided = policy.decide(&finding(severity, strength));
                assert!(
                    !decided.is_containment(),
                    "{severity:?}/{strength:?} contained under an advisory policy"
                );
            }
        }
    }

    #[test]
    fn a_protected_agent_is_never_contained_automatically() {
        let policy = ResponsePolicy::autonomous().protecting("did:syntriass:agent:AGT-1");
        assert_eq!(
            policy.decide(&finding(Severity::Critical, Strength::Proof)),
            Response::Alert
        );
        // Another agent with the same finding is contained, so the exemption
        // is scoped to the DID and not a global downgrade.
        let other = finding(Severity::Critical, Strength::Proof).about("did:syntriass:agent:AGT-2");
        assert_eq!(policy.decide(&other), Response::Quarantine);
    }

    #[test]
    fn low_severity_findings_are_recorded_rather_than_escalated() {
        let policy = ResponsePolicy::autonomous();
        assert_eq!(
            policy.decide(&finding(Severity::Low, Strength::Proof)),
            Response::Observe
        );
        assert_eq!(
            policy.decide(&finding(Severity::Medium, Strength::Proof)),
            Response::Alert
        );
    }

    #[test]
    fn an_enforcement_action_carries_the_evidence_that_justified_it() {
        let action = EnforcementAction {
            sentinel_did: "did:syntriass:sentinel:SENT-1".into(),
            subject_did: Some("did:syntriass:agent:AGT-1".into()),
            response: Response::Quarantine,
            finding: finding(Severity::Critical, Strength::Proof),
            decided_at_utc: "2026-08-27T00:00:00.000Z".into(),
        };
        let payload = action.to_payload();
        assert_eq!(payload["response"], "QUARANTINE");
        assert_eq!(payload["subjectDid"], "did:syntriass:agent:AGT-1");
        assert_eq!(payload["finding"]["strength"], "PROOF");
        assert_eq!(
            payload["finding"]["evidence"].as_array().unwrap().len(),
            1,
            "an action must carry citations, not just a verdict"
        );
        assert!(action.is_containment());
    }
}
