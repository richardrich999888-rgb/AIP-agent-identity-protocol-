//! Experience records and what they may be used for. Pure.
//!
//! Rules:
//! - an experience is ingested only into the tenant and security domain of
//!   the principal recording it (no cross-domain ingestion);
//! - a success reported by the agent itself is stored as `SelfReported` and
//!   is never treated as verified;
//! - only `Verified` experiences, verified by a principal other than the
//!   actor, with an expected outcome, may become expert validation cases —
//!   and they count only after that verifier signs them into an
//!   [`ExpertSuite`](super::suite::ExpertSuite); the `verifier` string alone
//!   is a claim, not evidence.

use serde::{Deserialize, Serialize};

use super::suite::SuiteCase;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    Unverified,
    /// The acting agent/model claims success. Not evidence.
    SelfReported {
        agent: String,
    },
    /// A human principal checked the outcome.
    Verified {
        verifier: String,
        at_ms: u64,
    },
}

/// One unit of organisational experience.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Experience {
    pub id: String,
    pub tenant: String,
    pub security_domain: String,
    /// "public" | "internal" | "restricted".
    pub classification: String,
    pub task: String,
    /// Document ids (within `tenant`) the task relied on.
    pub evidence_refs: Vec<String>,
    pub actions_attempted: Vec<String>,
    pub observed_outcome: Option<String>,
    pub human_correction: Option<String>,
    /// The outcome that should have been produced, when known.
    pub expected_outcome: Option<String>,
    pub actor: String,
    pub verification: Verification,
    pub policies: Vec<String>,
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExperienceError {
    CrossTenant,
    CrossDomain,
    SelfVerified,
    Empty(&'static str),
}

/// Accept an experience for storage by `principal_tenant` in `domain`.
pub fn admit(e: &Experience, principal_tenant: &str, domain: &str) -> Result<(), ExperienceError> {
    if e.task.trim().is_empty() {
        return Err(ExperienceError::Empty("task"));
    }
    if e.tenant != principal_tenant {
        return Err(ExperienceError::CrossTenant);
    }
    if e.security_domain != domain {
        return Err(ExperienceError::CrossDomain);
    }
    if let Verification::Verified { verifier, .. } = &e.verification {
        if verifier == &e.actor {
            return Err(ExperienceError::SelfVerified);
        }
    }
    Ok(())
}

/// Candidate suite case for `verifier_id`, if and only if the experience was
/// verified by that principal, who is not the actor, and carries an expected
/// outcome. The case becomes evidence only when `verifier_id` signs a suite.
pub fn as_suite_case(e: &Experience, verifier_id: &str, counterexample: bool) -> Option<SuiteCase> {
    match (&e.verification, &e.expected_outcome) {
        (Verification::Verified { verifier, .. }, Some(expected))
            if verifier != &e.actor && verifier == verifier_id =>
        {
            Some(SuiteCase {
                id: e.id.clone(),
                text: e.task.clone(),
                expected: expected.clone(),
                counterexample,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exp(v: Verification) -> Experience {
        Experience {
            id: "x1".into(),
            tenant: "koravi-process".into(),
            security_domain: "koravi-ot".into(),
            classification: "restricted".into(),
            task: "M-1 6.6 kV 100 megohm at 40 C PI 2.1".into(),
            evidence_refs: vec!["ep-114".into()],
            actions_attempted: vec![],
            observed_outcome: Some("PASS".into()),
            human_correction: None,
            expected_outcome: Some("PASS".into()),
            actor: "agent:runtime".into(),
            verification: v,
            policies: vec!["ep-114-revC".into()],
            provenance: "demo".into(),
        }
    }

    #[test]
    fn only_independently_verified_experience_becomes_a_test() {
        let v = exp(Verification::Verified {
            verifier: "expert:lead".into(),
            at_ms: 1,
        });
        assert!(as_suite_case(&v, "expert:lead", false).is_some());
        assert!(
            as_suite_case(&v, "expert:someone-else", false).is_none(),
            "only the verifier may sign its own verifications into a suite"
        );
        assert!(as_suite_case(
            &exp(Verification::SelfReported {
                agent: "agent:runtime".into()
            }),
            "agent:runtime",
            false
        )
        .is_none());
        assert!(as_suite_case(&exp(Verification::Unverified), "expert:lead", false).is_none());
        let selfv = exp(Verification::Verified {
            verifier: "agent:runtime".into(),
            at_ms: 1,
        });
        assert!(as_suite_case(&selfv, "agent:runtime", false).is_none());
        assert_eq!(
            admit(&selfv, "koravi-process", "koravi-ot"),
            Err(ExperienceError::SelfVerified)
        );
    }

    #[test]
    fn no_cross_tenant_or_cross_domain_ingestion() {
        let e = exp(Verification::Unverified);
        assert_eq!(
            admit(&e, "tarvel-grid", "koravi-ot"),
            Err(ExperienceError::CrossTenant)
        );
        assert_eq!(
            admit(&e, "koravi-process", "tarvel-ot"),
            Err(ExperienceError::CrossDomain)
        );
        assert_eq!(admit(&e, "koravi-process", "koravi-ot"), Ok(()));
    }
}
