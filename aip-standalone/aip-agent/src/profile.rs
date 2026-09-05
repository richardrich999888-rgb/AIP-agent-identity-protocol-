//! SD-02 — the agent profile: a dimension-separated **view** over artifacts
//! that were each re-verified while building it.
//!
//! The profile is not authoritative for anything. It has no signature, no
//! store and no summary field. Each partition names the authority behind it:
//!
//! | partition | authority |
//! |---|---|
//! | `identity` | the agent's self-signed document or packet summary, re-derived |
//! | `self_declared` | the agent; labelled unverified; nothing else reads it |
//! | `issuers`, `authority` | token issuers, by signature, under the decision point's rules |
//! | `instances` | the decision point (`AuthorizedTarget`) or the agent (`Claimed`) |
//! | `reconciled` | the reconciler, joined through this agent's verified decisions |
//! | `lineage`, `experience` | later phases; explicit placeholders |

use std::collections::HashSet;

use aip_authorize::{
    verify_expected_execution_for_agent, DecisionPointTrustAnchors, ExpectedExecution,
};
use aip_protocol::AgentIdentitySummary;
use aip_reconcile::Reconciliation;
use aip_types::{AgentIdentityDocument, ExecutionBinding};
use serde::Serialize;

use crate::authority::{project_authority, AuthorityChain, AuthorityProjection, IssuerKeys};
use crate::identity::{AgentIdentity, IdentityError};
use crate::IssuerAssertion;

/// The label every self-declared entry carries.
pub const SELF_DECLARED_LABEL: &str = "SELF_DECLARED · UNVERIFIED";

/// Free text the agent supplied about itself. It is carried so a reader can
/// compare it with the verified partitions; it feeds none of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelfDeclared {
    pub label: &'static str,
    pub text: String,
}

/// The identity input: the agent's document (optionally with the parent the
/// caller asserts, whose key verifies the lineage proof) or the summary from
/// an `EvidencePacket`.
#[derive(Debug, Clone, Copy)]
pub enum IdentityInput<'a> {
    Document {
        document: &'a AgentIdentityDocument,
        parent: Option<(&'a str, &'a [u8])>,
    },
    Summary(&'a AgentIdentitySummary),
}

/// Everything a profile is built from. Trust anchors are the builder's;
/// nothing is read from the artifacts about whom to trust.
#[derive(Debug, Clone, Copy)]
pub struct ProfileInputs<'a> {
    pub identity: IdentityInput<'a>,
    pub self_declared: &'a [String],
    pub authority: &'a [AuthorityChain],
    pub issuer_keys: &'a IssuerKeys,
    /// Decision-point-signed expectations; verified here against the anchors
    /// and against the validated agent key (`DecisionKeyIsAgentKey`).
    pub expectations: &'a [ExpectedExecution],
    pub decision_point_anchors: &'a DecisionPointTrustAnchors,
    /// Bindings the agent presented in packets (already through R15 by the
    /// caller). They remain the agent's claim about its own process.
    pub claimed_bindings: &'a [ExecutionBinding],
    /// Reconciliation records produced in the builder's own trust domain.
    pub reconciliations: &'a [Reconciliation],
    pub as_of_ms: u64,
}

/// Who vouched for a binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum InstanceAssertion {
    /// The agent presented this binding about itself; nobody else has.
    Claimed,
    /// A trusted decision point signed an expectation naming this binding as
    /// the authorized target. Still the binding the agent presented at
    /// request time; the decision point vouches for the authorization, not
    /// for the process.
    AuthorizedTarget {
        decision_id: [u8; 16],
        decision_point_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionInstance {
    pub binding: ExecutionBinding,
    pub assertion: InstanceAssertion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ExpectationExclusion {
    /// `verify_expected_execution_for_agent` refused it (rendered `Debug`).
    Unverified(String),
    /// Verified, but issued for another agent.
    AgentMismatch { agent_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExcludedExpectation {
    pub decision_id: [u8; 16],
    pub reason: ExpectationExclusion,
}

/// Where a reconciliation record came from. Records are unsigned today, so
/// the only admissible source is the builder's own verifier run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecordSource {
    VerifierLocal,
}

/// A reconciliation record carried verbatim — result, strength, reason,
/// comparisons and evidence references untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconciledRecord {
    pub record: Reconciliation,
    pub source: RecordSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ReconciliationExclusion {
    /// A record with no decision id cannot be joined to any agent.
    NoDecisionId,
    /// The decision is not among this agent's verified expectations.
    DecisionNotForAgent { decision_id: [u8; 16] },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExcludedReconciliation {
    /// Index into `ProfileInputs::reconciliations`.
    pub index: u32,
    pub reason: ReconciliationExclusion,
}

/// Phase C fills this in. Until then the profile says so explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LineageSection {
    NotEvaluated,
}

/// Phase F fills this in. Until then the profile says so explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ExperienceSection {
    NotDerived,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    Identity(IdentityError),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Identity(e) => write!(f, "identity: {e}"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// The profile. Field order is the partition order; every field is public
/// so a reader sees exactly what was and was not established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentProfile {
    pub identity: AgentIdentity,
    pub self_declared: Vec<SelfDeclared>,
    pub issuers: Vec<IssuerAssertion>,
    pub authority: AuthorityProjection,
    pub instances: Vec<ExecutionInstance>,
    pub excluded_expectations: Vec<ExcludedExpectation>,
    /// Claimed bindings that name another agent.
    pub excluded_bindings: Vec<ExecutionBinding>,
    pub reconciled: Vec<ReconciledRecord>,
    pub excluded_reconciliations: Vec<ExcludedReconciliation>,
    pub lineage: LineageSection,
    pub experience: ExperienceSection,
    pub as_of_ms: u64,
}

/// Build the profile. Fails only when the identity itself does not validate;
/// every other defect in the inputs is recorded in an `excluded_*` partition.
pub fn build_profile(inputs: &ProfileInputs<'_>) -> Result<AgentProfile, ProfileError> {
    let identity = match inputs.identity {
        IdentityInput::Document { document, parent } => {
            AgentIdentity::from_document(document, parent)
        }
        IdentityInput::Summary(s) => AgentIdentity::from_summary(s),
    }
    .map_err(ProfileError::Identity)?;
    let agent_id = identity.id().to_string();
    let agent_key = identity.public_key().key_bytes.clone();

    let self_declared = inputs
        .self_declared
        .iter()
        .map(|t| SelfDeclared {
            label: SELF_DECLARED_LABEL,
            text: t.clone(),
        })
        .collect();

    let authority = project_authority(
        &agent_id,
        inputs.authority,
        inputs.issuer_keys,
        inputs.as_of_ms,
    );
    let issuers = authority.issuers();

    let mut instances = Vec::new();
    let mut excluded_expectations = Vec::new();
    let mut decisions: HashSet<[u8; 16]> = HashSet::new();
    for ee in inputs.expectations {
        if let Err(e) =
            verify_expected_execution_for_agent(ee, inputs.decision_point_anchors, &agent_key)
        {
            excluded_expectations.push(ExcludedExpectation {
                decision_id: ee.decision_id,
                reason: ExpectationExclusion::Unverified(format!("{e:?}")),
            });
            continue;
        }
        if ee.agent_id != agent_id || !identity.names_binding(&ee.execution_binding) {
            excluded_expectations.push(ExcludedExpectation {
                decision_id: ee.decision_id,
                reason: ExpectationExclusion::AgentMismatch {
                    agent_id: ee.agent_id.clone(),
                },
            });
            continue;
        }
        decisions.insert(ee.decision_id);
        instances.push(ExecutionInstance {
            binding: ee.execution_binding.clone(),
            assertion: InstanceAssertion::AuthorizedTarget {
                decision_id: ee.decision_id,
                decision_point_id: ee.decision_point_id.clone(),
            },
        });
    }

    let mut excluded_bindings = Vec::new();
    for b in inputs.claimed_bindings {
        if identity.names_binding(b) {
            instances.push(ExecutionInstance {
                binding: b.clone(),
                assertion: InstanceAssertion::Claimed,
            });
        } else {
            excluded_bindings.push(b.clone());
        }
    }

    let mut reconciled = Vec::new();
    let mut excluded_reconciliations = Vec::new();
    for (i, r) in inputs.reconciliations.iter().enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        match r.decision_id {
            None => excluded_reconciliations.push(ExcludedReconciliation {
                index,
                reason: ReconciliationExclusion::NoDecisionId,
            }),
            Some(d) if !decisions.contains(d.as_bytes()) => {
                excluded_reconciliations.push(ExcludedReconciliation {
                    index,
                    reason: ReconciliationExclusion::DecisionNotForAgent {
                        decision_id: *d.as_bytes(),
                    },
                })
            }
            Some(_) => reconciled.push(ReconciledRecord {
                record: r.clone(),
                source: RecordSource::VerifierLocal,
            }),
        }
    }

    Ok(AgentProfile {
        identity,
        self_declared,
        issuers,
        authority,
        instances,
        excluded_expectations,
        excluded_bindings,
        reconciled,
        excluded_reconciliations,
        lineage: LineageSection::NotEvaluated,
        experience: ExperienceSection::NotDerived,
        as_of_ms: inputs.as_of_ms,
    })
}
