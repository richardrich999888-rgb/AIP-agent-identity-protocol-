//! C5 — spending limits and approval thresholds, against signed spend
//! authority (ADR-018).
//!
//! Three verifiers, none of them this crate's:
//!
//! - `SignedSpendPolicy::verify`, under the assessor's policy-issuer anchors:
//!   the institution signed this per-action maximum and approval threshold
//!   for this agent. A declared limit that matches is `Verified`; one that
//!   differs is `Contradicted`.
//! - `SignedSpendAttestation::verify` and `SignedSpendRefusal::verify`, under
//!   the assessor's decision-point anchors: the decision point enforced that
//!   policy on a decision. A refusal carries the amount that was refused.
//!
//! # What this cannot establish
//!
//! A signed policy establishes what the institution authorised, not that
//! every request went through a decision point that holds it. Records show
//! enforcement for the decisions offered; completeness over a window is the
//! decision point's coverage statement, not this module. Per-day and
//! per-month limits are carried by no artifact and stay `SelfReported`.

use super::{Inputs, Sheet};
use crate::finding::FindingKind;
use crate::model::{Amount, ApprovalGate, Component, Limit, LimitPeriod};
use crate::standing::{Standing, Verifier};
use aip_authorize::expectation_digest;
use aip_spend::{PolicyCitation, SpendRule, SpendVerdict, VerifiedSpendPolicy};

/// What the spend evidence offered for this agent established.
#[derive(Default)]
pub(super) struct SpendEvidence {
    /// The highest-revision verified policy for this agent, if exactly one
    /// policy holds that revision.
    pub(super) current: Option<VerifiedSpendPolicy>,
    /// A verified decision-point record cites `current` by digest.
    pub(super) enforced: bool,
    /// Bundle index and decision id of each verified attestation marked
    /// approval-required.
    pub(super) approval_required: Vec<(usize, [u8; 16])>,
}

impl SpendEvidence {
    /// The rule `current` holds for `action`, if any.
    fn rule(&self, action: &aip_types::ScopeAction) -> Option<&SpendRule> {
        self.current.as_ref()?.rule_for(action)
    }
}

fn reject(sheet: &mut Sheet, path: String, reason: String) {
    sheet.finding(
        Component::Permissions,
        path,
        FindingKind::EvidenceRejected { reason },
    );
}

/// True when the assessor anchors `key_id` under the agent's own key: a
/// record the agent could sign is its self-report under another name.
fn anchored_to_agent(i: &Inputs<'_>, key: Option<&[u8]>) -> bool {
    matches!((key, i.context.agent_public_key.as_deref()), (Some(k), Some(a)) if k == a)
}

/// Verify every offered policy and record, and report what they establish
/// beyond the manifest: refusals, and records citing another policy.
pub(super) fn gather(i: &Inputs<'_>, sheet: &mut Sheet) -> SpendEvidence {
    let mut ev = SpendEvidence {
        current: current_policy(i, sheet),
        ..SpendEvidence::default()
    };
    let agent = i.manifest.agent.id.as_str();
    let mut foreign = 0usize;

    for (k, s) in i.bundle.spend_attestations.iter().enumerate() {
        let a = &s.attestation;
        let path = format!("bundle.spend_attestations[{k}]");
        if a.agent_id != agent {
            foreign += 1;
            continue;
        }
        if !record_verifies(
            i,
            sheet,
            &path,
            &a.decision_point_id,
            s.verify(&i.context.decision_points),
        ) {
            continue;
        }
        let bound = i
            .bundle
            .expectations
            .iter()
            .find(|e| e.decision_id == a.decision_id);
        if bound.is_some_and(|ee| expectation_digest(ee) != a.expectation_digest) {
            reject(
                sheet,
                path,
                "the attestation binds a different expectation than the one offered for its decision".into(),
            );
            continue;
        }
        cite(&mut ev, &a.policy, &path, sheet);
        if a.verdict == SpendVerdict::ApprovalRequired {
            ev.approval_required.push((k, a.decision_id));
        }
    }

    for (k, s) in i.bundle.spend_refusals.iter().enumerate() {
        let r = &s.refusal;
        let path = format!("bundle.spend_refusals[{k}]");
        if r.agent_id != agent {
            foreign += 1;
            continue;
        }
        if !record_verifies(
            i,
            sheet,
            &path,
            &r.decision_point_id,
            s.verify(&i.context.decision_points),
        ) {
            continue;
        }
        cite(&mut ev, &r.policy, &path, sheet);
        sheet.finding(
            Component::Permissions,
            path,
            FindingKind::SpendRefused {
                action: super::authority_label(&r.action),
                reason: format!("{:?}", r.reason),
                requested_minor_units: r.requested_minor_units,
                limit_minor_units: r.limit_minor_units,
                currency: r.currency.clone(),
                exponent: r.exponent,
            },
        );
    }

    if foreign > 0 {
        sheet.finding(
            Component::Permissions,
            "bundle.spend_*",
            FindingKind::ForeignEvidence { count: foreign },
        );
    }
    ev
}

/// The governing policy: the highest verified revision for this agent.
/// Two different policies at that revision is equivocation by the issuer,
/// and neither is relied on.
fn current_policy(i: &Inputs<'_>, sheet: &mut Sheet) -> Option<VerifiedSpendPolicy> {
    let agent = i.manifest.agent.id.as_str();
    let anchors = &i.context.spend_policy_anchors;
    let mut verified: Vec<VerifiedSpendPolicy> = Vec::new();
    let mut foreign = 0usize;
    for (k, s) in i.bundle.spend_policies.iter().enumerate() {
        let path = format!("bundle.spend_policies[{k}]");
        if s.policy.agent_id != agent {
            foreign += 1;
            continue;
        }
        if anchored_to_agent(i, anchors.get(&s.policy.issuer_id)) {
            reject(
                sheet,
                path,
                "the policy issuer is anchored under the agent's own key".into(),
            );
            continue;
        }
        match s.verify(anchors) {
            Ok(v) => verified.push(v),
            Err(e) => reject(
                sheet,
                path,
                format!("SignedSpendPolicy::verify refused the policy: {e:?}"),
            ),
        }
    }
    if foreign > 0 {
        sheet.finding(
            Component::Permissions,
            "bundle.spend_policies",
            FindingKind::ForeignEvidence { count: foreign },
        );
    }
    let top = verified.iter().map(|v| v.policy().revision).max()?;
    let mut at_top = verified.into_iter().filter(|v| v.policy().revision == top);
    let first = at_top.next()?;
    if at_top.any(|v| v.policy().digest() != first.policy().digest()) {
        reject(
            sheet,
            "bundle.spend_policies".into(),
            format!(
                "two different signed spend policies claim revision {top}; neither is relied on"
            ),
        );
        return None;
    }
    Some(first)
}

/// Verify a decision-point record, refusing one whose decision point the
/// assessor anchors under the agent's own key. Reports and returns false on
/// failure.
fn record_verifies(
    i: &Inputs<'_>,
    sheet: &mut Sheet,
    path: &str,
    decision_point_id: &str,
    verified: Result<(), aip_spend::RecordError>,
) -> bool {
    if anchored_to_agent(i, i.context.decision_points.get(decision_point_id)) {
        reject(
            sheet,
            path.into(),
            "the decision point is anchored under the agent's own key".into(),
        );
        return false;
    }
    match verified {
        Ok(()) => true,
        Err(e) => {
            reject(
                sheet,
                path.into(),
                format!("the spend record failed verification: {e:?}"),
            );
            false
        }
    }
}

/// Compare a record's policy citation with the governing policy.
fn cite(ev: &mut SpendEvidence, cited: &PolicyCitation, path: &str, sheet: &mut Sheet) {
    let Some(held) = ev.current.as_ref().map(VerifiedSpendPolicy::policy) else {
        return;
    };
    if cited.digest == held.digest() {
        ev.enforced = true;
    } else {
        sheet.finding(
            Component::Permissions,
            path,
            FindingKind::SpendPolicyMismatch {
                cited_revision: cited.revision,
                current_revision: held.revision,
            },
        );
    }
}

/// True when `value` in the rule's unit is exactly `declared`.
fn same_amount(value: u64, rule: &SpendRule, declared: &Amount) -> bool {
    value == declared.minor_units
        && rule.currency == declared.currency
        && rule.exponent == declared.exponent
}

fn describe(value: u64, currency: &str, exponent: u8) -> String {
    format!("{value} minor units ({currency}, exponent {exponent})")
}

/// Standing of every declared limit.
pub(super) fn limits(i: &Inputs<'_>, ev: &SpendEvidence, sheet: &mut Sheet) {
    for (k, limit) in i.manifest.permissions.limits.iter().enumerate() {
        let path = format!("$.permissions.limits[{k}]");
        let standing = match governing(ev, limit) {
            None => {
                sheet.finding(
                    Component::Permissions,
                    path.clone(),
                    FindingKind::LimitNotEnforceable,
                );
                Standing::SelfReported
            }
            Some(rule) if same_amount(rule.max_per_action, rule, &limit.max) => {
                if !ev.enforced {
                    sheet.finding(
                        Component::Permissions,
                        path.clone(),
                        FindingKind::SpendEnforcementNotEvidenced,
                    );
                }
                Standing::Verified {
                    verifier: Verifier::SpendPolicy,
                }
            }
            Some(rule) => Standing::Contradicted {
                reason: format!(
                    "the signed spend policy caps {} at {}; the manifest declares {}",
                    super::authority_label(&limit.action),
                    describe(rule.max_per_action, &rule.currency, rule.exponent),
                    describe(
                        limit.max.minor_units,
                        &limit.max.currency,
                        limit.max.exponent
                    ),
                ),
            },
        };
        sheet.field(Component::Permissions, path, standing);
    }
}

/// The rule that governs a declared limit. A policy carries per-action
/// maxima only; a per-day or per-month limit is governed by nothing.
fn governing<'e>(ev: &'e SpendEvidence, limit: &Limit) -> Option<&'e SpendRule> {
    match limit.per {
        LimitPeriod::PerAction => ev.rule(&limit.action),
        LimitPeriod::PerDay | LimitPeriod::PerMonth => None,
    }
}

/// The standing of a declared gate's threshold, when a signed rule governs
/// its action. `None` when no rule does.
pub(super) fn gate_threshold(ev: &SpendEvidence, gate: &ApprovalGate) -> Option<Standing> {
    let rule = ev.rule(&gate.action)?;
    let label = super::authority_label(&gate.action);
    let declared = describe(
        gate.above.minor_units,
        &gate.above.currency,
        gate.above.exponent,
    );
    Some(match rule.approval_above {
        Some(t) if same_amount(t, rule, &gate.above) => Standing::Verified {
            verifier: Verifier::SpendPolicy,
        },
        Some(t) => Standing::Contradicted {
            reason: format!(
                "the signed spend policy requires approval for {label} above {}; the manifest declares {declared}",
                describe(t, &rule.currency, rule.exponent)
            ),
        },
        None => Standing::Contradicted {
            reason: format!(
                "the signed spend policy requires no approval for {label}; the manifest declares one above {declared}"
            ),
        },
    })
}
