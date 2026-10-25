//! C5 — human approval gates, against the approval tier.
//!
//! An approval artifact records what an approval surface showed a human for
//! one decision, signed by the surface. `aip_approval::verify_artifact`
//! verifies it under the assessor's surface anchors; then
//! `compare_shown_to_authorized` compares it, arithmetically, with the
//! decision point's signed expectation. Both are the approval tier's
//! verifiers; this module calls them and restates neither.
//!
//! # What that can and cannot establish about a declared gate
//!
//! It can show that approvals *happen* for this agent's decisions, and —
//! decisively — whether the human was shown what was sealed. A divergence is
//! signature arithmetic and is reported as critical.
//!
//! It cannot show that *every* action above a threshold was approved: an
//! expectation carries a parameter digest, not an amount. So a gate's standing
//! stays `SelfReported` however many approvals agree, and the report says how
//! many did.

use super::{Inputs, Sheet};
use crate::assess::authority_label;
use crate::finding::FindingKind;
use crate::model::Component;
use crate::standing::Standing;
use aip_approval::{compare_shown_to_authorized, verify_artifact, Divergence, ShownVsAuthorized};
use aip_types::ScopeAction;

fn divergence_label(d: &Divergence) -> &'static str {
    match d {
        Divergence::ParametersDiffer { .. } => "the parameters shown differ from those sealed",
        Divergence::ActionDiffers { .. } => "the action shown differs from the action sealed",
        Divergence::ExpectationDiffers { .. } => "the artifact approves a different expectation",
    }
}

pub(super) fn run(i: &Inputs<'_>, sheet: &mut Sheet) {
    let agent = i.manifest.agent.id.as_str();
    let mut agreed: Vec<ScopeAction> = Vec::new();

    for (k, signed) in i.bundle.approvals.iter().enumerate() {
        let path = format!("bundle.approvals[{k}]");
        let Some(ee) = i
            .bundle
            .expectations
            .iter()
            .find(|e| e.decision_id == signed.artifact.decision_id)
        else {
            sheet.finding(
                Component::Permissions,
                path,
                FindingKind::ApprovalNotEvaluated {
                    reason: "no expectation for its decision was offered".into(),
                },
            );
            continue;
        };
        if ee.agent_id != agent {
            continue;
        }
        let verified = match verify_artifact(
            signed,
            &i.context.approval_surfaces,
            i.context.agent_public_key.as_deref(),
        ) {
            Ok(v) => v,
            Err(e) => {
                sheet.finding(
                    Component::Permissions,
                    path,
                    FindingKind::EvidenceRejected {
                        reason: format!("verify_artifact refused the approval: {e:?}"),
                    },
                );
                continue;
            }
        };
        match compare_shown_to_authorized(Some(&verified), ee, &i.context.decision_points) {
            ShownVsAuthorized::Agrees { .. } => agreed.push(ee.action_kind.clone()),
            ShownVsAuthorized::Diverges { divergence, .. } => sheet.finding(
                Component::Permissions,
                path,
                FindingKind::ApprovalDiverged {
                    divergence: divergence_label(&divergence).into(),
                },
            ),
            ShownVsAuthorized::NotEvaluated { reason } => sheet.finding(
                Component::Permissions,
                path,
                FindingKind::ApprovalNotEvaluated {
                    reason: format!("{reason:?}"),
                },
            ),
        }
    }

    for (k, gate) in i.manifest.permissions.approval_gates.iter().enumerate() {
        let path = format!("$.permissions.approval_gates[{k}]");
        let label = authority_label(&gate.action);
        let approvals = agreed
            .iter()
            .filter(|a| authority_label(a) == label)
            .count();
        let kind = if approvals > 0 {
            FindingKind::ApprovalGateNotEnforceable { approvals }
        } else {
            FindingKind::ApprovalGateNotEvidenced
        };
        sheet.finding(Component::Permissions, path.clone(), kind);
        sheet.field(Component::Permissions, path, Standing::SelfReported);
    }
}
