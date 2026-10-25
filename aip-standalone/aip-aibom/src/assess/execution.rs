//! C7 — execution environment.
//!
//! Two kinds of evidence bear on the agent's binary, and they say different
//! things:
//!
//! - a **decision point** authorised an execution of this content
//!   (`verify_expected_execution`) → `Verified`;
//! - **NEXORA** accepted a proof whose re-derived identity comparison matched
//!   (`verify_nexora_proof`) → `Observed`, at NEXORA's verdict and strength.
//!
//! The assessor never calls the reconciler. It reads `VerifiedProof`.

use super::{Inputs, Sheet};
use crate::finding::FindingKind;
use crate::model::Component;
use crate::standing::{combine, Standing, Verifier};
use aip_nexora::verify_nexora_proof;
use aip_reconcile::IdentityComparison;

const BINARY_PATH: &str = "$.environment.binary.exe_sha256";

pub(super) fn run(i: &Inputs<'_>, sheet: &mut Sheet) {
    let agent = i.manifest.agent.id.as_str();
    let declared = i
        .manifest
        .environment
        .binary
        .as_ref()
        .map(|b| b.exe_sha256.as_str());
    let mut candidates = Vec::new();
    let mut evidenced_binary = false;
    let mut foreign = 0usize;

    for (k, ee) in i.bundle.expectations.iter().enumerate() {
        if ee.agent_id != agent {
            foreign += 1;
            continue;
        }
        match aip_authorize::verify_expected_execution(ee, &i.context.decision_points) {
            Err(e) => {
                let reason = format!("verify_expected_execution refused the expectation: {e:?}");
                sheet.finding(
                    Component::Environment,
                    format!("bundle.expectations[{k}]"),
                    FindingKind::EvidenceRejected {
                        reason: reason.clone(),
                    },
                );
                candidates.push(Standing::EvidenceRejected { reason });
            }
            Ok(()) => {
                evidenced_binary = true;
                let authorised = hex::encode(ee.execution_binding.exe_content_sha256);
                candidates.push(match declared {
                    Some(d) if d == authorised => Standing::Verified {
                        verifier: Verifier::DecisionPoint,
                    },
                    Some(_) => Standing::Contradicted {
                        reason: "a trusted decision point authorised a different executable".into(),
                    },
                    None => continue,
                });
            }
        }
    }

    proofs(
        i,
        declared,
        &mut candidates,
        &mut evidenced_binary,
        &mut foreign,
        sheet,
    );

    if foreign > 0 {
        sheet.finding(
            Component::Environment,
            "bundle",
            FindingKind::ForeignEvidence { count: foreign },
        );
    }
    match declared {
        Some(_) => sheet.field(Component::Environment, BINARY_PATH, combine(candidates)),
        None if evidenced_binary => sheet.finding(
            Component::Environment,
            "$.environment",
            FindingKind::UndeclaredBinary,
        ),
        None => {}
    }
    sheet.field(
        Component::Environment,
        "$.environment.runtime",
        Standing::SelfReported,
    );
    sheet.field(
        Component::Environment,
        "$.environment.network",
        Standing::SelfReported,
    );
}

fn proofs(
    i: &Inputs<'_>,
    declared: Option<&str>,
    candidates: &mut Vec<Standing>,
    evidenced_binary: &mut bool,
    foreign: &mut usize,
    sheet: &mut Sheet,
) {
    let agent = i.manifest.agent.id.as_str();
    let mine: Vec<(usize, &aip_nexora::NexoraProof)> = i
        .bundle
        .proofs
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            let ours = p.subject.agent_id == agent;
            if !ours {
                *foreign += 1;
            }
            ours
        })
        .collect();
    let Some(anchors) = i.context.nexora.as_ref() else {
        if !mine.is_empty() {
            sheet.finding(
                Component::Environment,
                "bundle.proofs",
                FindingKind::ProofsNotEvaluated { count: mine.len() },
            );
        }
        return;
    };
    for (k, p) in mine {
        let v = verify_nexora_proof(p, anchors);
        if !v.is_valid() {
            let reason = format!("NEXORA refused the proof: {:?}", v.verdict);
            sheet.finding(
                Component::Environment,
                format!("bundle.proofs[{k}]"),
                FindingKind::EvidenceRejected {
                    reason: reason.clone(),
                },
            );
            candidates.push(Standing::EvidenceRejected { reason });
            continue;
        }
        let (Some(rec), Some(ee)) = (v.rederived.as_ref(), p.expectation.as_ref()) else {
            continue;
        };
        let observed = hex::encode(ee.execution_binding.exe_content_sha256);
        let standing = match (&rec.identity, v.result, v.strength) {
            (IdentityComparison::Divergent { .. }, _, _) => Standing::Contradicted {
                reason: "NEXORA re-derived an identity divergence: the measured executable is not the authorised one".into(),
            },
            (IdentityComparison::Match { .. }, Some(verdict), Some(strength)) => {
                *evidenced_binary = true;
                match declared {
                    Some(d) if d == observed => Standing::Observed { verdict, strength },
                    Some(_) => Standing::Contradicted {
                        reason: "NEXORA observed the agent running an executable other than the one declared".into(),
                    },
                    None => continue,
                }
            }
            _ => continue,
        };
        candidates.push(standing);
    }
}
