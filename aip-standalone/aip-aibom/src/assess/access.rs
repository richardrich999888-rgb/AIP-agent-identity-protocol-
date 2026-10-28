//! C6 — data access, against the signed access ledger.
//!
//! `aip_ledger::AccessLedger` is the evidence attachment `aip-ledger` itself
//! describes: built from attested observation batches resolved against the
//! institution's signed resource registry, with reconciliation verdicts cited
//! verbatim, signed by a ledger signer and verified here under the assessor's
//! anchors. The manifest is the institution's declaration; the ledger is what
//! the agent was observed reaching. This module compares the two and restates
//! nothing.
//!
//! # What a ledger can and cannot back
//!
//! It backs *the agent reaches resource R*. It says nothing about whether the
//! access is read or write — that remains the author's word. And a resource
//! the ledger does not show is `SelfReported`, never contradicted: the
//! agent may simply not have reached it inside the ledger's window.

use super::{Inputs, Sheet};
use crate::finding::FindingKind;
use crate::model::Component;
use crate::standing::{combine, Standing, Verifier};
use aip_ledger::{AccessLedger, ResourceRef, Standing as RowStanding};
use std::collections::{BTreeMap, BTreeSet};

/// What one verified ledger showed, keyed by the registry's resource id.
#[derive(Default)]
struct Reached {
    named: BTreeSet<String>,
    adverse: BTreeSet<String>,
    unregistered: usize,
}

/// The registry's name for an entry, as the ledger recorded it.
fn name_of(r: &ResourceRef) -> Option<&str> {
    match r {
        ResourceRef::Named { id, .. } => Some(id),
        ResourceRef::Unregistered => None,
    }
}

/// Resource names a *failed* ledger claimed — unauthenticated, used only to
/// decide which declared field the rejected evidence had been offered for.
fn claimed(l: &AccessLedger) -> BTreeSet<String> {
    l.entries
        .iter()
        .filter_map(|e| name_of(&e.resource).map(str::to_string))
        .collect()
}

pub(super) fn run(i: &Inputs<'_>, sheet: &mut Sheet) {
    let agent = i.manifest.agent.id.as_str();
    let mut reached = Reached::default();
    let mut rejected: BTreeMap<String, String> = BTreeMap::new();
    let mut foreign = 0usize;

    for (k, ledger) in i.bundle.access_ledgers.iter().enumerate() {
        if ledger.agent_id != agent {
            foreign += 1;
            continue;
        }
        if let Err(e) = ledger.verify(&i.context.ledger_signers) {
            let reason = format!("AccessLedger::verify refused the ledger: {e:?}");
            sheet.finding(
                Component::DataAccess,
                format!("bundle.access_ledgers[{k}]"),
                FindingKind::EvidenceRejected {
                    reason: reason.clone(),
                },
            );
            for name in claimed(ledger) {
                rejected.entry(name).or_insert_with(|| reason.clone());
            }
            continue;
        }
        for entry in &ledger.entries {
            match name_of(&entry.resource) {
                Some(name) => {
                    reached.named.insert(name.to_string());
                    if entry.standing == RowStanding::Adverse {
                        reached.adverse.insert(name.to_string());
                    }
                }
                None => {
                    reached.unregistered += 1;
                    if entry.standing == RowStanding::Adverse {
                        reached.adverse.insert("an unregistered endpoint".into());
                    }
                }
            }
        }
    }

    let declared: BTreeSet<&str> = i
        .manifest
        .data_access
        .iter()
        .map(|d| d.resource.as_str())
        .collect();
    for (k, d) in i.manifest.data_access.iter().enumerate() {
        let mut candidates = Vec::new();
        if let Some(reason) = rejected.get(&d.resource) {
            candidates.push(Standing::EvidenceRejected {
                reason: reason.clone(),
            });
        }
        if reached.named.contains(&d.resource) {
            candidates.push(Standing::Verified {
                verifier: Verifier::AccessLedger,
            });
        }
        sheet.field(
            Component::DataAccess,
            format!("$.data_access[{k}]"),
            combine(candidates),
        );
        sheet.field(
            Component::DataAccess,
            format!("$.data_access[{k}].access"),
            Standing::SelfReported,
        );
    }

    for name in reached
        .named
        .iter()
        .filter(|n| !declared.contains(n.as_str()))
    {
        sheet.finding(
            Component::DataAccess,
            "$.data_access",
            FindingKind::UndeclaredResourceReached {
                resource: name.clone(),
            },
        );
    }
    for resource in reached.adverse {
        sheet.finding(
            Component::DataAccess,
            "bundle.access_ledgers",
            FindingKind::AdverseAccess { resource },
        );
    }
    if reached.unregistered > 0 {
        sheet.finding(
            Component::DataAccess,
            "bundle.access_ledgers",
            FindingKind::UnregisteredEndpointReached {
                count: reached.unregistered,
            },
        );
    }
    if foreign > 0 {
        sheet.finding(
            Component::DataAccess,
            "bundle.access_ledgers",
            FindingKind::ForeignEvidence { count: foreign },
        );
    }
}
