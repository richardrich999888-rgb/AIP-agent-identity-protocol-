//! The assessment engine.
//!
//! [`assess`] is a pure function of a manifest, an optional seal, the
//! evidence the assessed party offered, the assessor's context, and the
//! discoveries the assessor ran. It reads no file, no clock and no network.
//!
//! Each component group has its own module, and each module reaches a
//! standing above `SelfReported` only by calling a verifier that already
//! exists in the core. None of them reconciles: execution evidence is
//! NEXORA's, and is read from `VerifiedProof` (ADR-017).

mod access;
mod approvals;
mod authority;
mod controls;
mod execution;
mod identity;
mod inventory;
mod tools;
mod validity;

pub(crate) use authority::action_label as authority_label;

use crate::canonical::manifest_digest_hex;
use crate::evidence::{AssessorContext, EvidenceBundle};
use crate::finding::{Finding, FindingKind, Priority};
use crate::model::{Component, Manifest};
use crate::ports::Discovery;
use crate::seal::{verify_seal, Seal};
use crate::standing::Standing;
use serde::Serialize;

/// One manifest field and what backs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssessedField {
    pub component: Component,
    pub path: String,
    pub standing: Standing,
}

/// Whether, and by whom, the manifest was sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "seal", rename_all = "snake_case")]
pub enum SealStanding {
    NotSealed,
    /// A publisher the assessor anchors put their name to this exact
    /// manifest. Raises no field's standing.
    Published {
        publisher_id: String,
        sealed_at_ms: u64,
    },
    Rejected {
        reason: String,
    },
}

/// Counts a reader needs before reading anything else.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub fields: usize,
    pub verified: usize,
    pub observed: usize,
    pub discovered: usize,
    pub self_reported: usize,
    pub unknowable: usize,
    pub lapsed: usize,
    pub contradicted: usize,
    pub evidence_rejected: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub info: usize,
}

/// The product's output. `Serialize` only: an assessment that could be read
/// back from bytes is one an author could write (ADR-017, decision 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assessment {
    pub schema_version: u16,
    pub manifest_sha256: String,
    pub agent_id: String,
    pub assessed_at_ms: u64,
    pub seal: SealStanding,
    pub summary: Summary,
    pub fields: Vec<AssessedField>,
    pub findings: Vec<Finding>,
}

impl Assessment {
    /// True when any finding is `Critical`.
    pub fn has_critical(&self) -> bool {
        self.summary.critical > 0
    }

    /// The standing recorded for `path`, if the manifest has that field.
    pub fn standing_of(&self, path: &str) -> Option<&Standing> {
        self.fields
            .iter()
            .find(|f| f.path == path)
            .map(|f| &f.standing)
    }
}

/// Accumulator the component modules write into.
pub(crate) struct Sheet {
    fields: Vec<AssessedField>,
    findings: Vec<Finding>,
}

impl Sheet {
    fn new() -> Self {
        Self {
            fields: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub(crate) fn field(
        &mut self,
        component: Component,
        path: impl Into<String>,
        standing: Standing,
    ) {
        self.fields.push(AssessedField {
            component,
            path: path.into(),
            standing,
        });
    }

    pub(crate) fn finding(
        &mut self,
        component: Component,
        path: impl Into<String>,
        kind: FindingKind,
    ) {
        self.findings.push(Finding::new(component, path, kind));
    }
}

/// Everything an assessment reads.
pub struct Inputs<'a> {
    pub manifest: &'a Manifest,
    pub seal: Option<&'a Seal>,
    pub bundle: &'a EvidenceBundle,
    pub context: &'a AssessorContext,
    pub discoveries: &'a [Discovery],
}

/// Assess a manifest. Deterministic: the same inputs give byte-identical
/// output.
pub fn assess(i: &Inputs<'_>) -> Assessment {
    let mut sheet = Sheet::new();
    let doc = identity::run(i, &mut sheet);
    authority::run(i, &mut sheet);
    approvals::run(i, &mut sheet);
    execution::run(i, &mut sheet);
    inventory::run(i, &mut sheet);
    tools::run(i, &mut sheet);
    access::run(i, &mut sheet);
    controls::run(i, doc, &mut sheet);
    validity::run(i, &mut sheet);
    let seal = seal_standing(i, &mut sheet);
    derive_findings(&mut sheet);

    sheet
        .fields
        .sort_by(|a, b| (a.component, &a.path).cmp(&(b.component, &b.path)));
    sheet.findings.sort_by_key(Finding::sort_key);
    sheet.findings.dedup();
    let summary = summarise(&sheet);
    Assessment {
        schema_version: crate::AIBOM_REPORT_SCHEMA_VERSION,
        manifest_sha256: manifest_digest_hex(i.manifest),
        agent_id: i.manifest.agent.id.clone(),
        assessed_at_ms: i.context.present_time_ms,
        seal,
        summary,
        fields: sheet.fields,
        findings: sheet.findings,
    }
}

fn seal_standing(i: &Inputs<'_>, sheet: &mut Sheet) -> SealStanding {
    match i.seal {
        None => {
            sheet.finding(Component::Validity, "seal", FindingKind::NotSealed);
            SealStanding::NotSealed
        }
        Some(s) => match verify_seal(s, i.manifest, &i.context.publishers) {
            Ok(()) => SealStanding::Published {
                publisher_id: s.publisher_id.clone(),
                sealed_at_ms: s.sealed_at_ms,
            },
            Err(e) => {
                let reason = format!("{e:?}");
                sheet.finding(
                    Component::Validity,
                    "seal",
                    FindingKind::SealRejected {
                        reason: reason.clone(),
                    },
                );
                SealStanding::Rejected { reason }
            }
        },
    }
}

/// Findings that follow mechanically from a field's standing. Written once,
/// here, so no component module can forget to raise one.
fn derive_findings(sheet: &mut Sheet) {
    let derived: Vec<Finding> = sheet
        .fields
        .iter()
        .filter_map(|f| {
            let kind = match &f.standing {
                Standing::EvidenceRejected { reason } => FindingKind::EvidenceRejected {
                    reason: reason.clone(),
                },
                Standing::Contradicted { reason } => FindingKind::Contradicted {
                    reason: reason.clone(),
                },
                Standing::Lapsed { .. } if f.component == Component::Validity => {
                    FindingKind::ManifestLapsed
                }
                Standing::Lapsed { .. } => FindingKind::LapsedAuthority,
                Standing::Unknowable { non_establishment } => FindingKind::Unknowable {
                    non_establishment: *non_establishment,
                },
                _ => return None,
            };
            Some(Finding::new(f.component, f.path.clone(), kind))
        })
        .collect();
    sheet.findings.extend(derived);
}

fn summarise(sheet: &Sheet) -> Summary {
    let mut s = Summary {
        fields: sheet.fields.len(),
        ..Summary::default()
    };
    for f in &sheet.fields {
        match f.standing {
            Standing::Verified { .. } => s.verified += 1,
            Standing::Observed { .. } => s.observed += 1,
            Standing::Discovered { .. } => s.discovered += 1,
            Standing::SelfReported => s.self_reported += 1,
            Standing::Unknowable { .. } => s.unknowable += 1,
            Standing::Lapsed { .. } => s.lapsed += 1,
            Standing::Contradicted { .. } => s.contradicted += 1,
            Standing::EvidenceRejected { .. } => s.evidence_rejected += 1,
        }
    }
    for f in &sheet.findings {
        match f.priority {
            Priority::Critical => s.critical += 1,
            Priority::High => s.high += 1,
            Priority::Medium => s.medium += 1,
            Priority::Info => s.info += 1,
        }
    }
    s
}
