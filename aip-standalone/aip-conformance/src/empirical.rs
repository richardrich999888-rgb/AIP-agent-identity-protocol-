//! The executed half of the threat model.
//!
//! [`crate::threat`] *declares* what each layer does about each threat. This
//! module is the vocabulary for *observing* what each layer actually did when
//! the attack was staged and run against it, and for failing when the two
//! disagree.
//!
//! # Why a separate vocabulary
//!
//! A declared disposition and an observed one must not share a type at the
//! point of measurement, or the executor could simply echo the declaration.
//! An attack produces an [`Outcome`] — a statement about what happened — and
//! [`Outcome::corroborates`] maps it to the one [`Disposition`] it supports.
//! The comparison against the declared model is then a real check rather than
//! an assignment.
//!
//! # Where the attacks are
//!
//! Not here. `tests/no_second_architecture.rs` forbids this crate's library
//! from referencing a key, a signer or an identity constructor, and staging a
//! real attack needs all three. That guard is correct — a conformance library
//! that could sign could manufacture the evidence it reports on — so the
//! staging lives in `tests/staging/` and the attacks in `tests/empirical.rs`.
//! This module holds no key, signs nothing, mints nothing, and decides no
//! security question.
//!
//! # `NotStageable` is not a pass
//!
//! An attack that could not be staged here corroborates nothing. It is
//! recorded, counted separately, and never allowed to stand in for agreement.
//! That is the same rule the reconciler applies to missing evidence, applied
//! to the thing that grades the reconciler.

use crate::threat::{Disposition, Layer, Threat, ThreatModel};
use serde::Serialize;

/// What executing a staged attack against one layer actually produced.
///
/// Five variants; four of them corroborate exactly one [`Disposition`] and the
/// fifth corroborates nothing. The mapping is total and fixed, so classifying
/// an execution involves no judgement at the point of classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Outcome {
    /// The adversarial value has no representation: every attempt to construct
    /// the thing the attacker needed produced something else. Corroborates
    /// [`Disposition::Prevented`], which is about unrepresentability rather
    /// than runtime refusal.
    Unrepresentable { evidence: String },
    /// The layer took the input and named a fault, a refusal or a verdict
    /// about it. Corroborates [`Disposition::Detected`].
    Rejected { evidence: String },
    /// The layer declined to settle the question — `CANNOT_PROVE`, or a
    /// ceiling below what the attack needed to reach.
    /// Corroborates [`Disposition::Uncertainty`].
    Declined { evidence: String },
    /// The layer processed the attack and produced no adverse signal. This is
    /// the negative control, and it is what a `NotDetectable` cell must
    /// produce for its claim to be worth anything.
    /// Corroborates [`Disposition::NotDetectable`].
    Unnoticed { evidence: String },
    /// The attack could not be staged in this environment. Corroborates
    /// **nothing** and is never promoted.
    NotStageable { reason: String },
}

impl Outcome {
    /// The single disposition this outcome supports, or `None` when it
    /// supports none.
    pub fn corroborates(&self) -> Option<Disposition> {
        match self {
            Self::Unrepresentable { .. } => Some(Disposition::Prevented),
            Self::Rejected { .. } => Some(Disposition::Detected),
            Self::Declined { .. } => Some(Disposition::Uncertainty),
            Self::Unnoticed { .. } => Some(Disposition::NotDetectable),
            Self::NotStageable { .. } => None,
        }
    }

    /// Whether this outcome came from running something.
    pub fn was_executed(&self) -> bool {
        !matches!(self, Self::NotStageable { .. })
    }

    /// The observation, in stable terms. Never a key, a digest, an id or a
    /// clock reading — the log has to be byte-identical across runs.
    pub fn detail(&self) -> &str {
        match self {
            Self::Unrepresentable { evidence }
            | Self::Rejected { evidence }
            | Self::Declined { evidence }
            | Self::Unnoticed { evidence } => evidence,
            Self::NotStageable { reason } => reason,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unrepresentable { .. } => "UNREPRESENTABLE",
            Self::Rejected { .. } => "REJECTED",
            Self::Declined { .. } => "DECLINED",
            Self::Unnoticed { .. } => "UNNOTICED",
            Self::NotStageable { .. } => "NOT-STAGEABLE",
        }
    }
}

/// One (threat, layer) cell, declared and observed side by side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutedCell {
    pub threat: Threat,
    pub threat_id: &'static str,
    pub layer: Layer,
    /// What `src/threat.rs` says this layer does about this threat.
    pub declared: Disposition,
    /// What the disposition would be, judged only from what happened.
    /// `None` when the attack was not stageable here.
    pub observed: Option<Disposition>,
    pub outcome: Outcome,
}

impl ExecutedCell {
    /// True when the cell was executed and the observation contradicts the
    /// declaration. The whole point of the module.
    pub fn disagrees(&self) -> bool {
        match self.observed {
            Some(o) => o != self.declared,
            None => false,
        }
    }
}

/// Counts a reader needs before believing any of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Coverage {
    pub cells: usize,
    pub executed: usize,
    pub not_stageable: usize,
    pub agreements: usize,
    pub disagreements: usize,
    /// Of `not_stageable`, those declaring a defence.
    pub unverified_defences: usize,
}

/// The record of one full execution of the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionLog {
    pub schema_version: u16,
    pub cells: Vec<ExecutedCell>,
}

impl ExecutionLog {
    /// An empty log over the declared model. Every cell starts unrecorded;
    /// [`Self::missing`] names the ones still unrecorded at the end, so a
    /// forgotten cell is a failure rather than an absence.
    pub fn new() -> Self {
        Self {
            schema_version: crate::CONFORMANCE_SCHEMA_VERSION,
            cells: Vec::new(),
        }
    }

    /// Record one observation. The declared disposition is read from the
    /// model, never supplied by the caller — an executor that could state the
    /// declaration would be grading its own answer.
    ///
    /// # Panics
    /// If the same cell is recorded twice, or if `(threat, layer)` is not in
    /// the declared model. Both are harness defects, not findings.
    pub fn record(&mut self, threat: Threat, layer: Layer, outcome: Outcome) {
        assert!(
            !self
                .cells
                .iter()
                .any(|c| c.threat == threat && c.layer == layer),
            "{}/{} recorded twice",
            threat.id(),
            layer.as_str()
        );
        let model = ThreatModel::build();
        let declared = model
            .get(threat, layer)
            .unwrap_or_else(|| panic!("{}/{} is not in the model", threat.id(), layer.as_str()))
            .disposition;
        self.cells.push(ExecutedCell {
            threat,
            threat_id: threat.id(),
            layer,
            declared,
            observed: outcome.corroborates(),
            outcome,
        });
    }

    /// Cells in the declared model with no observation recorded.
    pub fn missing(&self) -> Vec<(Threat, Layer)> {
        let mut out = Vec::new();
        for t in Threat::ALL {
            for l in Layer::ALL {
                if !self.cells.iter().any(|c| c.threat == t && c.layer == l) {
                    out.push((t, l));
                }
            }
        }
        out
    }

    /// Executed cells whose observation contradicts the declaration.
    pub fn disagreements(&self) -> Vec<&ExecutedCell> {
        self.cells.iter().filter(|c| c.disagrees()).collect()
    }

    /// Cells that could not be staged here, with their reasons.
    pub fn not_stageable(&self) -> Vec<&ExecutedCell> {
        self.cells
            .iter()
            .filter(|c| !c.outcome.was_executed())
            .collect()
    }

    /// Cells declaring a **defence** — `Prevented` or `Detected` — that the
    /// run could not stage. The number a skeptical reader should look at
    /// first: a claimed defence nobody could execute is a claim, not a
    /// control.
    pub fn unverified_defences(&self) -> Vec<&ExecutedCell> {
        self.cells
            .iter()
            .filter(|c| !c.outcome.was_executed() && c.declared.is_a_defence())
            .collect()
    }

    pub fn coverage(&self) -> Coverage {
        let executed = self
            .cells
            .iter()
            .filter(|c| c.outcome.was_executed())
            .count();
        let disagreements = self.disagreements().len();
        Coverage {
            cells: self.cells.len(),
            executed,
            not_stageable: self.cells.len() - executed,
            agreements: executed - disagreements,
            disagreements,
            unverified_defences: self.unverified_defences().len(),
        }
    }

    /// Executed cells for one threat.
    pub fn executed_for(&self, t: Threat) -> Vec<&ExecutedCell> {
        self.cells
            .iter()
            .filter(|c| c.threat == t && c.outcome.was_executed())
            .collect()
    }

    /// Cells sorted into the model's own order, so the artifact is stable
    /// regardless of the order the attacks ran in.
    pub fn sorted(&self) -> Self {
        let mut cells = self.cells.clone();
        cells.sort_by_key(|c| (c.threat, c.layer));
        Self {
            schema_version: self.schema_version,
            cells,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.sorted()).expect("execution log is plain data")
    }

    pub fn to_csv(&self) -> String {
        let mut out =
            String::from("threat_id,threat,layer,declared,observed,outcome,agrees,detail\n");
        for c in self.sorted().cells {
            let observed = match c.observed {
                Some(d) => d.as_str(),
                None => "NOT-OBSERVED",
            };
            let agrees = match c.observed {
                Some(_) => {
                    if c.disagrees() {
                        "no"
                    } else {
                        "yes"
                    }
                }
                None => "n/a",
            };
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                c.threat_id,
                crate::matrix::csv_field(&format!("{:?}", c.threat)),
                c.layer.as_str(),
                c.declared.as_str(),
                observed,
                c.outcome.as_str(),
                agrees,
                crate::matrix::csv_field(c.outcome.detail()),
            ));
        }
        out
    }
}

impl Default for ExecutionLog {
    fn default() -> Self {
        Self::new()
    }
}
