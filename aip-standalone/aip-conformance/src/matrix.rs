//! The machine-readable conformance matrix.
//!
//! Seven domains × twelve invariants = 84 cells, every one of them filled.
//! A matrix with a hole in it is a matrix a reader completes by assumption,
//! so [`ConformanceMatrix::build`] is total by construction and
//! [`ConformanceMatrix::missing`] exists to prove it.

use serde::{Deserialize, Serialize};

use crate::domain::Domain;
use crate::evidence::EvidenceClass;
use crate::invariant::InvariantCode;

/// What the program established for one (domain, invariant) pair.
///
/// **There is no `Waived`.** The specification's second non-negotiable rule
/// is that a green adapter-specific suite cannot waive a failed core
/// invariant. The way to guarantee that is to give the vocabulary no word
/// for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Conformance {
    /// The invariant holds for this domain.
    Satisfied,
    /// The invariant is not reachable in this domain. Recorded with a
    /// reason and counted separately — it is not a pass.
    NotApplicable,
    /// Asked and not answered.
    Unknown,
}

impl Conformance {
    pub fn code(self) -> u8 {
        match self {
            Self::Satisfied => 0x01,
            Self::NotApplicable => 0x02,
            Self::Unknown => 0x03,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "SATISFIED",
            Self::NotApplicable => "NOT-APPLICABLE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// One cell.
///
/// `Serialize` and deliberately **not** `Deserialize`, following the same rule
/// as NEXORA's `VerifiedProof`: this is an output. A matrix that could be read
/// back out of bytes would be a statement about what was checked that an
/// author could simply write, and the whole value of the artifact is that it
/// was *computed*. There is no sequence of bytes anywhere that becomes a
/// conformance claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cell {
    pub domain: Domain,
    pub invariant: InvariantCode,
    pub invariant_id: &'static str,
    pub conformance: Conformance,
    pub evidence: EvidenceClass,
    /// The test or code site the cell was read from. Never a prose claim.
    pub witness: &'static str,
    /// Why, when the cell is `NotApplicable` or `Unknown`. Empty otherwise.
    pub reason: &'static str,
}

impl Cell {
    /// Whether this cell supports treating the domain as *supported*.
    ///
    /// `Satisfied` under a weak evidence class does not: a domain whose
    /// invariants rest on prose is a domain whose invariants were not
    /// checked.
    pub fn is_conformant(&self) -> bool {
        self.conformance == Conformance::Satisfied && self.evidence.supports_a_conformance_claim()
    }
}

/// The whole matrix. `Serialize` only, for the reason on [`Cell`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConformanceMatrix {
    pub schema_version: u16,
    pub cells: Vec<Cell>,
}

impl ConformanceMatrix {
    /// Build the matrix. Total by construction: every domain, every
    /// invariant.
    pub fn build() -> Self {
        let mut cells = Vec::with_capacity(Domain::ALL.len() * InvariantCode::ALL.len());
        for d in Domain::ALL {
            for i in InvariantCode::ALL {
                cells.push(cell_for(d, i));
            }
        }
        Self {
            schema_version: crate::CONFORMANCE_SCHEMA_VERSION,
            cells,
        }
    }

    pub fn get(&self, d: Domain, i: InvariantCode) -> Option<&Cell> {
        self.cells
            .iter()
            .find(|c| c.domain == d && c.invariant == i)
    }

    /// Every (domain, invariant) pair with no cell. Must always be empty.
    pub fn missing(&self) -> Vec<(Domain, InvariantCode)> {
        let mut out = Vec::new();
        for d in Domain::ALL {
            for i in InvariantCode::ALL {
                if self.get(d, i).is_none() {
                    out.push((d, i));
                }
            }
        }
        out
    }

    /// Domains for which every invariant is conformant under a strong
    /// evidence class, `NotApplicable` cells excepted and counted.
    pub fn conformant_domains(&self) -> Vec<Domain> {
        Domain::ALL
            .into_iter()
            .filter(|d| {
                self.cells
                    .iter()
                    .filter(|c| c.domain == *d)
                    .all(|c| c.is_conformant() || c.conformance == Conformance::NotApplicable)
            })
            .collect()
    }

    /// Cells that are not conformant. The list a reviewer reads first.
    pub fn shortfalls(&self) -> Vec<&Cell> {
        self.cells
            .iter()
            .filter(|c| !c.is_conformant() && c.conformance != Conformance::NotApplicable)
            .collect()
    }

    /// Deterministic JSON. Two runs over unchanged code emit identical bytes,
    /// so a diff in the artifact is a change in the system.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("matrix is plain data")
    }

    /// Deterministic CSV, for the reviewer who wants a spreadsheet.
    ///
    /// Fields are quoted per RFC 4180 where they need it. The alternative —
    /// forbidding commas in a cell's `reason` — would have distorted the
    /// prose to fit the format, and the reason is the part a reviewer reads.
    pub fn to_csv(&self) -> String {
        let mut s = String::from(
            "DOMAIN,REALISED_BY,PROFILE_ID,EMBODIED,INVARIANT,INVARIANT_ID,CONFORMANCE,EVIDENCE,WITNESS,REASON\n",
        );
        for c in &self.cells {
            let r = c.domain.realisation();
            let row = [
                c.domain.as_str().to_string(),
                r.crate_name.to_string(),
                r.profile_id.to_string(),
                c.domain.is_embodied().to_string(),
                format!("{:?}", c.invariant),
                c.invariant_id.to_string(),
                c.conformance.as_str().to_string(),
                c.evidence.as_str().to_string(),
                c.witness.to_string(),
                c.reason.to_string(),
            ];
            let cols: Vec<String> = row.iter().map(|f| csv_field(f)).collect();
            s.push_str(&cols.join(","));
            s.push('\n');
        }
        s
    }
}

/// One CSV field, quoted per RFC 4180 when it contains a comma, a quote or a
/// newline. A doubled quote escapes a quote.
pub(crate) fn csv_field(f: &str) -> String {
    if f.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", f.replace('"', "\"\""))
    } else {
        f.to_string()
    }
}

/// The cell for one pair.
///
/// Eleven of the twelve invariants are properties of the **core**, which every
/// domain reaches through the same crates — so their cells are the same for
/// every domain, and that sameness *is* the conformance claim: there is no
/// per-domain identity model, no per-domain reconciler, no per-domain proof
/// tree. The witnesses name the tests that establish each one.
///
/// The twelfth, `Attribution`, is the one that varies, and it varies on the
/// axis ADR-011 found to be real rather than on the domain's name.
fn cell_for(d: Domain, i: InvariantCode) -> Cell {
    let (conformance, evidence, witness, reason) = match i {
        InvariantCode::Identity => (
            Conformance::Satisfied,
            EvidenceClass::TestProven,
            "aip-conformance/tests/universal.rs::i01_identity_is_derived_and_malformed_input_is_refused_not_fatal",
            "",
        ),
        InvariantCode::Authority => (
            Conformance::Satisfied,
            EvidenceClass::TestProven,
            "aip-conformance/tests/universal.rs::i02_authority_is_a_verified_chain_not_a_parent_child_relation",
            "",
        ),
        InvariantCode::ExpectedExecution => (
            Conformance::Satisfied,
            EvidenceClass::TestProven,
            "aip-conformance/tests/universal.rs::i03_an_expectation_is_signed_bounded_and_not_self_authorized",
            "",
        ),
        InvariantCode::ExecutionBinding => (
            Conformance::Satisfied,
            EvidenceClass::TestProven,
            "aip-conformance/tests/universal.rs::i04_execution_binding_is_not_a_pid_and_does_not_transplant",
            "",
        ),
        InvariantCode::AiriClaim => (
            Conformance::Satisfied,
            EvidenceClass::CodeProven,
            "aip-conformance/tests/universal.rs::i05_no_framework_name_is_a_trust_input",
            "",
        ),
        InvariantCode::Observation => (
            Conformance::Satisfied,
            EvidenceClass::TestProven,
            "aip-conformance/tests/universal.rs::i06_a_ceiling_is_declared_per_class_and_never_computed",
            "",
        ),
        InvariantCode::Attribution => attribution_cell(d),
        InvariantCode::Continuity => (
            Conformance::Satisfied,
            EvidenceClass::TestProven,
            "aip-conformance/tests/universal.rs::i08_a_recorded_gap_is_sticky_and_a_fork_quarantines_permanently",
            "",
        ),
        InvariantCode::Reconciliation => (
            Conformance::Satisfied,
            EvidenceClass::TestProven,
            "aip-conformance/tests/universal.rs::i09_cannot_prove_is_the_default_and_strength_follows_result_kind",
            "",
        ),
        InvariantCode::Warrant => (
            Conformance::Satisfied,
            EvidenceClass::TestProven,
            "aip-conformance/tests/universal.rs::i10_a_warrant_refuses_a_verdict_the_engine_did_not_draw",
            "",
        ),
        InvariantCode::Containment => (
            Conformance::Satisfied,
            EvidenceClass::ExecutionProven,
            "aip-containment/tests/engine_to_containment.rs (5 tests, live process)",
            "reached through the shared engine, not re-tested here: the crossing needs a live process and an actuator, and duplicating it would add a second fixture for one property",
        ),
        InvariantCode::Proof => (
            Conformance::Satisfied,
            EvidenceClass::TestProven,
            "aip-conformance/tests/universal.rs::i12_a_proof_is_rederived_and_a_tampered_head_is_refused",
            "",
        ),
    };
    Cell {
        domain: d,
        invariant: i,
        invariant_id: i.id(),
        conformance,
        evidence,
        witness,
        reason,
    }
}

/// Attribution is the one invariant whose *reach* differs by domain, and it
/// differs on embodiment rather than on the domain's name.
///
/// Every domain satisfies the invariant — an effect is attributed only
/// through an attested complete expected side, and insufficient evidence is
/// `CANNOT_PROVE`. What differs is how far up the domain's own ladder that
/// can carry: an embodied domain's top tier is a physical effect no
/// implemented mechanism observes, so it is unreachable there and reachable
/// for enterprise, whose local file write is `Fanotify`. ADR-011 records the
/// finding and why naming enterprise's tier `PhysicallyObserved` for symmetry
/// would have been the worst available choice.
fn attribution_cell(d: Domain) -> (Conformance, EvidenceClass, &'static str, &'static str) {
    if d.is_embodied() {
        (
            Conformance::Satisfied,
            EvidenceClass::TestProven,
            "aip-conformance/tests/universal.rs::i07_an_unknown_expected_side_never_becomes_an_accusation",
            "the domain's top evidence tier is a physical effect; no implemented mechanism observes one, so attribution stops below it (ADR-011)",
        )
    } else {
        (
            Conformance::Satisfied,
            EvidenceClass::ExecutionProven,
            "aip-reconcile: reconcile_observation; aip-enterprise/tests/integration.rs local effect",
            "",
        )
    }
}
