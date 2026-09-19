//! The regulatory control map (R18 of
//! `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`, matrix row F2).
//!
//! # What this is for
//!
//! An evaluator at a supervisor or an empanelled auditor does not read
//! Rust. They hold a direction — a clause of the IT Governance Directions, a
//! paragraph of the FREE-AI framework — and ask what in this system
//! addresses it and how they can check. This maps one to the other.
//!
//! # The rule that keeps it honest
//!
//! **A row may not claim a control without naming the test that exercises
//! it.** [`Coverage::Implemented`] carries a test path, and a test in this
//! crate asserts that every such path exists in the repository. Where
//! nothing exists, the row says [`Coverage::None`] and why — an explicit
//! gap, because a control map whose gaps are omitted is worse than no map:
//! it reads as complete.
//!
//! This is the same discipline as the invariant matrix next door, applied to
//! a different question. The invariant matrix asks "does the architecture
//! hold its own rules"; this asks "which of a regulator's requirements does
//! it touch, and where is the proof".
//!
//! # What it deliberately does not claim
//!
//! Nothing here is a compliance opinion. A control being implemented and
//! tested is a fact about this repository; whether it *satisfies* a
//! direction is a judgement for the regulated entity's compliance function
//! and its auditor, who know the deployment. The map gives them the inputs
//! and says nothing about the conclusion.

use serde::{Deserialize, Serialize};

/// The instruments this map indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Instrument {
    /// RBI Master Direction on Information Technology Governance, Risk,
    /// Controls and Assurance Practices.
    ItGovernance,
    /// RBI Master Direction on Outsourcing of IT Services.
    ItOutsourcing,
    /// RBI Framework for Responsible and Ethical Enablement of AI (FREE-AI).
    FreeAi,
    /// RBI draft guidance on Model Risk Management.
    ModelRiskManagement,
    /// RBI Digital Lending Directions.
    DigitalLending,
    /// CERT-In Directions on cyber-security incident reporting.
    CertIn,
    /// Digital Personal Data Protection Act and Rules.
    Dpdp,
}

impl Instrument {
    pub const ALL: [Instrument; 7] = [
        Instrument::ItGovernance,
        Instrument::ItOutsourcing,
        Instrument::FreeAi,
        Instrument::ModelRiskManagement,
        Instrument::DigitalLending,
        Instrument::CertIn,
        Instrument::Dpdp,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ItGovernance => "RBI-IT-GOVERNANCE",
            Self::ItOutsourcing => "RBI-IT-OUTSOURCING",
            Self::FreeAi => "RBI-FREE-AI",
            Self::ModelRiskManagement => "RBI-MRM-DRAFT",
            Self::DigitalLending => "RBI-DIGITAL-LENDING",
            Self::CertIn => "CERT-IN",
            Self::Dpdp => "DPDP",
        }
    }
}

/// What this repository does about a control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Coverage {
    /// Implemented, with a test that exercises it. The path is checked to
    /// exist; a row cannot claim a control by naming a file that is not
    /// there.
    Implemented { test: &'static str },
    /// Implemented as a deployment artefact rather than code — a SQL script,
    /// a workflow, a systemd unit — with the file named. Checked to exist
    /// for the same reason.
    Deployment { artefact: &'static str },
    /// The control belongs to the regulated entity, not to this system. Not
    /// a gap: a vendor that claimed a customer's control would be wrong.
    EntityResponsibility { note: &'static str },
    /// Nothing here addresses it. Stated, with what would.
    None { note: &'static str },
}

impl Coverage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Implemented { .. } => "IMPLEMENTED",
            Self::Deployment { .. } => "DEPLOYMENT-ARTEFACT",
            Self::EntityResponsibility { .. } => "ENTITY-RESPONSIBILITY",
            Self::None { .. } => "NONE",
        }
    }

    /// The repository path this row rests on, if any.
    pub fn evidence_path(&self) -> Option<&'static str> {
        match self {
            Self::Implemented { test } => Some(test),
            Self::Deployment { artefact } => Some(artefact),
            _ => None,
        }
    }
}

/// One control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlRow {
    pub instrument: Instrument,
    /// Stable identifier for this row, so an auditor can cite it.
    pub control_id: &'static str,
    /// What the instrument requires, in the instrument's own terms.
    pub requirement: &'static str,
    /// What in this system addresses it.
    pub mechanism: &'static str,
    pub coverage: Coverage,
}

/// The map.
///
/// Ordered by `(instrument, control_id)` so the emitted artefact is stable.
pub fn control_map() -> Vec<ControlRow> {
    let mut rows = vec![
        // ── IT Governance ──
        ControlRow {
            instrument: Instrument::ItGovernance,
            control_id: "ITG-AUDIT-TRAIL",
            requirement: "Maintain an audit trail of system activity sufficient to reconstruct events.",
            mechanism: "Kernel-level observation signed off-host, hash-chained and sequence-numbered; a gap in the chain is refused rather than absorbed.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-observe/tests/adversarial.rs",
            },
        },
        ControlRow {
            instrument: Instrument::ItGovernance,
            control_id: "ITG-NON-REPUDIATION",
            requirement: "Records must be attributable and resistant to repudiation.",
            mechanism: "Every artefact is Ed25519-signed over a domain-separated, length-prefixed canonical encoding; a signature over one artefact type cannot be presented as another.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-protocol/tests/evidence_packet.rs",
            },
        },
        ControlRow {
            instrument: Instrument::ItGovernance,
            control_id: "ITG-ACCESS-CONTROL",
            requirement: "Access rights are granted on least privilege and withdrawn when no longer needed.",
            mechanism: "Capability scopes attenuate only down a delegation chain; resource grants name institutional systems; revocation is tenant-scoped and reaches verification.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-authorize/tests/resources.rs",
            },
        },
        ControlRow {
            instrument: Instrument::ItGovernance,
            control_id: "ITG-KEY-MANAGEMENT",
            requirement: "Cryptographic keys are managed under defined custody with rotation.",
            mechanism: "The evidence key is generated on the collector host, wrapped at rest, and never present on the observed host; key versions are part of every anchor.",
            coverage: Coverage::Implemented {
                test: "aip-service/tests/key_custody.rs",
            },
        },
        ControlRow {
            instrument: Instrument::ItGovernance,
            control_id: "ITG-IMMUTABLE-STORAGE",
            requirement: "Records are protected against unauthorised alteration or deletion.",
            mechanism: "The service's database role holds SELECT and INSERT only; triggers make evidence append-only and enforce legal hold against the owner as well.",
            coverage: Coverage::Deployment {
                artefact: "deploy/sql/hardening.sql",
            },
        },
        ControlRow {
            instrument: Instrument::ItGovernance,
            control_id: "ITG-BCP-DR",
            requirement: "Business continuity and disaster recovery for critical records.",
            mechanism: "None. Immutability is not durability: a table nobody can delete from is still lost with its disk.",
            coverage: Coverage::None {
                note: "Backup, DR and a tested restore drill are open (R13/E5). Until they exist the evidence store is a single point of loss.",
            },
        },
        ControlRow {
            instrument: Instrument::ItGovernance,
            control_id: "ITG-INGRESS-SECURITY",
            requirement: "Transport security and rate limiting at service boundaries.",
            mechanism: "None in-process. The probe-to-collector link is authenticated but not encrypted.",
            coverage: Coverage::None {
                note: "TLS terminates at the institution's proxy today; in-process TLS, request timeouts, body limits and rate limiting are open (R9).",
            },
        },
        // ── IT Outsourcing ──
        ControlRow {
            instrument: Instrument::ItOutsourcing,
            control_id: "OUT-ACCOUNTABILITY-RETAINED",
            requirement: "A regulated entity cannot outsource its accountability for an outsourced activity.",
            mechanism: "Every verifier input is the institution's own: trust anchors come from the verifier, never from the artefact, and verification is offline with no call-home.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-verify/tests/cli.rs",
            },
        },
        ControlRow {
            instrument: Instrument::ItOutsourcing,
            control_id: "OUT-VENDOR-AGENT-VISIBILITY",
            requirement: "Activity of a service provider's systems within the entity's environment is visible to the entity.",
            mechanism: "Observation is external to the observed process, so a vendor-supplied agent is observed on the same terms as any other workload.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-observe/tests/sniffer_dog.rs",
            },
        },
        // ── FREE-AI ──
        ControlRow {
            instrument: Instrument::FreeAi,
            control_id: "FREEAI-ACCOUNTABILITY",
            requirement: "An accountable human or entity for every AI-driven action.",
            mechanism: "Authorization is adjudicated outside the agent and signed before the act; a self-issued root is refused where the verifier requires independence.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-authorize/tests/adversarial.rs",
            },
        },
        ControlRow {
            instrument: Instrument::FreeAi,
            control_id: "FREEAI-AI-INVENTORY",
            requirement: "Maintain an inventory of AI systems in use, reviewed periodically.",
            mechanism: "The per-agent access ledger is the evidence attachment for an inventory entry: which institutional resources an agent reached, in a window, with standing per row.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-ledger/tests/ledger.rs",
            },
        },
        ControlRow {
            instrument: Instrument::FreeAi,
            control_id: "FREEAI-UNDERSTANDING-BY-DESIGN",
            requirement: "Outputs must be intelligible to those who must act on them.",
            mechanism: "A closed verdict vocabulary with a machine-readable reason code, and evidence strength separated from severity so a serious-looking finding on weak evidence stays weak.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-reconcile/tests/adversarial.rs",
            },
        },
        ControlRow {
            instrument: Instrument::FreeAi,
            control_id: "FREEAI-RED-TEAMING",
            requirement: "Adversarial testing of AI systems, trigger-based as well as periodic.",
            mechanism: "A recorded adversarial ledger with raw output, and adversarial suites across the observer, reconciler, warrant and containment tiers.",
            coverage: Coverage::Deployment {
                artefact: "docs/security/ADVERSARIAL_RESULTS.md",
            },
        },
        ControlRow {
            instrument: Instrument::FreeAi,
            control_id: "FREEAI-FAIRNESS",
            requirement: "Fairness, bias and drift management for models.",
            mechanism: "Nothing. This system observes execution, not model behaviour; it holds no opinion about a model's outputs.",
            coverage: Coverage::EntityResponsibility {
                note: "Model risk function and model vendors. Out of scope by design, and claiming it would be a false claim.",
            },
        },
        // ── Model Risk Management (draft) ──
        ControlRow {
            instrument: Instrument::ModelRiskManagement,
            control_id: "MRM-KILL-SWITCH",
            requirement: "A means to stop an AI system promptly.",
            mechanism: "A seccomp user-notify execve gate under a signed, counter-bearing capability epoch, and a dead-man heartbeat that trips on silence or a signed 'I am blind'.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-enforce/tests/adversarial.rs",
            },
        },
        ControlRow {
            instrument: Instrument::ModelRiskManagement,
            control_id: "MRM-AGENT-AUTHORITY-MATRIX",
            requirement: "Defined authority per agent over defined systems.",
            mechanism: "A signed resource registry names institutional systems; `res:` grants inside the capability scope attenuate down the chain; an unregistered destination is refused.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-registry/tests/registry.rs",
            },
        },
        ControlRow {
            instrument: Instrument::ModelRiskManagement,
            control_id: "MRM-HUMAN-APPROVAL-INTEGRITY",
            requirement: "Where a human approves an AI action, the approval must be of what was actually authorised.",
            mechanism: "A signed record of what the human was shown, compared against the sealed expectation as arithmetic over two signed documents.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-approval/tests/adversarial.rs",
            },
        },
        // ── Digital Lending ──
        ControlRow {
            instrument: Instrument::DigitalLending,
            control_id: "DL-LSP-ACCOUNTABILITY",
            requirement: "The regulated entity remains accountable for a lending service provider's conduct.",
            mechanism: "The access ledger attributes each resource an agent reached to signed verdicts, so an LSP's agent is accounted for on the entity's own evidence.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-nexora/tests/access_ledger.rs",
            },
        },
        ControlRow {
            instrument: Instrument::DigitalLending,
            control_id: "DL-BORROWER-DISCLOSURE",
            requirement: "Disclosure to the borrower and grievance redress.",
            mechanism: "Nothing. This system produces no borrower-facing artefact.",
            coverage: Coverage::EntityResponsibility {
                note: "Compliance function and the customer-facing channels.",
            },
        },
        // ── CERT-In ──
        ControlRow {
            instrument: Instrument::CertIn,
            control_id: "CERTIN-LOG-RETENTION-180",
            requirement: "Retain logs for a rolling period of 180 days.",
            mechanism: "A per-tenant retention policy with the 180-day floor expressed as a database CHECK, so a misconfigured policy is refused at write time.",
            coverage: Coverage::Deployment {
                artefact: "deploy/sql/hardening.sql",
            },
        },
        ControlRow {
            instrument: Instrument::CertIn,
            control_id: "CERTIN-INCIDENT-REPORT-6H",
            requirement: "Report a reportable incident within six hours of noticing it.",
            mechanism: "Nothing that assembles a bundle on demand. The evidence exists and verifies, but an operator assembles it by hand today.",
            coverage: Coverage::None {
                note: "An `aip-incident export --agent --window` producing a signed bundle with coverage gaps listed is open (R14). Six hours is not a lot of hand assembly.",
            },
        },
        ControlRow {
            instrument: Instrument::CertIn,
            control_id: "CERTIN-CLOCK-SYNC",
            requirement: "Synchronise system clocks to a designated time source.",
            mechanism: "Each batch carries a boot-clock anchor so kernel timestamps are placed on the wall clock; the host's own NTP discipline is the operator's.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-reconcile/tests/transition_evidence.rs",
            },
        },
        // ── DPDP ──
        ControlRow {
            instrument: Instrument::Dpdp,
            control_id: "DPDP-DATA-MINIMISATION",
            requirement: "Collect only the personal data necessary for the stated purpose.",
            mechanism: "No payload is captured or hashed anywhere in the observation pipeline; transaction arguments enter signed documents only as domain-separated commitments.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-airi/tests/tool_boundary.rs",
            },
        },
        ControlRow {
            instrument: Instrument::Dpdp,
            control_id: "DPDP-FIELD-INVENTORY",
            requirement: "Know and record what personal data is processed, and why.",
            mechanism: "A field-by-field inventory of everything that leaves the observed host, checked against the structure so a new field fails the build until it is documented.",
            coverage: Coverage::Implemented {
                test: "aip-standalone/aip-conformance/tests/dpdp_inventory.rs",
            },
        },
        ControlRow {
            instrument: Instrument::Dpdp,
            control_id: "DPDP-CONSENT-NOTICE",
            requirement: "Notice and consent, where consent is the basis of processing.",
            mechanism: "Nothing. This system processes no data subject's data on its own account.",
            coverage: Coverage::EntityResponsibility {
                note: "The entity's own notice and consent management. A DPO field-level review of the inventory above is the input it needs.",
            },
        },
    ];
    rows.sort_by(|a, b| {
        a.instrument
            .cmp(&b.instrument)
            .then(a.control_id.cmp(b.control_id))
    });
    rows
}

pub fn to_json() -> String {
    serde_json::to_string_pretty(&control_map()).expect("control map is serialisable")
}

pub fn to_csv() -> String {
    let mut out = String::from("INSTRUMENT,CONTROL_ID,REQUIREMENT,MECHANISM,COVERAGE,EVIDENCE\n");
    for r in control_map() {
        out.push_str(&format!(
            "{},{},{},{},{},{}\n",
            r.instrument.as_str(),
            r.control_id,
            csv_cell(r.requirement),
            csv_cell(r.mechanism),
            r.coverage.as_str(),
            csv_cell(r.coverage.evidence_path().unwrap_or(""))
        ));
    }
    out
}

fn csv_cell(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
