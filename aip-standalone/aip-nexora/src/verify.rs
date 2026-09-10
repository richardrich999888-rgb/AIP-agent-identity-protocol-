//! Skill 10 Gates 3–5 — the offline verifier.
//!
//! ```text
//! NexoraProof + VerifierAnchors ──▶ verify_nexora_proof ──▶ VerifiedProof
//! ```
//!
//! No network, no service, no database, no clock, no filesystem, and no
//! relationship to the party that produced the package. Everything the
//! verifier trusts, it was handed: decision-point keys, observer keys,
//! issuer keys, warrant keys, NEXORA keys, and — if it has one — the
//! agent's own public key.
//!
//! # The load-bearing property
//!
//! The verifier does not believe the claim. It **re-runs this repository's
//! reconciler** over the package's own inputs, under the anchors the
//! verifier supplied and the parameters the package declared, and compares
//! the canonical digest of what comes out with the claim. A package whose
//! verdict is not derivable from its own evidence is
//! [`InvalidReason::ClaimNotDerivable`].
//!
//! That is why nothing here can upgrade evidence: the result and the
//! strength in a [`VerifiedProof`] are fields of the record
//! [`aip_reconcile`] produced during verification. This module contains no
//! code that writes a [`ReconciliationResult`] or an [`EvidenceStrength`],
//! so `CANNOT_PROVE` stays `CANNOT_PROVE` and `Attested` never becomes
//! `Proven` — not by policy, but because there is no statement that could.
//!
//! # What "replay" means here
//!
//! Recomputing canonical bytes, commitments, signatures and the
//! reconciliation verdict from the evidence in the package. It is not, and
//! never claims to be, a replay of any model's reasoning.

use std::collections::HashMap;

use aip_authorize::{
    verify_expected_execution, verify_expected_execution_for_agent, DecisionPointTrustAnchors,
};
use aip_core::delegation::verify_delegation_chain;
use aip_observe::{
    verify_attested_batch_independent_of_agent, verify_continuity_report, verify_signed_health,
    ObservationAvailability, ObserverState, ObserverTrustAnchors, SignedSensorHealth,
};
use aip_reconcile::{
    reconcile_expectation, reconcile_lineage, DecisionAuthority, EvidenceStrength,
    ExpectedSideCoverage, IdentityLineageInput, LineageComparison, LineageInputs, ObserverEvidence,
    Reconciliation, ReconciliationContext, ReconciliationResult,
};
use aip_warrant::{verify_warrant, WarrantTrustAnchors};
use serde::{Deserialize, Serialize};

use crate::capability::{ReconciliationAge, VerifierCapability};
use crate::commitment::{verify_proof, NexoraTrustAnchors, VerifiedInclusion};
use crate::proof::{verify_envelope, BindingFault, Component, NexoraProof, StructuralFault};
use crate::replay::AuthorityStanding;

/// Everything the verifier trusts, and nothing it does not. Each field is
/// the verifier's own decision; none of it comes from the package.
///
/// There is deliberately no `Default`. The bounds in
/// [`VerifierCapability`] have no safe blank value — an unstated bound used
/// to mean an unlimited one — so a verifier that never said what it accepts
/// cannot be constructed at all. `VerifierCapability::strict()` is the
/// shortest honest answer.
#[derive(Debug, Clone)]
pub struct VerifierAnchors {
    pub decision_point: DecisionPointTrustAnchors,
    pub observer: ObserverTrustAnchors,
    pub warrant: WarrantTrustAnchors,
    /// NEXORA's head-signing keys, and any proof assembler's.
    pub nexora: NexoraTrustAnchors,
    /// Issuer public keys by AIP-ID, for the authority chain.
    pub issuers: HashMap<String, Vec<u8>>,
    /// The observed agent's public key, when the verifier knows it.
    /// Supplying it lets the independence invariants be checked (I1, I10).
    pub agent_public_key: Option<Vec<u8>>,
    /// What this verifier is prepared to establish: the proof versions it
    /// reads, and the declared parameters it will accept a package to have
    /// been reconciled under.
    ///
    /// This exists because a declared parameter is an input to the verdict,
    /// and re-derivation alone cannot object to it: widening the staleness
    /// allowance from a minute to a century leaves a record that is still
    /// derivable from the same evidence and still *true* under those
    /// parameters. Whether those parameters are acceptable is the
    /// verifier's judgement, not the package's — and it now has no way to
    /// decline to make it.
    pub capability: VerifierCapability,
    /// The verifier's own view of *now*, used to say whether the authority
    /// behind the execution has since expired, and to age the reconciliation
    /// when the capability bounds that. It never enters the reconciliation
    /// itself: what happened does not change because time passed, and a
    /// stale authority is not an invalid proof.
    ///
    /// `None` here is not permissive. It means staleness was not assessed —
    /// reported as `AuthorityStanding::NotAssessed`, which grants nothing —
    /// and if the capability bounds the reconciliation's age, a verifier
    /// with no clock cannot compute that age and refuses.
    pub present_time_ms: Option<u64>,
}

/// What the verifier could establish about one component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentVerdict {
    Verified,
    /// The package does not carry it. Not a failure and not a pass.
    Absent,
    /// Carried, but the verifier could not establish it — an unanchored
    /// key, a broken signature, a refused structure. Never treated as
    /// absent, and never assumed away.
    Unverifiable(String),
}

/// Whether the two independence invariants could be checked at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Independence {
    /// The agent's key was available and the checks ran.
    Checked,
    /// The reconciliation was computed without the agent's key, so I1 and
    /// I10 were not checked. Reported, never silently a pass.
    NotChecked,
}

/// What the observation channel could say, as the verifier read it back
/// off signed evidence and the record re-drawn from that evidence. Derived
/// here; a package states no coverage at all, so there is nothing for an
/// assembler to overstate.
///
/// The distinction that carries the most weight is between
/// [`AvailableAndEmpty`](Self::AvailableAndEmpty) and
/// [`CannotEstablish`](Self::CannotEstablish). "The observer was
/// demonstrably watching and carried nothing" is evidence about the world.
/// "The observer carried nothing" is not — it is equally consistent with
/// the observer not having been watching. Only the first licenses a
/// statement about something *not* having happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationCoverage {
    /// The action was observed in evidence the collector attested.
    Observed,
    /// Kernel-pushed coverage over the window is attested and the channel
    /// carried no matching event. The only state that speaks of absence.
    AvailableAndEmpty,
    /// Evidence exists and does not resolve to one answer.
    Ambiguous,
    /// The channel reported dropped events over the window.
    Loss,
    /// No attested coverage: no observer, a gap, a restart, stale health,
    /// quarantine. Nothing may be concluded about what did or did not
    /// happen.
    CannotEstablish,
}

impl ObservationCoverage {
    pub const ALL: [ObservationCoverage; 5] = [
        ObservationCoverage::Observed,
        ObservationCoverage::AvailableAndEmpty,
        ObservationCoverage::Ambiguous,
        ObservationCoverage::Loss,
        ObservationCoverage::CannotEstablish,
    ];

    pub fn code(self) -> u8 {
        match self {
            ObservationCoverage::Observed => 0x01,
            ObservationCoverage::AvailableAndEmpty => 0x02,
            ObservationCoverage::Ambiguous => 0x03,
            ObservationCoverage::Loss => 0x04,
            ObservationCoverage::CannotEstablish => 0x05,
        }
    }

    /// May a statement about something *not* having happened rest on this?
    /// True for exactly one state.
    pub fn licenses_absence_claim(self) -> bool {
        matches!(self, ObservationCoverage::AvailableAndEmpty)
    }
}

/// Whether the evidence covers the whole of what the claim speaks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Completeness {
    Complete,
    Partial,
}

/// The coverage the verifier derived. A proof cannot overstate this
/// because a proof does not state it at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub observation: ObservationCoverage,
    pub completeness: Completeness,
}

/// What the evidence establishes about one kind of lineage. `Verified` is
/// the only standing that asserts two things are related; every other one
/// is a way of saying the package does not establish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineageStanding {
    /// Evidence the package carries, checked here, establishes the link.
    Verified,
    /// A required piece is missing from what was carried.
    Incomplete,
    /// More than one candidate; the evidence does not pick one.
    Ambiguous,
    /// Both sides are present and they disagree.
    Contradicted,
    /// The package carries nothing about this kind. `CANNOT_PROVE`, and
    /// never "assumed related".
    Unavailable,
    /// The evidence is genuine and the operator has withdrawn it. A revoked
    /// token is not a forged one — every signature still checks — so this
    /// is deliberately not `Contradicted`, and the package did carry the
    /// evidence, so it is deliberately not `Unavailable`. It is its own
    /// answer: the link existed and no longer counts.
    Revoked,
}

impl LineageStanding {
    pub const ALL: [LineageStanding; 6] = [
        LineageStanding::Verified,
        LineageStanding::Incomplete,
        LineageStanding::Ambiguous,
        LineageStanding::Contradicted,
        LineageStanding::Unavailable,
        LineageStanding::Revoked,
    ];

    pub fn code(self) -> u8 {
        match self {
            LineageStanding::Verified => 0x01,
            LineageStanding::Incomplete => 0x02,
            LineageStanding::Ambiguous => 0x03,
            LineageStanding::Contradicted => 0x04,
            LineageStanding::Unavailable => 0x05,
            LineageStanding::Revoked => 0x06,
        }
    }

    /// Does this standing assert that two things are related?
    pub fn asserts_a_link(self) -> bool {
        matches!(self, LineageStanding::Verified)
    }
}

/// The three kinds, kept apart. One being established says nothing about
/// the others: an agent may hold delegated authority from a party that did
/// not spawn it, and a process may be spawned by one whose identity
/// document claims no relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageReport {
    /// Is this agent's identity document descended from that one?
    pub identity: LineageStanding,
    /// Did the authority this decision rests on reach it by delegation?
    pub authority: LineageStanding,
    /// Did the observed process instance come from another one?
    pub process: LineageStanding,
}

/// What the package establishes about the observer's own record across
/// time. `Continuous` is the only value that asserts an unbroken chain.
///
/// `Unknown` and `CannotProve` are deliberately distinct: the first says
/// the package carries nothing about continuity, the second says it
/// carries something the verifier could not establish. A verifier that
/// collapsed them would let an unverifiable report read as an absent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContinuityStanding {
    /// The chain is unbroken across what the package carries.
    Continuous,
    /// A break is established: the collector said so, under its own key.
    Discontinuous,
    /// The package carries nothing about continuity.
    Unknown,
    /// Something was carried and it does not settle the question.
    CannotProve,
}

impl ContinuityStanding {
    pub const ALL: [ContinuityStanding; 4] = [
        ContinuityStanding::Continuous,
        ContinuityStanding::Discontinuous,
        ContinuityStanding::Unknown,
        ContinuityStanding::CannotProve,
    ];

    pub fn code(self) -> u8 {
        match self {
            ContinuityStanding::Continuous => 0x01,
            ContinuityStanding::Discontinuous => 0x02,
            ContinuityStanding::Unknown => 0x03,
            ContinuityStanding::CannotProve => 0x04,
        }
    }

    /// Does this standing assert an unbroken chain?
    pub fn asserts_unbroken(self) -> bool {
        matches!(self, ContinuityStanding::Continuous)
    }
}

/// Why a package is not valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidReason {
    UnsupportedVersion(u16),
    Structural(StructuralFault),
    Binding(BindingFault),
    /// A carried component could not be established.
    Component {
        component: Component,
        reason: String,
    },
    /// The package does not carry what the claim would have to be derived
    /// from, so the claim cannot be checked at all.
    NotDerivable(String),
    /// The reconciler, re-run over this package's own inputs, did not
    /// produce this claim.
    ClaimNotDerivable {
        claimed: [u8; 32],
        rederived: [u8; 32],
    },
    /// The package was reconciled under a parameter this verifier will not
    /// accept. The claim may well be derivable under it; the verifier
    /// declines to treat a verdict drawn under those terms as its own.
    DeclaredParameterRefused {
        parameter: String,
        declared: u64,
        max_accepted: u64,
    },
}

impl std::fmt::Display for InvalidReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofVerdict {
    Valid,
    Invalid(InvalidReason),
}

/// What a carried component's verdict says before the verifier reached it.
pub const NOT_REACHED: &str =
    "not evaluated: the package was refused before this component was reached";

/// Everything the verifier established, and nothing more.
///
/// `Deserialize` is deliberately not implemented. A `VerifiedProof`
/// carries the [`VerifierCapability`] its result was reached under, and a
/// capability that could be read out of bytes would be a capability an
/// attacker could write — so neither type can be deserialized, and there
/// is no sequence of bytes anywhere that becomes a statement about what a
/// verifier is prepared to establish. Nothing in this repository ever
/// deserialized a `VerifiedProof`; it is an output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedProof {
    pub proof_id: [u8; 32],
    pub subject: ComponentVerdict,
    pub authority: ComponentVerdict,
    pub expectation: ComponentVerdict,
    pub observer: ComponentVerdict,
    pub continuity: ComponentVerdict,
    pub lineage: ComponentVerdict,
    pub warrant: ComponentVerdict,
    pub commitment: ComponentVerdict,
    pub envelope: ComponentVerdict,
    /// The AI-stack provenance, re-derived. `Absent` when the package
    /// carries none — which is not a failure and not a pass.
    pub airi: ComponentVerdict,
    /// Number of AIRI events whose signature and chain position the verifier
    /// re-derived. Zero when `airi` is `Absent`.
    pub airi_events_verified: usize,
    /// The record the verifier recomputed from the package's inputs.
    pub rederived: Option<Reconciliation>,
    /// The re-derived result. Not the claimed one.
    pub result: Option<ReconciliationResult>,
    /// The re-derived strength. Not the claimed one, and never raised.
    pub strength: Option<EvidenceStrength>,
    pub coverage: Coverage,
    /// What the package establishes about each kind of lineage.
    pub lineage_report: LineageReport,
    /// What it establishes about the observer's record across time.
    pub continuity_standing: ContinuityStanding,
    /// Where the authority behind the execution stands at the verifier's
    /// present time. No value of it grants anything (Gate 11).
    pub authority_standing: AuthorityStanding,
    pub independence: Independence,
    /// Where the claim was committed, when a commitment was carried and
    /// verified.
    pub inclusion: Option<VerifiedInclusion>,
    /// Who sealed the package, when a seal was carried and verified.
    pub assembled_by: Option<String>,
    /// The terms this result was reached under. A verdict without them is
    /// half a sentence: "valid" means valid *given* the parameters this
    /// verifier agreed to accept, and a reader is entitled to see which.
    pub evaluated_under: VerifierCapability,
    pub verdict: ProofVerdict,
}

impl VerifiedProof {
    pub fn is_valid(&self) -> bool {
        self.verdict == ProofVerdict::Valid
    }
}

/// Verify a package offline against anchors the verifier supplied.
///
/// Deterministic: the same package and anchors always give the same
/// answer. Reads no clock — every time reference comes from the package's
/// declared parameters or from the evidence itself.
pub fn verify_nexora_proof(proof: &NexoraProof, anchors: &VerifierAnchors) -> VerifiedProof {
    // A component starts as *carried and not yet established*, never as
    // absent. The verifier can refuse a package before it reaches a given
    // component — a structural fault, a refused parameter, a binding that
    // does not hold — and on that path these values are what the report
    // keeps. "The package does not carry it" and "the package carries it
    // and the verifier could not establish it" are different facts, and
    // collapsing the second into the first is the same error as reading
    // absence of evidence as evidence of absence, one level down.
    let unreached = |carried: bool| {
        if carried {
            ComponentVerdict::Unverifiable(NOT_REACHED.to_string())
        } else {
            ComponentVerdict::Absent
        }
    };
    let mut v = VerifiedProof {
        proof_id: proof.proof_id(),
        // Settled below, once the package agrees with itself. Gate 12: a
        // component the package *carried* but which verification never
        // reached is `Unverifiable`, never `Absent` — collapsing the two
        // reads absence of evidence as evidence of absence.
        subject: unreached(true),
        authority: unreached(proof.authority.is_some()),
        expectation: unreached(proof.expectation.is_some()),
        observer: unreached(proof.observer.is_some()),
        continuity: unreached(proof.continuity.is_some()),
        lineage: unreached(proof.lineage.is_some()),
        warrant: unreached(proof.warrant.is_some()),
        commitment: unreached(proof.commitment.is_some()),
        // AIRI (Skill 15) carries the same rule: a carried AIRI component
        // that verification did not reach is unverifiable, not absent.
        airi: unreached(proof.airi.is_some()),
        airi_events_verified: 0,
        envelope: unreached(proof.envelope.is_some()),
        rederived: None,
        result: None,
        strength: None,
        coverage: Coverage {
            observation: ObservationCoverage::CannotEstablish,
            completeness: Completeness::Partial,
        },
        lineage_report: LineageReport {
            identity: LineageStanding::Unavailable,
            authority: LineageStanding::Unavailable,
            process: LineageStanding::Unavailable,
        },
        continuity_standing: ContinuityStanding::Unknown,
        authority_standing: authority_standing(proof, anchors),
        // What *this* verifier did, not what the package says the original
        // run did. Both must hold: the reconciliation ran with the agent's
        // key, and this verifier holds that key so it could re-run the
        // checks. A package asserting the first does not give the verifier
        // the second (Defect #5).
        independence: if proof.parameters.agent_key_supplied && anchors.agent_public_key.is_some() {
            Independence::Checked
        } else {
            Independence::NotChecked
        },
        inclusion: None,
        assembled_by: None,
        evaluated_under: anchors.capability.clone(),
        verdict: ProofVerdict::Valid,
    };

    // 1. Version, then the package's own agreement with itself. A package
    //    that disagrees with itself is refused before any key is consulted.
    if !anchors.capability.understands(proof.version) {
        v.verdict = ProofVerdict::Invalid(InvalidReason::UnsupportedVersion(proof.version));
        return v;
    }
    let max = anchors.capability.health_age_bound();
    if proof.parameters.health_max_age_ms > max {
        v.verdict = ProofVerdict::Invalid(InvalidReason::DeclaredParameterRefused {
            parameter: "health_max_age_ms".into(),
            declared: proof.parameters.health_max_age_ms,
            max_accepted: max,
        });
        return v;
    }
    let max = anchors.capability.window_tolerance_bound();
    if proof.parameters.window_tolerance_ms > max {
        v.verdict = ProofVerdict::Invalid(InvalidReason::DeclaredParameterRefused {
            parameter: "window_tolerance_ms".into(),
            declared: proof.parameters.window_tolerance_ms,
            max_accepted: max,
        });
        return v;
    }
    // How old the reconciliation may be. A verifier that bounds this and
    // holds no clock cannot compute the age, so it refuses rather than
    // skipping the check it said it would make.
    if let ReconciliationAge::AtMost(max_age) = anchors.capability.reconciliation_age_bound() {
        let declared = proof.parameters.verification_time_ms;
        let age = match anchors.present_time_ms {
            Some(now) => now.saturating_sub(declared),
            None => u64::MAX,
        };
        if age > max_age {
            v.verdict = ProofVerdict::Invalid(InvalidReason::DeclaredParameterRefused {
                parameter: "verification_time_ms".into(),
                declared,
                max_accepted: max_age,
            });
            return v;
        }
    }
    if let Some(f) = proof.structural_faults().into_iter().next() {
        v.verdict = ProofVerdict::Invalid(InvalidReason::Structural(f));
        return v;
    }
    if let Some(f) = proof.binding_faults().into_iter().next() {
        v.verdict = ProofVerdict::Invalid(InvalidReason::Binding(f));
        return v;
    }

    // The subject's id is settled by the structural checks just passed —
    // it is the agent the expectation names. Without a document there is
    // nothing further to establish; with one, the check below settles it.
    if proof.subject.identity.is_none() {
        v.subject = ComponentVerdict::Verified;
    }

    // 2. Each carried component, under the verifier's own anchors.
    let mut first_failure: Option<InvalidReason> = None;
    let mut fail = |c: Component, reason: String, slot: &mut ComponentVerdict| {
        *slot = ComponentVerdict::Unverifiable(reason.clone());
        if first_failure.is_none() {
            first_failure = Some(InvalidReason::Component {
                component: c,
                reason,
            });
        }
    };

    // The subject's identity document, when carried.
    if let Some(doc) = &proof.subject.identity {
        match aip_core::validate_aid(doc) {
            Ok(()) => v.subject = ComponentVerdict::Verified,
            Err(e) => fail(Component::Subject, format!("{e:?}"), &mut v.subject),
        }
    }

    // The expectation: decision-point signature, and the independence of
    // that key from the agent's when the verifier knows the agent's key.
    if let Some(ee) = &proof.expectation {
        let checked = match &anchors.agent_public_key {
            Some(k) => verify_expected_execution_for_agent(ee, &anchors.decision_point, k),
            None => verify_expected_execution(ee, &anchors.decision_point),
        };
        match checked {
            Ok(()) => v.expectation = ComponentVerdict::Verified,
            Err(e) => fail(Component::Expectation, format!("{e:?}"), &mut v.expectation),
        }
    }

    // The authority chain, under the verifier's issuer keys.
    if let Some(a) = &proof.authority {
        match verify_delegation_chain(&a.root, &a.chain, &anchors.issuers) {
            Ok(_) => v.authority = ComponentVerdict::Verified,
            Err(e) => fail(Component::Authority, format!("{e:?}"), &mut v.authority),
        }
    }

    // The observer's records: every batch and the health, each refusing an
    // anchor that is the agent's own key (I10).
    if let Some(o) = &proof.observer {
        let agent_key = anchors.agent_public_key.clone().unwrap_or_default();
        let mut ok = true;
        for b in &o.batches {
            if let Err(e) =
                verify_attested_batch_independent_of_agent(b, &anchors.observer, &agent_key)
            {
                fail(Component::Observer, format!("{e:?}"), &mut v.observer);
                ok = false;
                break;
            }
        }
        if ok {
            match verify_signed_health(&o.health, &anchors.observer) {
                Ok(()) => {
                    if anchors
                        .observer
                        .get(&o.health.health.observer_id, o.health.health.key_version)
                        == Some(agent_key.as_slice())
                        && !agent_key.is_empty()
                    {
                        fail(
                            Component::Observer,
                            "the anchored observer key is the agent's own key".into(),
                            &mut v.observer,
                        );
                    } else {
                        v.observer = ComponentVerdict::Verified;
                    }
                }
                Err(e) => fail(Component::Observer, format!("{e:?}"), &mut v.observer),
            }
        }
    }

    // The continuity report, under the observer's anchors. A report is the
    // collector's own signed statement that its record broke; the verifier
    // checks the signature and carries the statement, and never softens a
    // break into continuity.
    if let Some(c) = &proof.continuity {
        match verify_continuity_report(c, &anchors.observer) {
            Ok(()) => {
                v.continuity = ComponentVerdict::Verified;
                // Any break the collector reports is a break. There is no
                // "mild" one: ArchiveTruncated means records it sealed are
                // missing, which is not a demonstration of continuity.
                v.continuity_standing = ContinuityStanding::Discontinuous;
            }
            Err(e) => {
                fail(Component::Continuity, format!("{e:?}"), &mut v.continuity);
                // Carried and unestablished. Not the same as absent: the
                // package asked the question and the evidence did not
                // answer it.
                v.continuity_standing = ContinuityStanding::CannotProve;
            }
        }
    }

    // Lineage: every peer expectation must itself be decision-point signed.
    if let Some(l) = &proof.lineage {
        let mut ok = true;
        for peer in &l.peer_expectations {
            if let Err(e) = verify_expected_execution(peer, &anchors.decision_point) {
                fail(Component::Lineage, format!("{e:?}"), &mut v.lineage);
                ok = false;
                break;
            }
        }
        if ok {
            v.lineage = ComponentVerdict::Verified;
        }
    }

    // The warrant, under the warrant authority's anchors. NEXORA checks it
    // and records it; it never acts on it and never recreates its logic.
    if let Some(w) = &proof.warrant {
        match verify_warrant(w, &anchors.warrant) {
            Ok(()) => v.warrant = ComponentVerdict::Verified,
            Err(e) => fail(Component::Warrant, format!("{e:?}"), &mut v.warrant),
        }
    }

    // The commitment, against the head it names and NEXORA's anchors.
    if let Some(c) = &proof.commitment {
        match verify_proof(c, &anchors.nexora) {
            Ok(inclusion) => {
                v.inclusion = Some(inclusion);
                v.commitment = ComponentVerdict::Verified;
            }
            Err(e) => fail(Component::Commitment, format!("{e:?}"), &mut v.commitment),
        }
    }

    // AI-stack provenance (v2). Re-derived, never trusted: every event's
    // signature is checked and the chain is re-walked from the package's own
    // bytes.
    //
    // Two things this deliberately does not do. It does not let AIRI touch
    // `v.result` or `v.strength` — those are fields of the record the
    // reconciler produced during verification, and nothing here writes
    // either. And it does not accept the package's own `agent_public_key`
    // when the verifier holds an anchor for that agent: the verifier's
    // anchor wins, and a disagreement is a finding rather than a preference.
    if let Some(bundle) = &proof.airi {
        match verify_airi_bundle(bundle, anchors) {
            Ok(n) => {
                v.airi = ComponentVerdict::Verified;
                v.airi_events_verified = n;
            }
            Err(e) => fail(Component::Airi, e, &mut v.airi),
        }
    }

    // The envelope, when the package was sealed.
    if proof.envelope.is_some() {
        match verify_envelope(proof, &anchors.nexora) {
            Ok(()) => {
                v.envelope = ComponentVerdict::Verified;
                v.assembled_by = proof.envelope.as_ref().map(|e| e.assembler_id.clone());
            }
            Err(e) => {
                let reason = format!("{e:?}");
                v.envelope = ComponentVerdict::Unverifiable(reason.clone());
                if first_failure.is_none() {
                    first_failure = Some(InvalidReason::Component {
                        component: Component::Subject,
                        reason,
                    });
                }
            }
        }
    }

    // 3. Re-derive the claim from the package's own inputs.
    let rederived = rederive(proof, anchors);
    match rederived {
        Err(reason) => {
            if first_failure.is_none() {
                first_failure = Some(reason);
            }
        }
        Ok(r) => {
            v.coverage = derive_coverage(proof, &r);
            v.lineage_report = derive_lineage(proof, &r, &v.authority);
            let claimed = proof.claim.digest();
            let got = r.digest();
            v.result = Some(r.result);
            v.strength = Some(r.strength);
            v.rederived = Some(r);
            if claimed != got && first_failure.is_none() {
                first_failure = Some(InvalidReason::ClaimNotDerivable {
                    claimed,
                    rederived: got,
                });
            }
        }
    }

    if let Some(reason) = first_failure {
        v.verdict = ProofVerdict::Invalid(reason);
        // A refused package establishes nothing. `result` and `strength`
        // are what the *package* establishes, so a refusal empties them —
        // otherwise a consumer reading `.result` without reading `.verdict`
        // could act on a package the verifier turned down. Nothing is lost:
        // `rederived` still carries the whole recomputed record, under a
        // name that says it is a recomputation and not a conclusion.
        v.result = None;
        v.strength = None;
    }
    v
}

/// Where the authority stands at the verifier's present time, if it named
/// one. Assessed against the expectation's own window, and used for
/// nothing else: a stale authority is a fact about now, and the proof is a
/// statement about then.
fn authority_standing(proof: &NexoraProof, anchors: &VerifierAnchors) -> AuthorityStanding {
    let (Some(now), Some(ee)) = (anchors.present_time_ms, proof.expectation.as_ref()) else {
        return AuthorityStanding::NotAssessed;
    };
    if now > ee.valid_until {
        AuthorityStanding::StaleSince {
            valid_until: ee.valid_until,
        }
    } else {
        AuthorityStanding::ValidNow
    }
}

/// Re-run the reconciler over the package's inputs. The anchors are the
/// verifier's; the parameters are the package's declaration of how the
/// original run was configured, so that a difference in configuration
/// shows up as a different record rather than passing unnoticed.
fn rederive(
    proof: &NexoraProof,
    anchors: &VerifierAnchors,
) -> Result<Reconciliation, InvalidReason> {
    let Some(ee) = &proof.expectation else {
        return Err(InvalidReason::NotDerivable(
            "no expectation: the claim cannot be recomputed from this package".into(),
        ));
    };
    // The declaration decides whether the independence checks ran; a
    // verifier that holds the key does not get to add a check the original
    // run did not make, because that would change the record.
    let agent_public_key = if proof.parameters.agent_key_supplied {
        match &anchors.agent_public_key {
            Some(k) => Some(k.clone()),
            None => {
                return Err(InvalidReason::NotDerivable(
                    "the package was reconciled with the agent key, which this verifier lacks"
                        .into(),
                ))
            }
        }
    } else {
        None
    };
    let ctx = ReconciliationContext {
        decision_point_anchors: anchors.decision_point.clone(),
        observer_anchors: anchors.observer.clone(),
        verification_time_ms: proof.parameters.verification_time_ms,
        health_max_age_ms: proof.parameters.health_max_age_ms,
        window_tolerance_ms: proof.parameters.window_tolerance_ms,
        expected_side: ExpectedSideCoverage::Unknown,
        agent_public_key,
    };
    let evidence = proof.observer.as_ref().map(|o| ObserverEvidence {
        batches: o.batches.clone(),
        health: o.health.clone(),
    });
    // Which entry point the assembler used is decided by the package, not
    // by the verifier: carrying lineage evidence *means* the record was
    // drawn by `reconcile_lineage`. Both sides read the same rule off the
    // same package, so a mismatch shows up as a different record rather
    // than as a verifier that guessed differently.
    let Some(l) = &proof.lineage else {
        return Ok(reconcile_expectation(ee, evidence.as_ref(), &ctx));
    };
    let authority = proof.authority.as_ref().map(|a| DecisionAuthority {
        root: a.root.clone(),
        chain: a.chain.clone(),
    });
    let identity = l
        .identity
        .as_ref()
        .map(|(child, parent)| IdentityLineageInput { child, parent });
    let inputs = LineageInputs {
        peer_expectations: &l.peer_expectations,
        authority: authority.as_ref(),
        issuer_keys: &anchors.issuers,
        revoked_jtis: &l.revoked_jtis,
        identity,
    };
    Ok(reconcile_lineage(ee, evidence.as_ref(), &ctx, &inputs))
}

/// Read the three lineage axes off what the package carries and what the
/// engine made of it. Each axis has its own evidence; none is inferred
/// from another, and none is `Verified` merely because nothing said
/// otherwise.
/// Has the operator withdrawn the root token or any hop of the chain this
/// package carries? The list is the *verifier's* operator's declaration,
/// carried beside the evidence rather than inside it, exactly as the
/// reconciler receives it.
fn is_revoked(proof: &NexoraProof, revoked: &[[u8; 16]]) -> bool {
    let Some(a) = proof.authority.as_ref() else {
        return false;
    };
    revoked.contains(&a.root.jti) || a.chain.iter().any(|h| revoked.contains(&h.jti))
}

fn derive_lineage(
    proof: &NexoraProof,
    r: &Reconciliation,
    authority_verdict: &ComponentVerdict,
) -> LineageReport {
    // Authority: the chain the expectation names, verified under the
    // verifier's issuer keys. `binding_faults` already refused a chain
    // that is not the one the expectation names, so reaching here with a
    // verified authority means both held.
    //
    // Revocation is checked separately and last, because it is a different
    // kind of fact from a signature: the operator has withdrawn a token
    // whose signatures are all still good. Without this a package would
    // report a live authority link for a token the operator revoked —
    // which the reconciler already refuses to draw an edge from, so the
    // two would disagree about the same evidence.
    let revoked = proof
        .lineage
        .as_ref()
        .is_some_and(|l| is_revoked(proof, &l.revoked_jtis));
    let authority = match authority_verdict {
        _ if revoked => LineageStanding::Revoked,
        ComponentVerdict::Verified => LineageStanding::Verified,
        ComponentVerdict::Absent => LineageStanding::Unavailable,
        ComponentVerdict::Unverifiable(_) => LineageStanding::Contradicted,
    };

    // Identity: the child's document must carry a lineage proof the
    // parent's key made. `validate_aid_with_parent` is the existing check;
    // a document with no proof at all is incomplete rather than wrong.
    let identity = match proof.lineage.as_ref().and_then(|l| l.identity.as_ref()) {
        None => LineageStanding::Unavailable,
        Some((child, parent)) => {
            if child.lineage_proof.is_none() {
                LineageStanding::Incomplete
            } else {
                match aip_core::validate_aid_with_parent(
                    child,
                    &parent.id,
                    &parent.primary_key.key_bytes,
                ) {
                    Ok(()) => LineageStanding::Verified,
                    Err(_) => LineageStanding::Contradicted,
                }
            }
        }
    };

    // Process: the engine's own answer, carried across without rounding.
    let process = if proof.lineage.is_none() {
        LineageStanding::Unavailable
    } else {
        match r.lineage {
            LineageComparison::NotEvaluated => LineageStanding::Unavailable,
            LineageComparison::Incomplete => LineageStanding::Incomplete,
            LineageComparison::Ambiguous { .. } => LineageStanding::Ambiguous,
            LineageComparison::Consistent { .. } => LineageStanding::Verified,
            LineageComparison::Contradicted => LineageStanding::Contradicted,
        }
    };

    LineageReport {
        identity,
        authority,
        process,
    }
}

/// Read coverage off the evidence and the record the reconciler re-drew
/// from it. Derived, so there is nothing for a package to overstate.
///
/// The result comes first, and deliberately. `availability` answers "was
/// the expectation's authorized *window* inside attested coverage" — a
/// verified execution routinely reports `WindowNotCovered` while its action
/// matched observed evidence, because the window runs on past the moment
/// the action was seen. Reading availability first would report an
/// execution the observer watched happen as unobserved.
fn derive_coverage(proof: &NexoraProof, r: &Reconciliation) -> Coverage {
    use ReconciliationResult as R;
    let observation = match r.result {
        // The reconciler resolved the action against observed evidence.
        R::VerifiedExecution
        | R::UnattributedEffect
        | R::IdentityDivergence
        | R::LineageViolation => ObservationCoverage::Observed,
        // PHANTOM_CLAIM is precisely the licensed absence: the reconciler
        // only reaches it with kernel-pushed lifecycle coverage over the
        // exact window and nothing in it.
        R::PhantomClaim => ObservationCoverage::AvailableAndEmpty,
        // The observer's own record failed. Nothing is established about
        // the workload either way.
        R::SensorIntegrityFailure | R::ContinuityFailure => ObservationCoverage::CannotEstablish,
        // No verdict. Which of the remaining states applies is a question
        // about the channel, and the evidence answers it.
        R::CannotProve => {
            if reported_loss(proof) {
                ObservationCoverage::Loss
            } else if matches!(r.availability, ObservationAvailability::Covered { .. }) {
                // Coverage held and the evidence still did not resolve.
                ObservationCoverage::Ambiguous
            } else {
                ObservationCoverage::CannotEstablish
            }
        }
    };
    // Completeness is about the action the expectation names: complete only
    // when the record settled it, either by observing it or by establishing
    // that the watched channel carried nothing.
    let completeness = match r.result {
        R::VerifiedExecution | R::PhantomClaim => Completeness::Complete,
        _ => Completeness::Partial,
    };
    Coverage {
        observation,
        completeness,
    }
}

/// Did the channel itself report dropped events, or is the observer in a
/// state that says it lost its footing? Both are the channel speaking, not
/// the verifier inferring.
fn reported_loss(proof: &NexoraProof) -> bool {
    let Some(o) = &proof.observer else {
        return false;
    };
    if o.batches
        .iter()
        .any(|b| b.batch.dropped_events.is_some_and(|n| n > 0))
    {
        return true;
    }
    degraded(&o.health)
}

fn degraded(h: &SignedSensorHealth) -> bool {
    matches!(h.health.state, ObserverState::Degraded)
}

/// Re-derive an [`AiriBundle`]: which key really signed these events, whether
/// each signature holds, and whether they form one intact chain.
///
/// Returns the number of events verified. Returns `Err` with a reason a human
/// can act on; the caller records it as `Unverifiable`, never as absent.
///
/// # Key selection
///
/// If the verifier anchored a public key for this agent, that key is used and
/// the package's own is required to match it. A package naming a different
/// key is not quietly verified against the one it supplied — that would let
/// an assembler choose whose signature counts.
///
/// If the verifier anchored no key, the package's is used and the caller is
/// told, through the reason string on any failure, that the check rested on a
/// self-supplied key. A `Verified` verdict under a self-supplied key means
/// "internally consistent", which is weaker than "signed by the agent the
/// verifier trusts" and must not be read as the latter.
fn verify_airi_bundle(
    bundle: &crate::proof::AiriBundle,
    anchors: &VerifierAnchors,
) -> Result<usize, String> {
    if bundle.events.is_empty() {
        return Err("bundle carries no events".to_string());
    }
    if bundle.agent_public_key.len() != 32 {
        return Err(format!(
            "agent_public_key is {} bytes; an Ed25519 key is 32",
            bundle.agent_public_key.len()
        ));
    }

    let key: &[u8] = match &anchors.agent_public_key {
        Some(anchored) => {
            if anchored.as_slice() != bundle.agent_public_key.as_slice() {
                return Err(
                    "the package names an agent key the verifier does not anchor; \
                     refusing to verify against a key the package chose"
                        .to_string(),
                );
            }
            anchored.as_slice()
        }
        None => bundle.agent_public_key.as_slice(),
    };

    for ev in &bundle.events {
        if ev.agent_id != bundle.agent_id {
            return Err(format!(
                "event at sequence {} is authored by {}, not the bundle's agent {}",
                ev.sequence, ev.agent_id, bundle.agent_id
            ));
        }
        aip_airi::verify_airi_event(ev, key)
            .map_err(|e| format!("event at sequence {}: {e}", ev.sequence))?;
    }

    match aip_airi::verify_event_chain(&bundle.events, key) {
        aip_airi::ChainReport::Intact(_) => Ok(bundle.events.len()),
        aip_airi::ChainReport::Defective(d) => Err(format!("chain defect: {d:?}")),
    }
}
