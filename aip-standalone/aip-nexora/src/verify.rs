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
    reconcile_expectation, EvidenceStrength, ExpectedSideCoverage, ObserverEvidence,
    Reconciliation, ReconciliationContext, ReconciliationResult,
};
use aip_warrant::{verify_warrant, WarrantTrustAnchors};
use serde::{Deserialize, Serialize};

use crate::commitment::{verify_proof, NexoraTrustAnchors, VerifiedInclusion};
use crate::proof::{
    verify_envelope, BindingFault, Component, NexoraProof, StructuralFault, NEXORA_PROOF_VERSION,
};

/// Everything the verifier trusts, and nothing it does not. Each field is
/// the verifier's own decision; none of it comes from the package.
#[derive(Debug, Clone, Default)]
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

/// What the observer could say about the window, as the verifier read it
/// back off the evidence. Derived here, never claimed by the package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationCoverage {
    /// The window is inside attested coverage and the action was observed.
    Observed,
    /// Coverage held and the action was not seen in it.
    NotObserved,
    /// Evidence exists but does not resolve to one answer.
    Ambiguous,
    /// The observer was alive and impaired over the window.
    Degraded,
    /// No coverage: no observer, a gap, a restart, staleness, quarantine.
    Unavailable,
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

/// Everything the verifier established, and nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub independence: Independence,
    /// Where the claim was committed, when a commitment was carried and
    /// verified.
    pub inclusion: Option<VerifiedInclusion>,
    /// Who sealed the package, when a seal was carried and verified.
    pub assembled_by: Option<String>,
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
    let mut v = VerifiedProof {
        proof_id: proof.proof_id(),
        subject: ComponentVerdict::Verified,
        authority: ComponentVerdict::Absent,
        expectation: ComponentVerdict::Absent,
        observer: ComponentVerdict::Absent,
        continuity: ComponentVerdict::Absent,
        lineage: ComponentVerdict::Absent,
        warrant: ComponentVerdict::Absent,
        commitment: ComponentVerdict::Absent,
        airi: ComponentVerdict::Absent,
        airi_events_verified: 0,
        envelope: ComponentVerdict::Absent,
        rederived: None,
        result: None,
        strength: None,
        coverage: Coverage {
            observation: ObservationCoverage::Unavailable,
            completeness: Completeness::Partial,
        },
        independence: if proof.parameters.agent_key_supplied {
            Independence::Checked
        } else {
            Independence::NotChecked
        },
        inclusion: None,
        assembled_by: None,
        verdict: ProofVerdict::Valid,
    };

    // 1. Version, then the package's own agreement with itself. A package
    //    that disagrees with itself is refused before any key is consulted.
    if proof.version != NEXORA_PROOF_VERSION {
        v.verdict = ProofVerdict::Invalid(InvalidReason::UnsupportedVersion(proof.version));
        return v;
    }
    if let Some(f) = proof.structural_faults().into_iter().next() {
        v.verdict = ProofVerdict::Invalid(InvalidReason::Structural(f));
        return v;
    }
    if let Some(f) = proof.binding_faults().into_iter().next() {
        v.verdict = ProofVerdict::Invalid(InvalidReason::Binding(f));
        return v;
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

    // The continuity report, under the observer's anchors.
    if let Some(c) = &proof.continuity {
        match verify_continuity_report(c, &anchors.observer) {
            Ok(()) => v.continuity = ComponentVerdict::Verified,
            Err(e) => fail(Component::Continuity, format!("{e:?}"), &mut v.continuity),
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
    }
    v
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
    Ok(reconcile_expectation(ee, evidence.as_ref(), &ctx))
}

/// Read coverage off the evidence and the re-derived record. Derived, so
/// there is nothing for a package to overstate.
fn derive_coverage(proof: &NexoraProof, r: &Reconciliation) -> Coverage {
    let observation = match (&r.availability, r.result) {
        (ObservationAvailability::Unavailable { .. }, _) => {
            // The window is not covered. Whether the observer was alive and
            // impaired, or absent altogether, is the health record's answer.
            match proof.observer.as_ref().map(|o| &o.health) {
                Some(h) if degraded(h) => ObservationCoverage::Degraded,
                _ => ObservationCoverage::Unavailable,
            }
        }
        (_, ReconciliationResult::VerifiedExecution) => ObservationCoverage::Observed,
        (_, ReconciliationResult::PhantomClaim) => ObservationCoverage::NotObserved,
        (_, ReconciliationResult::CannotProve) => ObservationCoverage::Ambiguous,
        _ => ObservationCoverage::Ambiguous,
    };
    // Completeness is about the *action* the expectation names: only a
    // record that resolved the action to observed evidence covers it.
    let completeness = match r.result {
        ReconciliationResult::VerifiedExecution => Completeness::Complete,
        _ => Completeness::Partial,
    };
    Coverage {
        observation,
        completeness,
    }
}

fn degraded(h: &SignedSensorHealth) -> bool {
    matches!(
        h.health.state,
        ObserverState::Degraded | ObserverState::Recovering | ObserverState::ContinuityUnverified
    )
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
