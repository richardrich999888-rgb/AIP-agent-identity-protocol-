//! Skill 10 Gate 1 — the NEXORA proof object.
//!
//! A NEXORA proof is a **package of evidence other authorities signed**,
//! together with the verdict this repository's reconciler drew from it. It
//! is not a new statement about the world. Nothing in this module authors a
//! result, a strength, a permission or a judgement; the only way a verdict
//! enters a proof is by carrying a [`Reconciliation`] somebody else
//! computed, and the only way it leaves is unchanged.
//!
//! ```text
//! subject ─┐
//! authority ┤   ┌──────────────┐
//! expectation ┤ │ NexoraProof  │ ── canonical_bytes ──▶ proof_id
//! observer ───┤ │  (carries)   │ ── structural_faults ▶ what it cites
//! continuity ─┤ └──────────────┘                        but does not carry
//! lineage ────┤        │
//! warrant ────┤        └── claim: the Reconciliation, verbatim
//! commitment ─┘
//! ```
//!
//! # Absence is a value
//!
//! Every component is an `Option`, and its presence is *encoded*: a package
//! with no expectation and a package with an expectation produce different
//! canonical bytes, and an authority with an empty delegation chain is not
//! the absence of an authority. A proof therefore cannot omit a dependency
//! quietly — it can only say it does not have it.
//!
//! # What binds what
//!
//! The canonical bytes bind every component **by the bytes its own
//! authority signed**: an expectation by
//! [`ExpectedExecution::signing_preimage`], a batch by
//! [`AttestedBatch::signing_preimage`], a token by
//! `aip_core::capability::token_signing_payload`, and so on, each followed
//! by that authority's signature envelope. This module defines no second
//! description of any signed object (I14, I18); it only states which
//! objects are in this package, in which order.
//!
//! # What cannot be swapped
//!
//! Two independent defences, and the module keeps them independent.
//! [`NexoraProof::binding_faults`] checks that the components agree with
//! each other — by digest, id, sequence, jti, head and leaf kind — using no
//! signature verification at all, so a transplant is visible in an unsealed
//! package a verifier has not yet anchored. The envelope, when present,
//! covers every byte, so a transplant breaks it too. Neither is allowed to
//! be the only line: a swap is caught with the seal removed, and caught
//! with the agreement checks skipped.
//!
//! # The envelope
//!
//! A [`ProofAssembler`] may seal a package. That signature means exactly
//! *"this party assembled these components at this time"*. It is not a
//! statement that the components are true, it never improves a component's
//! verdict, and a package without one verifies exactly as well as a package
//! with one — provided every component verifies on its own.

use aip_core::capability::token_signing_payload;
use aip_core::delegation::delegation_signing_payload;
use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_observe::{AttestedBatch, SignedContinuityReport, SignedSensorHealth};
use aip_reconcile::{EvidenceRef, EvidenceStrength, Reconciliation, ReconciliationResult};
use aip_types::canonical::*;
use aip_types::{AgentIdentityDocument, DelegationToken, ScopedToken, Signature};
use aip_warrant::Warrant;
use serde::{Deserialize, Serialize};

use crate::commitment::{NexoraError, NexoraTrustAnchors, ProofObject};

/// Version of the proof bundle. Independent of `NEXORA_VERSION`, which
/// versions heads and inclusion proofs and is unchanged by this gate.
/// Structure version.
///
/// v2 adds the optional [`AiriBundle`] component: the agent-signed AI-stack
/// events a reconciliation rested on, so an offline verifier can re-derive
/// their integrity rather than take them on trust. v1 packages are refused
/// rather than reinterpreted — the component codes shifted no existing
/// field, but a v1 verifier and a v2 package disagree about what follows
/// the warrant, and guessing is how a signature ends up covering something
/// other than what a verifier reads.
pub const NEXORA_PROOF_VERSION: u16 = 2;
/// Domain tag leading a bundle's canonical bytes.
pub const PROOF_BUNDLE_DOMAIN: &str = "SYNTRIASS/NEXORA/PROOF_BUNDLE/v1";
/// Domain tag leading an assembler's envelope signature.
pub const PROOF_ENVELOPE_DOMAIN: &str = "SYNTRIASS/NEXORA/ENVELOPE/v1";

// ─── Components ───

/// The parts a package may carry. `Subject` and `Claim` are always present;
/// every other part is representable as absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Component {
    Subject,
    Authority,
    Expectation,
    Observer,
    Continuity,
    Lineage,
    Claim,
    Warrant,
    Commitment,
    /// AI-stack provenance (AIRI). Optional; absent in a package from a
    /// deployment that runs no instrumented agents.
    Airi,
}

impl Component {
    pub const ALL: [Component; 9] = [
        Component::Subject,
        Component::Authority,
        Component::Expectation,
        Component::Observer,
        Component::Continuity,
        Component::Lineage,
        Component::Claim,
        Component::Warrant,
        Component::Commitment,
    ];

    pub fn code(self) -> u8 {
        match self {
            Component::Subject => 0x01,
            Component::Authority => 0x02,
            Component::Expectation => 0x03,
            Component::Observer => 0x04,
            Component::Continuity => 0x05,
            Component::Lineage => 0x06,
            Component::Claim => 0x07,
            Component::Warrant => 0x08,
            Component::Commitment => 0x09,
            Component::Airi => 0x0A,
        }
    }
}

/// Who the package is about. The identity document, when carried, is the
/// agent's own signed document — carrying it proves nothing by itself and
/// is checked by the verifier like anything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub agent_id: String,
    pub identity: Option<AgentIdentityDocument>,
}

/// The authority the decision was made under, as the issuer signed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityEvidence {
    pub root: ScopedToken,
    pub chain: Vec<DelegationToken>,
}

/// What the observer contributed: the attested batches and the health
/// record whose head they must chain to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverBundle {
    pub batches: Vec<AttestedBatch>,
    pub health: SignedSensorHealth,
}

/// Lineage inputs, each of which the verifier checks rather than believes.
/// Nothing here is synthesised from a name or from an agent's own say-so.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LineageEvidence {
    /// Decision-point-signed expectations of other agents, used to
    /// attribute a spawning instance.
    pub peer_expectations: Vec<aip_authorize::ExpectedExecution>,
    /// The child's and the parent's identity documents, in that order.
    pub identity: Option<(AgentIdentityDocument, AgentIdentityDocument)>,
    /// Token ids the verifier's operator declared revoked.
    pub revoked_jtis: Vec<[u8; 16]>,
}

/// The knobs the reconciliation was computed under. **Declared, not
/// trusted**: they are inside the signed bytes so they cannot be changed
/// after the fact, and the verifier re-runs the reconciler under them while
/// supplying its own anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DeclaredParameters {
    pub verification_time_ms: u64,
    pub health_max_age_ms: u64,
    pub window_tolerance_ms: u64,
    /// Whether the agent's public key was supplied when the reconciliation
    /// ran. When it was not, two independence checks (I1, I10) were skipped
    /// and the verifier must report that rather than pass silently.
    pub agent_key_supplied: bool,
}

/// An assembler's signature over the package. Provenance of the packaging,
/// never of the contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub assembler_id: String,
    pub key_version: u32,
    pub sealed_at_ms: u64,
    pub signature: Signature,
}

// ─── The proof ───

/// Agent-signed AI-stack events carried in a proof package.
///
/// # What the verifier does with this
///
/// It re-derives, it does not trust. Every event's signature is checked
/// against `agent_public_key`, the chain is re-walked, and the result is a
/// [`ComponentVerdict`] — never an upgrade to any other component. AIRI
/// evidence cannot raise a reconciliation result or an evidence strength
/// here for the same reason it cannot anywhere else: there is no statement
/// in this crate that would.
///
/// # Why the key travels with the events
///
/// `agent_public_key` is the key the *package author* says signed these
/// events. It is a claim, exactly like the rest of the package. A verifier
/// that holds its own anchor for this agent must compare the two — the
/// verifier's anchor wins, and a mismatch is a finding. Carrying the key
/// makes the package self-describing without making it self-authorising.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiriBundle {
    /// The agent's AIP-ID, repeated so a reader need not parse an event.
    pub agent_id: String,
    /// The key the package says signed the events. A claim, not an anchor.
    pub agent_public_key: Vec<u8>,
    /// One execution's events, in the order they were emitted. Order is
    /// load-bearing: the chain check exists to detect reordering.
    pub events: Vec<aip_airi::AiriEvent>,
}

/// A portable package of signed evidence and the verdict drawn from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NexoraProof {
    pub version: u16,
    pub issued_at_ms: u64,
    pub subject: Subject,
    pub authority: Option<AuthorityEvidence>,
    pub expectation: Option<aip_authorize::ExpectedExecution>,
    pub observer: Option<ObserverBundle>,
    pub continuity: Option<SignedContinuityReport>,
    pub lineage: Option<LineageEvidence>,
    pub parameters: DeclaredParameters,
    /// The reconciliation record, exactly as the reconciler produced it.
    pub claim: Reconciliation,
    pub warrant: Option<Warrant>,
    /// AI-stack provenance, when the deployment runs instrumented agents.
    pub airi: Option<AiriBundle>,
    pub commitment: Option<ProofObject>,
    pub envelope: Option<Envelope>,
}

impl NexoraProof {
    pub fn builder(agent_id: String, claim: Reconciliation) -> ProofBuilder {
        ProofBuilder {
            proof: NexoraProof {
                version: NEXORA_PROOF_VERSION,
                issued_at_ms: 0,
                airi: None,
                subject: Subject {
                    agent_id,
                    identity: None,
                },
                authority: None,
                expectation: None,
                observer: None,
                continuity: None,
                lineage: None,
                parameters: DeclaredParameters::default(),
                claim,
                warrant: None,
                commitment: None,
                envelope: None,
            },
        }
    }

    /// The result the reconciler produced. Carried, never restated.
    pub fn result(&self) -> ReconciliationResult {
        self.claim.result
    }

    /// The evidence strength the reconciler produced. Carried, never raised.
    pub fn strength(&self) -> EvidenceStrength {
        self.claim.strength
    }

    pub fn present(&self, c: Component) -> bool {
        match c {
            Component::Subject | Component::Claim => true,
            Component::Authority => self.authority.is_some(),
            Component::Expectation => self.expectation.is_some(),
            Component::Observer => self.observer.is_some(),
            Component::Continuity => self.continuity.is_some(),
            Component::Lineage => self.lineage.is_some(),
            Component::Warrant => self.warrant.is_some(),
            Component::Commitment => self.commitment.is_some(),
            Component::Airi => self.airi.is_some(),
        }
    }

    /// Canonical, domain-separated, injective bytes over every component,
    /// **excluding** the envelope (which signs these bytes).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, PROOF_BUNDLE_DOMAIN);
        put_u16(&mut buf, self.version);
        put_u64(&mut buf, self.issued_at_ms);

        // Subject
        put_u8(&mut buf, Component::Subject.code());
        put_str(&mut buf, &self.subject.agent_id);
        match &self.subject.identity {
            Some(doc) => {
                put_u8(&mut buf, 1);
                put_identity(&mut buf, doc);
            }
            None => put_u8(&mut buf, 0),
        }

        // Authority
        put_u8(&mut buf, Component::Authority.code());
        match &self.authority {
            Some(a) => {
                put_u8(&mut buf, 1);
                put_bytes(&mut buf, &token_signing_payload(&a.root));
                put_signature(&mut buf, &a.root.issuer_sig);
                put_u32(&mut buf, a.chain.len() as u32);
                for hop in &a.chain {
                    put_bytes(&mut buf, &delegation_signing_payload(hop));
                    put_signature(&mut buf, &hop.issuer_sig);
                }
            }
            None => put_u8(&mut buf, 0),
        }

        // Expectation
        put_u8(&mut buf, Component::Expectation.code());
        match &self.expectation {
            Some(ee) => {
                put_u8(&mut buf, 1);
                put_bytes(&mut buf, &ee.signing_preimage());
                put_signature(&mut buf, &ee.decision_sig);
            }
            None => put_u8(&mut buf, 0),
        }

        // Observer
        put_u8(&mut buf, Component::Observer.code());
        match &self.observer {
            Some(o) => {
                put_u8(&mut buf, 1);
                put_u32(&mut buf, o.batches.len() as u32);
                for b in &o.batches {
                    put_bytes(&mut buf, &b.signing_preimage());
                    put_signature(&mut buf, &b.attestation);
                }
                put_bytes(&mut buf, &o.health.health.canonical_bytes());
                put_signature(&mut buf, &o.health.attestation);
            }
            None => put_u8(&mut buf, 0),
        }

        // Continuity
        put_u8(&mut buf, Component::Continuity.code());
        match &self.continuity {
            Some(r) => {
                put_u8(&mut buf, 1);
                put_bytes(&mut buf, &r.report.canonical_bytes());
                put_signature(&mut buf, &r.signature);
            }
            None => put_u8(&mut buf, 0),
        }

        // Lineage
        put_u8(&mut buf, Component::Lineage.code());
        match &self.lineage {
            Some(l) => {
                put_u8(&mut buf, 1);
                put_u32(&mut buf, l.peer_expectations.len() as u32);
                for ee in &l.peer_expectations {
                    put_bytes(&mut buf, &ee.signing_preimage());
                    put_signature(&mut buf, &ee.decision_sig);
                }
                match &l.identity {
                    Some((child, parent)) => {
                        put_u8(&mut buf, 1);
                        put_identity(&mut buf, child);
                        put_identity(&mut buf, parent);
                    }
                    None => put_u8(&mut buf, 0),
                }
                put_u32(&mut buf, l.revoked_jtis.len() as u32);
                for j in &l.revoked_jtis {
                    buf.extend_from_slice(j);
                }
            }
            None => put_u8(&mut buf, 0),
        }

        // Declared parameters
        put_u64(&mut buf, self.parameters.verification_time_ms);
        put_u64(&mut buf, self.parameters.health_max_age_ms);
        put_u64(&mut buf, self.parameters.window_tolerance_ms);
        put_u8(&mut buf, u8::from(self.parameters.agent_key_supplied));

        // Claim
        put_u8(&mut buf, Component::Claim.code());
        put_bytes(&mut buf, &self.claim.canonical_bytes());

        // Warrant
        put_u8(&mut buf, Component::Warrant.code());
        match &self.warrant {
            Some(w) => {
                put_u8(&mut buf, 1);
                put_bytes(&mut buf, &w.signing_preimage());
                match &w.signature {
                    Some(sig) => {
                        put_u8(&mut buf, 1);
                        put_signature(&mut buf, sig);
                    }
                    None => put_u8(&mut buf, 0),
                }
            }
            None => put_u8(&mut buf, 0),
        }

        // Commitment
        put_u8(&mut buf, Component::Commitment.code());
        match &self.commitment {
            Some(c) => {
                put_u8(&mut buf, 1);
                put_bytes(&mut buf, &c.canonical_bytes());
                put_signature(&mut buf, &c.head.signature);
            }
            None => put_u8(&mut buf, 0),
        }

        // AIRI (v2). Appended last so every field a v1 package encoded sits
        // at the same offset it always did; the version byte, not the
        // layout, is what tells the two apart.
        put_u8(&mut buf, Component::Airi.code());
        match &self.airi {
            Some(a) => {
                put_u8(&mut buf, 1);
                put_str(&mut buf, &a.agent_id);
                put_bytes(&mut buf, &a.agent_public_key);
                put_u32(&mut buf, a.events.len() as u32);
                for ev in &a.events {
                    // The event's own signing preimage, so the committed
                    // bytes are the bytes the agent signed — not a
                    // re-serialisation a verifier would have to trust.
                    put_bytes(&mut buf, &ev.signing_preimage());
                    put_signature(&mut buf, &ev.signature);
                }
            }
            None => put_u8(&mut buf, 0),
        }
        buf
    }

    /// The package's identity: SHA-256 of its canonical bytes. Independent
    /// of the container it travelled in.
    pub fn proof_id(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// Every fault in the package: what it cites but does not carry, and
    /// where its components disagree with each other.
    pub fn faults(&self) -> Vec<ProofFault> {
        let mut all: Vec<ProofFault> = self
            .structural_faults()
            .into_iter()
            .map(ProofFault::Structural)
            .collect();
        all.extend(self.binding_faults().into_iter().map(ProofFault::Binding));
        all
    }

    /// Whether the components agree with each other. **No signature is
    /// verified here**: this is the defence that still works on an unsealed
    /// package, and it is deliberately independent of the envelope.
    pub fn binding_faults(&self) -> Vec<BindingFault> {
        let mut f = Vec::new();

        if let Some(doc) = &self.subject.identity {
            if doc.id != self.subject.agent_id {
                f.push(BindingFault::IdentityIsNotTheSubject {
                    document_id: doc.id.clone(),
                    subject: self.subject.agent_id.clone(),
                });
            }
            if let Some(sig) = &doc.self_signature {
                unsupported(&mut f, sig, Component::Subject);
            }
        }

        // The authority must be the one the expectation names.
        if let (Some(a), Some(ee)) = (&self.authority, &self.expectation) {
            let chain_jtis: Vec<[u8; 16]> = a.chain.iter().map(|h| h.jti).collect();
            if a.root.jti != ee.authority.root_jti || chain_jtis != ee.authority.chain_jtis {
                f.push(BindingFault::AuthorityNotTheExpectations);
            }
            unsupported(&mut f, &a.root.issuer_sig, Component::Authority);
            for hop in &a.chain {
                unsupported(&mut f, &hop.issuer_sig, Component::Authority);
            }
        }
        if let Some(ee) = &self.expectation {
            unsupported(&mut f, &ee.decision_sig, Component::Expectation);
        }

        // Every observer record the claim cites must be the one carried.
        if let Some(o) = &self.observer {
            for r in &self.claim.evidence {
                match r {
                    EvidenceRef::Batch { sequence, head, .. } => {
                        match o.batches.iter().find(|b| b.sequence == sequence.0) {
                            None => f.push(BindingFault::CitedBatchNotCarried {
                                sequence: sequence.0,
                            }),
                            Some(b) if b.head() != *head => {
                                f.push(BindingFault::CitedBatchHeadMismatch {
                                    sequence: sequence.0,
                                })
                            }
                            Some(_) => {}
                        }
                    }
                    EvidenceRef::Health {
                        sequence,
                        emitted_at_ms,
                        ..
                    } => {
                        if o.health.health.sequence != sequence.0
                            || o.health.health.emitted_at_ms != *emitted_at_ms
                        {
                            f.push(BindingFault::CitedHealthNotCarried {
                                sequence: sequence.0,
                            });
                        }
                    }
                    _ => {}
                }
            }
            for b in &o.batches {
                unsupported(&mut f, &b.attestation, Component::Observer);
            }
            unsupported(&mut f, &o.health.attestation, Component::Observer);

            // A continuity report must be this observer's own record.
            if let Some(c) = &self.continuity {
                if c.report.observer_id != o.health.health.observer_id {
                    f.push(BindingFault::ContinuityForAnotherObserver {
                        report_observer: c.report.observer_id.clone(),
                        observer: o.health.health.observer_id.clone(),
                    });
                }
            }
        }
        if let Some(c) = &self.continuity {
            unsupported(&mut f, &c.signature, Component::Continuity);
        }

        // Lineage never names the subject as its own peer.
        if let Some(l) = &self.lineage {
            for peer in &l.peer_expectations {
                if peer.agent_id == self.subject.agent_id {
                    f.push(BindingFault::LineagePeerIsTheSubject {
                        agent_id: peer.agent_id.clone(),
                    });
                }
                unsupported(&mut f, &peer.decision_sig, Component::Lineage);
            }
        }

        // A warrant must rest on this record and name this subject.
        if let Some(w) = &self.warrant {
            if w.reconciliation_digest != self.claim.digest() {
                f.push(BindingFault::WarrantForAnotherRecord);
            }
            if w.subject_agent.as_deref() != Some(self.subject.agent_id.as_str()) {
                f.push(BindingFault::WarrantForAnotherSubject {
                    warrant_subject: w.subject_agent.clone(),
                    subject: self.subject.agent_id.clone(),
                });
            }
            if let Some(sig) = &w.signature {
                unsupported(&mut f, sig, Component::Warrant);
            }
        }

        // A commitment must commit this claim's bytes, as a reconciliation.
        if let Some(c) = &self.commitment {
            if c.kind != crate::merkle::LeafKind::Reconciliation
                || c.record != self.claim.canonical_bytes()
            {
                f.push(BindingFault::CommitmentIsNotOfTheClaim);
            }
            unsupported(&mut f, &c.head.signature, Component::Commitment);
        }
        f
    }

    /// What the claim cites that this package does not carry, and where the
    /// components it does carry disagree with each other. A fault is a
    /// statement about the package, not about the execution.
    pub fn structural_faults(&self) -> Vec<StructuralFault> {
        let mut faults = Vec::new();
        for r in &self.claim.evidence {
            match r {
                EvidenceRef::Expected { .. } | EvidenceRef::CoverageStatement { .. } => {
                    if self.expectation.is_none() {
                        push_once(
                            &mut faults,
                            StructuralFault::ClaimCitesExpectationNotCarried,
                        );
                    }
                }
                EvidenceRef::Batch { observer_id, .. }
                | EvidenceRef::Health { observer_id, .. } => {
                    if self.observer.is_none() {
                        push_once(
                            &mut faults,
                            StructuralFault::ClaimCitesObserverNotCarried {
                                observer_id: observer_id.0.clone(),
                            },
                        );
                    }
                }
                EvidenceRef::Observation { .. } | EvidenceRef::KernelEvent { .. } => {
                    if self.observer.is_none() {
                        push_once(
                            &mut faults,
                            StructuralFault::ClaimCitesObservationNotCarried,
                        );
                    }
                }
            }
        }
        if let Some(ee) = &self.expectation {
            if let Some(claimed) = &self.claim.decision_id {
                if claimed.as_bytes() != &ee.decision_id {
                    push_once(&mut faults, StructuralFault::ExpectationDecisionMismatch);
                }
            }
            if ee.agent_id != self.subject.agent_id {
                push_once(&mut faults, StructuralFault::SubjectNotTheExpectationsAgent);
            }
        }
        faults
    }
}

fn push_once(v: &mut Vec<StructuralFault>, f: StructuralFault) {
    if !v.contains(&f) {
        v.push(f);
    }
}

/// A disagreement inside the package itself. Never a statement about the
/// execution, and never a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuralFault {
    /// The claim rests on an expectation the package does not carry.
    ClaimCitesExpectationNotCarried,
    /// The claim rests on an observer's records the package does not carry.
    ClaimCitesObserverNotCarried { observer_id: String },
    /// The claim rests on an observation the package does not carry.
    ClaimCitesObservationNotCarried,
    /// The carried expectation is for a different decision than the claim.
    ExpectationDecisionMismatch,
    /// The package's subject is not the agent the expectation names.
    SubjectNotTheExpectationsAgent,
}

impl std::fmt::Display for StructuralFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A disagreement *between* the components a package carries. Detected
/// without verifying a single signature: a transplanted component stops
/// matching the digests, ids, sequences and heads the rest of the package
/// names. Never a statement about the execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingFault {
    /// The carried identity document is not the subject's.
    IdentityIsNotTheSubject {
        document_id: String,
        subject: String,
    },
    /// The carried authority is not the one the expectation was issued
    /// under: a different root, or a different chain of hops.
    AuthorityNotTheExpectations,
    /// The claim cites a batch at this sequence that the package does not
    /// carry.
    CitedBatchNotCarried { sequence: u64 },
    /// The package carries a batch at the cited sequence, but its
    /// recomputed head is not the one the claim cites.
    CitedBatchHeadMismatch { sequence: u64 },
    /// The claim cites a health record the package does not carry.
    CitedHealthNotCarried { sequence: u64 },
    /// The continuity report is another observer's record.
    ContinuityForAnotherObserver {
        report_observer: String,
        observer: String,
    },
    /// A lineage peer expectation is the subject's own: an agent cannot be
    /// its own parent, and lineage is never synthesised from self-report.
    LineagePeerIsTheSubject { agent_id: String },
    /// The warrant rests on a different reconciliation record.
    WarrantForAnotherRecord,
    /// The warrant names a different subject.
    WarrantForAnotherSubject {
        warrant_subject: Option<String>,
        subject: String,
    },
    /// The commitment does not commit this claim's canonical bytes under
    /// the reconciliation leaf kind.
    CommitmentIsNotOfTheClaim,
    /// A carried signature declares an algorithm this repository does not
    /// implement. Ed25519 is the only one; a package says so rather than
    /// checking foreign bytes as Ed25519 anyway.
    UnsupportedAlgorithm { component: Component },
}

impl std::fmt::Display for BindingFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Either kind of fault, for callers that want one list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofFault {
    Structural(StructuralFault),
    Binding(BindingFault),
}

impl std::fmt::Display for ProofFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofFault::Structural(x) => write!(f, "{x}"),
            ProofFault::Binding(x) => write!(f, "{x}"),
        }
    }
}

// ─── Encoding helpers ───

/// A signature envelope, every field of it, so two different signatures can
/// never encode alike.
fn put_signature(buf: &mut Vec<u8>, sig: &Signature) {
    put_u8(buf, algorithm_code(sig.algorithm));
    put_str(buf, &sig.signer_id);
    put_u64(buf, sig.timestamp);
    buf.extend_from_slice(&sig.nonce);
    buf.extend_from_slice(&sig.payload_hash);
    put_bytes(buf, &sig.signature_bytes);
}

/// Ed25519 is the only signature algorithm this repository implements. A
/// carried signature declaring anything else is recorded as a fault, never
/// verified as Ed25519 regardless.
fn unsupported(f: &mut Vec<BindingFault>, sig: &Signature, component: Component) {
    if sig.algorithm != aip_types::AlgorithmId::Ed25519 {
        let fault = BindingFault::UnsupportedAlgorithm { component };
        if !f.contains(&fault) {
            f.push(fault);
        }
    }
}

/// Explicit algorithm identifiers: a verifier refuses what it does not
/// implement rather than assuming Ed25519.
fn algorithm_code(a: aip_types::AlgorithmId) -> u8 {
    match a {
        aip_types::AlgorithmId::Ed25519 => 0x01,
        aip_types::AlgorithmId::MlDsa65 => 0x02,
        aip_types::AlgorithmId::Hybrid => 0x03,
    }
}

/// An identity document, bound by the bytes its own self-signature covers
/// plus that signature — the same rule as every other component.
fn put_identity(buf: &mut Vec<u8>, doc: &AgentIdentityDocument) {
    put_bytes(buf, &aip_core::identity_signing_payload(doc));
    match &doc.self_signature {
        Some(sig) => {
            put_u8(buf, 1);
            put_signature(buf, sig);
        }
        None => put_u8(buf, 0),
    }
}

// ─── Builder ───

/// Assembles a package. Every setter carries evidence; none of them can
/// state a result, a strength or a judgement.
#[derive(Debug, Clone)]
pub struct ProofBuilder {
    proof: NexoraProof,
}

impl ProofBuilder {
    pub fn issued_at(mut self, ms: u64) -> Self {
        self.proof.issued_at_ms = ms;
        self
    }

    pub fn identity(mut self, doc: AgentIdentityDocument) -> Self {
        self.proof.subject.identity = Some(doc);
        self
    }

    pub fn authority(mut self, root: ScopedToken, chain: Vec<DelegationToken>) -> Self {
        self.proof.authority = Some(AuthorityEvidence { root, chain });
        self
    }

    pub fn expectation(mut self, ee: aip_authorize::ExpectedExecution) -> Self {
        self.proof.expectation = Some(ee);
        self
    }

    pub fn observer(mut self, batches: Vec<AttestedBatch>, health: SignedSensorHealth) -> Self {
        self.proof.observer = Some(ObserverBundle { batches, health });
        self
    }

    pub fn continuity(mut self, report: SignedContinuityReport) -> Self {
        self.proof.continuity = Some(report);
        self
    }

    pub fn lineage(mut self, lineage: LineageEvidence) -> Self {
        self.proof.lineage = Some(lineage);
        self
    }

    pub fn parameters(mut self, p: DeclaredParameters) -> Self {
        self.proof.parameters = p;
        self
    }

    pub fn warrant(mut self, w: Warrant) -> Self {
        self.proof.warrant = Some(w);
        self
    }

    /// Attach the AI-stack events a reconciliation rested on.
    ///
    /// `agent_public_key` is what the package *says* signed them. A verifier
    /// holding its own anchor for this agent compares the two and the
    /// verifier's wins; carrying it here makes the package self-describing
    /// without making it self-authorising.
    pub fn airi(mut self, agent_id: String, agent_public_key: Vec<u8>, events: Vec<aip_airi::AiriEvent>) -> Self {
        self.proof.airi = Some(AiriBundle {
            agent_id,
            agent_public_key,
            events,
        });
        self
    }

    pub fn commitment(mut self, c: ProofObject) -> Self {
        self.proof.commitment = Some(c);
        self
    }

    pub fn build(self) -> NexoraProof {
        self.proof
    }
}

// ─── The assembler and its envelope ───

/// A party that packages proofs. Its key says who assembled a package —
/// nothing about whether the package's contents are true.
pub struct ProofAssembler {
    id: String,
    key_version: u32,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for ProofAssembler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofAssembler")
            .field("id", &self.id)
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl ProofAssembler {
    pub fn new(
        id: &str,
        key_version: u32,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, NexoraError> {
        if id.is_empty() {
            return Err(NexoraError::EmptySignerId);
        }
        if private_key.len() != 32 {
            return Err(NexoraError::InvalidKeyLength(private_key.len()));
        }
        if public_key.len() != 32 {
            return Err(NexoraError::InvalidKeyLength(public_key.len()));
        }
        Ok(Self {
            id: id.to_string(),
            key_version,
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Seal a package: sign its canonical bytes. Changes nothing else about
    /// it, and adds nothing to any component's standing.
    pub fn seal(&self, proof: NexoraProof) -> Result<NexoraProof, NexoraError> {
        self.seal_at(proof, 0)
    }

    pub fn seal_at(&self, mut proof: NexoraProof, at_ms: u64) -> Result<NexoraProof, NexoraError> {
        proof.envelope = None;
        let signature = sign_ed25519(
            &self.private_key,
            &self.id,
            &envelope_preimage(&proof, at_ms),
        )
        .map_err(NexoraError::Crypto)?;
        proof.envelope = Some(Envelope {
            assembler_id: self.id.clone(),
            key_version: self.key_version,
            sealed_at_ms: at_ms,
            signature,
        });
        Ok(proof)
    }
}

fn envelope_preimage(proof: &NexoraProof, sealed_at_ms: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    put_domain(&mut buf, PROOF_ENVELOPE_DOMAIN);
    put_u16(&mut buf, proof.version);
    put_u64(&mut buf, sealed_at_ms);
    put_bytes(&mut buf, &proof.canonical_bytes());
    buf
}

/// Verify an assembler's envelope. Success says *this party sealed exactly
/// these bytes*; it says nothing about the evidence inside, and a package
/// with no envelope is not less valid — it is unattributed packaging.
pub fn verify_envelope(
    proof: &NexoraProof,
    anchors: &NexoraTrustAnchors,
) -> Result<(), NexoraError> {
    let env = proof.envelope.as_ref().ok_or(NexoraError::EmptySignerId)?;
    let key = anchors
        .get(&env.assembler_id, env.key_version)
        .ok_or_else(|| NexoraError::UntrustedKey {
            signer_id: env.assembler_id.clone(),
            key_version: env.key_version,
        })?;
    if env.signature.signer_id != env.assembler_id {
        return Err(NexoraError::SignerMismatch);
    }
    let mut unsealed = proof.clone();
    unsealed.envelope = None;
    let preimage = envelope_preimage(&unsealed, env.sealed_at_ms);
    if env.signature.payload_hash != sha256(&preimage) {
        return Err(NexoraError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &env.signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(NexoraError::SignatureInvalid),
        Err(e) => Err(NexoraError::Crypto(e)),
    }
}
