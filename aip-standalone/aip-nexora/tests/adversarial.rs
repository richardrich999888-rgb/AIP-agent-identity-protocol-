//! Skill 10 Gate 12 — the dedicated adversarial suite (directive §12).
//!
//! Twenty attacks, A through T, each named by the directive and each
//! stating the exact invariant it protects. Nothing here is a happy path
//! with an inverted assertion: every case starts from the shared *real*
//! scenario — a real issuer delegating to a real agent, a real decision
//! point authorising, a real collector attesting kernel socket-state
//! events, and the repository's own reconciler drawing the verdict — and
//! then does to it what an attacker would.
//!
//! Two disciplines run through the whole file.
//!
//! **The verdict is re-derived, never read.** The verifier recomputes the
//! reconciliation from the package's own inputs under the verifier's own
//! anchors. So a tampered component does not have to be caught by a
//! signature check to be caught at all: it stops producing the claim the
//! package carries, and the package is refused for that reason.
//!
//! **Refusal is not the same as disproof.** Several cases end in
//! `CANNOT_PROVE`, `Unavailable` or `CannotEstablish`. Those are the right
//! answers. An attack that succeeds in destroying evidence has destroyed
//! evidence; it has not established that nothing happened, and this suite
//! asserts that the system says so rather than filling the hole.

mod common;

use aip_nexora::capability::VerifierCapability;
use aip_nexora::export::*;
use aip_nexora::proof::*;
use aip_nexora::replay::*;
use aip_nexora::verify::*;
use aip_reconcile::{EvidenceStrength, ReconciliationResult};

// ─── The package under attack, and the verifier that checks it ───

/// A full package over a scenario: everything a verifier could want, so
/// that every attack below has a component to reach for.
fn package(s: &common::Scenario) -> NexoraProof {
    NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .parameters(params(s))
        .build()
}

fn params(s: &common::Scenario) -> DeclaredParameters {
    DeclaredParameters {
        verification_time_ms: s.at,
        health_max_age_ms: common::HEALTH_MAX_AGE,
        window_tolerance_ms: 0,
        agent_key_supplied: true,
    }
}

/// The verifier's own anchors. Every field is a key this verifier chose to
/// trust; none of it comes from the package.
fn anchors(s: &common::Scenario) -> VerifierAnchors {
    VerifierAnchors {
        decision_point: s.a.dp_anchors.clone(),
        observer: s.o.anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: s.a.issuer_keys.clone(),
        agent_public_key: Some(s.a.agent_kp.public_key.clone()),
        capability: VerifierCapability::strict(),
        present_time_ms: None,
    }
}

/// Assert a package is refused, and hand back why so the case can say
/// which refusal it expected.
#[track_caller]
fn refused(v: &VerifiedProof) -> InvalidReason {
    match &v.verdict {
        ProofVerdict::Invalid(r) => r.clone(),
        ProofVerdict::Valid => panic!("the package was accepted; it must not be"),
    }
}

/// Whatever else a refusal does, it must never leave the verifier stating
/// a result or a strength: a refused package establishes nothing.
#[track_caller]
fn establishes_nothing(v: &VerifiedProof) {
    assert!(!v.is_valid());
    assert_eq!(v.result, None, "a refused package must state no result");
    assert_eq!(v.strength, None, "a refused package must state no strength");
}

// ═══════════════════════════════════════════════════════════════════
// A. Proof substitution
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: a package is the evidence of *one* execution, and its
/// identity is the canonical encoding of everything it carries. Presenting
/// one execution's package as another's changes `proof_id`, and the claim
/// inside names its own decision.
#[test]
fn a_proof_substitution_a_package_is_evidence_of_exactly_one_execution() {
    let s1 = common::verified_execution();
    let s2 = common::verified_execution();
    let p1 = package(&s1);
    let p2 = package(&s2);

    // Both are honest packages, and both verify — against their own
    // anchors. That is the attacker's starting material.
    assert!(verify_nexora_proof(&p1, &anchors(&s1)).is_valid());
    assert!(verify_nexora_proof(&p2, &anchors(&s2)).is_valid());

    // They are not interchangeable: different identity, different subject,
    // different decision.
    assert_ne!(p1.proof_id(), p2.proof_id());
    assert_ne!(p1.subject.agent_id, p2.subject.agent_id);
    assert_ne!(
        p1.claim.decision_id, p2.claim.decision_id,
        "each claim names the decision it is about"
    );

    // And substituting one for the other under the first verifier's anchors
    // does not pass: the second execution's decision point is not one this
    // verifier trusts.
    let v = verify_nexora_proof(&p2, &anchors(&s1));
    establishes_nothing(&v);
}

// ═══════════════════════════════════════════════════════════════════
// B. Commitment substitution
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: an inclusion proof is only evidence for the record it
/// commits. A valid commitment to *something else* is not a commitment to
/// this claim, and the mismatch is caught before any signature is checked.
#[test]
fn b_commitment_substitution_an_inclusion_proof_is_of_one_record_only() {
    let s1 = common::verified_execution();
    let s2 = common::verified_execution();
    // A genuine, verifiable commitment — to the *other* scenario's record.
    let (foreign_commitment, foreign_nexora) = common::commit(&s2.reconciliation);

    let p = NexoraProof::builder(s1.a.agent_id.clone(), s1.reconciliation.clone())
        .issued_at(s1.at + 1)
        .authority(s1.a.root.clone(), s1.a.chain.clone())
        .expectation(s1.a.ee.clone())
        .observer(s1.evidence.batches.clone(), s1.evidence.health.clone())
        .parameters(params(&s1))
        .commitment(foreign_commitment)
        .build();

    // Even with the foreign log's key anchored — the strongest form of the
    // attack — the binding fails.
    let mut a = anchors(&s1);
    a.nexora = foreign_nexora;
    let v = verify_nexora_proof(&p, &a);
    assert_eq!(
        refused(&v),
        InvalidReason::Binding(BindingFault::CommitmentIsNotOfTheClaim)
    );
    establishes_nothing(&v);
}

// ═══════════════════════════════════════════════════════════════════
// C. Evidence substitution
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: the claim is re-derived from the evidence the package
/// carries. Swapping in another collector's genuinely signed batches
/// changes what the reconciler produces, so the carried claim stops being
/// derivable — no signature has to break for the substitution to fail.
#[test]
fn c_evidence_substitution_another_runs_batches_do_not_support_this_claim() {
    let s1 = common::verified_execution();
    let s2 = common::verified_execution();
    let mut p = package(&s1);
    // s2's batches are real, correctly signed, and about another execution.
    p.observer = Some(ObserverBundle {
        batches: s2.evidence.batches.clone(),
        health: s2.evidence.health.clone(),
    });

    // Anchor *both* observers, so the attack does not merely fail on an
    // unknown key.
    let mut a = anchors(&s1);
    for (id, ver, key) in s2.o.anchors.entries() {
        a.observer = a.observer.trust(&id, ver, &key);
    }
    let v = verify_nexora_proof(&p, &a);
    establishes_nothing(&v);
    match refused(&v) {
        InvalidReason::Binding(_) | InvalidReason::ClaimNotDerivable { .. } => {}
        other => panic!("substituted evidence must break the binding, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════
// D. Identity substitution
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: the identity document a package carries must be the
/// subject's. A real, well-formed document for somebody else is not
/// evidence about this agent.
#[test]
fn d_identity_substitution_a_document_for_another_agent_is_not_the_subjects() {
    let s = common::verified_execution();
    let (other, _parent, _kp) = common::identity_lineage();
    assert_ne!(other.id, s.a.agent_id);
    let p = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .identity(other.clone())
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .parameters(params(&s))
        .build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(
        refused(&v),
        InvalidReason::Binding(BindingFault::IdentityIsNotTheSubject {
            document_id: other.id,
            subject: s.a.agent_id.clone(),
        })
    );
    establishes_nothing(&v);
}

// ═══════════════════════════════════════════════════════════════════
// E. Authority substitution
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: the authority a package carries must be the authority the
/// expectation was issued under. Another agent's perfectly valid, properly
/// signed token chain does not become this execution's warrant to act by
/// being placed beside it.
#[test]
fn e_authority_substitution_a_valid_chain_for_another_execution_is_refused() {
    let s1 = common::verified_execution();
    let s2 = common::verified_execution();
    let mut p = package(&s1);
    p.authority = Some(AuthorityEvidence {
        root: s2.a.root.clone(),
        chain: s2.a.chain.clone(),
    });
    // Anchor s2's issuers too: the chain itself is impeccable.
    let mut a = anchors(&s1);
    for (id, key) in &s2.a.issuer_keys {
        a.issuers.insert(id.clone(), key.clone());
    }
    let v = verify_nexora_proof(&p, &a);
    assert_eq!(
        refused(&v),
        InvalidReason::Binding(BindingFault::AuthorityNotTheExpectations)
    );
    establishes_nothing(&v);
}

// ═══════════════════════════════════════════════════════════════════
// F. Expected-execution substitution
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: the expectation must be the one the claim is about. A
/// decision point's genuine signature over a *different* authorisation
/// does not transfer to this record.
#[test]
fn f_expected_execution_substitution_the_claim_names_its_own_decision() {
    let s1 = common::verified_execution();
    let s2 = common::verified_execution();
    let mut p = package(&s1);
    p.expectation = Some(s2.a.ee.clone());
    let mut a = anchors(&s1);
    for (id, key) in s2.a.dp_anchors.entries() {
        a.decision_point = a.decision_point.trust(&id, &key);
    }
    let v = verify_nexora_proof(&p, &a);
    assert_eq!(
        refused(&v),
        InvalidReason::Structural(StructuralFault::ExpectationDecisionMismatch)
    );
    establishes_nothing(&v);
}

// ═══════════════════════════════════════════════════════════════════
// G. Observation substitution
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: a batch is signed over its contents. Editing one kernel
/// event inside an otherwise genuine batch breaks the collector's
/// signature, and the observer component becomes `Unverifiable` — never
/// `Absent`, because a broken record is not a missing one.
#[test]
fn g_observation_substitution_an_edited_event_breaks_the_collectors_signature() {
    let s = common::verified_execution();
    let mut p = package(&s);
    let bundle = p.observer.as_mut().unwrap();
    // Move the observed window by one millisecond. Nothing else changes.
    bundle.batches[1].batch.claimed_to_ms += 1;

    let v = verify_nexora_proof(&p, &anchors(&s));
    establishes_nothing(&v);
    match v.observer {
        ComponentVerdict::Unverifiable(_) => {}
        other => panic!("an edited batch must be unverifiable, got {other:?}"),
    }
    // And specifically not treated as absent.
    assert_ne!(v.observer, ComponentVerdict::Absent);
}

// ═══════════════════════════════════════════════════════════════════
// H. Lineage substitution
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: lineage is never synthesised. An agent cannot be its own
/// parent, and an unrelated pair of documents does not become a lineage by
/// being carried together — the standing says `Unavailable`,
/// `Incomplete` or `Contradicted`, never a link.
#[test]
fn h_lineage_substitution_a_carried_pair_is_not_by_itself_a_link() {
    let s = common::verified_execution();

    // H1 — the subject offered as its own lineage peer.
    let mut p = package(&s);
    p.lineage = Some(LineageEvidence {
        peer_expectations: vec![s.a.ee.clone()],
        identity: None,
        revoked_jtis: vec![],
    });
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(
        refused(&v),
        InvalidReason::Binding(BindingFault::LineagePeerIsTheSubject {
            agent_id: s.a.agent_id.clone(),
        })
    );
    establishes_nothing(&v);

    // H2 — two unrelated real identity documents presented as parent and
    // child. Neither is signed into a relationship with the other.
    let (child, _real_parent, _kp) = common::identity_lineage();
    let (stranger, _p2, _k2) = common::identity_lineage();
    let mut p = package(&s);
    p.lineage = Some(LineageEvidence {
        peer_expectations: vec![],
        identity: Some((child, stranger)),
        revoked_jtis: vec![],
    });
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(
        !v.lineage_report.identity.asserts_a_link(),
        "unrelated documents must not establish identity lineage, got {:?}",
        v.lineage_report.identity
    );
    // No process lineage was carried, so none may be asserted. Authority
    // lineage is a different matter and deliberately not asserted against
    // here: this package carries a real, verified issuer→grantee chain, so
    // a verified authority link is the true answer and substituting the
    // identity documents does not touch it. The three kinds are separate
    // exactly so that forging one cannot borrow another's standing.
    assert!(!v.lineage_report.process.asserts_a_link());
}

// ═══════════════════════════════════════════════════════════════════
// I. Continuity rollback
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: a collector that reports a rollback of its own record has
/// reported a break, and a break is never read as continuity. Every
/// variant of `ContinuityBreak` — including the rollback the directive
/// names — must leave the standing not asserting an unbroken chain.
#[test]
fn i_continuity_rollback_a_reported_break_never_reads_as_continuous() {
    let s = common::verified_execution();
    for brk in common::every_continuity_break() {
        let mut p = package(&s);
        p.continuity = Some(common::continuity_report_for(
            common::OBSERVER_ID,
            &s.o,
            brk.clone(),
        ));
        let v = verify_nexora_proof(&p, &anchors(&s));
        assert!(
            !v.continuity_standing.asserts_unbroken(),
            "{brk:?} must not read as an unbroken record, got {:?}",
            v.continuity_standing
        );
        assert_eq!(v.continuity_standing, ContinuityStanding::Discontinuous);
    }
}

// ═══════════════════════════════════════════════════════════════════
// J. Proof replay
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: verification is a pure function of a package and a set of
/// anchors, so replaying a proof cannot change what it establishes; and a
/// duplicate submission is a fact about submissions, recorded by the
/// consumer, that never becomes authority to act.
#[test]
fn j_proof_replay_a_second_submission_changes_nothing_and_grants_nothing() {
    let s = common::verified_execution();
    let p = package(&s);
    let a = anchors(&s);

    let first = verify_nexora_proof(&p, &a);
    assert!(first.is_valid());

    let mut ledger = MemoryProofLedger::default();
    assert_eq!(
        record_submission(&mut ledger, &first).unwrap(),
        ReplayStanding::FirstSeen
    );
    let second = verify_nexora_proof(&p, &a);
    assert_eq!(
        first, second,
        "replay must not change a deterministic verdict"
    );
    match record_submission(&mut ledger, &second).unwrap() {
        ReplayStanding::DuplicateSubmission { first_seen_count } => {
            assert_eq!(first_seen_count, 1)
        }
        other => panic!("a second submission must be a duplicate, got {other:?}"),
    }
    // The proof is no less true for having been shown twice.
    assert!(second.is_valid());
    assert_eq!(second.result, Some(ReconciliationResult::VerifiedExecution));
    // And no standing anywhere grants anything now.
    assert!(!second.authority_standing.grants_authority_now());
}

// ═══════════════════════════════════════════════════════════════════
// K. Cross-protocol proof reuse
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: every signed structure is domain-separated, so a signature
/// made for one purpose is not a valid signature for another. A signature
/// lifted from one component and dropped into another does not verify.
#[test]
fn k_cross_protocol_reuse_a_signature_does_not_travel_between_purposes() {
    // The domains themselves are distinct, which is what makes the rest
    // possible.
    let domains = [
        aip_nexora::PROOF_BUNDLE_DOMAIN,
        aip_nexora::PROOF_ENVELOPE_DOMAIN,
        aip_nexora::HEAD_DOMAIN,
        aip_nexora::PROOF_DOMAIN,
        aip_nexora::LEAF_DOMAIN,
    ];
    let mut seen: Vec<&str> = domains.to_vec();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), domains.len(), "domains must be distinct");

    let s = common::verified_execution();
    let (commitment, nexora_anchors) = common::commit(&s.reconciliation);

    // Seal a package, then transplant the *head's* signature into the
    // envelope. Both were made by NEXORA-side keys over canonical bytes;
    // only the domain separates them.
    let kp = aip_crypto::generate_ed25519_keypair();
    let assembler = ProofAssembler::new("assembler-1", 1, &kp.private_key, &kp.public_key).unwrap();
    let sealed = assembler
        .seal_at(
            NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
                .issued_at(s.at + 1)
                .authority(s.a.root.clone(), s.a.chain.clone())
                .expectation(s.a.ee.clone())
                .observer(s.evidence.batches.clone(), s.evidence.health.clone())
                .parameters(params(&s))
                .commitment(commitment.clone())
                .build(),
            s.at + 2,
        )
        .unwrap();

    let mut a = anchors(&s);
    a.nexora = nexora_anchors.trust("assembler-1", 1, &kp.public_key);
    assert!(
        verify_nexora_proof(&sealed, &a).is_valid(),
        "the honest sealed package must verify first"
    );

    let mut attacked = sealed.clone();
    attacked.envelope.as_mut().unwrap().signature = commitment.head.signature.clone();
    let v = verify_nexora_proof(&attacked, &a);
    establishes_nothing(&v);
    match v.envelope {
        ComponentVerdict::Unverifiable(_) => {}
        other => panic!("a transplanted signature must not verify, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════
// L. Cross-agent proof transplantation
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: the subject of a package is the agent the expectation names.
/// Relabelling somebody else's verified execution as your own is caught
/// structurally, before any key is consulted.
#[test]
fn l_cross_agent_transplantation_a_relabelled_subject_is_refused() {
    let s = common::verified_execution();
    let other = common::verified_execution();
    let mut p = package(&s);
    p.subject.agent_id = other.a.agent_id.clone();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(
        refused(&v),
        InvalidReason::Structural(StructuralFault::SubjectNotTheExpectationsAgent)
    );
    establishes_nothing(&v);
}

// ═══════════════════════════════════════════════════════════════════
// M. Stale proof acceptance
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: a proof is a statement about the past, and the past does not
/// expire. A closed authority window neither invalidates the proof nor
/// silently reads as current permission — the verifier reports staleness
/// as its own fact, and no value of it grants anything.
#[test]
fn m_stale_proof_is_still_true_and_is_still_not_authority() {
    let s = common::verified_execution();
    let p = package(&s);
    let valid_until = s.a.ee.valid_until;

    // Long after the window closed.
    let mut later = anchors(&s);
    later.present_time_ms = Some(valid_until + 10_000_000);
    let v = verify_nexora_proof(&p, &later);
    assert!(
        v.is_valid(),
        "what happened does not stop having happened: {:?}",
        v.verdict
    );
    assert_eq!(v.result, Some(ReconciliationResult::VerifiedExecution));
    assert_eq!(
        v.authority_standing,
        AuthorityStanding::StaleSince { valid_until }
    );
    assert!(!v.authority_standing.grants_authority_now());

    // Inside the window, the answer is different — and still not authority.
    let mut inside = anchors(&s);
    inside.present_time_ms = Some(valid_until - 1);
    let v = verify_nexora_proof(&p, &inside);
    assert_eq!(v.authority_standing, AuthorityStanding::ValidNow);
    assert!(!v.authority_standing.grants_authority_now());

    // With no present time supplied, staleness is not assessed — and that
    // is reported, not defaulted to "still valid".
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(v.authority_standing, AuthorityStanding::NotAssessed);
    assert!(!v.authority_standing.grants_authority_now());

    // Every variant answers the same way when asked for permission.
    for st in AuthorityStanding::ALL {
        assert!(!st.grants_authority_now(), "{st:?} must grant nothing");
    }
}

// ═══════════════════════════════════════════════════════════════════
// N. Verifier-context substitution
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: the package declares the parameters its reconciliation ran
/// under, and the verifier decides whether it will accept them. A package
/// cannot widen a verifier's tolerance, and anchors that travel beside a
/// proof never carry the verifier's own judgement.
#[test]
fn n_verifier_context_substitution_a_package_cannot_set_the_verifiers_terms() {
    let s = common::verified_execution();

    // A package reconciled under a very stale health tolerance, offered to
    // a verifier that bounds it.
    let mut p = package(&s);
    p.parameters.health_max_age_ms = 30 * 24 * 3_600_000;
    let mut a = anchors(&s);
    a.capability = a
        .capability
        .clone()
        .max_health_age_ms(common::HEALTH_MAX_AGE);
    let v = verify_nexora_proof(&p, &a);
    match refused(&v) {
        InvalidReason::DeclaredParameterRefused {
            parameter,
            declared,
            max_accepted,
        } => {
            assert_eq!(parameter, "health_max_age_ms");
            assert_eq!(declared, 30 * 24 * 3_600_000);
            assert_eq!(max_accepted, common::HEALTH_MAX_AGE);
        }
        other => panic!("a widened parameter must be refused by name, got {other:?}"),
    }
    establishes_nothing(&v);

    // The same for the window tolerance.
    let mut p = package(&s);
    p.parameters.window_tolerance_ms = 86_400_000;
    let mut a = anchors(&s);
    a.capability = a.capability.clone().max_window_tolerance_ms(0);
    match refused(&verify_nexora_proof(&p, &a)) {
        InvalidReason::DeclaredParameterRefused { parameter, .. } => {
            assert_eq!(parameter, "window_tolerance_ms")
        }
        other => panic!("a widened tolerance must be refused by name, got {other:?}"),
    }

    // Anchors shipped beside a proof carry keys and nothing else: no
    // bounds, and no opinion about what time it is.
    let mut source = anchors(&s);
    source.capability = VerifierCapability::strict()
        .max_health_age_ms(1)
        .max_window_tolerance_ms(2);
    source.present_time_ms = Some(3);
    // The importing verifier supplies its own capability; nothing in the
    // file contributes to it, so the source's bounds simply do not arrive.
    let mine = VerifierCapability::strict().max_health_age_ms(999);
    let imported = import_anchors(&export_anchors(&source).unwrap(), mine.clone()).unwrap();
    assert_eq!(
        imported.capability, mine,
        "the importer's own terms, unchanged"
    );
    assert_ne!(imported.capability, source.capability);
    assert_eq!(imported.present_time_ms, None);
    // There is no bound field in the anchor file at all, so there is
    // nothing for a forger to put one in.
    let text = String::from_utf8(export_anchors(&source).unwrap()).unwrap();
    for word in [
        "max_health",
        "capability",
        "window_tolerance",
        "present_time",
    ] {
        assert!(
            !text.contains(word),
            "{word} is stateable in an anchor file"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// O. Malformed package
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: bytes that are not a package are refused as such, and a
/// format version this build does not implement is named rather than
/// parsed for whatever happens to fit.
#[test]
fn o_malformed_package_is_refused_rather_than_partially_believed() {
    for bad in [
        &b""[..],
        b"{",
        b"not json at all",
        b"{\"version\":1}",
        b"[]",
        b"null",
    ] {
        assert!(
            import_proof(bad).is_err(),
            "{bad:?} must not import as a proof"
        );
    }

    let s = common::verified_execution();
    let p = package(&s);
    let bytes = export_proof(&p).unwrap();

    // Truncation at every quarter: a partially-read package is never a
    // package.
    for cut in [bytes.len() / 4, bytes.len() / 2, bytes.len() * 3 / 4] {
        assert!(import_proof(&bytes[..cut]).is_err());
    }

    // A future format version is named, not guessed at.
    let mut future = p.clone();
    future.version = NEXORA_PROOF_VERSION + 1;
    match import_proof(&export_proof(&future).unwrap()) {
        Err(ExportError::UnsupportedVersion(v)) => assert_eq!(v, NEXORA_PROOF_VERSION + 1),
        other => panic!("a future version must be named, got {other:?}"),
    }
    // And a package that reached the verifier at an unimplemented version
    // is refused there too, rather than checked with this build's rules.
    assert_eq!(
        refused(&verify_nexora_proof(&future, &anchors(&s))),
        InvalidReason::UnsupportedVersion(NEXORA_PROOF_VERSION + 1)
    );
}

// ═══════════════════════════════════════════════════════════════════
// P. Partial package
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: a claim that rests on evidence the package does not carry
/// cannot be checked, and is refused for naming what is missing. Dropping
/// the inconvenient half of a package is not a way to make it verify.
#[test]
fn p_partial_package_a_claim_cannot_rest_on_what_was_not_shipped() {
    let s = common::verified_execution();

    // The observer bundle removed, the claim left citing it.
    let mut p = package(&s);
    p.observer = None;
    let v = verify_nexora_proof(&p, &anchors(&s));
    establishes_nothing(&v);
    match refused(&v) {
        InvalidReason::Structural(StructuralFault::ClaimCitesObserverNotCarried { .. })
        | InvalidReason::Structural(StructuralFault::ClaimCitesObservationNotCarried) => {}
        other => panic!("a missing observer must be named, got {other:?}"),
    }

    // The expectation removed.
    let mut p = package(&s);
    p.expectation = None;
    let v = verify_nexora_proof(&p, &anchors(&s));
    establishes_nothing(&v);
    assert_eq!(
        refused(&v),
        InvalidReason::Structural(StructuralFault::ClaimCitesExpectationNotCarried)
    );

    // A carried component that cannot be checked is not the same as an
    // absent one, and neither is silently passed over.
    let mut p = package(&s);
    p.observer.as_mut().unwrap().batches.pop();
    let v = verify_nexora_proof(&p, &anchors(&s));
    establishes_nothing(&v);
}

// ═══════════════════════════════════════════════════════════════════
// Q. Missing observation
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: absence of evidence is never evidence of absence. With no
/// observation at all the answer is `CANNOT_PROVE`, coverage is
/// `CannotEstablish`, and nothing licenses a statement that the execution
/// did not happen. `PHANTOM_CLAIM` requires attested coverage of the
/// window, which is a different thing entirely.
#[test]
fn q_missing_observation_is_cannot_prove_and_never_a_phantom_claim() {
    let s = common::cannot_prove();
    let p = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .parameters(params(&s))
        .build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(v.is_valid(), "{:?}", v.verdict);
    assert_eq!(v.result, Some(ReconciliationResult::CannotProve));
    assert_ne!(v.result, Some(ReconciliationResult::PhantomClaim));
    assert_eq!(v.coverage.observation, ObservationCoverage::CannotEstablish);
    assert!(
        !v.coverage.observation.licenses_absence_claim(),
        "no observation must never license an absence claim"
    );
    assert_eq!(v.observer, ComponentVerdict::Absent);

    // Exactly one coverage state may speak of absence, and it is not this
    // one — nor loss.
    let lossy = common::with_loss();
    let lp = package(&lossy);
    let lv = verify_nexora_proof(&lp, &anchors(&lossy));
    assert!(!lv.coverage.observation.licenses_absence_claim());
    assert_eq!(
        ObservationCoverage::ALL
            .iter()
            .filter(|c| c.licenses_absence_claim())
            .count(),
        1
    );
}

// ═══════════════════════════════════════════════════════════════════
// R. Conflicting observation
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: evidence the claim was not drawn over cannot be added to a
/// package after the fact. A verifier re-derives from what it is given, so
/// appending a genuine extra batch makes the carried claim stop matching —
/// the conflict is refused rather than absorbed.
#[test]
fn r_conflicting_observation_extra_evidence_is_not_silently_absorbed() {
    let s = common::verified_execution();
    let other = common::verified_execution();
    let mut p = package(&s);
    // A real, correctly signed batch from another run, appended to this
    // package's bundle: the claim was never drawn over it.
    let extra = other.evidence.batches[1].clone();
    p.observer.as_mut().unwrap().batches.push(extra);

    let mut a = anchors(&s);
    for (id, ver, key) in other.o.anchors.entries() {
        a.observer = a.observer.trust(&id, ver, &key);
    }
    let v = verify_nexora_proof(&p, &a);
    establishes_nothing(&v);
}

// ═══════════════════════════════════════════════════════════════════
// S. Forged coverage
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: coverage is derived by the verifier from the collector's
/// signed records, never read from the package. A package has no field in
/// which to assert coverage, and the collector's own signed statement is
/// what the derivation rests on.
#[test]
fn s_forged_coverage_the_verifier_derives_it_and_the_package_cannot_state_it() {
    let s = common::verified_execution();
    let p = package(&s);
    let json = serde_json::to_string(&p).unwrap();

    // The verifier's coverage vocabulary appears nowhere in a package:
    // there is no field to forge.
    for word in [
        "AvailableAndEmpty",
        "CannotEstablish",
        "licenses_absence",
        "observation_coverage",
    ] {
        assert!(!json.contains(word), "{word} is stateable in a package");
    }
    // What *is* carried is the collector's own signed attestation, which
    // the derivation reads.
    assert!(
        json.contains("attested_coverage"),
        "the collector's signed statement must be what coverage rests on"
    );

    // A lossy window cannot be presented as a covered one: the loss is
    // inside the collector's signature, so raising it is not available.
    let lossy = common::with_loss();
    let lv = verify_nexora_proof(&package(&lossy), &anchors(&lossy));
    assert_ne!(
        lv.coverage.observation,
        ObservationCoverage::AvailableAndEmpty
    );

    // And a package whose evidence was edited to remove the loss stops
    // deriving its claim rather than gaining coverage.
    let mut forged = package(&lossy);
    forged.observer.as_mut().unwrap().batches[1]
        .batch
        .dropped_events = Some(0);
    establishes_nothing(&verify_nexora_proof(&forged, &anchors(&lossy)));
}

// ═══════════════════════════════════════════════════════════════════
// T. Altered verdict
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: the carried result and strength are re-derived, never
/// trusted. `CANNOT_PROVE` cannot be promoted to a verified execution, and
/// `Attested` cannot be raised to `Proven`, by editing the package — in
/// transit or after import. A record that came off the wire is also not
/// engine-produced, and the warrant engine refuses it.
#[test]
fn t_altered_verdict_cannot_prove_never_becomes_proven() {
    let weak = common::cannot_prove();
    let strong = common::verified_execution();

    // T1 — promote the result in flight, then import.
    let mut p = NexoraProof::builder(weak.a.agent_id.clone(), weak.reconciliation.clone())
        .issued_at(weak.at + 1)
        .authority(weak.a.root.clone(), weak.a.chain.clone())
        .expectation(weak.a.ee.clone())
        .parameters(params(&weak))
        .build();
    assert!(verify_nexora_proof(&p, &anchors(&weak)).is_valid());
    p.claim.result = ReconciliationResult::VerifiedExecution;
    p.claim.strength = EvidenceStrength::Proven;
    let round_tripped = import_proof(&export_proof(&p).unwrap()).unwrap();
    let v = verify_nexora_proof(&round_tripped, &anchors(&weak));
    establishes_nothing(&v);
    match refused(&v) {
        InvalidReason::ClaimNotDerivable { claimed, rederived } => {
            assert_ne!(claimed, rederived)
        }
        other => panic!("a promoted verdict must not be derivable, got {other:?}"),
    }

    // T2 — raise only the strength on a genuinely verified execution.
    let mut p = package(&strong);
    assert_eq!(p.claim.strength, EvidenceStrength::Attested);
    p.claim.strength = EvidenceStrength::Proven;
    let v = verify_nexora_proof(&p, &anchors(&strong));
    establishes_nothing(&v);

    // T3 — the honest package still reports the strength the engine drew,
    // and the verifier's own re-derivation, never the carried one.
    let v = verify_nexora_proof(&package(&strong), &anchors(&strong));
    assert_eq!(v.strength, Some(EvidenceStrength::Attested));
    assert_ne!(v.strength, Some(EvidenceStrength::Proven));

    // T4 — a record that arrived over the wire is not engine-produced, and
    // the warrant engine refuses to rest on it (audit §14).
    let imported = import_proof(&export_proof(&package(&strong)).unwrap()).unwrap();
    assert!(
        !imported.claim.is_engine_produced(),
        "a deserialized record must not pass as engine-produced"
    );
    let finding = aip_warrant::Finding {
        finding_id: [0xd4; 16],
        reconciliation: imported.claim.clone(),
        subject_agent: Some(strong.a.agent_id.clone()),
    };
    match aip_warrant::evaluate(
        &finding,
        &aip_warrant::WarrantPolicy::default(),
        imported.claim.verification_time_ms + 1,
    ) {
        Err(aip_warrant::Refusal::ReconciliationNotEngineProduced) => {}
        other => panic!("a deserialized record must not warrant anything, got {other:?}"),
    }

    // T5 — and the verifier's own re-derivation *is* engine-produced, so
    // the pipeline has a legitimate path that the wire does not.
    assert!(v.rederived.as_ref().unwrap().is_engine_produced());
}

// ═══════════════════════════════════════════════════════════════════
// U. Revoked authority  (Skill 10 Gate 12 item 16)
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: revocation is the verifier's operator's declaration, carried
/// beside the evidence and applied by the re-derivation. A chain whose root
/// or any hop has been revoked stops supporting an authority link — the
/// signatures are still perfectly valid, and that is precisely the point:
/// a revoked token is not a forged one, it is a real one that no longer
/// counts.
#[test]
fn u_revoked_authority_a_valid_chain_stops_conferring_a_link() {
    let s = common::verified_execution();

    let authority = aip_reconcile::DecisionAuthority {
        root: s.a.root.clone(),
        chain: s.a.chain.clone(),
    };
    // The honest package, with lineage evidence and nothing revoked.
    let inputs = aip_reconcile::LineageInputs {
        peer_expectations: &[],
        authority: Some(&authority),
        issuer_keys: &s.a.issuer_keys,
        revoked_jtis: &[],
        identity: None,
    };
    let honest = aip_reconcile::reconcile_lineage(&s.a.ee, Some(&s.evidence), &s.ctx(), &inputs);
    let mut p = package(&s);
    p.claim = honest;
    p.lineage = Some(LineageEvidence {
        peer_expectations: vec![],
        identity: None,
        revoked_jtis: vec![],
    });
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(v.is_valid(), "{:?}", v.verdict);
    assert!(
        v.lineage_report.authority.asserts_a_link(),
        "the unrevoked chain must establish an authority link, got {:?}",
        v.lineage_report.authority
    );

    // Now the operator revokes the delegation hop. Same signatures, same
    // chain, same keys — and the link is gone.
    for revoked in [s.a.root.jti, s.a.chain[0].jti] {
        let inputs = aip_reconcile::LineageInputs {
            peer_expectations: &[],
            authority: Some(&authority),
            issuer_keys: &s.a.issuer_keys,
            revoked_jtis: &[revoked],
            identity: None,
        };
        let claim = aip_reconcile::reconcile_lineage(&s.a.ee, Some(&s.evidence), &s.ctx(), &inputs);
        let mut p = package(&s);
        p.claim = claim;
        p.lineage = Some(LineageEvidence {
            peer_expectations: vec![],
            identity: None,
            revoked_jtis: vec![revoked],
        });
        let v = verify_nexora_proof(&p, &anchors(&s));
        assert!(
            !v.lineage_report.authority.asserts_a_link(),
            "a revoked token still conferred authority lineage, got {:?}",
            v.lineage_report.authority
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// V. Revoked observer  (Skill 10 Gate 12 item 17)
// ═══════════════════════════════════════════════════════════════════

/// INVARIANT: an observer is trusted because the verifier anchors its key,
/// so revocation is withdrawing that anchor. The package does not change;
/// what changes is who the verifier is willing to believe. The result is
/// `Unverifiable` and a refusal — never `Absent`, because the records were
/// carried, and never a quiet pass because they look well-formed.
#[test]
fn v_revoked_observer_withdrawing_the_anchor_withdraws_the_evidence() {
    let s = common::verified_execution();
    let p = package(&s);
    assert!(verify_nexora_proof(&p, &anchors(&s)).is_valid());

    // V1 — the anchor withdrawn entirely.
    let mut a = anchors(&s);
    a.observer = aip_observe::ObserverTrustAnchors::new();
    let v = verify_nexora_proof(&p, &a);
    establishes_nothing(&v);
    match v.observer {
        ComponentVerdict::Unverifiable(_) => {}
        other => panic!("a revoked observer must be unverifiable, got {other:?}"),
    }
    assert_ne!(v.observer, ComponentVerdict::Absent);

    // V2 — the key rotated: the verifier now anchors a *different* version,
    // so records signed under the old one are no longer believed.
    let fresh = aip_crypto::generate_ed25519_keypair();
    let mut a = anchors(&s);
    a.observer =
        aip_observe::ObserverTrustAnchors::new().trust(common::OBSERVER_ID, 2, &fresh.public_key);
    let v = verify_nexora_proof(&p, &a);
    establishes_nothing(&v);
    assert_ne!(v.observer, ComponentVerdict::Absent);

    // V3 — and the coverage that rested on those records goes with them.
    assert!(
        !v.coverage.observation.licenses_absence_claim(),
        "a revoked observer's records must not license an absence claim"
    );
}

// ═══ Mutation-driven regression ═══

/// N-22. I10, verifier side: an observer whose *anchored key is the agent's
/// own key* is not an independent observer, and the check holds on the
/// health record as well as on each batch.
///
/// Why this needed its own test. Every batch runs through
/// `verify_attested_batch_independent_of_agent`, which makes the same
/// refusal, so with batches present the health-level check is shadowed and
/// deleting it changed no result in this suite. The arrangement that
/// reaches it is a package whose claim cites no batch — a reconciliation
/// that ran with no observer evidence — carrying an observer bundle that is
/// a health record and nothing else.
///
/// That is not a contrived shape. It is what an attacker would assemble:
/// strip the batches so the per-batch guard never runs, keep a health record
/// signed by the agent itself, and present the agent as its own witness.
#[test]
fn w_the_agent_as_its_own_observer_is_refused_on_the_health_record_alone() {
    let s = common::verified_execution();

    // A reconciliation that ran with no observer evidence: CANNOT_PROVE, and
    // its evidence cites the expectation only — no batch, so the binding gate
    // has nothing to demand and the observer component is actually reached.
    let claim = aip_reconcile::reconcile_expectation(&s.a.ee, None, &s.ctx());
    assert_eq!(claim.result, ReconciliationResult::CannotProve);

    // The health record, re-signed under the agent's own private key, and the
    // observer id anchored to the agent's own public key. Everything about it
    // verifies; that is the point.
    let agent_pub = s.a.agent_kp.public_key.clone();
    let mut health = s.evidence.health.clone();
    health.attestation = aip_crypto::sign_ed25519(
        &s.a.agent_kp.private_key,
        &health.health.observer_id,
        &health.health.canonical_bytes(),
    )
    .unwrap();

    let p = NexoraProof::builder(s.a.agent_id.clone(), claim)
        .issued_at(s.at + 1)
        .expectation(s.a.ee.clone())
        .observer(vec![], health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build();

    let mut a = anchors(&s);
    a.observer = aip_observe::ObserverTrustAnchors::new().trust(
        &health.health.observer_id,
        health.health.key_version,
        &agent_pub,
    );

    let v = verify_nexora_proof(&p, &a);
    assert!(
        matches!(
            &v.observer,
            ComponentVerdict::Unverifiable(r) if r.contains("the agent's own key")
        ),
        "the agent may not witness for itself: {:?}",
        v.observer
    );
    assert!(matches!(v.verdict, ProofVerdict::Invalid(_)), "{v:#?}");
    establishes_nothing(&v);
}
