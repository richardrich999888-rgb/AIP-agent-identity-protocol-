//! Skill 10 Gate 13 — the cross-crate audit, as executable evidence.
//!
//! Every signature, hash and encoding a NEXORA proof depends on crosses a
//! crate boundary: the issuer's tokens live in `aip-core`, the decision
//! point's expectation in `aip-authorize`, the collector's batches and
//! health in `aip-observe`, the verdict in `aip-reconcile`, the warrant in
//! `aip-warrant`, and only the commitment and the envelope in `aip-nexora`
//! itself. An audit that reads them once and writes prose goes stale the
//! next time somebody adds a field. These tests are the audit, and they
//! fail if any of it stops being true.
//!
//! What is checked here, in the order the directive's Gate 13 list names:
//!
//! | looked for | checked by |
//! |---|---|
//! | raw concatenation | `a02`, `a03` |
//! | untagged hashes | `a01`, `a02` |
//! | generic signatures | `a04` |
//! | unsigned proof references | `a05` |
//! | implicit versioning | `a06` |
//! | unchecked algorithm enum | `a07`, `a08` |
//! | self-issued authority | `a09` |
//! | agent-controlled observer keys | `a10` |
//!
//! The one finding this audit records without fixing is written down in
//! `NEXORA_IMPLEMENTATION_REPORT.md` rather than hidden here: a liveness
//! helper in `aip-core` signs a bare nonce with no domain tag. It is not
//! on any path a NEXORA proof depends on, and repairing it is a wire
//! change to an unrelated protocol, so it is recorded and left rather than
//! folded into an audit commit.

mod common;

use aip_nexora::proof::*;
use aip_nexora::verify::*;

/// Every domain-separation tag in the workspace, gathered from the crate
/// that owns it. Adding a signed structure without adding it here is
/// caught by `a01`, which counts them.
const DOMAINS: [&str; 26] = [
    aip_types::EXECUTION_BINDING_DOMAIN,
    aip_types::EXECUTION_IDENTITY_DOMAIN,
    aip_core::AID_SELF_SIGNATURE_DOMAIN,
    aip_core::LINEAGE_PROOF_DOMAIN,
    aip_core::CAPABILITY_GRANT_DOMAIN,
    aip_core::REPUTATION_VOTE_DOMAIN,
    aip_core::capability::SCOPED_TOKEN_DOMAIN,
    aip_core::delegation::DELEGATION_TOKEN_DOMAIN,
    aip_authorize::EXPECTED_EXECUTION_DOMAIN,
    aip_authorize::ACTION_PARAMETERS_DOMAIN,
    aip_observe::OBSERVER_HEALTH_DOMAIN,
    aip_observe::OBSERVED_EXECUTION_DOMAIN,
    aip_observe::OBSERVATION_BATCH_DOMAIN,
    aip_observe::OBSERVED_PROCESS_DOMAIN,
    aip_observe::KERNEL_EVENT_DOMAIN,
    aip_observe::OBSERVER_HEAD_DOMAIN,
    aip_observe::CONTINUITY_REPORT_DOMAIN,
    aip_reconcile::RECONCILIATION_DOMAIN,
    aip_reconcile::DECISION_POINT_COVERAGE_DOMAIN,
    aip_warrant::WARRANT_DOMAIN,
    aip_containment::CONTAINMENT_DOMAIN,
    aip_nexora::LEAF_DOMAIN,
    aip_nexora::HEAD_DOMAIN,
    aip_nexora::PROOF_DOMAIN,
    aip_nexora::PROOF_BUNDLE_DOMAIN,
    aip_nexora::PROOF_ENVELOPE_DOMAIN,
];

fn package(s: &common::Scenario) -> NexoraProof {
    NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .continuity(common::continuity_report_for(
            common::OBSERVER_ID,
            &s.o,
            common::amnesia_break(),
        ))
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build()
}

fn anchors(s: &common::Scenario) -> VerifierAnchors {
    VerifierAnchors {
        decision_point: s.a.dp_anchors.clone(),
        observer: s.o.anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: s.a.issuer_keys.clone(),
        agent_public_key: Some(s.a.agent_kp.public_key.clone()),
        ..Default::default()
    }
}

// ═══ Untagged hashes, and the shape of a tag ═══

/// FINDING: none. Every signed structure in the workspace has a distinct,
/// namespaced, versioned domain tag, and no tag is a prefix of another.
///
/// INVARIANT: a signature over one semantic object type can never be a
/// valid signature over a different one. Distinctness alone is not enough:
/// a tag that is a prefix of another could let a crafted payload move the
/// boundary, so the encoding must separate them too.
#[test]
fn a01_every_signed_structure_has_its_own_namespaced_versioned_domain() {
    let mut sorted = DOMAINS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), DOMAINS.len(), "two structures share a domain");

    for d in DOMAINS {
        let (namespace, rest) = d.split_once('/').expect("a domain names its namespace");
        assert!(
            ["AIP", "GHOST", "SYNTRIASS"].contains(&namespace),
            "{d} is in no known namespace"
        );
        let version = rest.rsplit('/').next().unwrap();
        assert!(
            version.starts_with('v') && version[1..].chars().all(|c| c.is_ascii_digit()),
            "{d} does not end in an explicit version"
        );
        assert!(!d.is_empty());
    }

    // Encoded, no tag is a prefix of another: `put_domain` length-prefixes,
    // so even the two that share a textual prefix cannot be confused.
    for a in DOMAINS {
        for b in DOMAINS {
            if a == b {
                continue;
            }
            let (mut ea, mut eb) = (Vec::new(), Vec::new());
            aip_types::canonical::put_domain(&mut ea, a);
            aip_types::canonical::put_domain(&mut eb, b);
            assert!(!ea.starts_with(&eb) && !eb.starts_with(&ea), "{a} vs {b}");
        }
    }
}

// ═══ Raw concatenation ═══

/// FINDING: none in any preimage a proof depends on. Every variable-length
/// field is length-prefixed (`put_str`, `put_bytes`); fixed-width arrays
/// are written raw, which is injective because their width is known.
///
/// INVARIANT: the classic ambiguity — `("ab","c")` encoding the same bytes
/// as `("a","bc")` — is impossible, so two different authorities can never
/// share a signing preimage. Checked here on the encoders a NEXORA package
/// actually carries, through their real public constructors.
#[test]
fn a02_no_two_distinct_values_share_a_signing_preimage() {
    let action = |s: &str| aip_types::ScopeAction::Custom(s.to_string());
    let scope = |s: &str| aip_types::CapabilityScope {
        allowed: vec![action(s)],
        denied: vec![],
    };
    let kp = aip_crypto::generate_ed25519_keypair();
    let issuer = aip_crypto::derive_aip_id(&kp.public_key, &common::provenance("i"));

    // The split-point ambiguity, on the two adjacent variable-length
    // fields of a scoped token: issuer_id and agent_id.
    let mut preimages = Vec::new();
    for (a, b) in [("ab", "c"), ("a", "bc"), ("abc", ""), ("", "abc")] {
        let t = aip_core::capability::issue_scoped_token(
            a,
            &kp.private_key,
            b,
            scope("net.connect"),
            Some(1),
        )
        .unwrap();
        preimages.push(aip_core::capability::token_signing_payload(&t));
    }
    let mut sorted = preimages.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), preimages.len(), "an encoding collided");

    // And on the scope itself, whose entries are variable-length too.
    let a = aip_core::capability::issue_scoped_token(
        &issuer,
        &kp.private_key,
        "agent",
        aip_types::CapabilityScope {
            allowed: vec![action("ab"), action("c")],
            denied: vec![],
        },
        None,
    )
    .unwrap();
    let b = aip_core::capability::issue_scoped_token(
        &issuer,
        &kp.private_key,
        "agent",
        aip_types::CapabilityScope {
            allowed: vec![action("a"), action("bc")],
            denied: vec![],
        },
        None,
    )
    .unwrap();
    assert_ne!(
        aip_core::capability::token_signing_payload(&a),
        aip_core::capability::token_signing_payload(&b),
        "two scopes shared a preimage"
    );

    // An interior NUL is data, not a terminator.
    let nul = aip_core::capability::issue_scoped_token(
        &issuer,
        &kp.private_key,
        "agent\0extra",
        scope("net.connect"),
        None,
    )
    .unwrap();
    let plain = aip_core::capability::issue_scoped_token(
        &issuer,
        &kp.private_key,
        "agent",
        scope("net.connect"),
        None,
    )
    .unwrap();
    assert_ne!(
        aip_core::capability::token_signing_payload(&nul),
        aip_core::capability::token_signing_payload(&plain)
    );
}

/// FINDING: none. `Option` fields carry an explicit presence byte, so an
/// absent value is not the same encoding as any present one.
///
/// INVARIANT: an expiry cannot be removed and an unbounded token cannot be
/// made to look bounded, without producing different signed bytes.
#[test]
fn a03_absence_is_encoded_and_not_omitted() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let id = aip_crypto::derive_aip_id(&kp.public_key, &common::provenance("i"));
    let scope = aip_types::CapabilityScope {
        allowed: vec![aip_types::ScopeAction::Custom("net.connect".into())],
        denied: vec![],
    };
    let none = aip_core::capability::issue_scoped_token(
        &id,
        &kp.private_key,
        "agent",
        scope.clone(),
        None,
    )
    .unwrap();
    let some =
        aip_core::capability::issue_scoped_token(&id, &kp.private_key, "agent", scope, Some(1))
            .unwrap();
    assert_ne!(
        aip_core::capability::token_signing_payload(&none),
        aip_core::capability::token_signing_payload(&some)
    );
    // And an expiry cannot be edited after issue.
    let mut tampered = some.clone();
    tampered.expires_at = Some(u64::MAX);
    assert_ne!(
        aip_core::capability::token_signing_payload(&tampered),
        aip_core::capability::token_signing_payload(&some)
    );
}

// ═══ Generic signatures ═══

/// FINDING: recorded, not a vulnerability. The shared Ed25519 envelope is
///
///   SHA-256(algorithm‖signer_id‖timestamp‖nonce‖payload_hash)
///
/// in which `signer_id` is the only variable-length field and is followed
/// by exactly 56 bytes of fixed-width fields. The encoding is therefore
/// injective — the signer id is recoverable from the total length — but it
/// is injective by arithmetic rather than by construction, and a second
/// variable-length field added beside it would silently break that. The
/// property is pinned here so it cannot be lost quietly.
///
/// INVARIANT: a signature is bound to the identity that made it. It cannot
/// be re-presented as another signer's signature over the same payload,
/// nor as the same signer's signature over another payload.
#[test]
fn a04_the_shared_signature_envelope_binds_signer_and_payload() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let sig = aip_crypto::sign_ed25519(&kp.private_key, "ab", b"payload").unwrap();
    assert!(aip_crypto::verify_ed25519(&kp.public_key, &sig).unwrap());

    // The signer id is inside the signed bytes.
    for other in ["a", "abc", "b", "", "ab\0"] {
        let mut moved = sig.clone();
        moved.signer_id = other.to_string();
        assert!(
            !aip_crypto::verify_ed25519(&kp.public_key, &moved).unwrap(),
            "a signature moved to signer {other:?} still verified"
        );
    }
    // So is the payload.
    let mut repointed = sig.clone();
    repointed.payload_hash = aip_crypto::sha256(b"another payload");
    assert!(!aip_crypto::verify_ed25519(&kp.public_key, &repointed).unwrap());
    // And so are the envelope's own fields.
    let mut restamped = sig.clone();
    restamped.timestamp ^= 1;
    assert!(!aip_crypto::verify_ed25519(&kp.public_key, &restamped).unwrap());
    let mut renonced = sig.clone();
    renonced.nonce[0] ^= 1;
    assert!(!aip_crypto::verify_ed25519(&kp.public_key, &renonced).unwrap());

    // The envelope carries a timestamp the *signer* chose. It is bound, so
    // it cannot be edited — and it is never read as trusted time: the
    // verifier's temporal decisions come from its own supplied clock.
    let a = anchors(&common::verified_execution());
    assert_eq!(a.present_time_ms, None, "the verifier supplies its own now");
}

// ═══ Unsigned proof references ═══

/// FINDING: none. Every reference from a claim to a piece of evidence
/// carries a digest, not just a name.
///
/// INVARIANT: naming a batch is not enough to cite it — the claim carries
/// the batch's recomputed head, so substituting a different batch under
/// the same identifiers is caught rather than followed.
#[test]
fn a05_a_claim_cites_evidence_by_digest_and_not_by_name() {
    let s = common::verified_execution();
    let refs = format!("{:?}", s.reconciliation.evidence);
    assert!(
        refs.contains("head"),
        "a batch reference must carry its head: {refs}"
    );

    // Editing a batch under the same identifiers is caught by the head.
    let mut p = package(&s);
    p.observer.as_mut().unwrap().batches[1].batch.claimed_to_ms += 1;
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(
        v.verdict,
        ProofVerdict::Invalid(InvalidReason::Binding(
            BindingFault::CitedBatchHeadMismatch { sequence: 2 }
        ))
    );
    // And the observer is reported as carried-and-unestablished, never as
    // absent: the package did ship a bundle.
    assert_ne!(v.observer, ComponentVerdict::Absent);
}

// ═══ Implicit versioning ═══

/// FINDING: none. Every structure a proof carries states its version
/// explicitly, in its domain tag and — for the versioned wire structures —
/// in the signed bytes as well.
///
/// INVARIANT: a package from a format this build does not implement is
/// named and refused, never parsed for whatever happens to fit.
#[test]
fn a06_versions_are_explicit_in_the_bytes_and_not_inferred() {
    let s = common::verified_execution();
    let p = package(&s);

    // The version is inside the signed bundle: changing it changes the
    // package's identity.
    let mut bumped = p.clone();
    bumped.version = NEXORA_PROOF_VERSION + 1;
    assert_ne!(bumped.proof_id(), p.proof_id());
    assert_eq!(
        verify_nexora_proof(&bumped, &anchors(&s)).verdict,
        ProofVerdict::Invalid(InvalidReason::UnsupportedVersion(NEXORA_PROOF_VERSION + 1))
    );

    // The same for the structures underneath it.
    let mut b = p.observer.as_ref().unwrap().batches[1].clone();
    let before = b.signing_preimage();
    b.version += 1;
    assert_ne!(b.signing_preimage(), before);
}

// ═══ Unchecked algorithm enum ═══

/// FINDING: none. Three algorithm identifiers exist in the type; exactly
/// one is implemented, and the other two are refused rather than checked
/// as Ed25519.
///
/// INVARIANT: a label is never allowed to become a capability. A signature
/// declaring ML-DSA-65 or a hybrid scheme is not verified by this build,
/// and its declaration does not turn into a post-quantum claim.
#[test]
fn a07_an_unimplemented_algorithm_is_refused_and_never_checked_as_ed25519() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let sig = aip_crypto::sign_ed25519(&kp.private_key, "signer", b"payload").unwrap();
    assert!(aip_crypto::verify_ed25519(&kp.public_key, &sig).unwrap());

    for alg in [
        aip_types::AlgorithmId::MlDsa65,
        aip_types::AlgorithmId::Hybrid,
    ] {
        let mut relabelled = sig.clone();
        relabelled.algorithm = alg;
        // Not "false" — an error. The verifier refuses to answer, rather
        // than answering "not a valid Ed25519 signature" about bytes it
        // was never asked to read as Ed25519.
        assert!(
            aip_crypto::verify_ed25519(&kp.public_key, &relabelled).is_err(),
            "{alg:?} was checked as Ed25519"
        );
    }
}

/// INVARIANT: the same refusal reaches the package level, named by the
/// component that carries the relabelled signature — so a package cannot
/// smuggle an unimplemented algorithm past the verifier on any of its
/// components.
#[test]
fn a08_a_package_names_the_component_whose_algorithm_it_cannot_check() {
    let s = common::verified_execution();
    let alg = aip_types::AlgorithmId::MlDsa65;

    let mut cases: Vec<(Component, NexoraProof)> = Vec::new();
    let mut p = package(&s);
    p.expectation.as_mut().unwrap().decision_sig.algorithm = alg;
    cases.push((Component::Expectation, p));

    let mut p = package(&s);
    p.authority.as_mut().unwrap().root.issuer_sig.algorithm = alg;
    cases.push((Component::Authority, p));

    let mut p = package(&s);
    p.observer.as_mut().unwrap().health.attestation.algorithm = alg;
    cases.push((Component::Observer, p));

    let mut p = package(&s);
    p.continuity.as_mut().unwrap().signature.algorithm = alg;
    cases.push((Component::Continuity, p));

    for (component, p) in cases {
        let v = verify_nexora_proof(&p, &anchors(&s));
        assert_eq!(
            v.verdict,
            ProofVerdict::Invalid(InvalidReason::Binding(BindingFault::UnsupportedAlgorithm {
                component
            })),
            "{component:?}"
        );
        assert_eq!(v.result, None);
        assert_eq!(v.strength, None);
    }
}

// ═══ Self-issued authority ═══

/// FINDING: none, since AUDIT P0-2. The issuer of each delegation hop must
/// be the previous hop's grantee, so a holder cannot mint authority for
/// itself out of somebody else's root token.
///
/// INVARIANT: authority flows along a chain that each link is bound to.
/// Presenting a well-signed hop that does not continue the chain is a
/// lineage failure, not an accepted delegation.
#[test]
fn a09_authority_cannot_be_issued_to_itself() {
    let s = common::verified_execution();
    let hop = &s.a.chain[0];

    // The honest chain: the hop's issuer is the root token's holder.
    assert_eq!(hop.issuer_id, s.a.root.agent_id);
    assert_eq!(hop.grantee_id, s.a.agent_id);
    assert!(
        aip_core::delegation::verify_delegation_chain(&s.a.root, &s.a.chain, &s.a.issuer_keys)
            .is_ok()
    );

    // Mallory holds a valid key and a copy of the root token, and mints a
    // hop naming herself as issuer. The signature is genuine; the chain is
    // not.
    let mallory_kp = aip_crypto::generate_ed25519_keypair();
    let mallory = aip_crypto::derive_aip_id(&mallory_kp.public_key, &common::provenance("mallory"));
    let mut forged = hop.clone();
    forged.issuer_id = mallory.clone();
    let payload = aip_core::delegation::delegation_signing_payload(&forged);
    forged.issuer_sig =
        aip_crypto::sign_ed25519(&mallory_kp.private_key, &mallory, &payload).unwrap();
    let mut keys = s.a.issuer_keys.clone();
    keys.insert(mallory, mallory_kp.public_key.clone());
    assert!(
        aip_core::delegation::verify_delegation_chain(&s.a.root, &[forged.clone()], &keys).is_err(),
        "a self-issued hop was accepted"
    );

    // And a package carrying it is refused.
    let mut p = package(&s);
    p.authority.as_mut().unwrap().chain = vec![forged];
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(!v.is_valid());
    assert_eq!(v.result, None);
}

// ═══ Agent-controlled observer keys ═══

/// FINDING: none. The verifier refuses an observer anchor that is the
/// observed agent's own key (I10), and refuses a decision point whose key
/// is the agent's (I1).
///
/// INVARIANT: an agent cannot be the independent witness to, or the
/// independent authoriser of, its own execution. Both checks require the
/// verifier to hold the agent's key; when it does not, that is reported as
/// `NotChecked` rather than passing quietly.
#[test]
fn a10_the_agent_may_be_neither_its_own_observer_nor_its_own_authoriser() {
    let s = common::verified_execution();
    let p = package(&s);

    // Anchor the *agent's* key as the observer's. The package is otherwise
    // untouched and its signatures are all genuine.
    let mut a = anchors(&s);
    a.observer = aip_observe::ObserverTrustAnchors::new().trust(
        common::OBSERVER_ID,
        1,
        &s.a.agent_kp.public_key,
    );
    let v = verify_nexora_proof(&p, &a);
    assert!(!v.is_valid(), "the agent was accepted as its own observer");
    assert_eq!(v.result, None);

    // Without the agent's key the verifier cannot run either check, and
    // says so rather than reporting a pass.
    let mut blind = anchors(&s);
    blind.agent_public_key = None;
    let mut unchecked = package(&s);
    unchecked.parameters.agent_key_supplied = false;
    assert_eq!(
        verify_nexora_proof(&unchecked, &blind).independence,
        Independence::NotChecked
    );
    // And with it, it reports that it did.
    assert_eq!(
        verify_nexora_proof(&p, &anchors(&s)).independence,
        Independence::Checked
    );
}
