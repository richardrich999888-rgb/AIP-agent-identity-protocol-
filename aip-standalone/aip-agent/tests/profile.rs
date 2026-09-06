//! Phase B — RED tests for the identity/profile model.
//!
//! Every test names a property the profile layer must have. At the RED
//! commit none of the named items exist and this file does not compile. No
//! assertion may be weakened to make it pass.
//!
//! Vocabulary used throughout: a *partition* of the profile is one of
//! identity / self_declared / issuers / authority / instances / reconciled /
//! lineage / experience; each partition has exactly one authority behind it
//! and nothing crosses between them.

use std::collections::BTreeSet;

use aip_agent::*;
use aip_authorize::{
    ActionParameters, AuthorizationRequest, DecisionPoint, DecisionPointTrustAnchors,
    ExpectedExecution,
};
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_observe::{ObservationAvailability, UnavailableReason};
use aip_protocol::AgentIdentitySummary;
use aip_reconcile::{
    ActionComparison, DecisionId, EvidenceStrength, IdentityComparison, LineageComparison,
    ReasonCode, Reconciliation, ReconciliationResult, TemporalComparison, WireCorroboration,
    RECONCILIATION_VERSION,
};
use aip_types::{
    Action, AgentIdentityDocument, AlgorithmId, ExecutionBinding, IdentityStatus, KeyPair,
    ProcessInstance, ProvenanceTriple, PublicKey, ScopeAction, EXECUTION_BINDING_VERSION,
};

// ─── fixtures ───

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn binding_for(agent_id: &str, pid: u32) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: 433_843 + u64::from(pid),
            boot_id: [0x0c; 16],
        },
        exe_content_sha256: sha256(b"payments-agent binary v1"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: 1_700_000_000_000,
    }
}

const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;

struct Fx {
    agent_aid: AgentIdentityDocument,
    agent_kp: KeyPair,
    cfo_id: String,
    cfo_kp: KeyPair,
    orch_aid: AgentIdentityDocument,
    orch_kp: KeyPair,
    chain: AuthorityChain,
    issuer_keys: IssuerKeys,
    dp: DecisionPoint,
    dp_anchors: DecisionPointTrustAnchors,
    now: u64,
}

fn fixture() -> Fx {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(provenance("payments-agent"), None).unwrap();

    let root = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(
        &root,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .unwrap();
    let now = root.issued_at.max(hop.issued_at) + 1;

    let dp_kp = generate_ed25519_keypair();
    let dp_id = derive_aip_id(&dp_kp.public_key, &provenance("decision-point"));
    let dp = DecisionPoint::new(&dp_id, &dp_kp.private_key, &dp_kp.public_key, MAX_TTL)
        .unwrap()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);
    let dp_anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);

    let issuer_keys = IssuerKeys::new()
        .trust(&cfo_id, &cfo_kp.public_key)
        .trust(&orch_aid.id, &orch_kp.public_key);

    Fx {
        agent_aid,
        agent_kp,
        cfo_id,
        cfo_kp,
        orch_aid,
        orch_kp,
        chain: AuthorityChain {
            root,
            chain: vec![hop],
        },
        issuer_keys,
        dp,
        dp_anchors,
        now,
    }
}

impl Fx {
    fn authorize(&self, pid: u32) -> ExpectedExecution {
        let req = AuthorizationRequest {
            agent_id: self.agent_aid.id.clone(),
            root_token: self.chain.root.clone(),
            delegation_chain: self.chain.chain.clone(),
            action_kind: ScopeAction::Standard(Action::Write),
            parameters: ActionParameters::from_pairs([("invoice", b"INV-1".to_vec())]).unwrap(),
            execution_binding: binding_for(&self.agent_aid.id, pid),
            requested_ttl_ms: TTL,
        };
        self.dp
            .authorize_at(&req, self.now)
            .expected()
            .expect("fixture authorizes")
            .clone()
    }

    fn reconciliation(
        &self,
        decision_id: Option<[u8; 16]>,
        result: ReconciliationResult,
    ) -> Reconciliation {
        {
            let mut r = Reconciliation::fixture_default();
            r.version = RECONCILIATION_VERSION;
            r.result = result;
            r.strength = match result {
                ReconciliationResult::CannotProve => EvidenceStrength::Heuristic,
                _ => EvidenceStrength::Attested,
            };
            r.reason = ReasonCode::ActionEvidenceUnavailable;
            r.decision_id = decision_id.map(DecisionId::from_bytes);
            r.availability = ObservationAvailability::Unavailable {
                reason: UnavailableReason::NoObserver,
            };
            r.identity = IdentityComparison::NoReference;
            r.action = ActionComparison::Unobservable;
            r.temporal = TemporalComparison::Indeterminate;
            r.lineage = LineageComparison::NotEvaluated;
            r.wire = WireCorroboration::NotEvaluated;
            r.replay_detected = false;
            r.evidence = vec![];
            r.verification_time_ms = self.now + 5;
            r
        }
    }

    fn inputs<'a>(
        &'a self,
        expectations: &'a [ExpectedExecution],
        reconciliations: &'a [Reconciliation],
        claimed: &'a [ExecutionBinding],
        self_declared: &'a [String],
    ) -> ProfileInputs<'a> {
        ProfileInputs {
            identity: IdentityInput::Document {
                document: &self.agent_aid,
                parent: None,
            },
            self_declared,
            authority: std::slice::from_ref(&self.chain),
            loose_hops: &[],
            revoked_jtis: &[],
            issuer_keys: &self.issuer_keys,
            expectations,
            decision_point_anchors: &self.dp_anchors,
            claimed_bindings: claimed,
            reconciliations,
            peer_expectations: &[],
            process_edges: &[],
            ancestor_documents: &[],
            as_of_ms: self.now + 10,
        }
    }
}

fn summary_of(aid: &AgentIdentityDocument) -> AgentIdentitySummary {
    AgentIdentitySummary {
        aip_id: aid.id.clone(),
        public_key: aid.primary_key.clone(),
        provenance: aid.provenance.clone(),
    }
}

fn json(p: &AgentProfile) -> serde_json::Value {
    serde_json::to_value(p).unwrap()
}

fn keys_recursive(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, v) in m {
                out.push(k.clone());
                keys_recursive(v, out);
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|v| keys_recursive(v, out)),
        _ => {}
    }
}

// ─── SD-01 identity ───

/// p01 — an identity is accepted only when the AIP-ID re-derives from the
/// key and provenance presented; from a document, only when the document's
/// own signature verifies. Neither constructor trusts the string.
#[test]
fn p01_identity_is_validated_by_rederivation_never_taken_from_the_string() {
    let fx = fixture();
    let id = AgentIdentity::from_document(&fx.agent_aid, None).unwrap();
    assert_eq!(id.id(), fx.agent_aid.id);
    assert_eq!(id.source(), IdentitySource::Document);

    // Summary path: same identity, weaker provenance label.
    let s = AgentIdentity::from_summary(&summary_of(&fx.agent_aid)).unwrap();
    assert_eq!(s.id(), id.id());
    assert_eq!(s.source(), IdentitySource::PacketSummary);

    // A summary whose id was minted for another key is refused.
    let mut wrong = summary_of(&fx.agent_aid);
    wrong.public_key = fx.orch_aid.primary_key.clone();
    assert_eq!(
        AgentIdentity::from_summary(&wrong).unwrap_err(),
        IdentityError::DerivationMismatch
    );

    // A summary whose id is not even well-formed is refused as malformed.
    let mut bad = summary_of(&fx.agent_aid);
    bad.aip_id = "aip1notanid".into();
    assert!(matches!(
        AgentIdentity::from_summary(&bad).unwrap_err(),
        IdentityError::MalformedId(_)
    ));

    // A summary with an impossible key length is refused.
    let mut short = summary_of(&fx.agent_aid);
    short.public_key = PublicKey {
        algorithm: AlgorithmId::Ed25519,
        key_bytes: vec![1, 2, 3],
    };
    assert!(matches!(
        AgentIdentity::from_summary(&short).unwrap_err(),
        IdentityError::KeyLength { .. }
    ));
}

/// p02 — a document whose lifecycle state was flipped after signing
/// (characterization c01) is not an identity at all; the profile never
/// carries an `Active` it cannot trace to a signature.
#[test]
fn p02_a_mutated_document_is_refused_not_relabelled() {
    let fx = fixture();
    let mut aid = fx.agent_aid.clone();
    aip_core::activate_identity(&mut aid).unwrap();
    assert!(matches!(
        AgentIdentity::from_document(&aid, None).unwrap_err(),
        IdentityError::Document(aip_types::AipError::SignatureInvalid)
    ));
}

/// p03 — lifecycle is the agent's own statement. The type has no variant
/// that could be read as authoritative, and the `match` below is exhaustive
/// so adding one is a compile error here.
#[test]
fn p03_lifecycle_has_no_authoritative_variant() {
    let fx = fixture();
    let id = AgentIdentity::from_document(&fx.agent_aid, None).unwrap();
    match id.lifecycle() {
        LifecycleAssertion::NotEstablished => panic!("a validated document does state a status"),
        LifecycleAssertion::SelfAsserted { status, sequence } => {
            assert_eq!(*status, IdentityStatus::Pending);
            assert_eq!(*sequence, 0);
        }
    }
    let s = AgentIdentity::from_summary(&summary_of(&fx.agent_aid)).unwrap();
    assert_eq!(s.lifecycle(), &LifecycleAssertion::NotEstablished);
}

/// p04 — the identity → execution-instance link is by validated AIP-ID and
/// nothing else. Same pid, other agent: not this identity's instance.
#[test]
fn p04_instance_link_is_by_validated_id_never_by_process_fields() {
    let fx = fixture();
    let id = AgentIdentity::from_document(&fx.agent_aid, None).unwrap();
    assert!(id.names_binding(&binding_for(&fx.agent_aid.id, 4242)));
    assert!(!id.names_binding(&binding_for(&fx.orch_aid.id, 4242)));
}

/// p05 — the lineage proof on a document is reported as present or absent
/// and, when a parent key is supplied, as verified or not. It is never
/// promoted to "parent" in the profile at this phase (that is Phase C).
#[test]
fn p05_lineage_proof_is_reported_as_proof_state_not_as_parent() {
    let (root, root_kp) = create_identity(provenance("root"), None).unwrap();
    let (child, _) =
        create_identity(provenance("child"), Some((&root.id, &root_kp.private_key))).unwrap();

    let unverified = AgentIdentity::from_document(&child, None).unwrap();
    assert_eq!(
        unverified.lineage_proof(),
        &LineageProofState::Present {
            signer_id: root.id.clone(),
            verified: None
        }
    );

    let verified =
        AgentIdentity::from_document(&child, Some((&root.id, &root_kp.public_key))).unwrap();
    assert_eq!(
        verified.lineage_proof(),
        &LineageProofState::Present {
            signer_id: root.id.clone(),
            verified: Some(true)
        }
    );

    // Wrong parent key: the document is refused, not downgraded — a proof
    // that fails against the key the caller asserts is a lineage error.
    let other = generate_ed25519_keypair();
    assert!(matches!(
        AgentIdentity::from_document(&child, Some((&root.id, &other.public_key))).unwrap_err(),
        IdentityError::Document(aip_types::AipError::LineageInvalid)
    ));

    let rootless = AgentIdentity::from_document(&root, None).unwrap();
    assert_eq!(rootless.lineage_proof(), &LineageProofState::Absent);
}

// ─── SD-05 authority projection (read-only over tokens) ───

/// p06 — the projection applies exactly the decision point's rules: trusted
/// root issuer, root signature, chain verified by aip-core, leaf is the agent.
/// It reports the effective scope and the authority path, nothing more.
#[test]
fn p06_authority_projection_reuses_decision_point_rules() {
    let fx = fixture();
    let p = project_authority(
        &fx.agent_aid.id,
        std::slice::from_ref(&fx.chain),
        &fx.issuer_keys,
        fx.now,
    );
    assert_eq!(p.authorized.len(), 1);
    assert!(p.not_in_standing.is_empty());
    assert!(p.excluded.is_empty());
    let a = &p.authorized[0];
    assert_eq!(a.root_jti, fx.chain.root.jti);
    assert_eq!(a.chain_jtis, vec![fx.chain.chain[0].jti]);
    assert_eq!(a.root_issuer, fx.cfo_id);
    assert_eq!(a.leaf_issuer, fx.orch_aid.id);
    assert_eq!(a.effective_scope, scope_submitter());
    assert_eq!(a.standing, Standing::Valid);
}

/// p07 — an untrusted issuer, an invalid signature, a chain that ends at
/// another agent, and a self-issued root are each excluded with the named
/// reason. None of them appears under `authorized`.
#[test]
fn p07_authority_exclusions_are_named_and_never_authorized() {
    let fx = fixture();

    // Untrusted root issuer.
    let no_cfo = IssuerKeys::new().trust(&fx.orch_aid.id, &fx.orch_kp.public_key);
    let p = project_authority(
        &fx.agent_aid.id,
        std::slice::from_ref(&fx.chain),
        &no_cfo,
        fx.now,
    );
    assert!(p.authorized.is_empty());
    assert_eq!(p.excluded.len(), 1);
    assert_eq!(
        p.excluded[0].reason,
        ExclusionReason::UntrustedIssuer(fx.cfo_id.clone())
    );

    // Root expiry rewritten after signing (the Skill 3 attack).
    let mut forged = fx.chain.clone();
    forged.root.expires_at = forged.root.expires_at.map(|e| e + 86_400_000);
    let p = project_authority(&fx.agent_aid.id, &[forged], &fx.issuer_keys, fx.now);
    assert!(p.authorized.is_empty());
    assert_eq!(p.excluded[0].reason, ExclusionReason::RootSignatureInvalid);

    // Hop grantee rewritten: the chain signature fails.
    let mut regrant = fx.chain.clone();
    regrant.chain[0].grantee_id = fx.orch_aid.id.clone();
    let p = project_authority(&fx.agent_aid.id, &[regrant], &fx.issuer_keys, fx.now);
    assert!(p.authorized.is_empty());
    assert!(matches!(
        p.excluded[0].reason,
        ExclusionReason::ChainInvalid(aip_types::AipError::SignatureInvalid)
    ));

    // A valid chain that ends at someone else is not this agent's authority.
    let p = project_authority(
        &fx.orch_aid.id,
        std::slice::from_ref(&fx.chain),
        &fx.issuer_keys,
        fx.now,
    );
    assert!(p.authorized.is_empty());
    assert_eq!(
        p.excluded[0].reason,
        ExclusionReason::LeafNotAgent {
            leaf: fx.agent_aid.id.clone()
        }
    );

    // Self-issued root: refused before any key lookup (I1).
    let self_root = issue_scoped_token(
        &fx.agent_aid.id,
        &fx.agent_kp.private_key,
        &fx.agent_aid.id,
        scope_submitter(),
        Some(3_600_000),
    )
    .unwrap();
    let keys = IssuerKeys::new().trust(&fx.agent_aid.id, &fx.agent_kp.public_key);
    let p = project_authority(
        &fx.agent_aid.id,
        &[AuthorityChain {
            root: self_root,
            chain: vec![],
        }],
        &keys,
        fx.now,
    );
    assert!(p.authorized.is_empty());
    assert_eq!(p.excluded[0].reason, ExclusionReason::SelfIssuedRoot);
}

/// p08 — a verified chain that is not in standing at `as_of` (expired, or
/// issued in the future) is reported as such, separately from `authorized`
/// and separately from `excluded`: it is real authority, just not now.
#[test]
fn p08_expired_or_future_authority_is_verified_but_not_in_standing() {
    let fx = fixture();
    let expiry = fx.chain.root.expires_at.unwrap();
    let p = project_authority(
        &fx.agent_aid.id,
        std::slice::from_ref(&fx.chain),
        &fx.issuer_keys,
        expiry + 1,
    );
    assert!(p.authorized.is_empty());
    assert_eq!(p.not_in_standing.len(), 1);
    assert_eq!(
        p.not_in_standing[0].standing,
        Standing::Expired { at_ms: expiry }
    );

    let p = project_authority(
        &fx.agent_aid.id,
        std::slice::from_ref(&fx.chain),
        &fx.issuer_keys,
        fx.chain.root.issued_at - 1,
    );
    assert!(p.authorized.is_empty());
    assert!(matches!(
        p.not_in_standing[0].standing,
        Standing::NotYetValid { .. }
    ));
}

// ─── SD-02 profile ───

/// p09 — the profile's partitions are exactly these, each labelled by its
/// authority, and no key anywhere in the serialized profile names a score,
/// trust, confidence, reputation, rating, rank or grade.
#[test]
fn p09_profile_partitions_are_fixed_and_no_scalar_summary_exists() {
    let fx = fixture();
    let ee = fx.authorize(4242);
    let recs = [fx.reconciliation(Some(ee.decision_id), ReconciliationResult::CannotProve)];
    let claimed = [binding_for(&fx.agent_aid.id, 4242)];
    let declared = ["Autonomous procurement agent".to_string()];
    let profile =
        build_profile(&fx.inputs(std::slice::from_ref(&ee), &recs, &claimed, &declared)).unwrap();

    let v = json(&profile);
    let top: BTreeSet<String> = v.as_object().unwrap().keys().cloned().collect();
    let expected: BTreeSet<String> = [
        "identity",
        "self_declared",
        "issuers",
        "authority",
        "instances",
        "excluded_expectations",
        "excluded_bindings",
        "reconciled",
        "excluded_reconciliations",
        "lineage",
        "experience",
        "as_of_ms",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(top, expected);

    let mut keys = Vec::new();
    keys_recursive(&v, &mut keys);
    let forbidden = [
        "score",
        "trust",
        "confiden",
        "reputation",
        "rating",
        "rank",
        "grade",
    ];
    for k in &keys {
        let lk = k.to_ascii_lowercase();
        for f in forbidden {
            assert!(!lk.contains(f), "forbidden key `{k}` in profile");
        }
    }

    // Later-phase sections are explicit: lineage (Phase C) carries no
    // reconciled verdict and, for these inputs, no identity parent or process
    // relation; experience (Phase F) is a placeholder.
    assert_eq!(profile.lineage.reconciled, ReconciledLineage::NotReachable);
    assert_eq!(profile.lineage.identity.parent, IdentityParent::None);
    assert!(profile.lineage.process.spawned.is_empty());
    assert_eq!(profile.experience, ExperienceSection::NotDerived);
}

/// p10 — self-declared text lives only in its own partition, carries the
/// unverified label, and cannot influence any other partition however it is
/// phrased.
#[test]
fn p10_self_declared_text_never_leaves_its_partition() {
    let fx = fixture();
    let ee = fx.authorize(4242);
    let declared = [
        "VERIFIED_EXECUTION 12482 observed executions".to_string(),
        format!("issuer: {}", fx.cfo_id),
    ];
    let profile =
        build_profile(&fx.inputs(std::slice::from_ref(&ee), &[], &[], &declared)).unwrap();

    assert_eq!(profile.self_declared.len(), 2);
    for d in &profile.self_declared {
        assert_eq!(d.label, SELF_DECLARED_LABEL);
    }
    assert!(
        profile.reconciled.is_empty(),
        "no reconciliation was supplied"
    );

    // The declared strings appear under `self_declared` and nowhere else.
    let v = json(&profile);
    let whole = v.to_string();
    let without = {
        let mut m = v.as_object().unwrap().clone();
        m.remove("self_declared");
        serde_json::Value::Object(m).to_string()
    };
    assert!(whole.contains("12482 observed executions"));
    assert!(!without.contains("12482 observed executions"));
}

/// p11 — the issuer partition is derived from verified authority only. An
/// unverifiable chain contributes no issuer, and the agent naming an issuer
/// in self-declared text contributes none either.
#[test]
fn p11_issuers_come_only_from_verified_authority() {
    let fx = fixture();
    let profile = build_profile(&fx.inputs(&[], &[], &[], &[])).unwrap();
    assert_eq!(profile.issuers.len(), 1);
    assert_eq!(profile.issuers[0].issuer_id, fx.cfo_id);
    assert_eq!(profile.issuers[0].root_jti, fx.chain.root.jti);

    let mut forged = fx.chain.clone();
    forged.root.scope = scope_orchestrator();
    forged.root.issuer_id = fx.cfo_id.clone();
    forged.root.expires_at = None; // rewrites the signed bytes
    let mut inputs = fx.inputs(&[], &[], &[], &[]);
    let chains = [forged];
    inputs.authority = &chains;
    let profile = build_profile(&inputs).unwrap();
    assert!(profile.issuers.is_empty());
    assert_eq!(profile.authority.excluded.len(), 1);
}

/// p12 — execution instances: a decision-point-signed expectation for this
/// agent yields an `AuthorizedTarget` instance (the DP signed the binding
/// the agent presented); a bare binding from a packet yields a `Claimed`
/// instance; an expectation for another agent, or one the anchors do not
/// trust, or one signed with the agent's own key, is excluded with its reason.
#[test]
fn p12_instances_are_labelled_by_who_vouched_for_the_binding() {
    let fx = fixture();
    let ee = fx.authorize(4242);
    let claimed = [
        binding_for(&fx.agent_aid.id, 5000),
        binding_for(&fx.orch_aid.id, 5001),
    ];
    let profile = build_profile(&fx.inputs(std::slice::from_ref(&ee), &[], &claimed, &[])).unwrap();

    assert_eq!(profile.instances.len(), 2);
    let authorized = profile
        .instances
        .iter()
        .find(|i| i.binding.process.pid == 4242)
        .unwrap();
    assert_eq!(
        authorized.assertion,
        InstanceAssertion::AuthorizedTarget {
            decision_id: ee.decision_id,
            decision_point_id: ee.decision_point_id.clone(),
        }
    );
    let claimed_i = profile
        .instances
        .iter()
        .find(|i| i.binding.process.pid == 5000)
        .unwrap();
    assert_eq!(claimed_i.assertion, InstanceAssertion::Claimed);
    assert_eq!(profile.excluded_bindings.len(), 1);
    assert_eq!(profile.excluded_bindings[0].process.pid, 5001);

    // Expectation signed by an untrusted decision point.
    let mut inputs = fx.inputs(std::slice::from_ref(&ee), &[], &[], &[]);
    let empty = DecisionPointTrustAnchors::new();
    inputs.decision_point_anchors = &empty;
    let profile = build_profile(&inputs).unwrap();
    assert!(profile.instances.is_empty());
    assert_eq!(profile.excluded_expectations.len(), 1);
    assert!(matches!(
        profile.excluded_expectations[0].reason,
        ExpectationExclusion::Unverified(_)
    ));

    // Expectation signed by the agent's own key (a self-run "decision
    // point"): refused because the anchor key is the agent key.
    let self_dp = DecisionPoint::new(
        derive_aip_id(&fx.agent_kp.public_key, &provenance("self-dp")),
        &fx.agent_kp.private_key,
        &fx.agent_kp.public_key,
        MAX_TTL,
    )
    .unwrap()
    .trust_issuer(&fx.cfo_id, &fx.cfo_kp.public_key)
    .trust_issuer(&fx.orch_aid.id, &fx.orch_kp.public_key);
    let req = AuthorizationRequest {
        agent_id: fx.agent_aid.id.clone(),
        root_token: fx.chain.root.clone(),
        delegation_chain: fx.chain.chain.clone(),
        action_kind: ScopeAction::Standard(Action::Write),
        parameters: ActionParameters::empty(),
        execution_binding: binding_for(&fx.agent_aid.id, 4243),
        requested_ttl_ms: TTL,
    };
    let self_ee = self_dp
        .authorize_at(&req, fx.now)
        .expected()
        .unwrap()
        .clone();
    let anchors = DecisionPointTrustAnchors::new().trust(self_dp.id(), self_dp.public_key());
    let mut inputs = fx.inputs(std::slice::from_ref(&self_ee), &[], &[], &[]);
    inputs.decision_point_anchors = &anchors;
    let profile = build_profile(&inputs).unwrap();
    assert!(profile.instances.is_empty());
    assert!(matches!(
        profile.excluded_expectations[0].reason,
        ExpectationExclusion::Unverified(_)
    ));

    // Expectation for another agent.
    let other_ee = {
        let req = AuthorizationRequest {
            agent_id: fx.orch_aid.id.clone(),
            root_token: fx.chain.root.clone(),
            delegation_chain: vec![],
            action_kind: ScopeAction::Standard(Action::Delegate),
            parameters: ActionParameters::empty(),
            execution_binding: binding_for(&fx.orch_aid.id, 7),
            requested_ttl_ms: TTL,
        };
        fx.dp.authorize_at(&req, fx.now).expected().unwrap().clone()
    };
    let profile =
        build_profile(&fx.inputs(std::slice::from_ref(&other_ee), &[], &[], &[])).unwrap();
    assert!(profile.instances.is_empty());
    assert_eq!(
        profile.excluded_expectations[0].reason,
        ExpectationExclusion::AgentMismatch {
            agent_id: fx.orch_aid.id.clone()
        }
    );
}

/// p13 — a reconciliation record joins the profile only through a verified
/// expectation of this agent (Agent → decision_id → ExpectedExecution →
/// Reconciliation). It is carried verbatim — result, strength, reason — and
/// labelled with its source. No record is aggregated, summarized or hidden.
#[test]
fn p13_reconciled_records_join_through_decision_id_and_are_verbatim() {
    let fx = fixture();
    let ee = fx.authorize(4242);
    let other = fx.authorize(4243);
    let recs = [
        fx.reconciliation(Some(ee.decision_id), ReconciliationResult::CannotProve),
        fx.reconciliation(Some(ee.decision_id), ReconciliationResult::PhantomClaim),
        fx.reconciliation(Some(other.decision_id), ReconciliationResult::CannotProve),
        fx.reconciliation(None, ReconciliationResult::CannotProve),
    ];
    // Only `ee` is supplied as an expectation; `other` is not this profile's.
    let profile = build_profile(&fx.inputs(std::slice::from_ref(&ee), &recs, &[], &[])).unwrap();

    assert_eq!(profile.reconciled.len(), 2);
    for r in &profile.reconciled {
        assert_eq!(r.source, RecordSource::VerifierLocal);
        assert_eq!(
            r.record.decision_id,
            Some(DecisionId::from_bytes(ee.decision_id))
        );
    }
    let results: Vec<_> = profile.reconciled.iter().map(|r| r.record.result).collect();
    assert!(results.contains(&ReconciliationResult::CannotProve));
    assert!(
        results.contains(&ReconciliationResult::PhantomClaim),
        "negative classes are part of the profile"
    );
    assert_eq!(profile.reconciled[0].record, recs[0], "verbatim");

    assert_eq!(profile.excluded_reconciliations.len(), 2);
    assert!(profile.excluded_reconciliations.iter().any(|e| matches!(
        e.reason,
        ReconciliationExclusion::DecisionNotForAgent { .. }
    )));
    assert!(profile
        .excluded_reconciliations
        .iter()
        .any(|e| e.reason == ReconciliationExclusion::NoDecisionId));
}

/// p14 — a profile with nothing behind it says nothing: every partition is
/// empty or an explicit placeholder; there is no "clean", no "new", no
/// default lifecycle, no zero that reads as a count of good behaviour.
#[test]
fn p14_an_empty_profile_asserts_nothing() {
    let fx = fixture();
    let mut inputs = fx.inputs(&[], &[], &[], &[]);
    inputs.authority = &[];
    let profile = build_profile(&inputs).unwrap();
    assert!(profile.issuers.is_empty());
    assert!(profile.authority.authorized.is_empty());
    assert!(profile.instances.is_empty());
    assert!(profile.reconciled.is_empty());
    assert_eq!(profile.experience, ExperienceSection::NotDerived);
    assert_eq!(profile.lineage.reconciled, ReconciledLineage::NotReachable);
    assert!(profile.lineage.authority.is_empty());
    assert_eq!(
        profile.identity.lifecycle(),
        &LifecycleAssertion::SelfAsserted {
            status: IdentityStatus::Pending,
            sequence: 0
        }
    );
}

/// p15 — the profile is built for the identity it validates; an identity
/// input that fails validation yields no profile at all rather than a profile
/// with an unverified header.
#[test]
fn p15_no_profile_without_a_validated_identity() {
    let fx = fixture();
    let mut aid = fx.agent_aid.clone();
    aid.id = fx.orch_aid.id.clone(); // id no longer derives from the key
    let mut inputs = fx.inputs(&[], &[], &[], &[]);
    inputs.identity = IdentityInput::Document {
        document: &aid,
        parent: None,
    };
    assert!(matches!(
        build_profile(&inputs).unwrap_err(),
        ProfileError::Identity(_)
    ));
}

/// p16 — the crate links none of the experimental scoring machinery. The
/// pin is textual on the crate's own sources: no identifier from the
/// reputation, liveness or hardware-trust modules, and no `score` symbol.
#[test]
fn p16_crate_sources_reference_no_scoring_machinery() {
    let sources = [
        include_str!("../src/lib.rs"),
        include_str!("../src/identity.rs"),
        include_str!("../src/authority.rs"),
        include_str!("../src/graph.rs"),
        include_str!("../src/lineage.rs"),
        include_str!("../src/profile.rs"),
    ];
    let forbidden = [
        "calculate_reputation",
        "ReputationVote",
        "reputation_root",
        "aggregate_reputation",
        "evaluate_hardware_trust",
        "verify_liveness",
        "score",
        "trust_level",
    ];
    for (i, src) in sources.iter().enumerate() {
        for f in forbidden {
            assert!(
                !src.contains(f),
                "source #{i} references forbidden symbol `{f}`"
            );
        }
    }
}
