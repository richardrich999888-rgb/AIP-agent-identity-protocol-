//! Cryptographic fixtures, never runtime-observation evidence.
use aip_authorize::*;
use aip_core::capability::issue_scoped_token;
use aip_core::delegation::create_delegation;
use aip_crypto::{generate_ed25519_keypair, sign_ed25519};
use aip_types::*;

struct Fixture {
    root: ScopedToken,
    chain: Vec<DelegationToken>,
    expected: ExpectedExecution,
    roots: AuthorityTrustAnchors,
    decisions: DecisionPointTrustAnchors,
    bank: KeyPair,
    parent: KeyPair,
    agent: KeyPair,
    decision: KeyPair,
}

fn fixture() -> Fixture {
    let bank = generate_ed25519_keypair();
    let parent = generate_ed25519_keypair();
    let agent = generate_ed25519_keypair();
    let decision = generate_ed25519_keypair();
    let scope = CapabilityScope {
        allowed: vec![tool_invoke_action()],
        denied: vec![],
    };
    let root = issue_scoped_token(
        "bank",
        &bank.private_key,
        "parent",
        scope.clone(),
        Some(60_000),
    )
    .unwrap();
    let hop = create_delegation(&root, &parent.private_key, "agent", scope).unwrap();
    let request = AuthorizationRequest {
        agent_id: "agent".into(),
        root_token: root.clone(),
        delegation_chain: vec![hop.clone()],
        action_kind: tool_invoke_action(),
        parameters: tool_invoke_parameters("loan.read", [7; 32]).unwrap(),
        execution_binding: ExecutionBinding {
            version: EXECUTION_BINDING_VERSION,
            agent_id: "agent".into(),
            process: ProcessInstance {
                pid: 42,
                pid_start_time_ticks: 100,
                boot_id: [1; 16],
            },
            exe_content_sha256: [2; 32],
            exe_path: "fixture-not-observed".into(),
            bound_at_ms: hop.issued_at,
            container: None,
        },
        requested_ttl_ms: 1000,
    };
    let dp = DecisionPoint::new("dp", &decision.private_key, &decision.public_key, 2000)
        .unwrap()
        .trust_issuer("bank", &bank.public_key)
        .trust_issuer("parent", &parent.public_key);
    let expected = dp
        .authorize_at(&request, hop.issued_at.max(root.issued_at))
        .expected()
        .unwrap()
        .clone();
    Fixture {
        root,
        chain: vec![hop],
        expected,
        roots: AuthorityTrustAnchors::new()
            .trust_root("bank", &bank.public_key)
            .trust_delegator("parent", &parent.public_key),
        decisions: DecisionPointTrustAnchors::new().trust("dp", &decision.public_key),
        bank,
        parent,
        agent,
        decision,
    }
}

impl Fixture {
    fn verify(&self) -> Result<VerifiedAuthorityReference, AuthorityReferenceError> {
        verify_authority_reference(
            &self.expected,
            &self.root,
            &self.chain,
            &self.decisions,
            &self.agent.public_key,
            &self.roots,
        )
    }
    fn resign(&mut self) {
        self.expected.decision_sig = sign_ed25519(
            &self.decision.private_key,
            "dp",
            &self.expected.signing_preimage(),
        )
        .unwrap();
    }
    fn expect(&self, reason: AuthorityReferenceError) {
        assert_eq!(self.verify().unwrap_err(), reason);
    }
}

#[test]
fn native_issued_chain_verifies_with_exact_references() {
    let f = fixture();
    let record = serde_json::to_value(f.verify().unwrap()).unwrap();
    assert_eq!(record["agent_id"], "agent");
    assert_eq!(record["evaluated_at_ms"], f.expected.issued_at);
    assert_eq!(record["chain_jtis"], serde_json::json!([f.chain[0].jti]));
}

#[test]
fn direct_root_grant_and_inclusive_expiry_use_native_semantics() {
    let mut f = fixture();
    f.root = issue_scoped_token(
        "bank",
        &f.bank.private_key,
        "agent",
        f.root.scope.clone(),
        Some(60_000),
    )
    .unwrap();
    f.chain.clear();
    f.expected.authority = AuthorityRef {
        root_jti: f.root.jti,
        chain_jtis: vec![],
    };
    f.expected.issued_at = f.root.issued_at;
    f.expected.valid_until = f.root.expires_at.unwrap();
    f.resign();
    assert!(f.verify().is_ok());
}

#[test]
fn decision_signature_is_checked_before_chain_claims() {
    let mut f = fixture();
    f.expected.parameter_digest[0] ^= 1;
    f.expect(AuthorityReferenceError::InvalidExpectation);
}

#[test]
fn known_delegator_is_not_a_trusted_root() {
    let mut f = fixture();
    f.roots = AuthorityTrustAnchors::new()
        .trust_delegator("bank", &f.bank.public_key)
        .trust_delegator("parent", &f.parent.public_key);
    f.expect(AuthorityReferenceError::UnknownRoot);
}

#[test]
fn swapped_root_and_missing_or_reordered_hops_are_refused() {
    let mut f = fixture();
    f.expected.authority.root_jti[0] ^= 1;
    f.resign();
    f.expect(AuthorityReferenceError::ReferenceMismatch);
    let mut f = fixture();
    f.expected.authority.chain_jtis.clear();
    f.resign();
    f.expect(AuthorityReferenceError::ReferenceMismatch);
    let mut f = fixture();
    f.chain.push(f.chain[0].clone());
    f.expect(AuthorityReferenceError::ReferenceMismatch);
}

#[test]
fn forged_root_or_hop_is_refused_even_under_a_valid_decision_signature() {
    let mut f = fixture();
    f.root
        .scope
        .allowed
        .push(ScopeAction::Standard(Action::Admin));
    f.expect(AuthorityReferenceError::InvalidChain);
    let mut f = fixture();
    f.chain[0].issuer_sig.signature_bytes[0] ^= 1;
    f.expect(AuthorityReferenceError::InvalidChain);
}

#[test]
fn chain_leaf_must_be_the_expectations_agent() {
    let mut f = fixture();
    f.expected.agent_id = "other".into();
    f.expected.execution_binding.agent_id = "other".into();
    f.resign();
    f.expect(AuthorityReferenceError::LeafMismatch);
}

#[test]
fn signed_decision_cannot_expand_the_chains_action_scope() {
    let mut f = fixture();
    f.expected.action_kind = ScopeAction::Standard(Action::Admin);
    f.resign();
    f.expect(AuthorityReferenceError::ActionOutOfScope);
}

#[test]
fn decision_before_issuance_or_after_chain_expiry_is_refused() {
    let mut f = fixture();
    f.expected.issued_at = f.root.issued_at - 1;
    f.resign();
    f.expect(AuthorityReferenceError::AuthorityNotYetValid);
    let mut f = fixture();
    f.expected.valid_until = f.root.expires_at.unwrap() + 1;
    f.resign();
    f.expect(AuthorityReferenceError::ExpectationOutlivesAuthority);
}

#[test]
fn conflicting_issuer_pins_are_not_silently_overwritten() {
    let mut f = fixture();
    f.roots = f.roots.trust_delegator("bank", &f.parent.public_key);
    f.expect(AuthorityReferenceError::ConflictingIssuerKeys);
}

#[test]
fn an_alias_does_not_hide_a_self_issued_root_key() {
    let mut f = fixture();
    f.root = issue_scoped_token(
        "bank-alias",
        &f.agent.private_key,
        "parent",
        f.root.scope.clone(),
        Some(60_000),
    )
    .unwrap();
    f.chain = vec![create_delegation(
        &f.root,
        &f.parent.private_key,
        "agent",
        f.root.scope.clone(),
    )
    .unwrap()];
    f.expected.authority = AuthorityRef {
        root_jti: f.root.jti,
        chain_jtis: vec![f.chain[0].jti],
    };
    f.expected.issued_at = f.chain[0].issued_at;
    f.expected.valid_until = f.expected.issued_at + 100;
    f.roots = f.roots.trust_root("bank-alias", &f.agent.public_key);
    f.resign();
    f.expect(AuthorityReferenceError::SelfIssuedRoot);
}

#[test]
fn missing_delegator_and_malformed_anchors_cannot_verify() {
    let mut f = fixture();
    f.roots = AuthorityTrustAnchors::new().trust_root("bank", &f.bank.public_key);
    f.expect(AuthorityReferenceError::InvalidChain);
    let mut f = fixture();
    f.roots = f.roots.trust_delegator("parent", &[1; 31]);
    f.expect(AuthorityReferenceError::InvalidTrustAnchor);
}
