//! Spend authority at the decision point (ADR-018, step 5c), attacked.
//!
//! The scenario throughout: an institution authorises its treasury agent to
//! pay up to $1,000 per payment, with human approval above $500. Amounts are
//! integer cents.

use aip_authorize::*;
use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_spend::{
    RefusalReason, SignedSpendPolicy, SpendPolicy, SpendPolicyAnchors, SpendRule, SpendVerdict,
    VerifiedSpendPolicy, SPEND_POLICY_VERSION,
};
use aip_types::{
    Action, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple, ScopeAction,
    EXECUTION_BINDING_VERSION,
};

const TTL: u64 = 60_000;
const MAX_TTL: u64 = 3_600_000;
const LIMIT: u64 = 100_000;
const THRESHOLD: u64 = 50_000;
const POLICY_ISSUER: &str = "bank.example/treasury-policy";

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn binding_for(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: 4242,
            pid_start_time_ticks: 433_843,
            boot_id: [0x0c; 16],
        },
        exe_content_sha256: sha256(b"treasury-agent binary v1"),
        exe_path: "/opt/agent/bin/treasury-agent".into(),
        bound_at_ms: 1_700_000_000_000,
        container: None,
    }
}

fn pay() -> ScopeAction {
    ScopeAction::Standard(Action::Write)
}

fn rule() -> SpendRule {
    SpendRule {
        action: pay(),
        amount_parameter: "amount_cents".into(),
        currency: "USD".into(),
        exponent: 2,
        max_per_action: LIMIT,
        approval_above: Some(THRESHOLD),
    }
}

/// An institution's policy authority.
struct Issuer {
    kp: KeyPair,
}

impl Issuer {
    fn new() -> Self {
        Self {
            kp: generate_ed25519_keypair(),
        }
    }

    fn policy(&self, agent_id: &str, revision: u64, rules: Vec<SpendRule>) -> SpendPolicy {
        SpendPolicy {
            version: SPEND_POLICY_VERSION,
            policy_id: "treasury-payments".into(),
            issuer_id: POLICY_ISSUER.into(),
            revision,
            issued_at_ms: 1_700_000_000_000,
            agent_id: agent_id.into(),
            rules,
        }
    }

    /// Signed by the issuer, verified by the operator against its anchor.
    fn verified(&self, policy: SpendPolicy) -> VerifiedSpendPolicy {
        SignedSpendPolicy::sign(policy, &self.kp.private_key)
            .unwrap()
            .verify(&SpendPolicyAnchors::new().trust(POLICY_ISSUER, &self.kp.public_key))
            .unwrap()
    }
}

struct Fx {
    dp: DecisionPoint,
    anchors: DecisionPointTrustAnchors,
    agent_id: String,
    agent_kp: KeyPair,
    req: AuthorizationRequest,
    now: u64,
    issuer: Issuer,
}

/// A decision point, without a spend policy, and a well-formed request.
fn fixture() -> Fx {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));
    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(provenance("treasury-agent"), None).unwrap();
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
    let anchors = DecisionPointTrustAnchors::new().trust(&dp_id, &dp_kp.public_key);

    let req = AuthorizationRequest {
        agent_id: agent_aid.id.clone(),
        root_token: root,
        delegation_chain: vec![hop],
        action_kind: pay(),
        parameters: params(b"40000"),
        execution_binding: binding_for(&agent_aid.id),
        requested_ttl_ms: TTL,
    };
    Fx {
        dp,
        anchors,
        agent_id: agent_aid.id,
        agent_kp,
        req,
        now,
        issuer: Issuer::new(),
    }
}

fn params(amount: &[u8]) -> ActionParameters {
    ActionParameters::from_pairs([
        ("payee", b"ACME-SUPPLIES-LTD".to_vec()),
        ("amount_cents", amount.to_vec()),
    ])
    .unwrap()
}

/// The fixture with the treasury policy in force.
fn governed() -> Fx {
    let mut f = fixture();
    let p = f
        .issuer
        .verified(f.issuer.policy(&f.agent_id, 3, vec![rule()]));
    f.dp = f.dp.with_spend_policy(p).unwrap();
    f
}

fn ask(f: &Fx, amount: &[u8]) -> SpendDecision {
    let mut req = f.req.clone();
    req.parameters = params(amount);
    f.dp.authorize_spend_at(&req, f.now)
}

fn refusal(d: &SpendDecision) -> &aip_spend::SignedSpendRefusal {
    match &d.record {
        Some(SpendRecord::Refused(r)) => r,
        other => panic!(
            "expected a refusal record, got {other:?} for {:?}",
            d.decision
        ),
    }
}

fn attestation(d: &SpendDecision) -> &aip_spend::SignedSpendAttestation {
    match &d.record {
        Some(SpendRecord::Attested(a)) => a,
        other => panic!(
            "expected an attestation, got {other:?} for {:?}",
            d.decision
        ),
    }
}

fn reason(d: &SpendDecision) -> Option<DenialReason> {
    d.decision.denial().map(|x| x.reason)
}

// ═══ The $5,000 attempt ═══

/// The centrepiece: $5,000 against a $1,000 limit is refused, and the
/// refusal is a signed record carrying the amount, the limit and the policy.
#[test]
fn five_thousand_against_one_thousand_is_refused_and_provably_so() {
    let f = governed();
    let d = ask(&f, b"500000");
    assert_eq!(reason(&d), Some(DenialReason::SpendLimitExceeded));
    assert!(
        d.decision.expected().is_none(),
        "a refusal carries no expectation"
    );

    let r = refusal(&d);
    r.verify(&f.anchors)
        .expect("refusal verifies under the decision point's anchor");
    let x = &r.refusal;
    assert_eq!(x.reason, RefusalReason::LimitExceeded);
    assert_eq!(x.requested_minor_units, Some(500_000));
    assert_eq!(x.limit_minor_units, LIMIT);
    assert_eq!((x.currency.as_str(), x.exponent), ("USD", 2));
    assert_eq!(x.agent_id, f.agent_id);
    assert_eq!(x.decision_point_id, f.dp.id());
    assert_eq!(x.refused_at_ms, f.now);
    assert_eq!(x.request_digest, params(b"500000").digest());
    let held = f.dp.spend_policy_for(&f.agent_id).unwrap().policy();
    assert_eq!(x.policy.digest, held.digest());
    assert_eq!(
        (x.policy.policy_id.as_str(), x.policy.revision),
        ("treasury-payments", 3)
    );
}

/// `authorize_at` drops the record but not the enforcement: there is no
/// entry point that skips step 5c.
#[test]
fn the_plain_entry_point_enforces_the_same_limit() {
    let f = governed();
    let mut req = f.req.clone();
    req.parameters = params(b"500000");
    let d = f.dp.authorize_at(&req, f.now);
    assert_eq!(
        d.denial().map(|x| x.reason),
        Some(DenialReason::SpendLimitExceeded)
    );
}

#[test]
fn a_refused_request_never_enters_the_decision_ledger() {
    let f = governed();
    let before = f.dp.issued_count();
    let _ = ask(&f, b"500000");
    assert_eq!(f.dp.issued_count(), before);
}

// ═══ Authorised spends ═══

#[test]
fn a_spend_within_the_limit_is_authorised_and_attested() {
    let f = governed();
    let d = ask(&f, b"40000");
    let ee = d.decision.expected().expect("authorised");
    verify_expected_execution(ee, &f.anchors).expect("the expectation is unchanged and verifies");

    let a = attestation(&d);
    a.verify(&f.anchors).unwrap();
    let x = &a.attestation;
    assert_eq!(x.verdict, SpendVerdict::Within);
    assert_eq!(x.decision_id, ee.decision_id);
    assert_eq!(x.expectation_digest, expectation_digest(ee));
    assert_eq!(x.attested_at_ms, ee.issued_at);
    assert_eq!(x.limit_minor_units, LIMIT);
    assert_eq!(x.approval_threshold, Some(THRESHOLD));
    assert_eq!(f.dp.issued_count(), 1);
}

#[test]
fn a_spend_above_the_threshold_is_authorised_and_marked_approval_required() {
    let f = governed();
    let d = ask(&f, b"75000");
    assert!(d.decision.expected().is_some());
    assert_eq!(
        attestation(&d).attestation.verdict,
        SpendVerdict::ApprovalRequired
    );
}

/// The attestation is bound to its own expectation and no other.
#[test]
fn an_attestation_names_only_its_own_expectation() {
    let f = governed();
    let a = ask(&f, b"40000");
    let b = ask(&f, b"40000");
    let (ea, eb) = (
        a.decision.expected().unwrap(),
        b.decision.expected().unwrap(),
    );
    assert_ne!(
        attestation(&a).attestation.expectation_digest,
        expectation_digest(eb)
    );
    assert_ne!(attestation(&a).attestation.decision_id, eb.decision_id);
    assert_eq!(
        attestation(&a).attestation.expectation_digest,
        expectation_digest(ea)
    );
}

// ═══ Boundaries ═══

#[test]
fn the_limit_is_inclusive_and_one_cent_over_is_refused() {
    let f = governed();
    assert_eq!(
        attestation(&ask(&f, b"100000")).attestation.verdict,
        SpendVerdict::ApprovalRequired
    );
    assert_eq!(
        attestation(&ask(&f, b"50000")).attestation.verdict,
        SpendVerdict::Within
    );
    assert_eq!(
        attestation(&ask(&f, b"50001")).attestation.verdict,
        SpendVerdict::ApprovalRequired
    );
    let over = ask(&f, b"100001");
    assert_eq!(reason(&over), Some(DenialReason::SpendLimitExceeded));
    assert_eq!(refusal(&over).refusal.requested_minor_units, Some(100_001));
}

#[test]
fn an_amount_that_cannot_be_read_is_refused_not_read_permissively() {
    let f = governed();
    for (amount, why) in [
        (&b"1,000.00"[..], RefusalReason::AmountNotDecimal),
        (b"-500000", RefusalReason::AmountNotDecimal),
        (b"", RefusalReason::AmountNotDecimal),
        (b"99999999999999999999999", RefusalReason::AmountOutOfRange),
    ] {
        let d = ask(&f, amount);
        assert_eq!(
            reason(&d),
            Some(DenialReason::SpendAmountUnreadable),
            "{amount:?}"
        );
        let r = refusal(&d);
        r.verify(&f.anchors).unwrap();
        assert_eq!(r.refusal.reason, why, "{amount:?}");
        assert_eq!(r.refusal.requested_minor_units, None);
    }
}

#[test]
fn an_omitted_amount_is_refused() {
    let f = governed();
    let mut req = f.req.clone();
    req.parameters = ActionParameters::from_pairs([("payee", b"ACME".to_vec())]).unwrap();
    let d = f.dp.authorize_spend_at(&req, f.now);
    assert_eq!(reason(&d), Some(DenialReason::SpendAmountUnreadable));
    assert_eq!(refusal(&d).refusal.reason, RefusalReason::AmountMissing);
}

// ═══ Scope of the check ═══

/// No policy: behaviour is exactly as before, and the decision point says
/// it performs no spend check.
#[test]
fn without_a_policy_nothing_changes_and_the_gap_is_visible() {
    let f = fixture();
    assert!(f.dp.spend_policy_for(&f.agent_id).is_none());
    let d = ask(&f, b"500000");
    assert!(d.decision.expected().is_some());
    assert!(d.record.is_none());
}

#[test]
fn an_ungoverned_action_or_another_agents_policy_is_not_checked() {
    let mut f = fixture();
    let other_rule = SpendRule {
        action: ScopeAction::Custom("refund".into()),
        ..rule()
    };
    let p = f
        .issuer
        .verified(f.issuer.policy(&f.agent_id, 1, vec![other_rule]));
    f.dp = f.dp.with_spend_policy(p).unwrap();
    let d = ask(&f, b"500000");
    assert!(d.decision.expected().is_some());
    assert!(d.record.is_none());

    let mut g = fixture();
    let p = g
        .issuer
        .verified(g.issuer.policy("aip1SomeoneElse", 1, vec![rule()]));
    g.dp = g.dp.with_spend_policy(p).unwrap();
    assert!(g.dp.spend_policy_for(&g.agent_id).is_none());
    assert!(ask(&g, b"500000").decision.expected().is_some());
}

// ═══ Configuration ═══

/// An older or equal revision cannot replace the one held: the limit cannot
/// be rolled back by configuration. A newer one takes effect.
#[test]
fn a_policy_cannot_be_rolled_back_and_a_newer_revision_takes_effect() {
    for stale in [3, 2] {
        let f = governed();
        let p = f
            .issuer
            .verified(f.issuer.policy(&f.agent_id, stale, vec![rule()]));
        assert_eq!(
            f.dp.with_spend_policy(p).unwrap_err(),
            SpendConfigError::RevisionNotNewer {
                agent_id: f.agent_id.clone(),
                held: 3,
                offered: stale,
            }
        );
    }

    let mut f = governed();
    let raised = SpendRule {
        max_per_action: 1_000_000,
        ..rule()
    };
    let p = f
        .issuer
        .verified(f.issuer.policy(&f.agent_id, 4, vec![raised]));
    f.dp = f.dp.with_spend_policy(p).unwrap();
    let d = ask(&f, b"500000");
    assert!(d.decision.expected().is_some());
    assert_eq!(attestation(&d).attestation.policy.revision, 4);
}

// ═══ Ordering and failure ═══

/// Denied before spend authority is reached: no spend record of any kind.
#[test]
fn a_request_denied_earlier_carries_no_spend_record() {
    let f = governed();
    let mut req = f.req.clone();
    req.root_token.scope.allowed.clear();
    req.parameters = params(b"500000");
    let d = f.dp.authorize_spend_at(&req, f.now);
    assert!(d.decision.denial().is_some());
    assert_ne!(reason(&d), Some(DenialReason::SpendLimitExceeded));
    assert!(d.record.is_none());
}

/// Passed spend authority but denied later: no attestation, because no
/// expectation exists to bind one to.
#[test]
fn a_request_denied_after_spend_authority_carries_no_attestation() {
    let f = governed();
    let mut req = f.req.clone();
    req.execution_binding.process.pid = 0;
    let d = f.dp.authorize_spend_at(&req, f.now);
    assert_eq!(reason(&d), Some(DenialReason::BindingMalformed));
    assert!(d.record.is_none());
}

/// A spend record verifies only under the decision point that signed it —
/// not under an anchor holding the agent's key under the same id.
#[test]
fn a_spend_record_verifies_only_under_its_own_decision_point() {
    let f = governed();
    let d = ask(&f, b"500000");
    let wrong = DecisionPointTrustAnchors::new().trust(f.dp.id(), &f.agent_kp.public_key);
    assert!(refusal(&d).verify(&wrong).is_err());
    assert!(refusal(&d)
        .verify(&DecisionPointTrustAnchors::new())
        .is_err());
}

#[test]
fn the_decision_point_debug_names_the_policy_but_never_the_key() {
    let f = governed();
    let s = format!("{:?}", f.dp);
    assert!(s.contains("treasury-payments"));
    assert!(s.contains("<redacted>"));
}
