//! Spend authority: the policy, the evaluation and the records — attacked.

use aip_crypto::generate_ed25519_keypair;
use aip_spend::*;
use aip_types::{KeyPair, ScopeAction};
use std::collections::BTreeMap;

const AGENT: &str = "aip1TreasuryAgent";
const ISSUER: &str = "bank.example/policy";

fn pay() -> ScopeAction {
    ScopeAction::Custom("create_payment".into())
}

/// $1,000 per payment; human approval above $500. In cents.
fn rule() -> SpendRule {
    SpendRule {
        action: pay(),
        amount_parameter: "amount_cents".into(),
        currency: "USD".into(),
        exponent: 2,
        max_per_action: 100_000,
        approval_above: Some(50_000),
    }
}

fn policy() -> SpendPolicy {
    SpendPolicy {
        version: SPEND_POLICY_VERSION,
        policy_id: "treasury-payments".into(),
        issuer_id: ISSUER.into(),
        revision: 3,
        issued_at_ms: 1_700_000_000_000,
        agent_id: AGENT.into(),
        rules: vec![rule()],
    }
}

fn signed() -> (SignedSpendPolicy, SpendPolicyAnchors, KeyPair) {
    let kp = generate_ed25519_keypair();
    let s = SignedSpendPolicy::sign(policy(), &kp.private_key).unwrap();
    (
        s,
        SpendPolicyAnchors::new().trust(ISSUER, &kp.public_key),
        kp,
    )
}

fn verified() -> VerifiedSpendPolicy {
    let (s, a, _) = signed();
    s.verify(&a).unwrap()
}

fn eval(amount: &[u8]) -> SpendOutcome {
    let p = verified();
    evaluate(&p, AGENT, &pay(), |k| {
        (k == "amount_cents").then_some(amount)
    })
}

// ═══ The policy ═══

#[test]
fn a_signed_policy_verifies_under_its_issuers_anchor() {
    let (s, a, _) = signed();
    assert_eq!(s.verify(&a).unwrap().policy(), &policy());
}

#[test]
fn a_policy_cannot_be_raised_after_signing() {
    let (mut s, a, _) = signed();
    s.policy.rules[0].max_per_action = 500_000;
    assert_eq!(s.verify(&a).unwrap_err(), SpendError::PayloadHashMismatch);
}

#[test]
fn a_policy_from_an_unanchored_issuer_is_refused() {
    let (s, _, _) = signed();
    assert_eq!(
        s.verify(&SpendPolicyAnchors::new()).unwrap_err(),
        SpendError::IssuerNotAnchored(ISSUER.into())
    );
}

#[test]
fn a_policy_under_the_wrong_key_is_refused() {
    let (s, _, _) = signed();
    let other = generate_ed25519_keypair();
    assert_eq!(
        s.verify(&SpendPolicyAnchors::new().trust(ISSUER, &other.public_key))
            .unwrap_err(),
        SpendError::SignatureInvalid
    );
}

#[test]
fn a_policy_must_be_well_formed_to_sign_or_verify() {
    let kp = generate_ed25519_keypair();
    let bad = |edit: fn(&mut SpendPolicy)| {
        let mut p = policy();
        edit(&mut p);
        SignedSpendPolicy::sign(p, &kp.private_key).unwrap_err()
    };
    assert_eq!(bad(|p| p.rules.push(rule())), SpendError::DuplicateRule);
    assert_eq!(
        bad(|p| p.rules[0].approval_above = Some(100_001)),
        SpendError::ThresholdAboveMaximum
    );
    assert_eq!(
        bad(|p| p.rules[0].currency = "usd".into()),
        SpendError::BadCurrency
    );
    assert_eq!(
        bad(|p| p.rules[0].exponent = 10),
        SpendError::ExponentTooLarge
    );
    assert_eq!(bad(|p| p.version = 2), SpendError::UnsupportedVersion(2));
    assert_eq!(bad(|p| p.agent_id.clear()), SpendError::Empty("agent_id"));
    assert_eq!(
        bad(|p| p.rules[0].amount_parameter.clear()),
        SpendError::Empty("amount_parameter")
    );
}

#[test]
fn rule_order_is_not_a_change_and_every_field_is_in_the_digest() {
    let mut a = policy();
    a.rules.push(SpendRule {
        action: ScopeAction::Custom("refund".into()),
        ..rule()
    });
    let mut b = a.clone();
    b.rules.reverse();
    assert_eq!(a.digest(), b.digest());

    type Edit = fn(&mut SpendPolicy);
    let edits: [(&str, Edit); 12] = [
        ("policy_id", |p| p.policy_id = "x".into()),
        ("issuer", |p| p.issuer_id = "x".into()),
        ("revision", |p| p.revision += 1),
        ("issued_at", |p| p.issued_at_ms += 1),
        ("agent", |p| p.agent_id = "x".into()),
        ("action", |p| {
            p.rules[0].action = ScopeAction::Custom("x".into())
        }),
        ("param", |p| p.rules[0].amount_parameter = "x".into()),
        ("currency", |p| p.rules[0].currency = "EUR".into()),
        ("exponent", |p| p.rules[0].exponent = 3),
        ("max", |p| p.rules[0].max_per_action += 1),
        ("threshold", |p| p.rules[0].approval_above = None),
        ("version", |p| p.version = 9),
    ];
    for (name, edit) in edits {
        let mut p = policy();
        edit(&mut p);
        assert_ne!(p.digest(), policy().digest(), "{name} is not in the digest");
    }
}

// ═══ Evaluation ═══

#[test]
fn amounts_are_parsed_strictly() {
    assert_eq!(parse_amount(b"0"), Ok(0));
    assert_eq!(parse_amount(b"007"), Ok(7));
    assert_eq!(parse_amount(b"18446744073709551615"), Ok(u64::MAX));
    for bad in [
        &b""[..],
        b"-1",
        b"+1",
        b"1.00",
        b" 1",
        b"1 ",
        b"1e5",
        b"\xd9\xa1",
    ] {
        assert_eq!(parse_amount(bad), Err(Unreadable::NotDecimal), "{bad:?}");
    }
    assert_eq!(
        parse_amount(b"18446744073709551616"),
        Err(Unreadable::OutOfRange)
    );
    // Overflows on the multiply, not the add: 9_999_999_999_999_999_999 * 10
    // exceeds u64::MAX before the last digit is added.
    assert_eq!(
        parse_amount(b"99999999999999999999"),
        Err(Unreadable::OutOfRange)
    );
    assert_eq!(
        parse_amount(b"000000000000000000001"),
        Err(Unreadable::OutOfRange)
    );
}

/// The boundaries are inclusive: exactly $1,000 is within the limit, exactly
/// $500 does not yet need approval.
#[test]
fn the_boundaries_are_exact() {
    assert_eq!(
        eval(b"50000"),
        SpendOutcome::Within {
            amount: 50_000,
            limit: 100_000
        }
    );
    assert_eq!(
        eval(b"50001"),
        SpendOutcome::ApprovalRequired {
            amount: 50_001,
            limit: 100_000,
            threshold: 50_000
        }
    );
    assert_eq!(
        eval(b"100000"),
        SpendOutcome::ApprovalRequired {
            amount: 100_000,
            limit: 100_000,
            threshold: 50_000
        }
    );
    assert_eq!(
        eval(b"100001"),
        SpendOutcome::Exceeded {
            amount: 100_001,
            limit: 100_000
        }
    );
}

/// The $5,000 attempt.
#[test]
fn five_thousand_against_one_thousand_is_exceeded_and_refused() {
    let o = eval(b"500000");
    assert_eq!(
        o,
        SpendOutcome::Exceeded {
            amount: 500_000,
            limit: 100_000
        }
    );
    assert!(o.refuses());
}

#[test]
fn an_unreadable_amount_is_refused_not_read_permissively() {
    let p = verified();
    let missing = evaluate(&p, AGENT, &pay(), |_| None);
    assert_eq!(
        missing,
        SpendOutcome::Unreadable {
            reason: Unreadable::Missing,
            limit: 100_000
        }
    );
    assert!(missing.refuses());
    assert!(eval(b"5,000.00").refuses());
}

#[test]
fn another_agent_or_an_ungoverned_action_is_not_governed() {
    let p = verified();
    let five = b"500000".as_slice();
    assert_eq!(
        evaluate(&p, "aip1SomeoneElse", &pay(), |_| Some(five)),
        SpendOutcome::NotGoverned
    );
    assert_eq!(
        evaluate(
            &p,
            AGENT,
            &ScopeAction::Custom("read_balance".into()),
            |_| Some(five)
        ),
        SpendOutcome::NotGoverned
    );
}

#[test]
fn a_policy_without_an_approval_threshold_never_requires_approval() {
    let mut r = rule();
    r.approval_above = None;
    assert_eq!(
        classify(&r, 100_000),
        SpendOutcome::Within {
            amount: 100_000,
            limit: 100_000
        }
    );
}

// ═══ Records ═══

struct Anchors(BTreeMap<String, Vec<u8>>);
impl DecisionPointKeys for Anchors {
    fn key(&self, id: &str) -> Option<&[u8]> {
        self.0.get(id).map(Vec::as_slice)
    }
}

fn dp() -> (KeyPair, Anchors) {
    let kp = generate_ed25519_keypair();
    let mut m = BTreeMap::new();
    m.insert("dp-1".to_string(), kp.public_key.clone());
    (kp, Anchors(m))
}

fn citation() -> PolicyCitation {
    PolicyCitation {
        issuer_id: ISSUER.into(),
        policy_id: "treasury-payments".into(),
        revision: 3,
        digest: policy().digest(),
    }
}

fn refusal() -> SpendRefusal {
    SpendRefusal {
        version: SPEND_RECORD_VERSION,
        decision_point_id: "dp-1".into(),
        agent_id: AGENT.into(),
        request_digest: [4; 32],
        policy: citation(),
        action: pay(),
        reason: RefusalReason::LimitExceeded,
        requested_minor_units: Some(500_000),
        limit_minor_units: 100_000,
        currency: "USD".into(),
        exponent: 2,
        refused_at_ms: 1_700_000_000_500,
    }
}

fn attestation() -> SpendAttestation {
    SpendAttestation {
        version: SPEND_RECORD_VERSION,
        decision_point_id: "dp-1".into(),
        decision_id: [8; 16],
        agent_id: AGENT.into(),
        expectation_digest: [6; 32],
        policy: citation(),
        action: pay(),
        verdict: SpendVerdict::ApprovalRequired,
        limit_minor_units: 100_000,
        approval_threshold: Some(50_000),
        currency: "USD".into(),
        exponent: 2,
        attested_at_ms: 1_700_000_000_500,
    }
}

#[test]
fn a_refusal_verifies_and_its_amount_cannot_be_rewritten() {
    let (kp, anchors) = dp();
    let s = SignedSpendRefusal::sign(refusal(), &kp.private_key).unwrap();
    assert_eq!(s.verify(&anchors), Ok(()));
    let mut t = s.clone();
    t.refusal.requested_minor_units = Some(100_000);
    assert_eq!(t.verify(&anchors), Err(RecordError::PayloadHashMismatch));
}

#[test]
fn an_attestation_verifies_and_its_verdict_cannot_be_rewritten() {
    let (kp, anchors) = dp();
    let s = SignedSpendAttestation::sign(attestation(), &kp.private_key).unwrap();
    assert_eq!(s.verify(&anchors), Ok(()));
    let mut t = s.clone();
    t.attestation.verdict = SpendVerdict::Within;
    assert_eq!(t.verify(&anchors), Err(RecordError::PayloadHashMismatch));
}

#[test]
fn a_record_from_an_unanchored_decision_point_is_refused() {
    let (kp, _) = dp();
    let s = SignedSpendRefusal::sign(refusal(), &kp.private_key).unwrap();
    assert_eq!(
        s.verify(&Anchors(BTreeMap::new())),
        Err(RecordError::DecisionPointNotAnchored("dp-1".into()))
    );
}

#[test]
fn a_record_signed_by_another_key_is_refused() {
    let (_, anchors) = dp();
    let other = generate_ed25519_keypair();
    let s = SignedSpendAttestation::sign(attestation(), &other.private_key).unwrap();
    assert_eq!(s.verify(&anchors), Err(RecordError::SignatureInvalid));
}

#[test]
fn the_two_records_cannot_be_confused_for_one_another() {
    let r = refusal().signing_preimage();
    let a = attestation().signing_preimage();
    assert!(r.windows(20).any(|w| w == b"AIP-SPEND-REFUSAL-v1"));
    assert!(a.windows(24).any(|w| w == b"AIP-SPEND-ATTESTATION-v1"));
    assert_ne!(r[..24], a[..24]);
}

/// `verify` validates on its own account: a malformed policy signed by some
/// path other than `SignedSpendPolicy::sign` is still refused.
#[test]
fn verify_refuses_a_malformed_policy_however_it_was_signed() {
    let kp = generate_ed25519_keypair();
    let mut p = policy();
    p.rules[0].approval_above = Some(p.rules[0].max_per_action + 1);
    let signature =
        aip_crypto::sign_ed25519(&kp.private_key, ISSUER, &p.canonical_bytes()).unwrap();
    let s = SignedSpendPolicy {
        policy: p,
        signature,
    };
    let anchors = SpendPolicyAnchors::new().trust(ISSUER, &kp.public_key);
    assert_eq!(
        s.verify(&anchors).unwrap_err(),
        SpendError::ThresholdAboveMaximum
    );
}

#[test]
fn a_record_whose_signature_names_another_signer_is_refused() {
    let (kp, anchors) = dp();
    let mut s = SignedSpendRefusal::sign(refusal(), &kp.private_key).unwrap();
    s.signature.signer_id = "dp-2".into();
    assert_eq!(s.verify(&anchors), Err(RecordError::SignerMismatch));
}

#[test]
fn a_record_of_an_unknown_version_is_refused_as_such() {
    let (kp, anchors) = dp();
    let mut r = refusal();
    r.version = SPEND_RECORD_VERSION + 1;
    let s = SignedSpendRefusal::sign(r, &kp.private_key).unwrap();
    assert_eq!(
        s.verify(&anchors),
        Err(RecordError::UnsupportedVersion(SPEND_RECORD_VERSION + 1))
    );
}
