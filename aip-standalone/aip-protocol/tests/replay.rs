//! B-8 — replay semantics for evidence packets.
//!
//! # What replay means here, and what it does not
//!
//! An `EvidencePacket` is a record of what happened, not a command. Verifying
//! the same packet twice is not an attack — archival, offline and delayed
//! verification all depend on it staying possible — so a nonce cache over
//! packets would break the design rather than protect it.
//!
//! The real exposure is duplication of a *claim*:
//!
//! - the same signed action attestation appearing twice inside one packet, and
//! - a second, different packet asserting a decision or action that an
//!   earlier packet already recorded.
//!
//! Either way, a consumer that sums a ledger over the evidence counts one
//! event twice. Neither was caught: R11 verifies each attestation's signature
//! independently, and a duplicate of a genuine attestation is genuinely
//! signed.
//!
//! # The split these tests pin
//!
//! R17 `ACTION_UNIQUENESS` is a property of the packet alone, so it is always
//! evaluated. R18 `REPLAY_SCOPE` is a property of the packet *relative to
//! what else exists*, which a stateless verifier cannot know, so it is
//! evaluated only when the verifier supplies its history — and is NOT
//! EVALUATED otherwise, never a pass.

use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::sha256;
use aip_protocol::verification_report::rules;
use aip_protocol::{
    verify_packet, ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacket,
    EvidencePacketBuilder, ObservedHistory, RootAuthority, TrustFloor, VerificationContext,
    VerificationReport,
};
use aip_types::{Action, AlgorithmId, ProvenanceTriple, PublicKey, ScopeAction};

const CENTURY_MS: u64 = 100 * 365 * 24 * 60 * 60 * 1000;

fn prov(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("m:{tag}").as_bytes()),
        environment_commitment: sha256(format!("e:{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("t:{tag}").as_bytes()),
    }
}

/// An agent with a full authority chain behind it, reusable across packets so
/// two packets can be built under the *same* identity — which is what a
/// replay looks like.
struct Chain {
    agent_id: String,
    agent_public: Vec<u8>,
    agent_private: Vec<u8>,
    provenance: ProvenanceTriple,
    root_authority: RootAuthority,
    delegation: Vec<aip_types::DelegationToken>,
    ctx: VerificationContext,
}

fn chain() -> Chain {
    let (cfo_aid, cfo_kp) = create_identity(prov("cfo"), None).unwrap();
    let (orch_aid, orch_kp) = create_identity(prov("orch"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(prov("agent"), None).unwrap();

    let root_token = issue_scoped_token(
        &cfo_aid.id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(CENTURY_MS),
    )
    .unwrap();
    let hop = create_delegation(
        &root_token,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .unwrap();

    let ctx = VerificationContext::new()
        .trust_issuer(&cfo_aid.id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);

    Chain {
        agent_id: agent_aid.id.clone(),
        agent_public: agent_kp.public_key.clone(),
        agent_private: agent_kp.private_key.clone(),
        provenance: agent_aid.provenance.clone(),
        root_authority: RootAuthority {
            principal_id: cfo_aid.id,
            display_role: "CFO".into(),
            root_token,
        },
        delegation: vec![hop],
        ctx,
    }
}

impl Chain {
    fn decision(&self, decision_id: [u8; 16], at: u64) -> DecisionRecord {
        DecisionRecord {
            decision_id,
            action_kind: ScopeAction::Standard(Action::Write),
            summary: "approve payment".into(),
            input_hash: sha256(b"inv-1"),
            rationale_hash: sha256(b"ok"),
            decided_at: at,
        }
    }

    fn action(&self, decision_id: &[u8; 16], payload: &[u8], at: u64) -> ActionAttestation {
        ActionAttestation::create(
            &self.agent_id,
            &self.agent_private,
            decision_id,
            ScopeAction::Standard(Action::Write),
            "POST /ledger/payments",
            sha256(payload),
            at,
        )
        .unwrap()
    }

    fn seal(&self, decision: DecisionRecord, actions: Vec<ActionAttestation>) -> EvidencePacket {
        let mut b = EvidencePacketBuilder::new(
            AgentIdentitySummary {
                aip_id: self.agent_id.clone(),
                public_key: PublicKey {
                    algorithm: AlgorithmId::Ed25519,
                    key_bytes: self.agent_public.clone(),
                },
                provenance: self.provenance.clone(),
            },
            self.root_authority.clone(),
        )
        .delegation_chain(self.delegation.clone())
        .decision(decision)
        .claimed_trust_floor(TrustFloor::AuthorityBound);
        for a in actions {
            b = b.action(a);
        }
        b.build_and_sign(&self.agent_private).unwrap()
    }
}

fn rule<'a>(report: &'a VerificationReport, name: &str) -> &'a aip_protocol::RuleResult {
    report
        .rule(name)
        .unwrap_or_else(|| panic!("{name} must appear in the report"))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// ═══ R17 — a duplicated attestation is one claim written twice ═══

#[test]
fn a_packet_repeating_an_attestation_is_refused() {
    // The intra-packet double count. The duplicate is a byte-identical copy
    // of a genuinely signed attestation, so it passes R11 exactly as the
    // original does. Only R17 sees it.
    let c = chain();
    let now = now_ms();
    let d = c.decision([0xD1; 16], now);
    let a = c.action(&d.decision_id, b"pay 1000", now + 1);
    let packet = c.seal(d, vec![a.clone(), a]);

    let report = verify_packet(&packet, &c.ctx);
    let r17 = rule(&report, rules::ACTION_UNIQUENESS);
    assert!(r17.evaluated, "R17 must always be evaluated");
    assert!(
        !r17.pass,
        "SECURITY (B-8): a packet carrying the same action attestation twice \
         was accepted; a ledger summing its actions would double count"
    );
    assert!(
        rule(&report, rules::ACTION_ATTESTATIONS).pass,
        "precondition: the duplicate must be individually valid, or R17 is \
         not the rule doing the work here"
    );
    assert!(!report.valid);
}

#[test]
fn the_refusal_names_the_repeated_action() {
    let c = chain();
    let now = now_ms();
    let d = c.decision([0xD2; 16], now);
    let a = c.action(&d.decision_id, b"pay 1000", now + 1);
    let id = hex::encode(a.action_id);
    let packet = c.seal(d, vec![a.clone(), a]);

    let report = verify_packet(&packet, &c.ctx);
    let detail = &rule(&report, rules::ACTION_UNIQUENESS).detail;
    assert!(detail.contains(&id), "must name the action: {detail}");
}

#[test]
fn distinct_actions_in_one_packet_are_fine() {
    // The counterweight. A packet legitimately carries several actions under
    // one decision; R17 must not object to that.
    let c = chain();
    let now = now_ms();
    let d = c.decision([0xD3; 16], now);
    let a1 = c.action(&d.decision_id, b"pay 1000", now + 1);
    let a2 = c.action(&d.decision_id, b"pay 2000", now + 2);
    assert_ne!(a1.action_id, a2.action_id);
    let packet = c.seal(d, vec![a1, a2]);

    let report = verify_packet(&packet, &c.ctx);
    assert!(rule(&report, rules::ACTION_UNIQUENESS).pass);
    assert!(report.valid, "failures: {:?}", report.failures());
}

// ═══ R18 — not evaluated without a history, never passed ═══

#[test]
fn a_stateless_verifier_reports_replay_as_not_evaluated() {
    // The epistemic core of B-8. Replay is not a property of a packet; it is
    // a property of a packet relative to what else exists. A verifier with no
    // memory cannot answer, and must say so rather than pass.
    let c = chain();
    let now = now_ms();
    let d = c.decision([0xD4; 16], now);
    let a = c.action(&d.decision_id, b"pay 1000", now + 1);
    let packet = c.seal(d, vec![a]);

    let report = verify_packet(&packet, &c.ctx);
    let r18 = rule(&report, rules::REPLAY_SCOPE);
    assert!(
        !r18.evaluated,
        "SECURITY (B-8): a stateless verifier claimed to have checked for \
         replay. It has no history; it cannot know."
    );
    assert!(
        report
            .not_evaluated()
            .iter()
            .any(|c| c.rule == rules::REPLAY_SCOPE),
        "R18 must appear in the not-evaluated set"
    );
    // And an unevaluated rule must not drag the verdict down either.
    assert!(report.valid, "failures: {:?}", report.failures());
}

#[test]
fn an_empty_history_is_an_evaluated_pass_not_a_skip() {
    // "I keep no history" and "I keep a history and it is empty" are
    // different claims. The first cannot be answered; the second is a genuine
    // answer from a stateful verifier whose store is empty.
    let c = chain();
    let now = now_ms();
    let d = c.decision([0xD5; 16], now);
    let a = c.action(&d.decision_id, b"pay 1000", now + 1);
    let packet = c.seal(d, vec![a]);

    let ctx = c.ctx.clone().with_history(ObservedHistory::new());
    let report = verify_packet(&packet, &ctx);
    let r18 = rule(&report, rules::REPLAY_SCOPE);
    assert!(r18.evaluated, "an empty history is still a history");
    assert!(r18.pass, "{}", r18.detail);
}

// ═══ R18 — a second packet reusing an identity is refused ═══

#[test]
fn a_second_packet_reusing_a_decision_is_refused() {
    // The cross-packet replay. Both packets are correctly signed by the same
    // agent under the same authority; nothing but history distinguishes them.
    let c = chain();
    let now = now_ms();

    let first = c.seal(
        c.decision([0xD6; 16], now),
        vec![c.action(&[0xD6; 16], b"pay 1000", now + 1)],
    );
    // A different packet — different payload, so a different action id and a
    // different packet id — reusing the decision.
    let second = c.seal(
        c.decision([0xD6; 16], now),
        vec![c.action(&[0xD6; 16], b"pay 9999", now + 2)],
    );
    assert_ne!(first.packet_id, second.packet_id);

    let mut history = ObservedHistory::new();
    history.observe(&first);
    let ctx = c.ctx.clone().with_history(history);

    let report = verify_packet(&second, &ctx);
    let r18 = rule(&report, rules::REPLAY_SCOPE);
    assert!(
        !r18.pass,
        "SECURITY (B-8): a second packet reusing an already-recorded decision \
         was accepted"
    );
    assert!(
        r18.detail.contains(&hex::encode(first.packet_id)),
        "the refusal must name the packet that established the identity: {}",
        r18.detail
    );
}

#[test]
fn a_second_packet_reusing_an_action_is_refused() {
    // The transplant: a genuine, signed attestation lifted into a second
    // packet. Its signature covers the decision id, so this only works under
    // the same decision — which is exactly the case a store keyed on packet
    // id does not catch, because the two packets differ.
    let c = chain();
    let now = now_ms();
    let d_id = [0xD7; 16];
    let action = c.action(&d_id, b"pay 1000", now + 1);

    let first = c.seal(c.decision(d_id, now), vec![action.clone()]);
    let second = c.seal(
        c.decision(d_id, now),
        vec![action.clone(), c.action(&d_id, b"pay 1", now + 2)],
    );
    assert_ne!(first.packet_id, second.packet_id);

    let mut history = ObservedHistory::new();
    history.observe(&first);
    let ctx = c.ctx.clone().with_history(history);

    let report = verify_packet(&second, &ctx);
    let r18 = rule(&report, rules::REPLAY_SCOPE);
    assert!(
        !r18.pass,
        "SECURITY (B-8): a transplanted action attestation was accepted"
    );
    assert!(
        r18.detail.contains(&hex::encode(action.action_id)),
        "the refusal must name the reused action: {}",
        r18.detail
    );
}

// ═══ The property that makes the design usable ═══

#[test]
fn re_verifying_a_packet_against_a_history_containing_it_still_passes() {
    // The failure mode a bare "seen" set would have introduced, and the
    // reason the history maps each identity to the packet that established
    // it. An ingest tier stores a packet, builds its history from the store,
    // and re-verifies: the packet must not be refused as a replay of itself.
    // Archival re-verification depends on this.
    let c = chain();
    let now = now_ms();
    let d = c.decision([0xD8; 16], now);
    let a = c.action(&d.decision_id, b"pay 1000", now + 1);
    let packet = c.seal(d, vec![a]);

    let mut history = ObservedHistory::new();
    history.observe(&packet);
    let ctx = c.ctx.clone().with_history(history);

    let report = verify_packet(&packet, &ctx);
    let r18 = rule(&report, rules::REPLAY_SCOPE);
    assert!(r18.evaluated);
    assert!(
        r18.pass,
        "SECURITY (B-8): a packet was refused as a replay of itself. \
         Archival re-verification is broken: {}",
        r18.detail
    );
    assert!(report.valid, "failures: {:?}", report.failures());
}

#[test]
fn observing_a_packet_twice_is_idempotent() {
    let c = chain();
    let now = now_ms();
    let d = c.decision([0xD9; 16], now);
    let packet = c.seal(d, vec![c.action(&[0xD9; 16], b"pay 1000", now + 1)]);

    let mut history = ObservedHistory::new();
    history.observe(&packet);
    let after_once = history.clone();
    history.observe(&packet);
    assert_eq!(history, after_once, "observe must be idempotent");
}

#[test]
fn the_first_packet_to_record_an_identity_keeps_it() {
    // First writer wins. A history built by replaying a store in order must
    // attribute each identity to the packet that established it, not to the
    // last one that reused it — otherwise the replaying packet would be
    // recorded as the owner and the genuine one refused.
    let c = chain();
    let now = now_ms();
    let d_id = [0xDA; 16];
    let first = c.seal(c.decision(d_id, now), vec![c.action(&d_id, b"a", now + 1)]);
    let second = c.seal(c.decision(d_id, now), vec![c.action(&d_id, b"b", now + 2)]);

    let mut history = ObservedHistory::new();
    history.observe(&first);
    history.observe(&second);

    assert_eq!(
        history.decisions.get(&d_id),
        Some(&first.packet_id),
        "the decision must still belong to the packet that established it"
    );
    // ...and so the genuine first packet still verifies.
    let ctx = c.ctx.clone().with_history(history);
    let report = verify_packet(&first, &ctx);
    assert!(rule(&report, rules::REPLAY_SCOPE).pass);
}
