//! The EvidencePacket verification engine.
//!
//! Input: an [`EvidencePacket`] + a [`VerificationContext`] (trusted keys,
//! revocation set, optional external artifacts).
//! Output: a [`VerificationReport`].
//!
//! Design rules:
//! - **Every check is real.** Each rule recomputes hashes or verifies
//!   signatures against supplied keys. There are no hardcoded passes.
//! - **No short-circuiting.** All rules run even after a failure, so an
//!   auditor sees the complete picture in one report.
//! - **Trust is derived, never asserted.** The packet's claimed trust floor
//!   is checked against the floor the evidence actually supports.

use std::collections::{HashMap, HashSet};

use aip_core::capability::{scope_permits, verify_scoped_token};
use aip_core::delegation::verify_delegation_chain;
use aip_crypto::{derive_aip_id, sha256, validate_aip_id, verify_ed25519};
use aip_types::CapabilityScope;

use crate::evidence_packet::{EvidencePacket, TrustFloor, PACKET_MAGIC, PACKET_VERSION};
use crate::revocation_list::RevocationEvidence;
use crate::verification_report::{rules, RuleResult, VerificationReport};
use aip_types::EXECUTION_BINDING_VERSION;

/// Trusted inputs for verification. The verifier — not the packet — decides
/// which issuer keys to trust and which tokens are revoked.
#[derive(Debug, Clone, Default)]
pub struct VerificationContext {
    /// AIP-ID → Ed25519 public key for the root principal and every
    /// delegation issuer in the chain.
    pub issuer_public_keys: HashMap<String, Vec<u8>>,
    /// Counterparty ID → Ed25519 public key for receipt countersignatures.
    pub counterparty_public_keys: HashMap<String, Vec<u8>>,
    /// JTIs (root token or delegation) known to be revoked.
    pub revoked_jtis: HashSet<[u8; 16]>,
    /// If provided, the exported trace data; must hash to the packet's
    /// `trace_binding.trace_hash`.
    pub trace_data: Option<Vec<u8>>,
    /// If provided, the receipt content; must hash to the packet's
    /// `receipt_binding.receipt_hash`.
    pub receipt_data: Option<Vec<u8>>,
    /// The verifier's own view of the current time, in Unix ms. When
    /// supplied, R16 refuses any packet dated after it. When absent, R16 is
    /// recorded as not evaluated — the verifier states that it applied no
    /// temporal bound rather than implying one (AUDIT P0-1).
    ///
    /// It is deliberately not read from the system clock: an offline
    /// verifier checking a historical packet, an air-gapped verifier and a
    /// test all need to say explicitly what "now" means to them.
    pub verification_time_ms: Option<u64>,
    /// How far ahead of `verification_time_ms` a timestamp may still be, to
    /// absorb declared clock skew. Zero by default; a tolerance is a bound,
    /// not a licence.
    pub future_tolerance_ms: u64,
    /// What this verifier has already observed, for replay detection.
    ///
    /// `None` means the verifier keeps no history — an offline or one-shot
    /// verifier, which is the common case. R18 is then recorded as not
    /// evaluated: a verifier with no memory has not established that a packet
    /// is fresh, and must not imply that it has (AUDIT B-8).
    ///
    /// `Some(empty)` is different and is a genuine evaluated pass: a stateful
    /// verifier whose store is empty has looked and found nothing.
    pub observed_history: Option<ObservedHistory>,
    /// Whether the verifier refuses an authority root the acting agent
    /// issued to itself (R6 of `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`).
    ///
    /// # What self-issued authority is
    ///
    /// An `EvidencePacket` carries a root token naming a principal who
    /// granted the agent its scope. Nothing in the packet format stops that
    /// principal from *being* the agent: an agent holding its own key can
    /// mint itself an admin root token, sign every hop, and produce a packet
    /// in which all fourteen original rules pass. The packet is internally
    /// consistent and cryptographically sound; it simply records the agent
    /// authorising itself, which is not authority at all.
    ///
    /// # Why this is a verifier choice and not a protocol rule
    ///
    /// Some legitimate deployments are self-issued by construction: a
    /// single-operator tool, a development environment, an agent that is its
    /// own principal because there is no institution above it. Refusing
    /// those by default would break existing packets and would make the
    /// verifier wrong about a deployment shape it was never told about.
    ///
    /// So the default is `false` and the behaviour is unchanged. What the
    /// report does *not* do is stay silent: whenever the root is
    /// self-issued, [`rules::AUTHORITY_CHAIN`]'s detail says so, whether or
    /// not this flag is set. A verifier that did not ask the question still
    /// learns the answer.
    ///
    /// A regulated entity — where the whole point is that something other
    /// than the agent decided — sets this to `true` and gets a failed
    /// `AUTHORITY_CHAIN` instead of a note.
    pub independent_authority_required: bool,
    /// A signed, time-bounded revocation list the verifier holds, or the
    /// reason one it was offered cannot be used (R7).
    ///
    /// This is the authoritative source. [`Self::revoked_jtis`] remains for
    /// a verifier that was simply told "this JTI is revoked" by some other
    /// means; both are consulted, and a hit in either is a failure.
    ///
    /// `None` means no list was offered. Combined with an empty
    /// `revoked_jtis` that makes [`rules::REVOCATION`] NOT EVALUATED rather
    /// than a pass: a verifier that was told nothing about revocation has
    /// established nothing about it.
    pub revocation_evidence: Option<RevocationEvidence>,
    /// Ed25519 public keys the verifier accepts as audit-export bundle
    /// signers.
    ///
    /// Used only by [`crate::bundle::verify_zip`]. A bundle's manifest names
    /// the key that signed it, and checking the signature against that key
    /// proves only that the manifest is internally consistent — anyone can
    /// produce such a bundle (AUDIT B-4). Establishing *who* exported it
    /// requires a key the verifier already trusts, which is what this holds.
    ///
    /// Empty means the verifier supplied no anchor. The signer-trust check is
    /// then reported as unestablished rather than passed: absent evidence is
    /// not evidence of absence, and it is certainly not a pass.
    pub trusted_bundle_signers: HashSet<[u8; 32]>,
}

/// Replay identities a stateful verifier has already recorded, each mapped to
/// the packet that established it.
///
/// # Why the value is a packet id and not a bare set
///
/// An evidence packet is a *record of what happened*, not a command, so
/// verifying the same packet twice is not an attack — archival and delayed
/// verification depend on it being possible. A bare "seen" set makes the
/// obvious wiring wrong: an ingest tier that populates it from its own store
/// and then re-verifies a stored packet would refuse the packet's own entry.
///
/// Mapping each identity to the packet that established it removes that
/// failure mode structurally. A packet re-verified against a history that
/// already contains it maps to itself and passes; only a *different* packet
/// reusing the identity is a replay. There is no way to hold this correctly
/// and no way to hold it incorrectly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedHistory {
    /// `decision_id` → the 16-byte packet id that first recorded that decision.
    pub decisions: HashMap<[u8; 16], [u8; 16]>,
    /// `action_id` → the 16-byte packet id that first recorded that action.
    pub actions: HashMap<[u8; 16], [u8; 16]>,
}

impl ObservedHistory {
    /// An empty history: a stateful verifier that has recorded nothing yet.
    ///
    /// Distinct from `None`, which is a verifier that keeps no history at all.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `packet`'s replay identities.
    ///
    /// First writer wins: if an identity is already present it is left alone,
    /// so a history built by replaying a store in order attributes each
    /// identity to the packet that genuinely established it rather than to
    /// the last one that reused it.
    pub fn observe(&mut self, packet: &EvidencePacket) {
        let packet_id = packet.packet_id;
        self.decisions
            .entry(packet.decision.decision_id)
            .or_insert(packet_id);
        for action in &packet.actions {
            self.actions.entry(action.action_id).or_insert(packet_id);
        }
    }
}

impl VerificationContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify against `history`, enabling R18.
    pub fn with_history(mut self, history: ObservedHistory) -> Self {
        self.observed_history = Some(history);
        self
    }

    /// Anchor an Ed25519 public key as an accepted bundle signer.
    ///
    /// A key of the wrong length is ignored rather than accepted: a
    /// malformed anchor must not silently become a trusted one. Callers that
    /// need to know supply the key through their own validated path.
    pub fn trust_bundle_signer(mut self, public_key: &[u8]) -> Self {
        if let Ok(key) = <[u8; 32]>::try_from(public_key) {
            self.trusted_bundle_signers.insert(key);
        }
        self
    }

    /// Verify as of `ms`: nothing in the packet may be dated after it.
    pub fn at_time(mut self, ms: u64) -> Self {
        self.verification_time_ms = Some(ms);
        self
    }

    /// Allow timestamps up to `ms` ahead of the verification time.
    pub fn with_future_tolerance(mut self, ms: u64) -> Self {
        self.future_tolerance_ms = ms;
        self
    }

    /// Require that the authority root be someone other than the acting
    /// agent (R6). See [`VerificationContext::independent_authority_required`]
    /// for what this refuses and why it is off by default.
    pub fn require_independent_authority(mut self) -> Self {
        self.independent_authority_required = true;
        self
    }

    pub fn trust_issuer(mut self, aip_id: &str, public_key: &[u8]) -> Self {
        self.issuer_public_keys
            .insert(aip_id.to_string(), public_key.to_vec());
        self
    }

    pub fn trust_counterparty(mut self, id: &str, public_key: &[u8]) -> Self {
        self.counterparty_public_keys
            .insert(id.to_string(), public_key.to_vec());
        self
    }

    pub fn revoke(mut self, jti: [u8; 16]) -> Self {
        self.revoked_jtis.insert(jti);
        self
    }
}

struct Engine {
    checks: Vec<RuleResult>,
    tamper_evidence: bool,
}

impl Engine {
    fn record(&mut self, rule: &str, pass: bool, detail: impl Into<String>) -> bool {
        self.checks.push(RuleResult {
            rule: rule.to_string(),
            pass,
            detail: detail.into(),
            evaluated: true,
        });
        pass
    }

    /// Record a rule the verifier could not run. Never a pass: `valid`
    /// ignores unevaluated rules, and the report says which they were.
    fn record_not_evaluated(&mut self, rule: &str, detail: impl Into<String>) {
        self.checks.push(RuleResult {
            rule: rule.to_string(),
            pass: false,
            detail: detail.into(),
            evaluated: false,
        });
    }

    fn record_tamper(&mut self, rule: &str, pass: bool, detail: impl Into<String>) -> bool {
        if !pass {
            self.tamper_evidence = true;
        }
        self.record(rule, pass, detail)
    }
}

/// Verify an EvidencePacket against trusted context. Runs every rule and
/// returns the complete report.
pub fn verify_packet(packet: &EvidencePacket, ctx: &VerificationContext) -> VerificationReport {
    let mut e = Engine {
        checks: vec![],
        tamper_evidence: false,
    };

    // ── R1 STRUCTURE ──────────────────────────────────────────────────────
    let structure_ok = check_structure(packet, &mut e);

    // ── R2 AGENT_ID_BINDING: AIP-ID must derive from (pubkey, provenance) ──
    let id_format_ok = validate_aip_id(&packet.agent.aip_id).is_ok();
    let derived = derive_aip_id(&packet.agent.public_key.key_bytes, &packet.agent.provenance);
    let binding_ok = id_format_ok && derived == packet.agent.aip_id;
    e.record(
        rules::AGENT_ID_BINDING,
        binding_ok,
        if binding_ok {
            "agent AIP-ID derives from embedded public key and provenance".to_string()
        } else if !id_format_ok {
            "agent AIP-ID fails format/checksum validation".to_string()
        } else {
            format!(
                "agent AIP-ID {} does not match derived ID {}",
                packet.agent.aip_id, derived
            )
        },
    );

    // ── R3 CANONICAL_HASH: recompute and compare ──────────────────────────
    let canonical = packet.canonical_bytes();
    let recomputed = sha256(&canonical);
    let hash_ok = recomputed == packet.packet_hash;
    e.record_tamper(
        rules::CANONICAL_HASH,
        hash_ok,
        if hash_ok {
            "recomputed canonical hash matches packet_hash".to_string()
        } else {
            format!(
                "packet_hash mismatch: stored {} recomputed {} — packet modified after sealing",
                hex::encode(packet.packet_hash),
                hex::encode(recomputed)
            )
        },
    );

    // ── R4 AGENT_SIGNATURE: agent signed the canonical bytes ──────────────
    let sig = &packet.agent_sig;
    let signer_ok = sig.signer_id == packet.agent.aip_id;
    let payload_ok = sig.payload_hash == recomputed;
    let crypto_ok =
        payload_ok && verify_ed25519(&packet.agent.public_key.key_bytes, sig).unwrap_or(false);
    let agent_sig_ok = signer_ok && crypto_ok;
    e.record_tamper(
        rules::AGENT_SIGNATURE,
        agent_sig_ok,
        if agent_sig_ok {
            "agent packet signature verifies over canonical bytes".to_string()
        } else if !signer_ok {
            format!(
                "signature signer_id {} is not the packet agent {}",
                sig.signer_id, packet.agent.aip_id
            )
        } else if !payload_ok {
            "signature payload hash does not cover current packet contents".to_string()
        } else {
            "agent signature cryptographic verification failed".to_string()
        },
    );

    // ── R5 ROOT_TOKEN_SIGNATURE ───────────────────────────────────────────
    // A missing trust anchor makes the packet unverifiable, not tampered;
    // a failing signature under a trusted key is tamper evidence.
    let root = &packet.root_authority;
    let root_issuer_key = ctx.issuer_public_keys.get(&root.root_token.issuer_id);
    let root_sig_ok = match root_issuer_key {
        Some(pk) => verify_scoped_token(&root.root_token, pk).unwrap_or(false),
        None => false,
    };
    if root_issuer_key.is_some() && !root_sig_ok {
        e.tamper_evidence = true;
    }
    e.record(
        rules::ROOT_TOKEN_SIGNATURE,
        root_sig_ok,
        if root_sig_ok {
            format!(
                "root token signed by trusted issuer {}",
                root.root_token.issuer_id
            )
        } else if root_issuer_key.is_none() {
            format!(
                "no trusted public key for root issuer {}",
                root.root_token.issuer_id
            )
        } else {
            "root token signature verification failed".to_string()
        },
    );

    // ── R6 DELEGATION_CHAIN: per-hop signatures, linkage, attenuation ─────
    let (chain_ok, effective_scope) = match verify_delegation_chain(
        &root.root_token,
        &packet.delegation_chain,
        &ctx.issuer_public_keys,
    ) {
        Ok(scope) => (true, Some(scope)),
        Err(err) => {
            // A missing issuer key (InvalidPublicKey) is a verifiability gap,
            // not tamper evidence; every other failure mode (broken linkage,
            // bad depth, scope escalation, signature mismatch) proves the
            // chain was altered or forged after issuance.
            if err != aip_types::AipError::InvalidPublicKey {
                e.tamper_evidence = true;
            }
            e.record(
                rules::DELEGATION_CHAIN,
                false,
                format!("delegation chain invalid: {err}"),
            );
            (false, None)
        }
    };
    if chain_ok {
        e.record(
            rules::DELEGATION_CHAIN,
            true,
            format!(
                "{}-hop delegation chain verified (per-hop signatures, JTI linkage, depth, scope attenuation)",
                packet.delegation_chain.len()
            ),
        );
    }

    // ── R7 AUTHORITY_CHAIN: principal → issuer → … → acting agent ─────────
    let authority_ok = check_authority_chain(packet, ctx, &mut e);

    // ── R8 SCOPE_AUTHORITY: decision and every action within effective scope ──
    let scope_ok = check_scope_authority(packet, effective_scope.as_ref(), &mut e);

    // ── R9 REVOCATION ─────────────────────────────────────────────────────
    let revocation_ok = check_revocation(packet, ctx, &mut e);

    // ── R10 TEMPORAL_VALIDITY ─────────────────────────────────────────────
    let temporal_ok = check_temporal_validity(packet, &mut e);

    // ── R11 ACTION_ATTESTATIONS: each action individually signed ──────────
    let actions_ok = check_action_attestations(packet, &mut e);

    // ── R12 TRACE_BINDING ─────────────────────────────────────────────────
    let (trace_present_and_ok, trace_rule_ok) = check_trace_binding(packet, ctx, &mut e);

    // ── R13 RECEIPT_BINDING ───────────────────────────────────────────────
    let (receipt_countersigned, receipt_rule_ok) = check_receipt_binding(packet, ctx, &mut e);

    // ── R15 EXECUTION_BINDING: self-reported binding must be well-formed
    //    and consistent with the packet agent. Does NOT affect the trust
    //    floor: a self-report cannot raise evidence strength (I5).
    check_execution_binding(packet, &mut e);

    // ── Derive trust floor from what actually verified ────────────────────
    let agent_signed = structure_ok && binding_ok && hash_ok && agent_sig_ok;
    let authority_bound = agent_signed
        && root_sig_ok
        && chain_ok
        && authority_ok
        && scope_ok
        && revocation_ok
        && temporal_ok
        && actions_ok;
    let counterparty_signed = authority_bound && receipt_rule_ok && receipt_countersigned;

    let derived_floor = if counterparty_signed {
        TrustFloor::CounterpartySigned
    } else if authority_bound {
        TrustFloor::AuthorityBound
    } else if agent_signed {
        TrustFloor::AgentSigned
    } else {
        TrustFloor::Unverified
    };

    // ── R14 TRUST_FLOOR: claim must not exceed evidence ───────────────────
    let floor_ok = derived_floor >= packet.claimed_trust_floor;
    e.record(
        rules::TRUST_FLOOR,
        floor_ok,
        if floor_ok {
            format!(
                "derived floor {:?} supports claimed floor {:?}",
                derived_floor, packet.claimed_trust_floor
            )
        } else {
            format!(
                "claimed floor {:?} exceeds what the evidence supports ({:?})",
                packet.claimed_trust_floor, derived_floor
            )
        },
    );

    // ── R16 VERIFICATION_TIME_BOUND: nothing is dated after the verifier's
    //    own time (AUDIT P0-1). Absent a supplied time, not evaluated. ────
    check_verification_time_bound(packet, ctx, &mut e);

    // ── R17/R18 replay (AUDIT B-8). R17 is a property of the packet alone
    //    and is always evaluated; R18 needs the verifier's own memory. ──
    check_action_uniqueness(packet, &mut e);
    check_replay_scope(packet, ctx, &mut e);

    // `valid` ignores rules that were not evaluated: a check the verifier
    // could not run is neither a pass nor a failure, and the report says
    // which is which.
    let valid = e.checks.iter().all(|c| !c.evaluated || c.pass);
    VerificationReport {
        valid,
        trust_floor: derived_floor,
        claimed_trust_floor: packet.claimed_trust_floor,
        tampered: e.tamper_evidence,
        authority_chain_verified: authority_ok && root_sig_ok && chain_ok,
        delegation_chain_verified: chain_ok,
        scope_verified: scope_ok,
        receipt_verified: receipt_countersigned && receipt_rule_ok,
        trace_verified: trace_present_and_ok && trace_rule_ok,
        revocation_clear: revocation_ok,
        packet_id: packet.packet_id_hex(),
        agent_id: packet.agent.aip_id.clone(),
        verified_at: now_ms(),
        verification_time_ms: ctx.verification_time_ms,
        verification_time_checked: ctx.verification_time_ms.is_some(),
        checks: e.checks,
    }
}

/// R17 — no two action attestations in this packet share an `action_id`.
///
/// A repeated attestation is one claim written twice, not two events. Nothing
/// else in the engine catches it: R11 verifies each attestation's signature
/// independently, and a duplicate of a genuine attestation is genuinely
/// signed, so it passes R11 as readily as the original. A downstream ledger
/// summing a packet's actions would count the payment twice.
///
/// Always evaluated: it is a property of the packet alone and needs nothing
/// from the verifier (AUDIT B-8).
fn check_action_uniqueness(packet: &EvidencePacket, e: &mut Engine) {
    let mut seen: HashSet<[u8; 16]> = HashSet::with_capacity(packet.actions.len());
    let mut duplicates: Vec<String> = vec![];
    for action in &packet.actions {
        if !seen.insert(action.action_id) {
            duplicates.push(hex::encode(action.action_id));
        }
    }
    // Duplicates are sorted so the message is identical for the same packet
    // whatever order the duplicates were found in: a report that differs
    // run to run cannot be diffed.
    duplicates.sort();
    duplicates.dedup();

    e.record(
        rules::ACTION_UNIQUENESS,
        duplicates.is_empty(),
        if duplicates.is_empty() {
            format!(
                "{} action attestation(s), all distinct",
                packet.actions.len()
            )
        } else {
            format!(
                "action id(s) repeated within the packet: {}. A repeated \
                 attestation is one claim written twice, not two events.",
                duplicates.join(", ")
            )
        },
    );
}

/// R18 — does this packet reuse a replay identity that a *different* packet
/// already established?
///
/// # What replay means for an evidence packet
///
/// Not what it means for a request. A packet records what happened; verifying
/// it again is not an attack, and archival verification depends on it staying
/// possible. So this rule is not "have I seen this packet before" — that
/// answer is routinely yes and routinely fine.
///
/// It is "has some *other* packet already claimed this decision, or this
/// action?" Two packets asserting the same signed action are two records of
/// one event. Whichever is authentic, a consumer that counts both is wrong.
///
/// # Why it is not evaluated without a history
///
/// Replay is not a property of a packet. It is a property of a packet
/// *relative to what else exists*, and a stateless verifier has no access to
/// that. Reporting a pass here would mean "no replay", which the verifier
/// cannot know; reporting a failure would mean "replay", which it also cannot
/// know. NOT EVALUATED is the only honest answer, and it is what R16
/// established as the shape for a rule whose input the verifier did not
/// supply (AUDIT B-8).
fn check_replay_scope(packet: &EvidencePacket, ctx: &VerificationContext, e: &mut Engine) {
    let Some(history) = &ctx.observed_history else {
        e.record_not_evaluated(
            rules::REPLAY_SCOPE,
            "no observed history supplied: this verifier keeps no record of \
             what it has seen, so nothing here rules out that another packet \
             already claimed this decision or these actions",
        );
        return;
    };

    let mut collisions: Vec<String> = vec![];

    // A packet re-verified against a history that already contains it maps to
    // itself. Only a *different* packet reusing the identity is a replay.
    if let Some(owner) = history.decisions.get(&packet.decision.decision_id) {
        if *owner != packet.packet_id {
            collisions.push(format!(
                "decision {} was already recorded by packet {}",
                hex::encode(packet.decision.decision_id),
                hex::encode(owner)
            ));
        }
    }
    for action in &packet.actions {
        if let Some(owner) = history.actions.get(&action.action_id) {
            if *owner != packet.packet_id {
                collisions.push(format!(
                    "action {} was already recorded by packet {}",
                    hex::encode(action.action_id),
                    hex::encode(owner)
                ));
            }
        }
    }
    collisions.sort();
    collisions.dedup();

    e.record(
        rules::REPLAY_SCOPE,
        collisions.is_empty(),
        if collisions.is_empty() {
            format!(
                "no decision or action in this packet was previously recorded \
                 by another packet ({} decision(s) and {} action(s) in history)",
                history.decisions.len(),
                history.actions.len()
            )
        } else {
            collisions.join("; ")
        },
    );
}

/// R16 — the bound the *verifier* supplies. Every timestamp the packet
/// asserts must be at or before it, allowing the declared tolerance.
///
/// This is not "the authority must still be valid now". A historical packet
/// stays verifiable long after its tokens expire — offline and delayed
/// verification depend on that — and whether the authority was valid *when
/// the decision was made* is R10's question, not this one.
fn check_verification_time_bound(
    packet: &EvidencePacket,
    ctx: &VerificationContext,
    e: &mut Engine,
) {
    let Some(now) = ctx.verification_time_ms else {
        e.record_not_evaluated(
            rules::VERIFICATION_TIME_BOUND,
            "no verification time supplied: the verifier applied no temporal bound, \
             so nothing here rules out a future-dated packet",
        );
        return;
    };
    let bound = now.saturating_add(ctx.future_tolerance_ms);
    let mut ahead: Vec<String> = vec![];
    if packet.decision.decided_at > bound {
        ahead.push(format!(
            "decision decided_at {} is after the bound {bound}",
            packet.decision.decided_at
        ));
    }
    for action in &packet.actions {
        if action.performed_at > bound {
            ahead.push(format!(
                "action {} performed_at {} is after the bound {bound}",
                hex::encode(action.action_id),
                action.performed_at
            ));
        }
    }
    let rt = &packet.root_authority.root_token;
    if rt.issued_at > bound {
        ahead.push(format!(
            "root token issued_at {} is after the bound {bound}",
            rt.issued_at
        ));
    }
    for (i, hop) in packet.delegation_chain.iter().enumerate() {
        if hop.issued_at > bound {
            ahead.push(format!(
                "delegation hop {i} issued_at {} is after the bound {bound}",
                hop.issued_at
            ));
        }
    }
    e.record(
        rules::VERIFICATION_TIME_BOUND,
        ahead.is_empty(),
        if ahead.is_empty() {
            format!("nothing in the packet is dated after {bound}")
        } else {
            format!("dated after the verification bound: {}", ahead.join("; "))
        },
    );
}

// ─── Individual rule implementations ───

fn check_structure(packet: &EvidencePacket, e: &mut Engine) -> bool {
    let mut problems: Vec<String> = vec![];
    if packet.magic != PACKET_MAGIC {
        problems.push("bad magic".into());
    }
    if packet.version != PACKET_VERSION {
        problems.push(format!(
            "unsupported version {} (this verifier implements v{}; embedded authority signatures of other versions are not comparable)",
            packet.version, PACKET_VERSION
        ));
    }
    if packet.agent.aip_id.is_empty() {
        problems.push("empty agent id".into());
    }
    if packet.root_authority.principal_id.is_empty() {
        problems.push("empty principal id".into());
    }
    if packet.actions.is_empty() {
        problems.push("no action attestations".into());
    }
    if packet.decision.summary.is_empty() {
        problems.push("empty decision summary".into());
    }
    let ok = problems.is_empty();
    e.record(
        rules::STRUCTURE,
        ok,
        if ok {
            format!(
                "AEP1 v{} structure valid: {} delegation hop(s), {} action(s)",
                packet.version,
                packet.delegation_chain.len(),
                packet.actions.len()
            )
        } else {
            format!("structural problems: {}", problems.join(", "))
        },
    );
    ok
}

/// Authority-chain connectivity: the named principal issued the root token,
/// each hop's issuer is the previous hop's grantee, and the leaf grantee is
/// the acting agent. (Cryptographic per-hop validity is R6; this rule checks
/// that the chain actually connects the principal to the agent.)
/// R9 REVOCATION — is any token in this authority chain revoked?
///
/// # Why an empty answer is not a pass (R7)
///
/// The rule used to report "no token in the authority chain is revoked"
/// whenever the verifier's revocation set was empty. That sentence is a
/// claim about the world, and a verifier holding nothing had not checked the
/// world. It now separates three states that were previously one:
///
/// - **A hit** in any source the verifier holds: FAIL, whatever else is
///   true. A positive finding never needs the source to be fresh — a list
///   that has expired still proves the issuer revoked that token once, and
///   nothing un-revokes a token.
/// - **A usable source with no hit**: PASS, citing the source, so a reader
///   can see which document the answer rests on and until when it stood.
/// - **No usable source**: NOT EVALUATED, naming what was missing. An
///   expired list lands here, which is the R7 acceptance criterion.
fn check_revocation(packet: &EvidencePacket, ctx: &VerificationContext, e: &mut Engine) -> bool {
    let root = &packet.root_authority;
    let chain: Vec<(&str, [u8; 16])> = std::iter::once(("root token", root.root_token.jti))
        .chain(
            packet
                .delegation_chain
                .iter()
                .map(|h| ("delegation", h.jti)),
        )
        .collect();

    let fresh = match &ctx.revocation_evidence {
        Some(RevocationEvidence::Fresh(list)) => Some(list.as_ref()),
        _ => None,
    };

    let mut hits: Vec<String> = vec![];
    for (what, jti) in &chain {
        let in_list = fresh.is_some_and(|l| l.contains(jti));
        let in_set = ctx.revoked_jtis.contains(jti);
        if in_list || in_set {
            let src = if in_list {
                "signed list"
            } else if matches!(
                ctx.revocation_evidence,
                Some(RevocationEvidence::Live { .. })
            ) {
                "the verifier's own record"
            } else {
                "verifier"
            };
            hits.push(format!("{what} {} (per {src})", hex::encode(jti)));
        }
    }
    if !hits.is_empty() {
        return e.record(
            rules::REVOCATION,
            false,
            format!("revoked tokens in chain: {}", hits.join(", ")),
        );
    }

    if let Some(list) = fresh {
        let (issuer, key_version, sequence, valid_until) = list.citation();
        return e.record(
            rules::REVOCATION,
            true,
            format!(
                "no token in the authority chain appears in revocation list \
                 sequence {sequence} from {issuer} (key version {key_version}), \
                 which the issuer stands behind until {valid_until}"
            ),
        );
    }

    if let Some(RevocationEvidence::Live { source, as_of_ms }) = &ctx.revocation_evidence {
        return e.record(
            rules::REVOCATION,
            true,
            format!(
                "no token in the authority chain is revoked according to \
                 {source}, consulted at {as_of_ms}"
            ),
        );
    }

    if !ctx.revoked_jtis.is_empty() {
        return e.record(
            rules::REVOCATION,
            true,
            format!(
                "no token in the authority chain is among the {} revoked \
                 identifier(s) this verifier supplied directly — note that an \
                 identifier list carries no issuer, issue time or expiry, so \
                 this is a statement about what the verifier was told and not \
                 about the issuer's current record",
                ctx.revoked_jtis.len()
            ),
        );
    }

    let detail = match &ctx.revocation_evidence {
        Some(RevocationEvidence::Unusable(err)) => format!(
            "a revocation list was supplied but cannot be used: {err} — this \
             verifier has established nothing about whether these tokens are \
             revoked"
        ),
        _ => "no revocation source supplied: this verifier holds no signed \
              revocation list and was told of no revoked identifiers, so \
              nothing here establishes that these tokens are live"
            .to_string(),
    };
    e.record_not_evaluated(rules::REVOCATION, detail);
    // Unevaluated rules do not invalidate a report; `valid` ignores them.
    true
}

fn check_authority_chain(
    packet: &EvidencePacket,
    ctx: &VerificationContext,
    e: &mut Engine,
) -> bool {
    let root = &packet.root_authority;
    let mut problems: Vec<String> = vec![];

    // R6 — is the root of this authority the acting agent itself?
    //
    // Two spellings of the same thing, and both count: the declared
    // principal being the agent, and the root token's issuer being the
    // agent. A packet can carry one without the other (a principal id that
    // differs from the issuer is already a separate defect, recorded below),
    // so the question is asked of each independently.
    let self_issued = root.principal_id == packet.agent.aip_id
        || root.root_token.issuer_id == packet.agent.aip_id;

    if root.root_token.issuer_id != root.principal_id {
        problems.push(format!(
            "root token issuer {} is not the declared principal {}",
            root.root_token.issuer_id, root.principal_id
        ));
    }

    if packet.delegation_chain.is_empty() {
        if root.root_token.agent_id != packet.agent.aip_id {
            problems.push(format!(
                "root token holder {} is not the acting agent {}",
                root.root_token.agent_id, packet.agent.aip_id
            ));
        }
    } else {
        let first = &packet.delegation_chain[0];
        if first.issuer_id != root.root_token.agent_id {
            problems.push(format!(
                "first delegation issuer {} does not hold the root token (holder {})",
                first.issuer_id, root.root_token.agent_id
            ));
        }
        for window in packet.delegation_chain.windows(2) {
            if window[1].issuer_id != window[0].grantee_id {
                problems.push(format!(
                    "broken handoff: hop issuer {} is not previous grantee {}",
                    window[1].issuer_id, window[0].grantee_id
                ));
            }
        }
        let leaf = packet.delegation_chain.last().unwrap();
        if leaf.grantee_id != packet.agent.aip_id {
            problems.push(format!(
                "leaf delegation grantee {} is not the acting agent {}",
                leaf.grantee_id, packet.agent.aip_id
            ));
        }
    }

    // The refusal is appended after the structural problems so a packet that
    // is both broken and self-issued reports both, in that order.
    if self_issued && ctx.independent_authority_required {
        problems.push(format!(
            "authority root is the acting agent itself ({}): no independent \
             party authorized this, and this verifier requires one",
            packet.agent.aip_id
        ));
    }

    let ok = problems.is_empty();
    e.record(
        rules::AUTHORITY_CHAIN,
        ok,
        if ok {
            let mut detail = format!(
                "authority chain connects principal {} to acting agent {}",
                root.principal_id, packet.agent.aip_id
            );
            // Passing while self-issued is a pass this verifier did not ask
            // about. Say so rather than let the pass imply independence.
            if self_issued {
                detail.push_str(
                    " — NOTE: the root is the agent itself; independence was \
                     not required by this verifier and is not established",
                );
            }
            detail
        } else {
            problems.join("; ")
        },
    );
    ok
}

fn check_scope_authority(
    packet: &EvidencePacket,
    effective_scope: Option<&CapabilityScope>,
    e: &mut Engine,
) -> bool {
    let Some(scope) = effective_scope else {
        e.record(
            rules::SCOPE_AUTHORITY,
            false,
            "no effective scope available (delegation chain failed verification)",
        );
        return false;
    };

    let mut violations: Vec<String> = vec![];
    if !scope_permits(scope, &packet.decision.action_kind) {
        violations.push(format!(
            "decision exercises {:?} which the effective scope does not permit",
            packet.decision.action_kind
        ));
    }
    for action in &packet.actions {
        if !scope_permits(scope, &action.action_kind) {
            violations.push(format!(
                "action {} performs {:?} outside the effective scope",
                hex::encode(action.action_id),
                action.action_kind
            ));
        }
    }

    let ok = violations.is_empty();
    e.record(
        rules::SCOPE_AUTHORITY,
        ok,
        if ok {
            "decision and all actions fall within the effective (most-attenuated) scope".to_string()
        } else {
            violations.join("; ")
        },
    );
    ok
}

/// R15. When a binding is present it must be version-1, refer to the packet
/// agent, and carry non-degenerate process/executable identity. Absence is
/// reported, not failed: a packet without a binding simply cannot be
/// attributed to a process instance (the reconciler's answer is CANNOT_PROVE).
fn check_execution_binding(packet: &EvidencePacket, e: &mut Engine) -> bool {
    let Some(b) = &packet.execution_binding else {
        return e.record(
            rules::EXECUTION_BINDING,
            true,
            "no execution binding present; process-instance attribution unavailable",
        );
    };
    let mut problems: Vec<String> = vec![];
    if b.version != EXECUTION_BINDING_VERSION {
        problems.push(format!(
            "binding version {} unsupported (expected {})",
            b.version, EXECUTION_BINDING_VERSION
        ));
    }
    if b.agent_id != packet.agent.aip_id {
        problems.push(format!(
            "binding agent {} is not the packet agent {}",
            b.agent_id, packet.agent.aip_id
        ));
    }
    if b.process.pid == 0 {
        problems.push("pid is 0".into());
    }
    if b.process.pid_start_time_ticks == 0 {
        problems.push("pid_start_time_ticks is 0".into());
    }
    if b.process.boot_id == [0u8; 16] {
        problems.push("boot_id is all zeros".into());
    }
    if b.exe_content_sha256 == [0u8; 32] {
        problems.push("exe_content_sha256 is all zeros".into());
    }
    let ok = problems.is_empty();
    e.record(
        rules::EXECUTION_BINDING,
        ok,
        if ok {
            format!(
                "self-reported execution binding present (pid {}, start {} ticks, boot {}, exe {}); NOT independently observed",
                b.process.pid,
                b.process.pid_start_time_ticks,
                hex::encode(b.process.boot_id),
                hex::encode(b.exe_content_sha256)
            )
        } else {
            format!("execution binding problems: {}", problems.join("; "))
        },
    )
}

fn check_temporal_validity(packet: &EvidencePacket, e: &mut Engine) -> bool {
    let mut problems: Vec<String> = vec![];
    let decided = packet.decision.decided_at;

    let mut check_window = |label: String, issued_at: u64, expires_at: Option<u64>| {
        if decided < issued_at {
            problems.push(format!("decision predates issuance of {label}"));
        }
        if let Some(exp) = expires_at {
            if decided > exp {
                problems.push(format!("decision occurred after {label} expired"));
            }
            for action in &packet.actions {
                if action.performed_at > exp {
                    problems.push(format!(
                        "action {} performed after {label} expired",
                        hex::encode(action.action_id)
                    ));
                }
            }
        }
    };

    let rt = &packet.root_authority.root_token;
    check_window("root token".to_string(), rt.issued_at, rt.expires_at);
    for (i, hop) in packet.delegation_chain.iter().enumerate() {
        check_window(format!("delegation hop {i}"), hop.issued_at, hop.expires_at);
    }

    for action in &packet.actions {
        if action.performed_at < packet.decision.decided_at {
            problems.push(format!(
                "action {} performed before its authorizing decision",
                hex::encode(action.action_id)
            ));
        }
    }

    let ok = problems.is_empty();
    e.record(
        rules::TEMPORAL_VALIDITY,
        ok,
        if ok {
            "decision and actions fall within the validity window of every token in the chain"
                .to_string()
        } else {
            problems.join("; ")
        },
    );
    ok
}

fn check_action_attestations(packet: &EvidencePacket, e: &mut Engine) -> bool {
    let mut problems: Vec<String> = vec![];
    for action in &packet.actions {
        let id = hex::encode(action.action_id);
        if action.agent_sig.signer_id != packet.agent.aip_id {
            problems.push(format!("action {id}: signed by a different identity"));
            continue;
        }
        let payload = action.canonical_bytes(&packet.decision.decision_id);
        if action.agent_sig.payload_hash != sha256(&payload) {
            problems.push(format!(
                "action {id}: signature does not cover current action contents"
            ));
            continue;
        }
        let valid =
            verify_ed25519(&packet.agent.public_key.key_bytes, &action.agent_sig).unwrap_or(false);
        if !valid {
            problems.push(format!("action {id}: signature verification failed"));
        }
    }

    let ok = problems.is_empty();
    if !ok {
        e.tamper_evidence = true;
    }
    e.record(
        rules::ACTION_ATTESTATIONS,
        ok,
        if ok {
            format!(
                "all {} action attestation(s) signed by the agent and bound to decision {}",
                packet.actions.len(),
                hex::encode(packet.decision.decision_id)
            )
        } else {
            problems.join("; ")
        },
    );
    ok
}

/// Returns (trace present and externally validated, rule passed).
fn check_trace_binding(
    packet: &EvidencePacket,
    ctx: &VerificationContext,
    e: &mut Engine,
) -> (bool, bool) {
    match (&packet.trace_binding, &ctx.trace_data) {
        (None, _) => {
            let ok = e.record(
                rules::TRACE_BINDING,
                true,
                "no trace binding present (optional)",
            );
            (false, ok)
        }
        (Some(t), None) => {
            let ok = !t.trace_id.is_empty();
            e.record(
                rules::TRACE_BINDING,
                ok,
                if ok {
                    format!(
                        "trace binding present (trace_id {}); no external trace data supplied to cross-check",
                        t.trace_id
                    )
                } else {
                    "trace binding present but trace_id is empty".to_string()
                },
            );
            (false, ok)
        }
        (Some(t), Some(data)) => {
            let ok = sha256(data) == t.trace_hash && !t.trace_id.is_empty();
            if !ok {
                e.tamper_evidence = true;
            }
            e.record(
                rules::TRACE_BINDING,
                ok,
                if ok {
                    format!(
                        "supplied trace data hashes to the bound trace_hash for {}",
                        t.trace_id
                    )
                } else {
                    "supplied trace data does NOT match the bound trace_hash".to_string()
                },
            );
            (ok, ok)
        }
    }
}

/// Returns (receipt countersignature verified, rule passed).
fn check_receipt_binding(
    packet: &EvidencePacket,
    ctx: &VerificationContext,
    e: &mut Engine,
) -> (bool, bool) {
    let Some(r) = &packet.receipt_binding else {
        let ok = e.record(
            rules::RECEIPT_BINDING,
            true,
            "no receipt binding present (optional)",
        );
        return (false, ok);
    };

    let mut problems: Vec<String> = vec![];
    let mut countersigned = false;

    if r.receipt_system.is_empty() || r.receipt_id.is_empty() {
        problems.push("receipt binding missing system or id".to_string());
    }

    // External receipt data, when supplied, must hash to the binding.
    if let Some(data) = &ctx.receipt_data {
        if sha256(data) != r.receipt_hash {
            problems
                .push("supplied receipt data does NOT match the bound receipt_hash".to_string());
            e.tamper_evidence = true;
        }
    }

    // Counterparty countersignature, when present, must verify.
    match (&r.counterparty_id, &r.counterparty_sig) {
        (Some(cp_id), Some(cp_sig)) => {
            if cp_sig.signer_id != *cp_id {
                problems.push("counterparty signature signer mismatch".to_string());
            } else {
                match ctx.counterparty_public_keys.get(cp_id) {
                    None => {
                        problems.push(format!("no trusted public key for counterparty {cp_id}"))
                    }
                    Some(pk) => {
                        let payload = r.canonical_receipt_payload(&packet.decision.decision_id);
                        if cp_sig.payload_hash != sha256(&payload) {
                            problems.push(
                                "counterparty signature does not cover current receipt contents"
                                    .to_string(),
                            );
                            e.tamper_evidence = true;
                        } else if !verify_ed25519(pk, cp_sig).unwrap_or(false) {
                            problems.push("counterparty signature verification failed".to_string());
                            e.tamper_evidence = true;
                        } else {
                            countersigned = true;
                        }
                    }
                }
            }
        }
        (None, None) => {} // uncountersigned receipt binding is allowed; floor stays lower
        _ => problems.push("counterparty id/signature must be present together".to_string()),
    }

    let ok = problems.is_empty();
    e.record(
        rules::RECEIPT_BINDING,
        ok,
        if !ok {
            problems.join("; ")
        } else if countersigned {
            format!(
                "receipt {} @ {} countersigned by {}",
                r.receipt_id,
                r.receipt_system,
                r.counterparty_id.as_deref().unwrap_or("?")
            )
        } else {
            format!(
                "receipt {} @ {} bound by hash (no countersignature)",
                r.receipt_id, r.receipt_system
            )
        },
    );
    (countersigned, ok)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
