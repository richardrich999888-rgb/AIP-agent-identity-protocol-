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
}

impl VerificationContext {
    pub fn new() -> Self {
        Self::default()
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
        });
        pass
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
    let authority_ok = check_authority_chain(packet, &mut e);

    // ── R8 SCOPE_AUTHORITY: decision and every action within effective scope ──
    let scope_ok = check_scope_authority(packet, effective_scope.as_ref(), &mut e);

    // ── R9 REVOCATION ─────────────────────────────────────────────────────
    let mut revoked: Vec<String> = vec![];
    if ctx.revoked_jtis.contains(&root.root_token.jti) {
        revoked.push(format!("root token {}", hex::encode(root.root_token.jti)));
    }
    for hop in &packet.delegation_chain {
        if ctx.revoked_jtis.contains(&hop.jti) {
            revoked.push(format!("delegation {}", hex::encode(hop.jti)));
        }
    }
    let revocation_ok = revoked.is_empty();
    e.record(
        rules::REVOCATION,
        revocation_ok,
        if revocation_ok {
            "no token in the authority chain is revoked".to_string()
        } else {
            format!("revoked tokens in chain: {}", revoked.join(", "))
        },
    );

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

    let valid = e.checks.iter().all(|c| c.pass);
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
        checks: e.checks,
    }
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
fn check_authority_chain(packet: &EvidencePacket, e: &mut Engine) -> bool {
    let root = &packet.root_authority;
    let mut problems: Vec<String> = vec![];

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

    let ok = problems.is_empty();
    e.record(
        rules::AUTHORITY_CHAIN,
        ok,
        if ok {
            format!(
                "authority chain connects principal {} to acting agent {}",
                root.principal_id, packet.agent.aip_id
            )
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
