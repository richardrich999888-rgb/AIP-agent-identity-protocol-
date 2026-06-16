//! EvidencePacket v1 — the primary artifact of the AIP accountability layer.
//!
//! An EvidencePacket is a self-contained, tamper-evident record that answers,
//! cryptographically: *what did the agent do, and who authorized it?*
//!
//! ## Integrity model
//!
//! - `packet_hash = SHA-256(canonical_bytes)` where `canonical_bytes` covers
//!   every field except `packet_hash` and `agent_sig` themselves.
//! - `agent_sig` is the agent's Ed25519 signature whose `payload_hash` is
//!   exactly `packet_hash`. Any post-signing modification of any field —
//!   including embedded delegation signatures and the counterparty receipt
//!   signature — changes the canonical bytes and is detected.
//! - Each [`ActionAttestation`] additionally carries its own agent signature
//!   bound to the packet's decision, so a single action cannot be
//!   transplanted into a different decision context.
//!
//! ## Assembly order
//!
//! Receipt countersignatures are obtained **before** the packet is sealed
//! (the receipt exists once the external system has acted), so the agent's
//! packet signature covers the countersignature too.

use aip_crypto::{sha256, sign_ed25519};
use aip_types::{
    AipError, DelegationToken, ProvenanceTriple, PublicKey, ScopeAction, ScopedToken, Signature,
};
use serde::{Deserialize, Serialize};

use crate::canonical::*;

/// Magic bytes identifying an AIP EvidencePacket ("AEP1").
pub const PACKET_MAGIC: [u8; 4] = *b"AEP1";
/// EvidencePacket wire-format version.
pub const PACKET_VERSION: u16 = 1;

// ─── Trust Floor ───

/// The minimum level of trust a verifier may place in a packet.
///
/// Ordered: each level implies all levels below it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustFloor {
    /// Structure parses but no signature has been verified.
    #[default]
    Unverified = 0,
    /// The agent's packet signature verifies against its bound public key.
    AgentSigned = 1,
    /// AgentSigned **and** the full authority chain verifies: root token
    /// signature, every delegation hop, scope attenuation, temporal
    /// validity, revocation freedom, and authority-chain connectivity from
    /// the root principal to the acting agent.
    AuthorityBound = 2,
    /// AuthorityBound **and** an external counterparty countersigned the
    /// receipt binding.
    CounterpartySigned = 3,
}

// ─── Component records ───

/// The acting agent's identity, embedded so packets are verifiable offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentitySummary {
    /// AIP-ID — must equal `derive_aip_id(public_key, provenance)`.
    pub aip_id: String,
    pub public_key: PublicKey,
    pub provenance: ProvenanceTriple,
}

/// The root of the authority chain: the principal (typically a human or an
/// organizational role) and the scoped token they issued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootAuthority {
    /// AIP-ID of the root principal (the original authorizer).
    pub principal_id: String,
    /// Human-meaningful role, e.g. "CFO" — display metadata, also covered
    /// by the packet hash so it cannot be rewritten after signing.
    pub display_role: String,
    /// The scoped token the principal issued (signed by the principal).
    pub root_token: ScopedToken,
}

/// What the agent decided to do, with inputs and rationale bound by hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub decision_id: [u8; 16],
    /// The capability this decision exercises — verified against the
    /// effective (most-attenuated) scope of the delegation chain.
    pub action_kind: ScopeAction,
    /// Short human-readable summary of the decision.
    pub summary: String,
    /// SHA-256 of the decision inputs (prompt, task, data references).
    pub input_hash: [u8; 32],
    /// SHA-256 of the decision rationale (model output, reasoning trace).
    pub rationale_hash: [u8; 32],
    pub decided_at: u64,
}

/// A single performed action, individually signed by the agent and bound to
/// the packet's decision so it cannot be replayed under another decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAttestation {
    pub action_id: [u8; 16],
    pub action_kind: ScopeAction,
    pub description: String,
    /// SHA-256 of the action payload (e.g. the API request actually sent).
    pub payload_hash: [u8; 32],
    pub performed_at: u64,
    /// Agent signature over `canonical_action_bytes(self, decision_id)`.
    pub agent_sig: Signature,
}

impl ActionAttestation {
    /// Canonical bytes the per-action signature covers. Includes the
    /// decision ID, binding this attestation to its authorizing decision.
    pub fn canonical_bytes(&self, decision_id: &[u8; 16]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(decision_id);
        buf.extend_from_slice(&self.action_id);
        encode_scope_action(&mut buf, &self.action_kind);
        put_str(&mut buf, &self.description);
        buf.extend_from_slice(&self.payload_hash);
        put_u64(&mut buf, self.performed_at);
        buf
    }

    /// Create and sign an action attestation.
    pub fn create(
        agent_id: &str,
        agent_private_key: &[u8],
        decision_id: &[u8; 16],
        action_kind: ScopeAction,
        description: &str,
        payload_hash: [u8; 32],
        performed_at: u64,
    ) -> Result<Self, AipError> {
        let mut att = ActionAttestation {
            action_id: aip_core::capability::random_jti(),
            action_kind,
            description: description.to_string(),
            payload_hash,
            performed_at,
            // Placeholder; replaced below once canonical bytes are known.
            agent_sig: sign_ed25519(agent_private_key, agent_id, b"placeholder")?,
        };
        let payload = att.canonical_bytes(decision_id);
        att.agent_sig = sign_ed25519(agent_private_key, agent_id, &payload)?;
        Ok(att)
    }
}

/// Binding to an external execution trace (e.g. an OpenTelemetry trace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBinding {
    /// External trace identifier (e.g. W3C trace-id).
    pub trace_id: String,
    /// SHA-256 of the exported trace data.
    pub trace_hash: [u8; 32],
}

/// Binding to an external system's receipt for the action (a ledger entry,
/// an order confirmation, a ticket ID), optionally countersigned by that
/// system so the evidence is bilateral.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptBinding {
    /// Identifier of the external system, e.g. "ledger.example-bank.com".
    pub receipt_system: String,
    /// The receipt identifier inside that system.
    pub receipt_id: String,
    /// SHA-256 of the receipt content.
    pub receipt_hash: [u8; 32],
    /// AIP-ID (or stable key ID) of the countersigning party, if any.
    pub counterparty_id: Option<String>,
    /// Counterparty signature over `canonical_receipt_payload(...)`.
    pub counterparty_sig: Option<Signature>,
}

impl ReceiptBinding {
    /// Canonical bytes the counterparty signs. Includes the decision ID so a
    /// receipt countersignature cannot be transplanted between decisions.
    pub fn canonical_receipt_payload(&self, decision_id: &[u8; 16]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(decision_id);
        put_str(&mut buf, &self.receipt_system);
        put_str(&mut buf, &self.receipt_id);
        buf.extend_from_slice(&self.receipt_hash);
        buf
    }

    /// Counterparty countersigns this receipt binding for the given decision.
    pub fn countersign(
        &mut self,
        decision_id: &[u8; 16],
        counterparty_id: &str,
        counterparty_private_key: &[u8],
    ) -> Result<(), AipError> {
        let payload = self.canonical_receipt_payload(decision_id);
        let sig = sign_ed25519(counterparty_private_key, counterparty_id, &payload)?;
        self.counterparty_id = Some(counterparty_id.to_string());
        self.counterparty_sig = Some(sig);
        Ok(())
    }
}

// ─── EvidencePacket ───

/// The primary artifact: a tamper-evident, signed record binding an agent's
/// action to the authority that permitted it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePacket {
    // Header
    pub magic: [u8; 4],
    pub version: u16,
    pub packet_id: [u8; 16],
    pub created_at: u64,

    // Who acted
    pub agent: AgentIdentitySummary,

    // Under whose authority
    pub root_authority: RootAuthority,
    /// Delegation chain from the root token to the acting agent.
    /// Empty when the agent holds the root token directly.
    pub delegation_chain: Vec<DelegationToken>,

    // What was decided and done
    pub decision: DecisionRecord,
    pub actions: Vec<ActionAttestation>,

    // External bindings
    pub trace_binding: Option<TraceBinding>,
    pub receipt_binding: Option<ReceiptBinding>,

    /// The trust floor the producer claims this packet supports. Verifiers
    /// independently derive the floor; a claim above the derived floor
    /// fails verification.
    pub claimed_trust_floor: TrustFloor,

    // Integrity (excluded from canonical bytes)
    /// SHA-256 of the canonical encoding of all fields above.
    pub packet_hash: [u8; 32],
    /// Agent signature whose payload is exactly the canonical bytes
    /// (`agent_sig.payload_hash == packet_hash`).
    pub agent_sig: Signature,
}

impl EvidencePacket {
    /// Canonical byte encoding of every field except `packet_hash` and
    /// `agent_sig`. This is the exact byte stream that is hashed and signed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Header
        buf.extend_from_slice(&self.magic);
        put_u16(&mut buf, self.version);
        buf.extend_from_slice(&self.packet_id);
        put_u64(&mut buf, self.created_at);

        // Agent identity
        put_str(&mut buf, &self.agent.aip_id);
        put_u8(&mut buf, self.agent.public_key.algorithm as u8);
        put_bytes(&mut buf, &self.agent.public_key.key_bytes);
        buf.extend_from_slice(&self.agent.provenance.to_bytes());

        // Root authority
        put_str(&mut buf, &self.root_authority.principal_id);
        put_str(&mut buf, &self.root_authority.display_role);
        let rt = &self.root_authority.root_token;
        buf.extend_from_slice(&rt.jti);
        put_str(&mut buf, &rt.agent_id);
        put_str(&mut buf, &rt.issuer_id);
        encode_scope(&mut buf, &rt.scope);
        put_u64(&mut buf, rt.issued_at);
        put_opt_u64(&mut buf, &rt.expires_at);
        encode_signature(&mut buf, &rt.issuer_sig);

        // Delegation chain
        buf.extend_from_slice(&(self.delegation_chain.len() as u32).to_le_bytes());
        for hop in &self.delegation_chain {
            buf.extend_from_slice(&hop.jti);
            buf.extend_from_slice(&hop.parent_jti);
            put_str(&mut buf, &hop.issuer_id);
            put_str(&mut buf, &hop.grantee_id);
            encode_scope(&mut buf, &hop.scope);
            put_u8(&mut buf, hop.depth);
            put_u64(&mut buf, hop.issued_at);
            put_opt_u64(&mut buf, &hop.expires_at);
            encode_signature(&mut buf, &hop.issuer_sig);
        }

        // Decision
        buf.extend_from_slice(&self.decision.decision_id);
        encode_scope_action(&mut buf, &self.decision.action_kind);
        put_str(&mut buf, &self.decision.summary);
        buf.extend_from_slice(&self.decision.input_hash);
        buf.extend_from_slice(&self.decision.rationale_hash);
        put_u64(&mut buf, self.decision.decided_at);

        // Actions (including their signatures — they are packet content)
        buf.extend_from_slice(&(self.actions.len() as u32).to_le_bytes());
        for action in &self.actions {
            buf.extend_from_slice(&action.canonical_bytes(&self.decision.decision_id));
            encode_signature(&mut buf, &action.agent_sig);
        }

        // Trace binding
        match &self.trace_binding {
            Some(t) => {
                put_u8(&mut buf, 1);
                put_str(&mut buf, &t.trace_id);
                buf.extend_from_slice(&t.trace_hash);
            }
            None => put_u8(&mut buf, 0),
        }

        // Receipt binding (including counterparty signature)
        match &self.receipt_binding {
            Some(r) => {
                put_u8(&mut buf, 1);
                put_str(&mut buf, &r.receipt_system);
                put_str(&mut buf, &r.receipt_id);
                buf.extend_from_slice(&r.receipt_hash);
                put_opt_str(&mut buf, &r.counterparty_id);
                put_opt_signature(&mut buf, &r.counterparty_sig);
            }
            None => put_u8(&mut buf, 0),
        }

        // Claimed trust floor
        put_u8(&mut buf, self.claimed_trust_floor as u8);

        buf
    }

    /// Recompute the packet hash from current contents.
    pub fn compute_hash(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    /// Export the packet as pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export the packet as single-line JSON (for JSONL storage / the wire).
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse a packet from JSON. (Integrity is NOT checked here — run the
    /// verification engine on the result.)
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Hex packet ID for display and report binding.
    pub fn packet_id_hex(&self) -> String {
        hex::encode(self.packet_id)
    }
}

// ─── Builder ───

/// Builds and seals an [`EvidencePacket`].
///
/// `build_and_sign` computes the canonical hash and produces the agent's
/// packet signature; after that, any mutation is detectable.
pub struct EvidencePacketBuilder {
    agent: AgentIdentitySummary,
    root_authority: RootAuthority,
    delegation_chain: Vec<DelegationToken>,
    decision: Option<DecisionRecord>,
    actions: Vec<ActionAttestation>,
    trace_binding: Option<TraceBinding>,
    receipt_binding: Option<ReceiptBinding>,
    claimed_trust_floor: TrustFloor,
    created_at: Option<u64>,
}

impl EvidencePacketBuilder {
    pub fn new(agent: AgentIdentitySummary, root_authority: RootAuthority) -> Self {
        Self {
            agent,
            root_authority,
            delegation_chain: vec![],
            decision: None,
            actions: vec![],
            trace_binding: None,
            receipt_binding: None,
            claimed_trust_floor: TrustFloor::AgentSigned,
            created_at: None,
        }
    }

    pub fn delegation_chain(mut self, chain: Vec<DelegationToken>) -> Self {
        self.delegation_chain = chain;
        self
    }

    pub fn decision(mut self, decision: DecisionRecord) -> Self {
        self.decision = Some(decision);
        self
    }

    pub fn action(mut self, action: ActionAttestation) -> Self {
        self.actions.push(action);
        self
    }

    pub fn trace(mut self, trace: TraceBinding) -> Self {
        self.trace_binding = Some(trace);
        self
    }

    pub fn receipt(mut self, receipt: ReceiptBinding) -> Self {
        self.receipt_binding = Some(receipt);
        self
    }

    pub fn claimed_trust_floor(mut self, floor: TrustFloor) -> Self {
        self.claimed_trust_floor = floor;
        self
    }

    /// Override `created_at` (defaults to current system time).
    pub fn created_at(mut self, ts: u64) -> Self {
        self.created_at = Some(ts);
        self
    }

    /// Seal the packet: compute the canonical hash and sign it as the agent.
    pub fn build_and_sign(self, agent_private_key: &[u8]) -> Result<EvidencePacket, AipError> {
        let decision = self.decision.ok_or(AipError::MissingRequiredField)?;
        if self.actions.is_empty() {
            return Err(AipError::MissingRequiredField);
        }

        let created_at = self.created_at.unwrap_or_else(now_ms);
        let agent_id = self.agent.aip_id.clone();

        let mut packet = EvidencePacket {
            magic: PACKET_MAGIC,
            version: PACKET_VERSION,
            packet_id: aip_core::capability::random_jti(),
            created_at,
            agent: self.agent,
            root_authority: self.root_authority,
            delegation_chain: self.delegation_chain,
            decision,
            actions: self.actions,
            trace_binding: self.trace_binding,
            receipt_binding: self.receipt_binding,
            claimed_trust_floor: self.claimed_trust_floor,
            packet_hash: [0u8; 32],
            // Placeholder; replaced below once canonical bytes are final.
            agent_sig: sign_ed25519(agent_private_key, &agent_id, b"placeholder")?,
        };

        let canonical = packet.canonical_bytes();
        packet.packet_hash = sha256(&canonical);
        packet.agent_sig = sign_ed25519(agent_private_key, &agent_id, &canonical)?;
        Ok(packet)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_floor_ordering() {
        assert!(TrustFloor::Unverified < TrustFloor::AgentSigned);
        assert!(TrustFloor::AgentSigned < TrustFloor::AuthorityBound);
        assert!(TrustFloor::AuthorityBound < TrustFloor::CounterpartySigned);
    }

    #[test]
    fn test_trust_floor_serializes_screaming_snake() {
        let s = serde_json::to_string(&TrustFloor::CounterpartySigned).unwrap();
        assert_eq!(s, "\"COUNTERPARTY_SIGNED\"");
    }
}
