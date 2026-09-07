//! The AIRI event: canonical encoding, signing, verification.
//!
//! # What is signed
//!
//! ```text
//! preimage = put_domain("SYNTRIASS/AIRI/EVENT/v1")
//!          ‖ put_u16(version)
//!          ‖ put_str(agent_id)
//!          ‖ execution_id            (fixed 16)
//!          ‖ put_opt_bytes16(parent_execution_id)
//!          ‖ put_opt_bytes16(decision_id)
//!          ‖ put_u64(sequence)
//!          ‖ prev_event_hash         (fixed 32)
//!          ‖ put_u64(emitted_at_ms)
//!          ‖ framework.encode()
//!          ‖ put_opt(runtime_binding.identity_bytes())
//!          ‖ put_u8(kind_code) ‖ payload.encode()
//! ```
//!
//! Every variable-length field is length-prefixed and every optional field
//! carries a presence byte, so the encoding is injective: no two distinct
//! events share a preimage. The domain tag leads, so an AIRI signature
//! cannot verify as a `ScopedToken`, a `DelegationToken`, an observer head,
//! a reconciliation record or a warrant, and none of theirs can verify here.
//!
//! # What signing proves
//!
//! That the holder of the agent's private key made this statement. Since the
//! agent is the party under scrutiny, that is a statement about authorship
//! and integrity only. `emitted_at_ms` is the agent's own clock and is
//! carried, never trusted: placing an event in time is the collector's job
//! (`aip_observe::AttestedBatch::attested_at_ms`) or the kernel's.

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u64, put_u8};
use aip_types::{ExecutionBinding, Signature};
use serde::{Deserialize, Serialize};

use crate::error::AiriError;
use crate::provenance::{
    AgentStart, Completion, ContextPropagation, FrameworkIdentity, ModelProvenance,
    SubprocessReport, ToolInvocation, ToolReport,
};

/// Signing domain for every AIRI event. Distinct from every other domain in
/// the repository.
pub const AIRI_EVENT_DOMAIN: &str = "SYNTRIASS/AIRI/EVENT/v1";

/// Structure version. A verifier refuses any other value rather than
/// guessing at field layout.
pub const AIRI_EVENT_VERSION: u16 = 1;

/// Upper bound on any single string field, so a malicious adapter cannot
/// make a verifier allocate without limit.
const MAX_FIELD_LEN: usize = 4096;

/// The kinds of statement an agent runtime can make.
///
/// The discriminant is part of the signed preimage, so an event of one kind
/// cannot be re-presented as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AiriEventKind {
    AgentExecutionStarted,
    ModelInvocationRequested,
    /// The framework reported back about an inference call.
    ///
    /// **Named "Observed" by the AIRI specification; it is not independent
    /// observation.** The observer is the framework, inside the process
    /// under scrutiny. Nothing in this crate treats this kind differently
    /// from any other self-report, and `corroborate` will not accept it as
    /// corroboration of itself.
    ModelInvocationObserved,
    ToolInvocationRequested,
    ToolExecutionReported,
    SubprocessExecution,
    ExecutionCompleted,
    ExecutionFailed,
    ExecutionContextPropagated,
}

impl AiriEventKind {
    pub fn code(self) -> u8 {
        match self {
            Self::AgentExecutionStarted => 0x01,
            Self::ModelInvocationRequested => 0x02,
            Self::ModelInvocationObserved => 0x03,
            Self::ToolInvocationRequested => 0x04,
            Self::ToolExecutionReported => 0x05,
            Self::SubprocessExecution => 0x06,
            Self::ExecutionCompleted => 0x07,
            Self::ExecutionFailed => 0x08,
            Self::ExecutionContextPropagated => 0x09,
        }
    }
}

/// The body of an event, one variant per kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiriPayload {
    AgentExecutionStarted(AgentStart),
    ModelInvocationRequested(ModelProvenance),
    ModelInvocationObserved(ModelProvenance),
    ToolInvocationRequested(ToolInvocation),
    ToolExecutionReported(ToolReport),
    SubprocessExecution(SubprocessReport),
    ExecutionCompleted(Completion),
    ExecutionFailed(Completion),
    ExecutionContextPropagated(ContextPropagation),
}

impl AiriPayload {
    pub fn kind(&self) -> AiriEventKind {
        match self {
            Self::AgentExecutionStarted(_) => AiriEventKind::AgentExecutionStarted,
            Self::ModelInvocationRequested(_) => AiriEventKind::ModelInvocationRequested,
            Self::ModelInvocationObserved(_) => AiriEventKind::ModelInvocationObserved,
            Self::ToolInvocationRequested(_) => AiriEventKind::ToolInvocationRequested,
            Self::ToolExecutionReported(_) => AiriEventKind::ToolExecutionReported,
            Self::SubprocessExecution(_) => AiriEventKind::SubprocessExecution,
            Self::ExecutionCompleted(_) => AiriEventKind::ExecutionCompleted,
            Self::ExecutionFailed(_) => AiriEventKind::ExecutionFailed,
            Self::ExecutionContextPropagated(_) => AiriEventKind::ExecutionContextPropagated,
        }
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.kind().code());
        match self {
            Self::AgentExecutionStarted(x) => x.encode(buf),
            Self::ModelInvocationRequested(x) | Self::ModelInvocationObserved(x) => x.encode(buf),
            Self::ToolInvocationRequested(x) => x.encode(buf),
            Self::ToolExecutionReported(x) => x.encode(buf),
            Self::SubprocessExecution(x) => x.encode(buf),
            Self::ExecutionCompleted(x) | Self::ExecutionFailed(x) => x.encode(buf),
            Self::ExecutionContextPropagated(x) => x.encode(buf),
        }
    }
}

/// One self-authored statement by an agent's runtime about its own AI stack.
///
/// See the crate documentation for what this does and does not establish.
/// In one line: an `AiriEvent` that verifies proves *authorship and
/// integrity*, never *occurrence*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiriEvent {
    pub version: u16,
    /// AIP-ID of the agent. Must equal `signature.signer_id`: an agent signs
    /// only for itself, checked in [`verify_airi_event`].
    pub agent_id: String,
    /// The AIRI execution instance this statement belongs to.
    pub execution_id: [u8; 16],
    /// The execution that spawned this one, for worker and subprocess
    /// handoff. Application lineage — deliberately distinct from identity
    /// lineage (`aip-agent`) and authority lineage (delegation chains).
    pub parent_execution_id: Option<[u8; 16]>,
    /// The `ExpectedExecution.decision_id` this run claims to be authorized
    /// by. `None` means the agent did not claim an authorization, which is a
    /// statement a verifier can act on.
    pub decision_id: Option<[u8; 16]>,
    /// Position within this execution's chain, from 0. Signed, so a
    /// reordering or a gap is detectable.
    pub sequence: u64,
    /// SHA-256 of the previous event's preimage; `[0u8; 32]` at sequence 0.
    /// Makes silent deletion from the middle of a chain detectable.
    pub prev_event_hash: [u8; 32],
    /// The agent's own clock. Carried for context, never trusted to order or
    /// place anything.
    pub emitted_at_ms: u64,
    pub framework: FrameworkIdentity,
    /// The process the agent believes it is running in.
    ///
    /// **Self-reported.** `aip-observe` produces the authoritative binding;
    /// this field lets a verifier compare the two and notice a disagreement.
    /// A match is not proof — a compromised process can report the truth
    /// about its own pid while lying about everything else.
    pub runtime_binding: Option<ExecutionBinding>,
    pub payload: AiriPayload,
    pub signature: Signature,
}

impl AiriEvent {
    /// The exact bytes hashed into `signature.payload_hash`.
    ///
    /// Injective by construction; see the module documentation for the
    /// layout and for why each optional field carries a presence byte.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(512);
        put_domain(&mut b, AIRI_EVENT_DOMAIN);
        put_u16(&mut b, self.version);
        put_str(&mut b, &self.agent_id);
        put_bytes(&mut b, &self.execution_id);
        put_opt_bytes16(&mut b, &self.parent_execution_id);
        put_opt_bytes16(&mut b, &self.decision_id);
        put_u64(&mut b, self.sequence);
        put_bytes(&mut b, &self.prev_event_hash);
        put_u64(&mut b, self.emitted_at_ms);
        self.framework.encode(&mut b);
        match &self.runtime_binding {
            None => put_u8(&mut b, 0),
            Some(eb) => {
                put_u8(&mut b, 1);
                // `identity_bytes` is the binding's instance identity: pid,
                // start ticks, boot id, exe content digest. Deliberately not
                // the full encoding — `bound_at_ms` and `exe_path` are
                // context and must not make two reports of the same instance
                // encode differently.
                put_bytes(&mut b, &eb.identity_bytes());
            }
        }
        self.payload.encode(&mut b);
        b
    }

    /// Hash of the preimage — the value the *next* event carries as
    /// `prev_event_hash`.
    pub fn event_hash(&self) -> [u8; 32] {
        sha256(&self.signing_preimage())
    }

    pub fn kind(&self) -> AiriEventKind {
        self.payload.kind()
    }

    /// Structural checks that do not need a key: version, required fields,
    /// field bounds, and the signer-is-the-agent rule.
    fn check_structure(&self) -> Result<(), AiriError> {
        if self.version != AIRI_EVENT_VERSION {
            return Err(AiriError::UnsupportedVersion(self.version));
        }
        if self.agent_id.is_empty() {
            return Err(AiriError::MissingField("agent_id"));
        }
        if self.signature.signer_id != self.agent_id {
            return Err(AiriError::SignerIsNotTheAgent {
                signer_id: self.signature.signer_id.clone(),
                agent_id: self.agent_id.clone(),
            });
        }
        for (field, s) in [
            ("agent_id", &self.agent_id),
            ("framework.name", &self.framework.name),
            ("framework.version", &self.framework.version),
            ("framework.adapter_version", &self.framework.adapter_version),
        ] {
            if s.len() > MAX_FIELD_LEN {
                return Err(AiriError::FieldTooLong {
                    field,
                    len: s.len(),
                    max: MAX_FIELD_LEN,
                });
            }
        }
        if self.framework.name.is_empty() {
            return Err(AiriError::MissingField("framework.name"));
        }
        Ok(())
    }
}

fn put_opt_bytes16(buf: &mut Vec<u8>, v: &Option<[u8; 16]>) {
    match v {
        None => put_u8(buf, 0),
        Some(x) => {
            put_u8(buf, 1);
            put_bytes(buf, x);
        }
    }
}

/// Commit to a parameter set under AIRI's parameter domain.
///
/// Re-exported at the crate root. See
/// [`crate::provenance::commit_bytes`] for the construction and why it is
/// not a bare SHA-256.
pub fn parameter_commitment(data: &[u8]) -> [u8; 32] {
    crate::provenance::commit_bytes(data)
}

/// Sign an event with the agent's own private key.
///
/// The caller supplies every field except the signature. `agent_id` becomes
/// the signature's `signer_id`, enforcing at construction the rule that
/// [`verify_airi_event`] enforces on the way back in.
pub fn sign_airi_event(
    private_key: &[u8],
    agent_id: &str,
    mut event: AiriEvent,
) -> Result<AiriEvent, aip_types::AipError> {
    event.agent_id = agent_id.to_string();
    let preimage = event.signing_preimage();
    event.signature = sign_ed25519(private_key, agent_id, &preimage)?;
    Ok(event)
}

/// Verify authorship and integrity of an event against the agent's public key.
///
/// Returns `Ok(())` when the event was signed by the holder of
/// `agent_public_key`, is of a version this build implements, is
/// structurally well formed, and has not been altered since signing.
///
/// # What `Ok` does not mean
///
/// It does not mean the described model ran, the described tool executed, or
/// the described effect occurred. It means the agent said so and the saying
/// is intact. Establishing occurrence requires [`crate::corroborate`] and
/// independent observer evidence — and even then the ceiling is what
/// `aip_reconcile` allows, which for content-derived facts is `Attested`.
pub fn verify_airi_event(event: &AiriEvent, agent_public_key: &[u8]) -> Result<(), AiriError> {
    event.check_structure()?;

    if agent_public_key.len() != 32 {
        return Err(AiriError::InvalidPublicKey);
    }
    let preimage = event.signing_preimage();
    if event.signature.payload_hash != sha256(&preimage) {
        return Err(AiriError::PayloadHashMismatch);
    }
    match verify_ed25519(agent_public_key, &event.signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(AiriError::SignatureInvalid),
        Err(_) => Err(AiriError::InvalidPublicKey),
    }
}
