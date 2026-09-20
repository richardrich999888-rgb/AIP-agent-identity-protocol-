//! The AIP funnel: the one path a consequential action travels.
//!
//! ```text
//! lifecycle checks (born, not closed, model digest matches the chain)
//!   → authority resolution (delegation graph, attenuated scope)
//!     → mandate checks (manifest, scope, clearance, taint, multi-sig)
//!       → [caller executes]
//!         → evidence packet sealed → ACTION_EXECUTION_SEAL anchor
//! ```
//!
//! This is the Rust port of `apps/ot-vis/src/telemetry/nexora/aip-evidence.ts`,
//! written so a Model Context Protocol gateway can sit in front of real tool
//! servers. It differs from the TypeScript sealer in one deliberate way.
//!
//! # Why the closure became a ticket
//!
//! The browser sealer takes an `execute: () => Promise<…>` closure and owns
//! the whole round trip. A gateway cannot: the tool body is an upstream MCP
//! server reached over stdio or HTTP, and the gateway's async runtime, not
//! this crate, must own that I/O. So the funnel is split in two —
//! [`AipFunnel::evaluate`] renders the verdict and hands back a
//! [`PendingExecution`], and [`AipFunnel::seal`] consumes that ticket to
//! write the evidence.
//!
//! The invariant the closure enforced survives the split, because the ticket
//! is the only thing `seal` accepts and it is `#[must_use]`: an evaluated
//! request that is never sealed is a compiler warning at the call site, and
//! a sealed request always carries the verdict that was rendered *before*
//! execution. A caller cannot execute first and ask permission afterwards,
//! because the permission answer is the object it needs in hand to execute.
//!
//! # What the ticket refuses to forget
//!
//! [`AipFunnel::seal`] takes the caller's claimed [`ExecutionOutcome`], but a
//! rejected ticket seals `BLOCKED_BY_POLICY` with `postStateHash ==
//! preStateHash` no matter what the caller claims happened — the same
//! construction-over-discipline rule
//! [`crate::lifecycle::ActiveExecution::complete`] applies. A gateway that
//! ran a denied tool anyway cannot launder the result into the record.
//!
//! # Memory
//!
//! The funnel retains only each agent's two chain heads and sequence numbers
//! (~200 bytes/agent), never the records themselves: sealed packets and
//! anchors are returned to the caller to persist. That is what lets one
//! gateway process front a fleet far larger than its own memory.

use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::authority::{
    resolve_authority, AuthorityStore, EdgeVerifier, EffectiveAuthority, ToolManifest, TrustTier,
};
use crate::identity::PrincipalBinding;
use crate::lifecycle::ExecutionStatus;
use crate::{canonical_json, chain_payload_bytes, seal_hash, sha256_hex, GENESIS_HASH};

/// Why a request was refused. Every code names a specific broken
/// precondition; there is no generic "denied".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AipRejectionCode {
    /// The caller did not prove it speaks for the DID it claimed.
    ///
    /// Checked before everything else: authority, clearance and lifecycle are
    /// all resolved *from* the DID, so an unproven DID makes every downstream
    /// answer meaningless rather than merely unauthorised.
    IdentityUnverified,
    /// No `AGENT_GENESIS` anchor: the DID names no agent this gateway knows.
    AgentNotBorn,
    /// A terminal revocation closed the lifecycle chain.
    LifecycleClosed,
    /// The runtime's weights do not match what the lifecycle chain binds.
    ModelIntegrityCompromised,
    /// No rooted, unrevoked delegation path to an officer.
    NoEffectiveAuthority,
    /// The tool has no mandate in the manifest — default-deny.
    UnknownTool,
    /// The delegation path never conferred this tool.
    ToolNotInScope,
    /// The path's weakest clearance is below the tool's mandate.
    ClearanceInsufficient,
    /// Untrusted content is live in context and this tool forbids it.
    TaintedContextEscalation,
    /// A supervisor co-signature is required and absent or invalid.
    RequiresSupervisorMultisig,
}

impl AipRejectionCode {
    /// The wire vocabulary, matching the TypeScript tier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdentityUnverified => "IDENTITY_UNVERIFIED",
            Self::AgentNotBorn => "AGENT_NOT_BORN",
            Self::LifecycleClosed => "LIFECYCLE_CLOSED",
            Self::ModelIntegrityCompromised => "MODEL_INTEGRITY_COMPROMISED",
            Self::NoEffectiveAuthority => "NO_EFFECTIVE_AUTHORITY",
            Self::UnknownTool => "UNKNOWN_TOOL",
            Self::ToolNotInScope => "TOOL_NOT_IN_SCOPE",
            Self::ClearanceInsufficient => "CLEARANCE_INSUFFICIENT",
            Self::TaintedContextEscalation => "TAINTED_CONTEXT_ESCALATION",
            Self::RequiresSupervisorMultisig => "REQUIRES_SUPERVISOR_MULTISIG",
        }
    }
}

/// A refusal: the code plus the specific detail an operator needs to fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AipRejection {
    /// Machine-readable cause.
    pub code: AipRejectionCode,
    /// Human-readable specifics.
    pub detail: String,
}

/// One piece of content the agent has read into context.
///
/// The gateway records these on `resources/read` and every tool result, so
/// "what has this agent been exposed to" is answered from evidence rather
/// than from the model's own account of itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSource {
    /// Where the content came from.
    pub uri: String,
    /// SHA-256 of the content, so the record identifies exactly what was read.
    pub digest: String,
    /// How far it may be trusted.
    pub trust: TrustTier,
}

impl ContextSource {
    /// The canonical JSON shape written into `contextProvenance`.
    fn to_json(&self) -> Value {
        json!({ "uri": self.uri, "digest": self.digest, "trust": self.trust.as_str() })
    }
}

/// A tool invocation awaiting adjudication.
#[derive(Debug, Clone, PartialEq)]
pub struct AipRequest {
    /// The calling agent.
    pub agent_did: String,
    /// SHA-256 of the weights/quant profile the runtime is executing.
    pub runtime_model_digest: String,
    /// The prompt that produced this call — recorded verbatim, so intent is
    /// auditable and not reconstructed after the fact.
    pub raw_prompt: String,
    /// Tool being invoked.
    pub tool_name: String,
    /// Arguments as sent upstream.
    pub input_params: Value,
    /// Observable state before the call.
    pub pre_state: Value,
    /// Supervisor co-signature, when the tool demands one.
    pub supervisor_co_signature: Option<String>,
    /// Everything read into context so far this session.
    pub context_sources: Vec<ContextSource>,
    /// Who the caller was *proven* to be, when anything was proven.
    ///
    /// `None` means no identity check ran at all — which
    /// [`AipFunnel::require_verified_identity`] refuses by default, because a
    /// funnel that adjudicates an unproven DID is adjudicating a wish.
    pub principal: Option<PrincipalBinding>,
}

impl AipRequest {
    /// A request with no co-signature and no recorded context.
    pub fn new(
        agent_did: impl Into<String>,
        runtime_model_digest: impl Into<String>,
        raw_prompt: impl Into<String>,
        tool_name: impl Into<String>,
        input_params: Value,
        pre_state: Value,
    ) -> Self {
        Self {
            agent_did: agent_did.into(),
            runtime_model_digest: runtime_model_digest.into(),
            raw_prompt: raw_prompt.into(),
            tool_name: tool_name.into(),
            input_params,
            pre_state,
            supervisor_co_signature: None,
            context_sources: Vec::new(),
            principal: None,
        }
    }

    /// Attaches the identity the transport established for this caller.
    pub fn with_principal(mut self, principal: PrincipalBinding) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Attaches a supervisor co-signature.
    pub fn with_co_signature(mut self, signature: impl Into<String>) -> Self {
        self.supervisor_co_signature = Some(signature.into());
        self
    }

    /// Attaches the context the agent has read.
    pub fn with_context(mut self, sources: Vec<ContextSource>) -> Self {
        self.context_sources = sources;
        self
    }

    /// The most-untrusted tier live in context, or [`TrustTier::Trusted`]
    /// when nothing has been read.
    pub fn context_taint(&self) -> TrustTier {
        self.context_sources
            .iter()
            .map(|s| s.trust)
            .max()
            .unwrap_or(TrustTier::Trusted)
    }
}

/// Verifies a supervisor's per-invocation co-signature over an edge.
///
/// No blanket implementation is provided: a deployment that wants multi-sig
/// tools must state how signatures are checked, because a permissive default
/// here would silently void the strongest control in the manifest.
pub trait CoSignatureVerifier {
    /// True when the presented signature authorises exactly this invocation.
    fn verify(&self, request: &CoSignatureRequest) -> bool;
}

/// What a supervisor is being asked to have approved.
///
/// Everything here is in the request rather than just the edge and tool name,
/// because an approval over `(edge, tool)` alone is reusable forever: get one
/// `send_command` co-signature and every later `send_command` is authorised,
/// including the ones the supervisor would have refused. A verifier that binds
/// to [`input_params_digest`](Self::input_params_digest) approves *this call*,
/// and `now_utc` lets it enforce an expiry so an approval is not a standing
/// permission.
#[derive(Debug, Clone, Copy)]
pub struct CoSignatureRequest<'a> {
    /// The delegation edge conferring the tool.
    pub edge_id: &'a str,
    /// The tool being invoked.
    pub tool_name: &'a str,
    /// The agent invoking it.
    pub agent_did: &'a str,
    /// SHA-256 of the canonical JSON of the arguments — what makes an
    /// approval specific to one call rather than to a verb.
    pub input_params_digest: &'a str,
    /// Adjudication time, for checking an approval's expiry.
    pub now_utc: &'a str,
    /// The signature the caller presented.
    pub signature: &'a str,
}

/// Refuses every co-signature — the correct default before a real verifier is
/// wired, since it fails closed: multi-sig tools become uninvocable rather
/// than unguarded.
pub struct DenyAllCoSignatures;

impl CoSignatureVerifier for DenyAllCoSignatures {
    fn verify(&self, _request: &CoSignatureRequest) -> bool {
        false
    }
}

/// What the caller reports happened after a permitted execution.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionOutcome {
    /// The tool ran; the value is the observable post-state.
    Succeeded(Value),
    /// The tool ran and errored.
    Failed(String),
    /// The tool was not run. The only honest outcome for a rejected ticket.
    NotAttempted,
}

/// A rendered verdict, and the authority it was rendered against.
///
/// `#[must_use]`: an evaluated request that is never sealed is evidence that
/// was decided and then dropped, which the compiler flags at the call site.
#[must_use = "an evaluated AIP request must be sealed — dropping the ticket discards the evidence"]
#[derive(Debug, Clone)]
pub struct PendingExecution {
    request: AipRequest,
    rejection: Option<AipRejection>,
    authority: Option<EffectiveAuthority>,
    /// Whether the lifecycle chain can take a seal anchor at all.
    chain_writable: bool,
}

impl PendingExecution {
    /// True when the caller may run the tool.
    pub fn permitted(&self) -> bool {
        self.rejection.is_none()
    }

    /// The refusal, when there is one.
    pub fn rejection(&self) -> Option<&AipRejection> {
        self.rejection.as_ref()
    }

    /// The resolved delegation path, when one was found.
    pub fn authority(&self) -> Option<&EffectiveAuthority> {
        self.authority.as_ref()
    }

    /// The request being adjudicated.
    pub fn request(&self) -> &AipRequest {
        &self.request
    }
}

/// The record a sealed execution produced.
#[derive(Debug, Clone, PartialEq)]
pub struct AipOutcome {
    /// Whether the call was permitted.
    pub permitted: bool,
    /// The refusal, when the call was denied.
    pub rejection: Option<AipRejection>,
    /// Recorded execution status.
    pub status: ExecutionStatus,
    /// The sealed, hash-chained evidence packet.
    pub packet: Value,
    /// The `ACTION_EXECUTION_SEAL` anchor naming that packet. `None` when the
    /// lifecycle chain was not writable — an unborn or terminated agent's
    /// attempts are still evidence, just unanchored.
    pub seal_anchor: Option<Value>,
}

/// One entry of a governed tool catalogue.
///
/// Carries the obligations alongside the name so a filtered `tools/list` can
/// tell the model that a tool needs a supervisor co-signature *before* it
/// calls — turning a guaranteed refusal into a request the model can form
/// correctly, without widening what it may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermittedTool {
    /// Tool name.
    pub name: String,
    /// Whether an invocation needs a supervisor co-signature.
    pub requires_co_signature: bool,
    /// The clearance the tool's material demands.
    pub minimum_clearance: crate::authority::ClearanceLevel,
    /// How far this tool's output may be trusted once it lands in context.
    pub result_trust: TrustTier,
}

/// Per-agent chain heads. Deliberately not the records themselves: see the
/// module docs on memory.
#[derive(Debug, Clone)]
struct AgentChainState {
    supervisor_did: String,
    model_digest: Option<String>,
    closed: bool,
    anchor_tail: String,
    anchor_sequence: u64,
    packet_tail: String,
    packet_sequence: u64,
}

/// The governed funnel. Holds the manifest, the delegation graph, and each
/// agent's chain heads.
pub struct AipFunnel {
    store: Box<dyn AuthorityStore + Send + Sync>,
    edges: Box<dyn EdgeVerifier + Send + Sync>,
    cosign: Box<dyn CoSignatureVerifier + Send + Sync>,
    manifest: ToolManifest,
    agents: BTreeMap<String, AgentChainState>,
    require_verified_identity: bool,
}

impl AipFunnel {
    /// Builds a funnel over a delegation store, an edge verifier, a
    /// co-signature verifier, and a tool manifest.
    pub fn new(
        store: Box<dyn AuthorityStore + Send + Sync>,
        edges: Box<dyn EdgeVerifier + Send + Sync>,
        cosign: Box<dyn CoSignatureVerifier + Send + Sync>,
        manifest: ToolManifest,
    ) -> Self {
        Self {
            store,
            edges,
            cosign,
            manifest,
            agents: BTreeMap::new(),
            // Fail closed. A funnel that adjudicates unproven DIDs produces
            // evidence recording who *said* they acted, which is exactly the
            // property the ledger exists to not have.
            require_verified_identity: true,
        }
    }

    /// Allows sessions whose identity was never proven.
    ///
    /// For development and for migrating a deployment that has not yet
    /// enrolled credentials. Every packet still records the
    /// `UNAUTHENTICATED` binding, so an auditor can tell exactly which
    /// records were produced under the relaxed rule rather than having to
    /// trust that the setting was off at the time.
    pub fn allowing_unverified_identity(mut self) -> Self {
        self.require_verified_identity = false;
        self
    }

    /// Whether a proven identity is required to act.
    pub fn requires_verified_identity(&self) -> bool {
        self.require_verified_identity
    }

    /// The tools this funnel knows mandates for.
    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    /// Births an agent, returning the sealed `AGENT_GENESIS` anchor. Until
    /// this runs, every request from the DID is refused as
    /// [`AipRejectionCode::AgentNotBorn`].
    pub fn register_genesis(
        &mut self,
        agent_did: &str,
        supervisor_did: &str,
        model_digest: &str,
        timestamp_utc: &str,
    ) -> Value {
        let state = self
            .agents
            .entry(agent_did.to_string())
            .or_insert_with(|| AgentChainState {
                supervisor_did: supervisor_did.to_string(),
                model_digest: None,
                closed: false,
                anchor_tail: GENESIS_HASH.to_string(),
                anchor_sequence: 0,
                packet_tail: GENESIS_HASH.to_string(),
                packet_sequence: 0,
            });
        state.model_digest = Some(model_digest.to_string());
        let actor = supervisor_did.to_string();
        Self::append_anchor(
            self.agents.get_mut(agent_did).expect("just inserted"),
            agent_did,
            "AGENT_GENESIS",
            &actor,
            timestamp_utc,
            json!({ "modelDigest": model_digest }),
        )
    }

    /// Rebinds the expected weights, returning the sealed
    /// `MODEL_VERSION_MIGRATION` anchor. The chain, not a mutable identity
    /// row, is what "which weights should be running" is answered from.
    pub fn register_model_migration(
        &mut self,
        agent_did: &str,
        model_digest: &str,
        timestamp_utc: &str,
    ) -> Option<Value> {
        let state = self.agents.get_mut(agent_did)?;
        if state.closed {
            return None;
        }
        state.model_digest = Some(model_digest.to_string());
        let actor = state.supervisor_did.clone();
        Some(Self::append_anchor(
            state,
            agent_did,
            "MODEL_VERSION_MIGRATION",
            &actor,
            timestamp_utc,
            json!({ "modelDigest": model_digest }),
        ))
    }

    /// Records that a credential may speak for an agent, returning the
    /// sealed [`ENROLMENT_ANCHOR`](crate::identity::ENROLMENT_ANCHOR).
    ///
    /// The anchor is the point of it: "this key is that agent" is the single
    /// most consequential authority decision in the system, and putting it on
    /// the same tamper-evident chain as everything else means an auditor can
    /// reconstruct who could speak for whom at any moment rather than being
    /// shown a configuration file and asked to believe it.
    pub fn register_credential_enrolment(
        &mut self,
        agent_did: &str,
        credential_digest: &str,
        method: crate::identity::AuthMethod,
        timestamp_utc: &str,
    ) -> Option<Value> {
        let state = self.agents.get_mut(agent_did)?;
        if state.closed {
            return None;
        }
        let actor = state.supervisor_did.clone();
        Some(Self::append_anchor(
            state,
            agent_did,
            crate::identity::ENROLMENT_ANCHOR,
            &actor,
            timestamp_utc,
            crate::identity::CredentialRegistry::enrolment_payload(credential_digest, method),
        ))
    }

    /// Records that a credential is withdrawn, returning the sealed
    /// [`REVOCATION_ANCHOR`](crate::identity::REVOCATION_ANCHOR).
    pub fn register_credential_revocation(
        &mut self,
        agent_did: &str,
        credential_digest: &str,
        reason: &str,
        timestamp_utc: &str,
    ) -> Option<Value> {
        let state = self.agents.get_mut(agent_did)?;
        if state.closed {
            return None;
        }
        let actor = state.supervisor_did.clone();
        Some(Self::append_anchor(
            state,
            agent_did,
            crate::identity::REVOCATION_ANCHOR,
            &actor,
            timestamp_utc,
            crate::identity::CredentialRegistry::revocation_payload(credential_digest, reason),
        ))
    }

    /// Terminally revokes an agent, returning the closing anchor. Every later
    /// request from the DID is refused as
    /// [`AipRejectionCode::LifecycleClosed`], and no further anchor can be
    /// written to the chain.
    pub fn register_revocation(
        &mut self,
        agent_did: &str,
        reason: &str,
        timestamp_utc: &str,
    ) -> Option<Value> {
        let state = self.agents.get_mut(agent_did)?;
        if state.closed {
            return None;
        }
        let actor = state.supervisor_did.clone();
        let anchor = Self::append_anchor(
            state,
            agent_did,
            "AUTHORITY_REVOCATION",
            &actor,
            timestamp_utc,
            json!({ "terminal": true, "reason": reason }),
        );
        state.closed = true;
        Some(anchor)
    }

    /// Renders the verdict for a request without executing anything.
    ///
    /// The returned ticket is the caller's only route to [`seal`](Self::seal),
    /// which is what keeps "decided before it ran" true by construction.
    pub fn evaluate(&self, request: AipRequest, now_utc: &str) -> PendingExecution {
        let state = self.agents.get(&request.agent_did);
        let chain_writable = state.is_some_and(|s| !s.closed);

        // Identity first: everything below resolves *from* the DID, so an
        // unproven DID makes every later answer meaningless rather than
        // merely unauthorised.
        let mut rejection = self.identity_rejection(&request);
        if rejection.is_none() {
            rejection = self.lifecycle_rejection(&request, state);
        }
        let mut authority = None;

        if rejection.is_none() {
            match resolve_authority(
                self.store.as_ref(),
                self.edges.as_ref(),
                &request.agent_did,
                now_utc,
            ) {
                None => {
                    rejection = Some(AipRejection {
                        code: AipRejectionCode::NoEffectiveAuthority,
                        detail: format!(
                            "no rooted, unrevoked delegation path for {}",
                            request.agent_did
                        ),
                    })
                }
                Some(effective) => {
                    rejection = self.mandate_rejection(&effective, &request, now_utc);
                    authority = Some(effective);
                }
            }
        }

        PendingExecution {
            request,
            rejection,
            authority,
            chain_writable,
        }
    }

    /// Seals a ticket into an evidence packet and, when the chain is
    /// writable, an `ACTION_EXECUTION_SEAL` anchor naming it.
    ///
    /// A rejected ticket seals `BLOCKED_BY_POLICY` with post-state equal to
    /// pre-state whatever `outcome` claims: the verdict rendered before
    /// execution is the one that gets recorded.
    pub fn seal(
        &mut self,
        pending: PendingExecution,
        outcome: ExecutionOutcome,
        timestamp_utc: &str,
    ) -> AipOutcome {
        let PendingExecution {
            request,
            rejection,
            authority,
            chain_writable,
        } = pending;

        let pre_state_hash = sha256_hex(&canonical_json(&request.pre_state));
        let (status, error, post_state_hash) = match &rejection {
            Some(r) => (
                ExecutionStatus::BlockedByPolicy,
                Some(format!(
                    "REJECTED_POLICY_VIOLATION {}: {}",
                    r.code.as_str(),
                    r.detail
                )),
                pre_state_hash.clone(),
            ),
            None => match outcome {
                ExecutionOutcome::Succeeded(post) => (
                    ExecutionStatus::Success,
                    None,
                    sha256_hex(&canonical_json(&post)),
                ),
                ExecutionOutcome::Failed(err) => {
                    // A failed tool may have mutated state before erroring,
                    // but the gateway has no post-state to hash: record the
                    // pre-state and say so in the error rather than inventing
                    // a digest.
                    (ExecutionStatus::Failed, Some(err), pre_state_hash.clone())
                }
                ExecutionOutcome::NotAttempted => (
                    ExecutionStatus::Failed,
                    Some("permitted call was not attempted by the gateway".to_string()),
                    pre_state_hash.clone(),
                ),
            },
        };

        // An unregistered agent still gets a packet — an unknown DID probing
        // the gateway is exactly the traffic an operator most wants recorded —
        // it is simply chained from genesis and left unanchored.
        let (previous_packet_hash, sequence, anchor_hash) =
            match self.agents.get(&request.agent_did) {
                Some(s) => (
                    s.packet_tail.clone(),
                    s.packet_sequence + 1,
                    if chain_writable {
                        s.anchor_tail.clone()
                    } else {
                        String::new()
                    },
                ),
                None => (GENESIS_HASH.to_string(), 1, String::new()),
            };

        let mut tool_executed = json!({
            "name": request.tool_name,
            "inputParams": request.input_params,
            "status": status.as_str(),
        });
        if let Some(sig) = &request.supervisor_co_signature {
            tool_executed["supervisorCoSignature"] = json!(sig);
        }
        if let Some(err) = &error {
            tool_executed["error"] = json!(err);
        }

        let mut packet = json!({
            "id": format!("{}#packet-{sequence}", request.agent_did),
            "sequenceNumber": sequence,
            "timestampUtc": timestamp_utc,
            "agentDid": request.agent_did,
            "anchorHash": anchor_hash,
            "delegationPath": authority.as_ref().map(|a| a.path.clone()).unwrap_or_default(),
            "edgeId": authority
                .as_ref()
                .and_then(|a| a.edge_ids.last().cloned())
                .unwrap_or_default(),
            "modelDigest": request.runtime_model_digest,
            "rawPrompt": request.raw_prompt,
            "toolExecuted": tool_executed,
            "preStateHash": pre_state_hash,
            "postStateHash": post_state_hash,
        });
        // Omitted when empty so packets from callers that record no context
        // hash exactly as they did before taint tracking existed — adding the
        // field must not invalidate an existing chain.
        // Who the caller was proven to be travels with the evidence, so an
        // offline verifier can check that the actor was authenticated and not
        // merely asserted. Omitted when absent so packets from writers that
        // predate identity binding hash exactly as they did before.
        if let Some(principal) = &request.principal {
            packet["principal"] = principal.to_json();
        }
        if !request.context_sources.is_empty() {
            packet["contextProvenance"] = Value::Array(
                request
                    .context_sources
                    .iter()
                    .map(ContextSource::to_json)
                    .collect(),
            );
        }

        let packet_hash = seal_hash(
            &previous_packet_hash,
            &chain_payload_bytes(&packet, &["previousPacketHash", "packetHash"]),
        );
        packet["previousPacketHash"] = json!(previous_packet_hash);
        packet["packetHash"] = json!(packet_hash);

        let packet_id = packet["id"].as_str().unwrap_or_default().to_string();
        let mut seal_anchor = None;
        if let Some(state) = self.agents.get_mut(&request.agent_did) {
            state.packet_tail = packet_hash.clone();
            state.packet_sequence = sequence;
            if chain_writable {
                let actor = request.agent_did.clone();
                seal_anchor = Some(Self::append_anchor(
                    state,
                    &request.agent_did,
                    "ACTION_EXECUTION_SEAL",
                    &actor,
                    timestamp_utc,
                    json!({
                        "packetId": packet_id,
                        "packetHash": packet_hash,
                        "status": status.as_str(),
                    }),
                ));
            }
        }

        AipOutcome {
            permitted: rejection.is_none(),
            rejection,
            status,
            packet,
            seal_anchor,
        }
    }

    /// The tools `agent_did` may invoke right now: in the manifest, in the
    /// effective delegated scope, cleared, and untainted for the context in
    /// hand.
    ///
    /// This is what a governed `tools/list` returns. Filtering the catalogue
    /// rather than only refusing calls matters because a tool the model never
    /// sees is one it cannot be talked into reaching for — the delegation
    /// boundary becomes the model's world, not a fence it can probe.
    pub fn permitted_tools(
        &self,
        agent_did: &str,
        context_taint: TrustTier,
        now_utc: &str,
    ) -> Vec<PermittedTool> {
        let Some(state) = self.agents.get(agent_did) else {
            return Vec::new();
        };
        if state.closed {
            return Vec::new();
        }
        let Some(effective) =
            resolve_authority(self.store.as_ref(), self.edges.as_ref(), agent_did, now_utc)
        else {
            return Vec::new();
        };
        self.manifest
            .iter()
            .filter(|(name, mandate)| {
                effective.scope.iter().any(|t| t == *name)
                    && effective.clearance_level.meets(mandate.minimum_clearance)
                    && context_taint <= mandate.max_context_taint
            })
            .map(|(name, mandate)| PermittedTool {
                name: name.clone(),
                requires_co_signature: effective.multi_sig_tools.contains(name),
                minimum_clearance: mandate.minimum_clearance,
                result_trust: mandate.result_trust,
            })
            .collect()
    }

    /// Just the names from [`permitted_tools`](Self::permitted_tools).
    pub fn permitted_tool_names(
        &self,
        agent_did: &str,
        context_taint: TrustTier,
        now_utc: &str,
    ) -> Vec<String> {
        self.permitted_tools(agent_did, context_taint, now_utc)
            .into_iter()
            .map(|t| t.name)
            .collect()
    }

    /// The mandate for `tool_name`, if the manifest has one.
    pub fn mandate(&self, tool_name: &str) -> Option<&crate::authority::ToolMandate> {
        self.manifest.get(tool_name)
    }

    /// Refuses a caller that did not prove it speaks for the DID it claims.
    fn identity_rejection(&self, request: &AipRequest) -> Option<AipRejection> {
        match &request.principal {
            // A binding for a *different* DID than the one being exercised is
            // the impersonation case, and is refused whatever the policy says
            // about unverified sessions: something proved it was A and is now
            // acting as B.
            Some(binding) if binding.agent_did != request.agent_did => Some(AipRejection {
                code: AipRejectionCode::IdentityUnverified,
                detail: format!(
                    "caller authenticated as {} but is acting as {}",
                    binding.agent_did, request.agent_did
                ),
            }),
            Some(binding) if binding.is_proven() => None,
            _ if !self.require_verified_identity => None,
            Some(_) => Some(AipRejection {
                code: AipRejectionCode::IdentityUnverified,
                detail: format!(
                    "{} presented no proof of identity and this funnel requires one",
                    request.agent_did
                ),
            }),
            None => Some(AipRejection {
                code: AipRejectionCode::IdentityUnverified,
                detail: format!(
                    "no identity check ran for {}; the claimed DID is unproven",
                    request.agent_did
                ),
            }),
        }
    }

    fn lifecycle_rejection(
        &self,
        request: &AipRequest,
        state: Option<&AgentChainState>,
    ) -> Option<AipRejection> {
        let state = state?;
        if state.closed {
            return Some(AipRejection {
                code: AipRejectionCode::LifecycleClosed,
                detail: format!(
                    "{} lifecycle is closed by a terminal revocation",
                    request.agent_did
                ),
            });
        }
        if let Some(expected) = &state.model_digest {
            if expected != &request.runtime_model_digest {
                return Some(AipRejection {
                    code: AipRejectionCode::ModelIntegrityCompromised,
                    detail: "runtime model digest does not match the lifecycle chain's binding"
                        .to_string(),
                });
            }
        }
        None
    }

    fn mandate_rejection(
        &self,
        effective: &EffectiveAuthority,
        request: &AipRequest,
        now_utc: &str,
    ) -> Option<AipRejection> {
        let Some(mandate) = self.manifest.get(&request.tool_name) else {
            return Some(AipRejection {
                code: AipRejectionCode::UnknownTool,
                detail: format!(
                    "tool \"{}\" has no mandate in the manifest",
                    request.tool_name
                ),
            });
        };
        if !effective.scope.iter().any(|t| t == &request.tool_name) {
            return Some(AipRejection {
                code: AipRejectionCode::ToolNotInScope,
                detail: format!(
                    "effective delegated scope does not include \"{}\"",
                    request.tool_name
                ),
            });
        }
        if !effective.clearance_level.meets(mandate.minimum_clearance) {
            return Some(AipRejection {
                code: AipRejectionCode::ClearanceInsufficient,
                detail: format!(
                    "tool \"{}\" requires {}; the delegation path holds {}",
                    request.tool_name,
                    mandate.minimum_clearance.as_str(),
                    effective.clearance_level.as_str()
                ),
            });
        }
        let taint = request.context_taint();
        if taint > mandate.max_context_taint {
            return Some(AipRejection {
                code: AipRejectionCode::TaintedContextEscalation,
                detail: format!(
                    "tool \"{}\" tolerates context up to {}; {} content is live in context",
                    request.tool_name,
                    mandate.max_context_taint.as_str(),
                    taint.as_str()
                ),
            });
        }
        if effective.multi_sig_tools.contains(&request.tool_name) {
            let edge_id = effective.edge_ids.last().map(String::as_str).unwrap_or("");
            let params_digest = sha256_hex(&canonical_json(&request.input_params));
            let ok = request
                .supervisor_co_signature
                .as_deref()
                .is_some_and(|sig| {
                    self.cosign.verify(&CoSignatureRequest {
                        edge_id,
                        tool_name: &request.tool_name,
                        agent_did: &request.agent_did,
                        input_params_digest: &params_digest,
                        now_utc,
                        signature: sig,
                    })
                });
            if !ok {
                return Some(AipRejection {
                    code: AipRejectionCode::RequiresSupervisorMultisig,
                    detail: format!(
                        "tool \"{}\" requires a valid human supervisor co-signature",
                        request.tool_name
                    ),
                });
            }
        }
        None
    }

    /// Seals one anchor onto an agent's lifecycle chain, under the same law
    /// [`crate::lifecycle`] uses.
    fn append_anchor(
        state: &mut AgentChainState,
        agent_did: &str,
        anchor_type: &str,
        actor_did: &str,
        timestamp_utc: &str,
        payload: Value,
    ) -> Value {
        let sequence = state.anchor_sequence + 1;
        let mut anchor = json!({
            "anchorId": format!("{agent_did}#anchor-{sequence}"),
            "sequenceNumber": sequence,
            "anchorType": anchor_type,
            "agentDid": agent_did,
            "actorDid": actor_did,
            "timestampUtc": timestamp_utc,
            "payload": payload,
        });
        let hash = seal_hash(
            &state.anchor_tail,
            &chain_payload_bytes(&anchor, &["previousAnchorHash", "anchorHash"]),
        );
        anchor["previousAnchorHash"] = json!(state.anchor_tail);
        anchor["anchorHash"] = json!(hash);
        state.anchor_tail = hash;
        state.anchor_sequence = sequence;
        anchor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{
        ClearanceLevel, DelegationEdge, EdgeStatus, MemoryAuthorityStore, ToolMandate,
        TrustedStoreVerifier,
    };
    use crate::chain::{verify_anchor_chain, verify_packet_chain};
    use crate::identity::{AuthMethod, PrincipalBinding};

    const OFFICER: &str = "did:syntriass:officer:OFF-1";
    const AGENT: &str = "did:syntriass:agent:AGT-1";
    const NOW: &str = "2026-06-01T00:00:00.000Z";

    fn digest() -> String {
        "a".repeat(64)
    }

    fn manifest() -> ToolManifest {
        let mut m = ToolManifest::new();
        m.insert(
            "read_catalog".into(),
            ToolMandate::new("read", ClearanceLevel::Unclassified),
        );
        m.insert(
            "fly_to_location".into(),
            ToolMandate::new("navigate", ClearanceLevel::Confidential),
        );
        m.insert(
            "task_sensor".into(),
            ToolMandate::new("task", ClearanceLevel::Secret),
        );
        m.insert(
            // The consequential tool: no untrusted content may be live.
            "send_command".into(),
            ToolMandate::new("command", ClearanceLevel::Confidential)
                .with_max_context_taint(TrustTier::Internal),
        );
        m
    }

    fn edge(
        id: &str,
        parent: &str,
        child: &str,
        scope: &[&str],
        c: ClearanceLevel,
    ) -> DelegationEdge {
        DelegationEdge {
            edge_id: id.into(),
            parent_did: parent.into(),
            child_did: child.into(),
            scope: scope.iter().map(|s| s.to_string()).collect(),
            multi_sig_tools: Vec::new(),
            clearance_level: c,
            valid_from_utc: "2026-01-01T00:00:00.000Z".into(),
            expires_at_utc: "2027-01-01T00:00:00.000Z".into(),
            status: EdgeStatus::Active,
            signature: None,
        }
    }

    struct AcceptCoSignature;
    impl CoSignatureVerifier for AcceptCoSignature {
        fn verify(&self, request: &CoSignatureRequest) -> bool {
            request.signature == "valid-supervisor-sig"
        }
    }

    /// A funnel with one agent born and one rooted edge conferring `scope`.
    fn funnel(
        scope: &[&str],
        clearance: ClearanceLevel,
        multi_sig: &[&str],
        cosign: Box<dyn CoSignatureVerifier + Send + Sync>,
    ) -> AipFunnel {
        let mut store = MemoryAuthorityStore::new();
        let mut e = edge("e1", OFFICER, AGENT, scope, clearance);
        e.multi_sig_tools = multi_sig.iter().map(|s| s.to_string()).collect();
        store.add(e);
        let mut f = AipFunnel::new(
            Box::new(store),
            Box::new(TrustedStoreVerifier),
            cosign,
            manifest(),
        );
        f.register_genesis(AGENT, OFFICER, &digest(), "2026-01-01T00:00:00.000Z");
        f
    }

    /// A request from a caller that proved who it is — the ordinary case now
    /// that identity binding is required.
    fn request(tool: &str) -> AipRequest {
        AipRequest::new(
            AGENT,
            digest(),
            format!("please {tool}"),
            tool,
            json!({ "q": 1 }),
            json!({ "view": "globe" }),
        )
        .with_principal(proven_as(AGENT))
    }

    fn proven_as(did: &str) -> PrincipalBinding {
        PrincipalBinding::proven(
            did,
            AuthMethod::ProofOfPossession,
            "c".repeat(64),
            "2026-06-01T00:00:00.000Z",
        )
    }

    fn run(f: &mut AipFunnel, req: AipRequest) -> AipOutcome {
        let pending = f.evaluate(req, NOW);
        let outcome = if pending.permitted() {
            ExecutionOutcome::Succeeded(json!({ "view": "hormuz" }))
        } else {
            ExecutionOutcome::NotAttempted
        };
        f.seal(pending, outcome, "2026-06-01T00:00:01.000Z")
    }

    #[test]
    fn a_permitted_call_seals_cross_bound_chains_the_shared_verifier_accepts() {
        let mut f = funnel(
            &["read_catalog", "fly_to_location"],
            ClearanceLevel::Secret,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        let out = run(&mut f, request("fly_to_location"));
        assert!(out.permitted);
        assert_eq!(out.status, ExecutionStatus::Success);

        let packet = &out.packet;
        let anchor = out.seal_anchor.as_ref().expect("chain was writable");
        // The seal anchor names the packet, and the packet names the anchor
        // head it ran under: neither can be rewritten alone.
        assert_eq!(anchor["payload"]["packetHash"], packet["packetHash"]);
        assert_eq!(anchor["payload"]["packetId"], packet["id"]);
        assert_eq!(
            packet["anchorHash"].as_str().unwrap(),
            anchor["previousAnchorHash"].as_str().unwrap(),
        );
        assert_eq!(packet["delegationPath"], json!([OFFICER, AGENT]));
        assert_eq!(packet["edgeId"], json!("e1"));
        assert!(verify_packet_chain(std::slice::from_ref(packet)).valid);
    }

    #[test]
    fn a_rejected_call_is_still_sealed_and_cannot_mutate_state() {
        let mut f = funnel(
            &["read_catalog"],
            ClearanceLevel::Secret,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        // In the manifest, cleared, but never delegated.
        let pending = f.evaluate(request("fly_to_location"), NOW);
        assert_eq!(
            pending.rejection().unwrap().code,
            AipRejectionCode::ToolNotInScope
        );
        // A gateway that ran it anyway and claims a mutated post-state…
        let out = f.seal(
            pending,
            ExecutionOutcome::Succeeded(json!({ "view": "somewhere-else" })),
            NOW,
        );
        // …still records a blocked call with post == pre.
        assert!(!out.permitted);
        assert_eq!(out.status, ExecutionStatus::BlockedByPolicy);
        assert_eq!(out.packet["preStateHash"], out.packet["postStateHash"]);
        assert!(out.packet["toolExecuted"]["error"]
            .as_str()
            .unwrap()
            .contains("TOOL_NOT_IN_SCOPE"));
        // The refusal is anchored: denials are evidence, not silence.
        assert!(out.seal_anchor.is_some());
    }

    #[test]
    fn every_lifecycle_and_mandate_precondition_has_its_own_code() {
        // Unknown DID.
        let mut f = funnel(
            &["read_catalog"],
            ClearanceLevel::Secret,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        let mut unknown = request("read_catalog");
        unknown.agent_did = "did:syntriass:agent:GHOST".into();
        // It genuinely proved it is the ghost — so this exercises missing
        // *authority*, not missing identity.
        unknown.principal = Some(proven_as("did:syntriass:agent:GHOST"));
        let out = run(&mut f, unknown);
        assert_eq!(
            out.rejection.unwrap().code,
            AipRejectionCode::NoEffectiveAuthority
        );

        // Wrong weights.
        let mut swapped = request("read_catalog");
        swapped.runtime_model_digest = "b".repeat(64);
        let out = run(&mut f, swapped);
        assert_eq!(
            out.rejection.unwrap().code,
            AipRejectionCode::ModelIntegrityCompromised
        );

        // Not in the manifest at all.
        let out = run(&mut f, request("exfiltrate"));
        assert_eq!(out.rejection.unwrap().code, AipRejectionCode::UnknownTool);

        // Delegated, in the manifest, but the path is under-cleared.
        let mut low = funnel(
            &["task_sensor"],
            ClearanceLevel::Confidential,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        let out = run(&mut low, request("task_sensor"));
        assert_eq!(
            out.rejection.unwrap().code,
            AipRejectionCode::ClearanceInsufficient
        );

        // Closed lifecycle.
        f.register_revocation(AGENT, "drill", "2026-05-01T00:00:00.000Z");
        let out = run(&mut f, request("read_catalog"));
        assert_eq!(
            out.rejection.unwrap().code,
            AipRejectionCode::LifecycleClosed
        );
        // A closed chain takes no further anchors, but the attempt is still
        // packet evidence.
        assert!(out.seal_anchor.is_none());
        assert_eq!(out.packet["anchorHash"], json!(""));
    }

    #[test]
    fn untrusted_context_removes_authority_for_a_taint_restricted_tool() {
        let mut f = funnel(
            &["send_command", "read_catalog"],
            ClearanceLevel::Secret,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        let tainted = vec![ContextSource {
            uri: "https://attacker.example/brief.txt".into(),
            digest: "c".repeat(64),
            trust: TrustTier::Untrusted,
        }];

        // Clean context: permitted.
        assert!(f.evaluate(request("send_command"), NOW).permitted());

        // The same agent, same delegation, after reading one untrusted
        // document: the tool is gone. Nothing in the document had to be
        // recognised as an attack.
        let out = run(
            &mut f,
            request("send_command").with_context(tainted.clone()),
        );
        assert_eq!(
            out.rejection.unwrap().code,
            AipRejectionCode::TaintedContextEscalation
        );
        // What it read is on the record, by digest.
        assert_eq!(
            out.packet["contextProvenance"][0]["uri"],
            json!("https://attacker.example/brief.txt")
        );
        assert_eq!(
            out.packet["contextProvenance"][0]["trust"],
            json!("UNTRUSTED")
        );

        // An unrestricted tool still works with the same tainted context.
        let out = run(&mut f, request("read_catalog").with_context(tainted));
        assert!(out.permitted);
    }

    #[test]
    fn empty_context_omits_the_field_so_pre_taint_packets_hash_unchanged() {
        let mut f = funnel(
            &["read_catalog"],
            ClearanceLevel::Secret,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        let out = run(&mut f, request("read_catalog"));
        assert!(out.packet.get("contextProvenance").is_none());
    }

    #[test]
    fn a_multisig_tool_needs_a_co_signature_that_actually_verifies() {
        let build = |cosign: Box<dyn CoSignatureVerifier + Send + Sync>| {
            funnel(
                &["fly_to_location"],
                ClearanceLevel::Secret,
                &["fly_to_location"],
                cosign,
            )
        };

        // No signature.
        let mut f = build(Box::new(AcceptCoSignature));
        let out = run(&mut f, request("fly_to_location"));
        assert_eq!(
            out.rejection.unwrap().code,
            AipRejectionCode::RequiresSupervisorMultisig
        );

        // Wrong signature.
        let out = run(
            &mut f,
            request("fly_to_location").with_co_signature("forged"),
        );
        assert_eq!(
            out.rejection.unwrap().code,
            AipRejectionCode::RequiresSupervisorMultisig
        );

        // Valid signature.
        let out = run(
            &mut f,
            request("fly_to_location").with_co_signature("valid-supervisor-sig"),
        );
        assert!(out.permitted);
        assert_eq!(
            out.packet["toolExecuted"]["supervisorCoSignature"],
            json!("valid-supervisor-sig")
        );

        // The fail-closed default makes the same tool uninvocable.
        let mut denied = build(Box::new(DenyAllCoSignatures));
        let out = run(
            &mut denied,
            request("fly_to_location").with_co_signature("valid-supervisor-sig"),
        );
        assert_eq!(
            out.rejection.unwrap().code,
            AipRejectionCode::RequiresSupervisorMultisig
        );
    }

    #[test]
    fn tools_list_is_filtered_by_scope_clearance_and_live_taint() {
        let f = funnel(
            // "task_sensor" is delegated but needs SECRET; the path holds
            // CONFIDENTIAL. "exfiltrate" is delegated but has no mandate.
            &["read_catalog", "send_command", "task_sensor", "exfiltrate"],
            ClearanceLevel::Confidential,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        let mut clean = f.permitted_tool_names(AGENT, TrustTier::Trusted, NOW);
        clean.sort();
        assert_eq!(clean, ["read_catalog", "send_command"]);

        // With untrusted content live, the catalogue itself shrinks — the
        // model is never shown the tool it could be talked into reaching for.
        let tainted = f.permitted_tool_names(AGENT, TrustTier::Untrusted, NOW);
        assert_eq!(tainted, ["read_catalog"]);

        // An unknown DID sees nothing at all.
        assert!(f
            .permitted_tools("did:syntriass:agent:GHOST", TrustTier::Trusted, NOW)
            .is_empty());
    }

    #[test]
    fn the_catalogue_declares_multisig_obligations_before_the_model_calls() {
        let f = funnel(
            &["read_catalog", "fly_to_location"],
            ClearanceLevel::Secret,
            &["fly_to_location"],
            Box::new(DenyAllCoSignatures),
        );
        let tools = f.permitted_tools(AGENT, TrustTier::Trusted, NOW);
        let flagged: Vec<(&str, bool)> = tools
            .iter()
            .map(|t| (t.name.as_str(), t.requires_co_signature))
            .collect();
        assert_eq!(
            flagged,
            [("fly_to_location", true), ("read_catalog", false)]
        );
    }

    #[test]
    fn a_whole_governed_session_verifies_end_to_end_under_the_shared_verifier() {
        // Built inline rather than via `funnel` so the genesis anchor — the
        // first link of the lifecycle chain — is in hand for verification.
        let mut store = MemoryAuthorityStore::new();
        store.add(edge(
            "e1",
            OFFICER,
            AGENT,
            &["read_catalog", "fly_to_location"],
            ClearanceLevel::Secret,
        ));
        let mut f = AipFunnel::new(
            Box::new(store),
            Box::new(TrustedStoreVerifier),
            Box::new(DenyAllCoSignatures),
            manifest(),
        );
        let genesis = f.register_genesis(AGENT, OFFICER, &digest(), "2026-01-01T00:00:00.000Z");

        let first = run(&mut f, request("read_catalog"));
        let second = run(&mut f, request("fly_to_location"));
        // A refused call takes a link in both chains too — a gap in the
        // sequence would itself be the tell.
        let refused = run(&mut f, request("exfiltrate"));
        assert!(!refused.permitted);

        assert_eq!(
            second.packet["previousPacketHash"],
            first.packet["packetHash"]
        );
        assert_eq!(refused.packet["sequenceNumber"], json!(3));

        let revocation = f
            .register_revocation(AGENT, "exercise complete", "2026-06-02T00:00:00.000Z")
            .unwrap();

        // The full lifecycle chain from genesis: one seal per call — refusals
        // included — then the terminal revocation.
        let anchors = [
            genesis,
            first.seal_anchor.clone().unwrap(),
            second.seal_anchor.clone().unwrap(),
            refused.seal_anchor.clone().unwrap(),
            revocation,
        ];
        let types: Vec<&str> = anchors
            .iter()
            .map(|a| a["anchorType"].as_str().unwrap())
            .collect();
        assert_eq!(
            types,
            [
                "AGENT_GENESIS",
                "ACTION_EXECUTION_SEAL",
                "ACTION_EXECUTION_SEAL",
                "ACTION_EXECUTION_SEAL",
                "AUTHORITY_REVOCATION",
            ],
        );
        assert!(verify_anchor_chain(&anchors).valid);
        assert!(
            verify_packet_chain(&[
                first.packet.clone(),
                second.packet.clone(),
                refused.packet.clone(),
            ])
            .valid
        );

        // Tampering with the recorded arguments of one call breaks that
        // packet, and its hash is what the seal anchor names — so the
        // lifecycle chain contradicts the edit too.
        let mut forged = second.packet.clone();
        forged["toolExecuted"]["inputParams"] = json!({ "q": 999 });
        let report = verify_packet_chain(&[first.packet.clone(), forged, refused.packet.clone()]);
        assert!(!report.valid);
    }

    #[test]
    fn an_unproven_did_is_refused_before_anything_downstream_is_consulted() {
        let mut f = funnel(
            &["read_catalog"],
            ClearanceLevel::Secret,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        // Fully authorised in every other respect — born, delegated, cleared,
        // right weights — and still refused, because the DID is only claimed.
        let mut unproven = request("read_catalog");
        unproven.principal = None;
        let out = run(&mut f, unproven);
        assert_eq!(
            out.rejection.unwrap().code,
            AipRejectionCode::IdentityUnverified
        );

        // An explicitly unauthenticated binding is refused the same way: it
        // records that no proof was offered, it does not substitute for one.
        let mut declared = request("read_catalog");
        declared.principal = Some(PrincipalBinding::unauthenticated(AGENT, NOW));
        assert_eq!(
            run(&mut f, declared).rejection.unwrap().code,
            AipRejectionCode::IdentityUnverified
        );
    }

    #[test]
    fn proving_one_identity_does_not_license_acting_as_another() {
        let mut f = funnel(
            &["read_catalog"],
            ClearanceLevel::Secret,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        // A genuinely authenticated caller — for a different agent.
        let mut impostor = request("read_catalog");
        impostor.principal = Some(proven_as("did:syntriass:agent:SOMEONE-ELSE"));
        let out = run(&mut f, impostor);
        let rejection = out.rejection.unwrap();
        assert_eq!(rejection.code, AipRejectionCode::IdentityUnverified);
        assert!(
            rejection.detail.contains("but is acting as"),
            "{}",
            rejection.detail
        );

        // And the mismatch is refused even where unverified sessions are
        // tolerated: permitting *no* proof is a different decision from
        // accepting proof of somebody else.
        let mut lax = funnel(
            &["read_catalog"],
            ClearanceLevel::Secret,
            &[],
            Box::new(DenyAllCoSignatures),
        )
        .allowing_unverified_identity();
        lax.register_genesis(AGENT, OFFICER, &digest(), "2026-01-01T00:00:00.000Z");
        let mut impostor = request("read_catalog");
        impostor.principal = Some(proven_as("did:syntriass:agent:SOMEONE-ELSE"));
        assert_eq!(
            run(&mut lax, impostor).rejection.unwrap().code,
            AipRejectionCode::IdentityUnverified
        );
    }

    #[test]
    fn the_established_identity_is_sealed_into_the_evidence() {
        let mut f = funnel(
            &["read_catalog"],
            ClearanceLevel::Secret,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        let out = run(&mut f, request("read_catalog"));
        assert!(out.permitted);
        let principal = &out.packet["principal"];
        assert_eq!(principal["agentDid"], json!(AGENT));
        assert_eq!(principal["method"], json!("PROOF_OF_POSSESSION"));
        assert_eq!(principal["credentialDigest"], json!("c".repeat(64)));
        // An offline verifier can read it back into the typed form.
        let parsed = PrincipalBinding::from_json(principal).unwrap();
        assert!(parsed.is_proven());
    }

    #[test]
    fn a_relaxed_funnel_still_records_that_nothing_was_proven() {
        let mut store = MemoryAuthorityStore::new();
        store.add(edge(
            "e1",
            OFFICER,
            AGENT,
            &["read_catalog"],
            ClearanceLevel::Secret,
        ));
        let mut f = AipFunnel::new(
            Box::new(store),
            Box::new(TrustedStoreVerifier),
            Box::new(DenyAllCoSignatures),
            manifest(),
        )
        .allowing_unverified_identity();
        assert!(!f.requires_verified_identity());
        f.register_genesis(AGENT, OFFICER, &digest(), "2026-01-01T00:00:00.000Z");

        let mut request = request("read_catalog");
        request.principal = Some(PrincipalBinding::unauthenticated(AGENT, NOW));
        let out = run(&mut f, request);
        assert!(out.permitted);
        // The relaxed rule is visible in the record, so an auditor can tell
        // which packets were produced under it rather than trusting that a
        // configuration flag was set the way somebody remembers.
        assert_eq!(out.packet["principal"]["method"], json!("UNAUTHENTICATED"));
    }

    #[test]
    fn packets_from_a_writer_with_no_identity_tier_hash_exactly_as_before() {
        let mut store = MemoryAuthorityStore::new();
        store.add(edge(
            "e1",
            OFFICER,
            AGENT,
            &["read_catalog"],
            ClearanceLevel::Secret,
        ));
        let mut f = AipFunnel::new(
            Box::new(store),
            Box::new(TrustedStoreVerifier),
            Box::new(DenyAllCoSignatures),
            manifest(),
        )
        .allowing_unverified_identity();
        f.register_genesis(AGENT, OFFICER, &digest(), "2026-01-01T00:00:00.000Z");

        let mut legacy = request("read_catalog");
        legacy.principal = None;
        let out = run(&mut f, legacy);
        assert!(out.permitted);
        // No `principal` key at all: adding the tier must not change the
        // canonical bytes of a chain written before it existed.
        assert!(out.packet.get("principal").is_none());
        assert!(verify_packet_chain(std::slice::from_ref(&out.packet)).valid);
    }

    #[test]
    fn a_model_migration_rebinds_the_expected_weights() {
        let mut f = funnel(
            &["read_catalog"],
            ClearanceLevel::Secret,
            &[],
            Box::new(DenyAllCoSignatures),
        );
        let new_digest = "d".repeat(64);
        let mut migrated = request("read_catalog");
        migrated.runtime_model_digest = new_digest.clone();
        // Before the migration the new weights are an integrity failure…
        assert_eq!(
            run(&mut f, migrated.clone()).rejection.unwrap().code,
            AipRejectionCode::ModelIntegrityCompromised
        );
        f.register_model_migration(AGENT, &new_digest, "2026-05-01T00:00:00.000Z");
        // …and after it, the old weights are.
        assert!(run(&mut f, migrated).permitted);
        assert_eq!(
            run(&mut f, request("read_catalog")).rejection.unwrap().code,
            AipRejectionCode::ModelIntegrityCompromised
        );
        // A closed lifecycle takes no migration.
        f.register_revocation(AGENT, "done", "2026-05-02T00:00:00.000Z");
        assert!(f
            .register_model_migration(AGENT, &digest(), "2026-05-03T00:00:00.000Z")
            .is_none());
    }
}
