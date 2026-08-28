//! The governed proxy: MCP in, adjudicated MCP out, evidence sealed either way.
//!
//! # Why this is transport-free
//!
//! [`McpGateway::handle`] never performs I/O. It returns a [`Handling`] — a
//! finished response, a [`ForwardTicket`] the transport must send upstream,
//! or silence for a notification — and [`McpGateway::complete`] consumes the
//! ticket with whatever the upstream said.
//!
//! That is the same split [`AipFunnel::evaluate`]/[`AipFunnel::seal`] uses,
//! raised to the protocol level, and it buys three things. The crate depends
//! on no async runtime, so it drops into a stdio child-process proxy, an
//! Axum handler, or an in-process shim unchanged. Every dispatch decision is
//! unit-testable without a server. And the ticket is `#[must_use]`, so a
//! transport that forwards a call and forgets to complete it — the one bug
//! that would produce an executed-but-unsealed action — is a compiler
//! warning at the call site rather than a hole discovered in an audit.
//!
//! # Default-deny at the protocol layer
//!
//! An MCP method the gateway does not recognise is refused, not relayed.
//! A proxy that passes unknown methods through is a proxy whose guarantees
//! expire the moment the protocol gains a method that can invoke something —
//! and the protocol is young enough that it will. The cost is that a new
//! method needs a line here; that is the intended cost.

use ot_accountability_core::aip::{
    AipFunnel, AipRequest, ContextSource, ExecutionOutcome, PendingExecution,
};
use ot_accountability_core::authority::TrustTier;
use serde_json::{json, Value};

use crate::identity::{IdentityAttestor, PeerCredential, SharedRegistry, UnauthenticatedAttestor};
use crate::protocol::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, Method, INTERNAL_ERROR, INVALID_PARAMS,
    INVALID_REQUEST, METHOD_NOT_FOUND, POLICY_DENIED,
};
use crate::session::{Session, TrustPolicy};
use crate::sink::EvidenceSink;
use ot_accountability_core::identity::AuthMethod;

/// The MCP revision this gateway speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// What the transport should do with a dispatched request.
#[derive(Debug)]
pub enum Handling {
    /// Answer the client with this; the upstream was not involved.
    Respond(Box<JsonRpcResponse>),
    /// Send the ticket's request upstream, then call
    /// [`McpGateway::complete`] with the outcome.
    Forward(ForwardTicket),
    /// A notification: nothing to answer.
    Silent,
}

/// What [`McpGateway::complete`] must do once the upstream replies.
#[derive(Debug)]
enum ForwardAction {
    /// Relay the outcome unchanged.
    Passthrough,
    /// Filter the returned catalogue to the agent's effective authority.
    FilterTools,
    /// Record what was read as context, at the policy's trust tier.
    RecordContext { uri: String, trust: TrustTier },
    /// Seal the execution against this adjudicated ticket.
    Governed {
        pending: Box<PendingExecution>,
        tool_name: String,
        result_trust: TrustTier,
    },
}

/// An adjudicated request awaiting its upstream round trip.
#[must_use = "a forwarded request must be completed — dropping the ticket executes without sealing"]
#[derive(Debug)]
pub struct ForwardTicket {
    id: Option<Value>,
    request: JsonRpcRequest,
    action: ForwardAction,
}

impl ForwardTicket {
    /// The request to send upstream.
    pub fn upstream_request(&self) -> &JsonRpcRequest {
        &self.request
    }

    /// True when no response is owed to the client.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// A governed Model Context Protocol proxy.
///
/// Generic over its sink and trust policy so a deployment pays no dispatch
/// cost for choices it made at compile time — and boxed trait objects
/// implement both traits, so a deployment that *does* choose at runtime uses
/// `McpGateway<Box<dyn EvidenceSink + Send + Sync>, Box<dyn TrustPolicy + Send + Sync>>`
/// with the same API.
pub struct McpGateway<S: EvidenceSink, P: TrustPolicy> {
    funnel: AipFunnel,
    sink: S,
    policy: P,
    attestor: Box<dyn IdentityAttestor>,
    /// The registry the attestor consults, when it has one. Held so
    /// enrolment can update it live and seal the matching anchor in one step.
    registry: Option<SharedRegistry>,
    server_name: String,
    server_version: String,
}

impl<S: EvidenceSink, P: TrustPolicy> McpGateway<S, P> {
    /// Builds a gateway over an adjudicating funnel, an evidence sink, and a
    /// trust policy for classifying what gets read.
    pub fn new(funnel: AipFunnel, sink: S, policy: P) -> Self {
        Self {
            funnel,
            sink,
            policy,
            // Proves nothing, and names itself. The funnel's default
            // `require_verified_identity` then refuses every call, so an
            // unconfigured gateway is inert rather than quietly open.
            attestor: Box::new(UnauthenticatedAttestor),
            registry: None,
            server_name: "ot-mcp-gateway".to_string(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Sets how callers prove which agent they are.
    pub fn with_attestor(mut self, attestor: Box<dyn IdentityAttestor>) -> Self {
        self.attestor = attestor;
        self
    }

    /// Shares the attestor's enrolment registry with the gateway, so
    /// [`enrol_credential`](Self::enrol_credential) and
    /// [`revoke_credential`](Self::revoke_credential) can update it.
    pub fn with_registry(mut self, registry: SharedRegistry) -> Self {
        self.registry = Some(registry);
        self
    }

    /// A snapshot of the live enrolment registry, for inspection and for
    /// comparing against what the sealed chain says.
    pub fn registry_snapshot(
        &self,
    ) -> Option<ot_accountability_core::identity::CredentialRegistry> {
        self.registry
            .as_ref()
            .and_then(|r| r.read().ok().map(|guard| guard.clone()))
    }

    /// Authorises a credential to speak for an agent: updates the live
    /// registry and seals the enrolment anchor.
    ///
    /// Both halves, or neither. A registry updated without an anchor is an
    /// authority change with no audit record; an anchor written without the
    /// registry update is a record of something that did not take effect.
    pub fn enrol_credential(
        &mut self,
        agent_did: &str,
        credential_digest: &str,
        method: AuthMethod,
        timestamp_utc: &str,
    ) -> Result<Option<Value>, String> {
        let Some(anchor) = self.funnel.register_credential_enrolment(
            agent_did,
            credential_digest,
            method,
            timestamp_utc,
        ) else {
            return Ok(None);
        };
        if let Some(registry) = &self.registry {
            registry
                .write()
                .map_err(|_| "credential registry lock is poisoned".to_string())?
                .enrol(agent_did, credential_digest, method, timestamp_utc);
        }
        self.sink.record_anchor(&anchor)?;
        Ok(Some(anchor))
    }

    /// Withdraws a credential: updates the live registry and seals the
    /// revocation anchor. Takes effect on the next authentication, not the
    /// next restart.
    pub fn revoke_credential(
        &mut self,
        agent_did: &str,
        credential_digest: &str,
        reason: &str,
        timestamp_utc: &str,
    ) -> Result<Option<Value>, String> {
        let Some(anchor) = self.funnel.register_credential_revocation(
            agent_did,
            credential_digest,
            reason,
            timestamp_utc,
        ) else {
            return Ok(None);
        };
        if let Some(registry) = &self.registry {
            registry
                .write()
                .map_err(|_| "credential registry lock is poisoned".to_string())?
                .revoke(agent_did, credential_digest);
        }
        self.sink.record_anchor(&anchor)?;
        Ok(Some(anchor))
    }

    /// Overrides the server identity reported at `initialize`.
    pub fn with_server_info(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.server_name = name.into();
        self.server_version = version.into();
        self
    }

    /// The adjudicating funnel, for provisioning agents and reading state.
    pub fn funnel_mut(&mut self) -> &mut AipFunnel {
        &mut self.funnel
    }

    /// The adjudicating funnel.
    pub fn funnel(&self) -> &AipFunnel {
        &self.funnel
    }

    /// The evidence sink, for callers that inspect or drain what was sealed.
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Births an agent and persists the genesis anchor, so calls from the DID
    /// are adjudicated rather than refused as unborn.
    pub fn register_agent(
        &mut self,
        agent_did: &str,
        supervisor_did: &str,
        model_digest: &str,
        timestamp_utc: &str,
    ) -> Result<Value, String> {
        let anchor =
            self.funnel
                .register_genesis(agent_did, supervisor_did, model_digest, timestamp_utc);
        self.sink.record_anchor(&anchor)?;
        Ok(anchor)
    }

    /// Terminally revokes an agent and persists the closing anchor. Every
    /// later call from the DID is refused, and the lifecycle chain takes no
    /// further anchors.
    pub fn revoke_agent(
        &mut self,
        agent_did: &str,
        reason: &str,
        timestamp_utc: &str,
    ) -> Result<Option<Value>, String> {
        match self
            .funnel
            .register_revocation(agent_did, reason, timestamp_utc)
        {
            None => Ok(None),
            Some(anchor) => {
                self.sink.record_anchor(&anchor)?;
                Ok(Some(anchor))
            }
        }
    }

    /// Dispatches one client request over a channel carrying no peer
    /// identity — stdio, or a socket with no TLS.
    ///
    /// Equivalent to [`handle_with_peer`](Self::handle_with_peer) with
    /// [`PeerCredential::None`]: callers on such a transport must prove
    /// themselves by signing the issued challenge instead.
    pub fn handle(
        &mut self,
        session: &mut Session,
        request: JsonRpcRequest,
        now_utc: &str,
    ) -> Handling {
        self.handle_with_peer(session, request, &PeerCredential::None, now_utc)
    }

    /// Dispatches one client request, given what the transport took from the
    /// channel.
    ///
    /// `peer` must come from the connection itself — a TLS client
    /// certificate, a SPIFFE SVID — and never from the request body, which
    /// the caller controls and could simply fill in with somebody else's
    /// name.
    pub fn handle_with_peer(
        &mut self,
        session: &mut Session,
        request: JsonRpcRequest,
        peer: &PeerCredential,
        now_utc: &str,
    ) -> Handling {
        let id = request.id.clone();

        // Authentication is attempted on every request rather than only at
        // `initialize`, because a challenge-response transport has nowhere
        // else to put the answer: the nonce is issued in the handshake reply,
        // so the proof can only arrive on a later message.
        self.try_authenticate(session, &request, peer, now_utc);

        match request.classify() {
            Method::Initialize => self.handle_initialize(session, request),
            Method::Initialized => {
                session.initialized = true;
                Handling::Silent
            }
            Method::Ping => match id {
                Some(id) => Handling::Respond(Box::new(JsonRpcResponse::result(id, json!({})))),
                None => Handling::Silent,
            },
            Method::ToolsList => self.guarded(session, request, ForwardAction::FilterTools),
            Method::ToolsCall => self.handle_tools_call(session, request, now_utc),
            Method::ResourcesRead => self.handle_resources_read(session, request),
            // Enumeration reveals what exists but invokes nothing, and the
            // catalogue an agent may *act* on is already filtered at
            // `tools/list`.
            Method::ResourcesList | Method::PromptsList | Method::PromptsGet => {
                self.guarded(session, request, ForwardAction::Passthrough)
            }
            Method::Other(name) => {
                let error = JsonRpcError::new(
                    METHOD_NOT_FOUND,
                    format!("method \"{name}\" is not proxied by this governed gateway"),
                );
                match id {
                    Some(id) => Handling::Respond(Box::new(JsonRpcResponse::error(id, error))),
                    None => Handling::Silent,
                }
            }
        }
    }

    /// Consumes a forward ticket with the upstream's outcome, producing the
    /// response owed to the client.
    ///
    /// For a governed ticket this is where the evidence packet is sealed —
    /// after execution, against the verdict rendered before it.
    pub fn complete(
        &mut self,
        session: &mut Session,
        ticket: ForwardTicket,
        outcome: Result<Value, JsonRpcError>,
        now_utc: &str,
    ) -> Option<JsonRpcResponse> {
        let ForwardTicket { id, action, .. } = ticket;
        let response = match action {
            ForwardAction::Passthrough => outcome,
            ForwardAction::FilterTools => {
                outcome.map(|result| self.filter_catalogue(session, result, now_utc))
            }
            ForwardAction::RecordContext { uri, trust } => {
                if let Ok(result) = &outcome {
                    // Digest the whole returned payload: the gateway cannot
                    // know which field the model will attend to, so the
                    // record covers everything that crossed the boundary.
                    let bytes = serde_json::to_string(result).unwrap_or_default();
                    session.record_context(uri, &bytes, trust);
                }
                outcome
            }
            ForwardAction::Governed {
                pending,
                tool_name,
                result_trust,
            } => {
                let execution = match &outcome {
                    Ok(result) => {
                        // An MCP tool reports its own failure in-band via
                        // `isError`, which is a failed execution, not a
                        // transport success.
                        if result.get("isError").and_then(Value::as_bool) == Some(true) {
                            ExecutionOutcome::Failed("upstream tool reported isError".to_string())
                        } else {
                            ExecutionOutcome::Succeeded(result.clone())
                        }
                    }
                    Err(e) => ExecutionOutcome::Failed(format!(
                        "upstream error {}: {}",
                        e.code, e.message
                    )),
                };
                let sealed = self.funnel.seal(*pending, execution, now_utc);
                if let Err(why) = self
                    .sink
                    .record(&sealed.packet, sealed.seal_anchor.as_ref())
                {
                    // Evidence that could not be written means the call is
                    // unaccounted for. Say so rather than returning a result
                    // the ledger has no record of.
                    return id.map(|id| {
                        JsonRpcResponse::error(
                            id,
                            JsonRpcError::new(
                                INTERNAL_ERROR,
                                format!("execution completed but its evidence could not be sealed: {why}"),
                            ),
                        )
                    });
                }
                // A tool's output taints context at the tier its mandate
                // declares, which is what makes read-then-act combinations
                // close themselves off without anyone annotating a flow.
                if let Ok(result) = &outcome {
                    let bytes = serde_json::to_string(result).unwrap_or_default();
                    session.record_context(format!("tool://{tool_name}"), &bytes, result_trust);
                }
                outcome.map(|mut result| {
                    Self::annotate(&mut result, &sealed.packet);
                    result
                })
            }
        };
        id.map(|id| JsonRpcResponse {
            id,
            outcome: response,
        })
    }

    fn handle_initialize(&mut self, session: &mut Session, request: JsonRpcRequest) -> Handling {
        let meta = request.governance_meta().clone();
        if let Some(did) = meta.get("agentDid").and_then(Value::as_str) {
            session.agent_did = did.to_string();
        }
        if let Some(digest) = meta.get("modelDigest").and_then(Value::as_str) {
            session.runtime_model_digest = digest.to_string();
        }
        session.initialized = true;
        // A fresh nonce per handshake, unless the session already
        // authenticated from the channel — in which case there is nothing
        // left to challenge.
        if !session.is_authenticated() {
            session.set_challenge(self.attestor.issue_challenge());
        }

        let Some(id) = request.id.clone() else {
            return Handling::Silent;
        };
        // Answered locally rather than relayed: the client is handshaking
        // with the gateway, which is the server enforcing the policy. An
        // upstream handshake is the transport's business at startup.
        Handling::Respond(Box::new(JsonRpcResponse::result(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": { "listChanged": true },
                    "resources": {},
                    "prompts": {},
                },
                "serverInfo": {
                    "name": self.server_name,
                    "version": self.server_version,
                },
                "instructions":
                    "Every tools/call through this gateway is adjudicated against a delegation \
                     graph and sealed into a hash-chained forensic ledger before it reaches the \
                     upstream server. tools/list is filtered to your effective authority, so a \
                     tool you cannot see is one you do not hold. Reading untrusted content may \
                     remove tools from that list for the rest of the session.",
                "_meta": {
                    "governance": {
                        "agentDid": session.agent_did,
                        "modelDigest": session.runtime_model_digest,
                        "authenticated": session.is_authenticated(),
                        // Sign this with an enrolled key and return it as
                        // `_meta.governance.identityProof` on any subsequent
                        // request. Absent once the channel already proved who
                        // you are.
                        "challenge": session.challenge(),
                    }
                },
            }),
        )))
    }

    fn handle_tools_call(
        &mut self,
        session: &mut Session,
        request: JsonRpcRequest,
        now_utc: &str,
    ) -> Handling {
        let Some(id) = request.id.clone() else {
            // A tool call with no id would execute with no way to report the
            // verdict. Refused rather than silently governed.
            return Handling::Silent;
        };
        if let Some(err) = self.require_initialized(session) {
            return Handling::Respond(Box::new(JsonRpcResponse::error(id, err)));
        }
        let Some(tool_name) = request.param_str("name").map(str::to_string) else {
            return Handling::Respond(Box::new(JsonRpcResponse::error(
                id,
                JsonRpcError::new(INVALID_PARAMS, "tools/call requires params.name"),
            )));
        };

        let meta = request.governance_meta().clone();
        let mut aip = AipRequest::new(
            session.agent_did.clone(),
            session.runtime_model_digest.clone(),
            // The prompt that produced the call is the client's to declare;
            // the gateway records what it is given, and an empty string is
            // itself a visible fact about that client's instrumentation.
            meta.get("rawPrompt")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            tool_name.clone(),
            request
                .params
                .get("arguments")
                .cloned()
                .unwrap_or(json!({})),
            // The gateway observes no world state of its own; a client that
            // has one supplies it, and `null` honestly records that none was
            // declared rather than inventing a digest.
            meta.get("preState").cloned().unwrap_or(Value::Null),
        );
        if let Some(sig) = meta.get("supervisorCoSignature").and_then(Value::as_str) {
            aip = aip.with_co_signature(sig);
        }
        aip = aip.with_context(session.context().to_vec());
        // What the transport actually established — not what the caller
        // claimed. `None` when nothing was proven, which the funnel refuses
        // by default.
        if let Some(principal) = &session.principal {
            aip = aip.with_principal(principal.clone());
        }

        let result_trust = self
            .funnel
            .mandate(&tool_name)
            .map(|m| m.result_trust)
            // An unknown tool is refused anyway; treating a hypothetical
            // result as untrusted keeps the fail-closed direction.
            .unwrap_or(TrustTier::Untrusted);

        let pending = self.funnel.evaluate(aip, now_utc);
        if !pending.permitted() {
            let rejection = pending.rejection().cloned();
            let sealed = self
                .funnel
                .seal(pending, ExecutionOutcome::NotAttempted, now_utc);
            if let Err(why) = self
                .sink
                .record(&sealed.packet, sealed.seal_anchor.as_ref())
            {
                return Handling::Respond(Box::new(JsonRpcResponse::error(
                    id,
                    JsonRpcError::new(
                        INTERNAL_ERROR,
                        format!("call was refused but the refusal could not be sealed: {why}"),
                    ),
                )));
            }
            let rejection = rejection.expect("a non-permitted ticket carries a rejection");
            return Handling::Respond(Box::new(JsonRpcResponse::error(
                id,
                JsonRpcError::new(
                    POLICY_DENIED,
                    format!("{}: {}", rejection.code.as_str(), rejection.detail),
                )
                // The denial is itself evidence, and the client is told
                // exactly which packet records it — a refused agent can cite
                // its own refusal.
                .with_data(json!({
                    "rejectionCode": rejection.code.as_str(),
                    "detail": rejection.detail,
                    "evidencePacketId": sealed.packet["id"],
                    "evidencePacketHash": sealed.packet["packetHash"],
                })),
            )));
        }

        Handling::Forward(ForwardTicket {
            id: Some(id),
            request,
            action: ForwardAction::Governed {
                pending: Box::new(pending),
                tool_name,
                result_trust,
            },
        })
    }

    fn handle_resources_read(
        &mut self,
        session: &mut Session,
        request: JsonRpcRequest,
    ) -> Handling {
        let id = request.id.clone();
        if let Some(err) = self.require_initialized(session) {
            return match id {
                Some(id) => Handling::Respond(Box::new(JsonRpcResponse::error(id, err))),
                None => Handling::Silent,
            };
        }
        let Some(uri) = request.param_str("uri").map(str::to_string) else {
            return match id {
                Some(id) => Handling::Respond(Box::new(JsonRpcResponse::error(
                    id,
                    JsonRpcError::new(INVALID_PARAMS, "resources/read requires params.uri"),
                ))),
                None => Handling::Silent,
            };
        };
        let trust = self.policy.classify_resource(&uri);
        Handling::Forward(ForwardTicket {
            id,
            request,
            action: ForwardAction::RecordContext { uri, trust },
        })
    }

    fn guarded(
        &mut self,
        session: &Session,
        request: JsonRpcRequest,
        action: ForwardAction,
    ) -> Handling {
        let id = request.id.clone();
        if let Some(err) = self.require_initialized(session) {
            return match id {
                Some(id) => Handling::Respond(Box::new(JsonRpcResponse::error(id, err))),
                None => Handling::Silent,
            };
        }
        Handling::Forward(ForwardTicket {
            id,
            request,
            action,
        })
    }

    /// Attempts to establish the session's identity from the channel or from
    /// a signed challenge, if it is not established already.
    ///
    /// Failure is deliberately silent here. The authoritative refusal happens
    /// in the funnel, where it becomes a sealed `IDENTITY_UNVERIFIED` packet
    /// with a specific reason — so a failed authentication leaves evidence
    /// rather than an unlogged error, and an attacker probing credentials
    /// cannot tell from the transport whether a DID exists.
    fn try_authenticate(
        &mut self,
        session: &mut Session,
        request: &JsonRpcRequest,
        peer: &PeerCredential,
        now_utc: &str,
    ) {
        if session.is_authenticated() {
            return;
        }
        // The DID being claimed: from the handshake envelope on `initialize`,
        // from the session afterwards.
        let claimed = request
            .governance_meta()
            .get("agentDid")
            .and_then(Value::as_str)
            .unwrap_or(session.agent_did.as_str())
            .to_string();
        if claimed.is_empty() {
            return;
        }
        let proof = request
            .governance_meta()
            .get("identityProof")
            .cloned()
            .unwrap_or(Value::Null);
        // Nothing to work with at all: skip rather than burn the challenge.
        if proof.is_null() && matches!(peer, PeerCredential::None) {
            return;
        }
        if let Ok(binding) =
            self.attestor
                .verify(&claimed, peer, &proof, session.challenge(), now_utc)
        {
            // Only a *proven* binding establishes the session. An attestor
            // that returns `UNAUTHENTICATED` has not authenticated anything,
            // and treating that as success would defeat the point.
            if binding.is_proven() {
                session.agent_did = binding.agent_did.clone();
                session.establish(binding);
            }
        }
    }

    fn require_initialized(&self, session: &Session) -> Option<JsonRpcError> {
        if session.initialized {
            return None;
        }
        Some(JsonRpcError::new(
            INVALID_REQUEST,
            "initialize must complete before any other method",
        ))
    }

    /// Reduces an upstream catalogue to what the agent may actually invoke,
    /// annotating each survivor with its obligations.
    fn filter_catalogue(&self, session: &Session, mut result: Value, now_utc: &str) -> Value {
        // An unproven session is shown nothing. The catalogue names exactly
        // which capabilities an agent holds, which is reconnaissance worth
        // having before an attack — so it is gated on the same proof as
        // invocation, not merely on the session naming a DID. Without this, a
        // caller whose certificate the CA signed but nobody enrolled could
        // map the whole authority surface while being refused every call.
        let permitted = if self.funnel.requires_verified_identity() && !session.is_authenticated() {
            Vec::new()
        } else {
            self.funnel
                .permitted_tools(&session.agent_did, session.taint(), now_utc)
        };
        let Some(tools) = result.get_mut("tools").and_then(Value::as_array_mut) else {
            return result;
        };
        let mut kept: Vec<Value> = Vec::with_capacity(permitted.len());
        for mut tool in std::mem::take(tools) {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(entry) = permitted.iter().find(|p| p.name == name) else {
                continue;
            };
            tool["_meta"] = json!({
                "governance": {
                    "requiresSupervisorCoSignature": entry.requires_co_signature,
                    "minimumClearance": entry.minimum_clearance.as_str(),
                    "resultTrust": entry.result_trust.as_str(),
                }
            });
            kept.push(tool);
        }
        *tools = kept;
        result
    }

    /// Attaches the sealed packet's identity to a successful tool result, so
    /// a client can cite the evidence for an action it just took without
    /// having to query the ledger.
    fn annotate(result: &mut Value, packet: &Value) {
        if !result.is_object() {
            return;
        }
        result["_meta"] = json!({
            "governance": {
                "evidencePacketId": packet["id"],
                "evidencePacketHash": packet["packetHash"],
                "anchorHash": packet["anchorHash"],
                "sequenceNumber": packet["sequenceNumber"],
            }
        });
    }
}

/// Re-exported for callers building requests programmatically.
pub use ot_accountability_core::aip::AipRejectionCode;

/// The context a session has accumulated, as the shape written into a packet.
pub fn context_snapshot(session: &Session) -> Vec<ContextSource> {
    session.context().to_vec()
}
