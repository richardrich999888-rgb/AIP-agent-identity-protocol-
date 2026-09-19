//! The decision point: adjudicates an [`AuthorizationRequest`] and, if and
//! only if every check passes, signs an [`ExpectedExecution`].
//!
//! Authority semantics are **consumed from `aip_core`**, not re-implemented:
//! `verify_scoped_token`, `verify_delegation_chain` (signatures, linkage,
//! depth, scope attenuation, child-not-outliving-parent) and `scope_permits`.
//! This module adds only what a decision point must add: a configured set of
//! trusted issuers, the leaf-is-the-agent check, temporal adjudication, the
//! binding check, and its own signature.

use std::collections::HashMap;
use std::sync::Mutex;

use aip_core::capability::{random_jti, scope_permits, verify_scoped_token};
use aip_core::delegation::verify_delegation_chain;
use aip_crypto::sign_ed25519;
use aip_types::{
    AipError, CoverageWindow, DelegationToken, ExecutionBinding, ScopeAction, ScopedToken,
    EXECUTION_BINDING_VERSION,
};

use crate::coverage::{
    CoverageIssueError, DecisionLedger, DecisionPointCoverageStatement, LedgerEntry,
    DECISION_POINT_COVERAGE_VERSION,
};
use crate::expected::{
    ActionParameters, AuthorityRef, ExpectedExecution, EXPECTED_EXECUTION_VERSION,
};
use crate::resource::{destination_of, ResourcePolicy};
use aip_registry::{granted_resources, Resolution};

// ─── Request ───

/// What an agent (or an orchestrator acting for it) submits to the decision
/// point. Deliberately contains **no key material**: the decision point
/// signs with its own key, the tokens carry their issuers' signatures, and
/// the binding is a claim to be checked, not a credential.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub agent_id: String,
    pub root_token: ScopedToken,
    pub delegation_chain: Vec<DelegationToken>,
    pub action_kind: ScopeAction,
    pub parameters: ActionParameters,
    pub execution_binding: ExecutionBinding,
    /// How long the caller asks the expectation to remain valid, in ms.
    /// Attenuated by policy and by the authority chain's own expiry.
    pub requested_ttl_ms: u64,
}

// ─── Outcome ───

/// The decision. Never a boolean: an authorization is a signed record, a
/// refusal is a reason.
#[derive(Debug, Clone)]
pub enum Decision {
    Authorized(Box<ExpectedExecution>),
    Denied(Denial),
}

impl Decision {
    /// The signed expectation, if the decision authorized.
    pub fn expected(&self) -> Option<&ExpectedExecution> {
        match self {
            Decision::Authorized(e) => Some(e.as_ref()),
            Decision::Denied(_) => None,
        }
    }

    pub fn denial(&self) -> Option<&Denial> {
        match self {
            Decision::Authorized(_) => None,
            Decision::Denied(d) => Some(d),
        }
    }
}

/// Why the decision point refused. A denial carries no `ExpectedExecution`
/// and says nothing about whether the agent will or did execute anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub reason: DenialReason,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialReason {
    /// The requesting agent is this decision point.
    SelfAuthorization,
    /// The root token was issued by the requesting agent itself.
    SelfIssuedAuthority,
    /// Root issuer or a chain issuer has no configured public key.
    UnknownIssuer,
    RootTokenSignatureInvalid,
    /// `verify_delegation_chain` rejected the chain (signature, linkage,
    /// depth, scope, or temporal attenuation).
    DelegationChainInvalid,
    /// The chain's leaf grantee (or the root token's agent) is not the
    /// requesting agent.
    ChainLeafNotAgent,
    /// The effective scope does not permit the requested action.
    ActionOutOfScope,
    /// Binding names a different agent.
    BindingAgentMismatch,
    /// Binding is degenerate (zero pid/start/boot/exe hash, wrong version).
    BindingMalformed,
    /// Some token in the chain is not yet issued at decision time.
    AuthorityNotYetValid,
    /// Some token in the chain has expired at decision time.
    AuthorityExpired,
    /// `requested_ttl_ms == 0`.
    InvalidTtl,
    /// `requested_ttl_ms` exceeds the decision point's `max_ttl_ms`.
    TtlExceedsPolicy,
    /// `now + ttl` overflowed.
    TimeOverflow,
    /// The decision point could not produce its signature.
    SigningFailed,
    /// The decision point has already signed a completeness statement for
    /// this agent covering the decision time; issuing now would falsify it.
    AttestedWindowClosed,
    /// The request names a network destination whose parameters cannot be
    /// read as one. Refused, not resolved permissively.
    DestinationMalformed,
    /// A resource policy is configured and the destination resolves to no
    /// resource the institution has named. Refused outright: an unnamed
    /// system is not a permitted one.
    DestinationUnregistered,
    /// The destination resolves to a named resource that the effective scope
    /// does not grant (`res:<id>` absent from `allowed`, or present in
    /// `denied` anywhere in the chain).
    ResourceNotGranted,
}

// ─── Decision point ───

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionPointError {
    EmptyId,
    InvalidPrivateKeyLength(usize),
    InvalidPublicKeyLength(usize),
    ZeroMaxTtl,
}

/// An independent signing authority. Constructed by its operator; the
/// private key never enters through a request.
///
/// Every expectation it signs is also recorded in its own
/// [`DecisionLedger`], from which it can later state — and sign — the
/// complete set of decisions for an agent over a window
/// ([`DecisionPoint::coverage_statement`]). The ledger is behind a mutex so
/// adjudication keeps `&self`; the guarded section is one check, one
/// signature and one append.
pub struct DecisionPoint {
    id: String,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    issuer_keys: HashMap<String, Vec<u8>>,
    max_ttl_ms: u64,
    ledger: Mutex<DecisionLedger>,
    /// The institution's verified resource registry, when configured. With
    /// it, every network destination must resolve to a resource the
    /// effective scope grants. Without it, no resource check is performed —
    /// visible through [`DecisionPoint::resource_policy`].
    resource_policy: Option<ResourcePolicy>,
}

impl std::fmt::Debug for DecisionPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionPoint")
            .field("id", &self.id)
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .field("issuer_keys", &self.issuer_keys.keys().collect::<Vec<_>>())
            .field("max_ttl_ms", &self.max_ttl_ms)
            .field("ledger_since_ms", &self.coverage_ledger_since())
            .field(
                "resource_policy",
                &self
                    .resource_policy
                    .as_ref()
                    .map(|p| p.registry().citation()),
            )
            .finish()
    }
}

impl DecisionPoint {
    /// Create a decision point with its own Ed25519 key pair and a policy
    /// ceiling on expectation lifetime. Trusted issuers are added with
    /// [`DecisionPoint::trust_issuer`].
    pub fn new(
        id: impl Into<String>,
        private_key: &[u8],
        public_key: &[u8],
        max_ttl_ms: u64,
    ) -> Result<Self, DecisionPointError> {
        let id = id.into();
        if id.is_empty() {
            return Err(DecisionPointError::EmptyId);
        }
        if private_key.len() != 32 {
            return Err(DecisionPointError::InvalidPrivateKeyLength(
                private_key.len(),
            ));
        }
        if public_key.len() != 32 {
            return Err(DecisionPointError::InvalidPublicKeyLength(public_key.len()));
        }
        if max_ttl_ms == 0 {
            return Err(DecisionPointError::ZeroMaxTtl);
        }
        Ok(Self {
            id,
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            issuer_keys: HashMap::new(),
            max_ttl_ms,
            ledger: Mutex::new(DecisionLedger::default()),
            resource_policy: None,
        })
    }

    /// Adopt the institution's verified resource registry as policy. From
    /// then on a request naming a network destination is authorized only if
    /// the destination resolves to a registered resource that the effective
    /// scope grants (`res:<id>`). See [`crate::resource`].
    pub fn with_resource_policy(mut self, policy: ResourcePolicy) -> Self {
        self.resource_policy = Some(policy);
        self
    }

    /// The configured resource policy, if any. `None` means network
    /// destinations are not resource-checked by this decision point.
    pub fn resource_policy(&self) -> Option<&ResourcePolicy> {
        self.resource_policy.as_ref()
    }

    /// Declare from which instant this decision point vouches for the
    /// completeness of its own ledger. Without this, no
    /// [`DecisionPoint::coverage_statement`] can be issued. `since_ms` must
    /// be no earlier than this process began recording — see the restart
    /// caveat on [`DecisionLedger`].
    pub fn with_coverage_ledger(self, since_ms: u64) -> Self {
        self.ledger().enable(since_ms);
        self
    }

    /// The declared ledger epoch, if any.
    pub fn coverage_ledger_since(&self) -> Option<u64> {
        self.ledger().since_ms()
    }

    /// How many expectations this decision point has signed since it was
    /// constructed.
    pub fn issued_count(&self) -> usize {
        self.ledger().len()
    }

    /// Sign a statement of every decision this point issued for `agent_id`
    /// whose validity intersects `window`. The list is derived from the
    /// ledger, never taken from the caller. Refuses a window that starts
    /// before the ledger epoch or ends after `issued_at_ms`. Once issued, a
    /// later decision for `agent_id` at or before `window.to_ms` is denied
    /// ([`DenialReason::AttestedWindowClosed`]) so the statement stays true.
    pub fn coverage_statement(
        &self,
        agent_id: &str,
        window: CoverageWindow,
        issued_at_ms: u64,
    ) -> Result<DecisionPointCoverageStatement, CoverageIssueError> {
        if agent_id.is_empty() {
            return Err(CoverageIssueError::EmptyAgentId);
        }
        if !window.is_well_formed() {
            return Err(CoverageIssueError::InvalidWindow);
        }
        if window.to_ms > issued_at_ms {
            return Err(CoverageIssueError::WindowNotClosed { issued_at_ms });
        }
        let mut ledger = self.ledger();
        let since_ms = ledger
            .since_ms()
            .ok_or(CoverageIssueError::LedgerNotEnabled)?;
        if window.from_ms < since_ms {
            return Err(CoverageIssueError::WindowPrecedesLedger { since_ms });
        }
        let decision_ids = ledger.decisions_for(agent_id, &window);
        // Close before signing: a signing failure leaves the window closed,
        // which over-refuses rather than lets a later decision slip in
        // under a statement that may have been emitted.
        ledger.close(agent_id, window.to_ms);
        let mut stmt = DecisionPointCoverageStatement {
            version: DECISION_POINT_COVERAGE_VERSION,
            decision_point_id: self.id.clone(),
            agent_id: agent_id.to_string(),
            window,
            decision_ids,
            issued_at_ms,
            signature: placeholder_signature(&self.id),
        };
        stmt.signature = sign_ed25519(&self.private_key, &self.id, &stmt.signing_preimage())
            .map_err(|e| CoverageIssueError::SigningFailed(e.to_string()))?;
        Ok(stmt)
    }

    /// The ledger guard. A poisoned lock is recovered: every guarded
    /// mutation is a single `Vec::push`, `HashMap` insert or field write, so
    /// a panic while holding the lock cannot leave the ledger half-updated.
    fn ledger(&self) -> std::sync::MutexGuard<'_, DecisionLedger> {
        self.ledger.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a trusted issuer (principal or intermediary) public key.
    /// This is operator configuration — the analogue of `aip-verify --trust`
    /// — never request data.
    pub fn trust_issuer(mut self, aip_id: &str, public_key: &[u8]) -> Self {
        self.issuer_keys
            .insert(aip_id.to_string(), public_key.to_vec());
        self
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn max_ttl_ms(&self) -> u64 {
        self.max_ttl_ms
    }

    /// Adjudicate at the current system time.
    pub fn authorize(&self, req: &AuthorizationRequest) -> Decision {
        self.authorize_at(req, now_ms())
    }

    /// Adjudicate at an explicit decision time `now_ms`. Deterministic.
    pub fn authorize_at(&self, req: &AuthorizationRequest, now_ms: u64) -> Decision {
        match self.adjudicate(req, now_ms) {
            Ok(ee) => Decision::Authorized(Box::new(ee)),
            Err(d) => Decision::Denied(d),
        }
    }

    fn adjudicate(
        &self,
        req: &AuthorizationRequest,
        now_ms: u64,
    ) -> Result<ExpectedExecution, Denial> {
        let deny = |reason: DenialReason, detail: String| Denial { reason, detail };

        // 1. The decision point is not the agent, and the agent did not
        //    issue its own root authority (I1).
        if req.agent_id == self.id {
            return Err(deny(
                DenialReason::SelfAuthorization,
                "requesting agent is this decision point".into(),
            ));
        }
        if req.root_token.issuer_id == req.agent_id {
            return Err(deny(
                DenialReason::SelfIssuedAuthority,
                "root token issuer is the requesting agent".into(),
            ));
        }

        // 2. Root token: issuer must be configured, signature must verify.
        let root = &req.root_token;
        let root_key = self.issuer_keys.get(&root.issuer_id).ok_or_else(|| {
            deny(
                DenialReason::UnknownIssuer,
                format!("no trusted key for root issuer {}", root.issuer_id),
            )
        })?;
        match verify_scoped_token(root, root_key) {
            Ok(true) => {}
            Ok(false) => {
                return Err(deny(
                    DenialReason::RootTokenSignatureInvalid,
                    "root token signature does not verify".into(),
                ))
            }
            Err(e) => {
                return Err(deny(
                    DenialReason::RootTokenSignatureInvalid,
                    format!("root token verification error: {e}"),
                ))
            }
        }

        // 3. Delegation chain: aip_core owns the semantics.
        let effective_scope =
            verify_delegation_chain(root, &req.delegation_chain, &self.issuer_keys).map_err(
                |e| match e {
                    AipError::InvalidPublicKey => deny(
                        DenialReason::UnknownIssuer,
                        "a delegation hop issuer has no trusted key".into(),
                    ),
                    other => deny(
                        DenialReason::DelegationChainInvalid,
                        format!("delegation chain rejected: {other}"),
                    ),
                },
            )?;

        // 4. The chain must end at the requesting agent.
        let leaf = req
            .delegation_chain
            .last()
            .map(|h| h.grantee_id.as_str())
            .unwrap_or(root.agent_id.as_str());
        if leaf != req.agent_id {
            return Err(deny(
                DenialReason::ChainLeafNotAgent,
                format!(
                    "authority chain ends at {leaf}, request is for {}",
                    req.agent_id
                ),
            ));
        }

        // 5. Scope.
        if !scope_permits(&effective_scope, &req.action_kind) {
            return Err(deny(
                DenialReason::ActionOutOfScope,
                format!("{:?} not permitted by effective scope", req.action_kind),
            ));
        }

        // 5b. Resource authority. The destination is read from the same
        //     parameter bytes the expectation will sign; it is resolved
        //     against the institution's verified registry; and it must be
        //     granted by the effective (most attenuated) scope. Each failure
        //     is a denial: an unparseable destination is not resolved
        //     permissively, an unnamed system is not a permitted one, and a
        //     name the chain never granted is not reachable.
        if let Some(policy) = &self.resource_policy {
            match destination_of(&req.parameters) {
                Err(e) => {
                    return Err(deny(
                        DenialReason::DestinationMalformed,
                        format!("network destination unreadable: {e}"),
                    ))
                }
                Ok(None) => {}
                Ok(Some(dest)) => {
                    match policy.registry().resolve(
                        dest.protocol,
                        dest.is_v6,
                        &dest.addr,
                        dest.port,
                    ) {
                        Resolution::Unregistered => {
                            let (rid, rev) = policy.registry().citation();
                            return Err(deny(
                                DenialReason::DestinationUnregistered,
                                format!(
                                    "destination port {} is not a resource named in registry {rid} revision {rev}",
                                    dest.port
                                ),
                            ));
                        }
                        Resolution::Resource(entry) => {
                            if !granted_resources(&effective_scope).contains(&entry.id) {
                                return Err(deny(
                                    DenialReason::ResourceNotGranted,
                                    format!(
                                        "resource {} ({}) is not granted by the effective scope",
                                        entry.id, entry.display_name
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }

        // 6. Binding: names this agent and is not degenerate.
        let b = &req.execution_binding;
        if b.agent_id != req.agent_id {
            return Err(deny(
                DenialReason::BindingAgentMismatch,
                format!(
                    "binding is for {}, request is for {}",
                    b.agent_id, req.agent_id
                ),
            ));
        }
        if b.version != EXECUTION_BINDING_VERSION
            || b.process.pid == 0
            || b.process.pid_start_time_ticks == 0
            || b.process.boot_id == [0u8; 16]
            || b.exe_content_sha256 == [0u8; 32]
        {
            return Err(deny(
                DenialReason::BindingMalformed,
                "execution binding has a degenerate identity field".into(),
            ));
        }

        // 7. Temporal adjudication at `now_ms`.
        let mut authority_expiry: Option<u64> = root.expires_at;
        if now_ms < root.issued_at {
            return Err(deny(
                DenialReason::AuthorityNotYetValid,
                "root token issued after decision time".into(),
            ));
        }
        for hop in &req.delegation_chain {
            if now_ms < hop.issued_at {
                return Err(deny(
                    DenialReason::AuthorityNotYetValid,
                    "a delegation hop is issued after decision time".into(),
                ));
            }
            authority_expiry = match (authority_expiry, hop.expires_at) {
                (Some(a), Some(h)) => Some(a.min(h)),
                (None, h) => h,
                (a, None) => a,
            };
        }
        if let Some(exp) = authority_expiry {
            if now_ms > exp {
                return Err(deny(
                    DenialReason::AuthorityExpired,
                    format!("authority chain expired at {exp}, decision time {now_ms}"),
                ));
            }
        }
        if req.requested_ttl_ms == 0 {
            return Err(deny(DenialReason::InvalidTtl, "requested ttl is 0".into()));
        }
        if req.requested_ttl_ms > self.max_ttl_ms {
            return Err(deny(
                DenialReason::TtlExceedsPolicy,
                format!(
                    "requested ttl {} exceeds policy max {}",
                    req.requested_ttl_ms, self.max_ttl_ms
                ),
            ));
        }
        let mut valid_until = now_ms
            .checked_add(req.requested_ttl_ms)
            .ok_or_else(|| deny(DenialReason::TimeOverflow, "now + ttl overflows u64".into()))?;
        // An expectation never outlives the authority it rests on.
        if let Some(exp) = authority_expiry {
            valid_until = valid_until.min(exp);
        }

        // 8. Sign and record, under one ledger guard: the closed-window
        //    check, the signature and the append are atomic with respect to
        //    a concurrent `coverage_statement`, so a statement can never
        //    miss a decision issued while it was being computed.
        let mut ledger = self.ledger();
        if let Some(closed) = ledger.closed_at(&req.agent_id, now_ms) {
            return Err(deny(
                DenialReason::AttestedWindowClosed,
                format!("completeness already attested for this agent through {closed}, decision time {now_ms}"),
            ));
        }
        let mut ee = ExpectedExecution {
            version: EXPECTED_EXECUTION_VERSION,
            decision_id: random_jti(),
            decision_point_id: self.id.clone(),
            agent_id: req.agent_id.clone(),
            authority: AuthorityRef {
                root_jti: root.jti,
                chain_jtis: req.delegation_chain.iter().map(|h| h.jti).collect(),
            },
            action_kind: req.action_kind.clone(),
            parameter_digest: req.parameters.digest(),
            execution_binding: req.execution_binding.clone(),
            issued_at: now_ms,
            valid_until,
            decision_sig: placeholder_signature(&self.id),
        };
        let preimage = ee.signing_preimage();
        ee.decision_sig = sign_ed25519(&self.private_key, &self.id, &preimage)
            .map_err(|e| deny(DenialReason::SigningFailed, format!("signing failed: {e}")))?;
        ledger.record(LedgerEntry {
            agent_id: ee.agent_id.clone(),
            decision_id: ee.decision_id,
            validity: CoverageWindow {
                from_ms: ee.issued_at,
                to_ms: ee.valid_until,
            },
        });
        Ok(ee)
    }
}

/// A structurally valid but meaningless signature used only while the
/// preimage is being assembled; it is always replaced before return.
fn placeholder_signature(signer_id: &str) -> aip_types::Signature {
    aip_types::Signature {
        algorithm: aip_types::AlgorithmId::Ed25519,
        signer_id: signer_id.to_string(),
        timestamp: 0,
        nonce: [0u8; 16],
        payload_hash: [0u8; 32],
        signature_bytes: vec![],
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
