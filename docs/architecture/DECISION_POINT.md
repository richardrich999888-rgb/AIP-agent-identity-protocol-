# DECISION_POINT

Status: **IMPLEMENTED as a library authority boundary (`aip-authorize`)** /
**NOT IMPLEMENTED: deployment as a separate process, service integration,
key-lifecycle management.**

Implemented under Skill 5 (`syntriass-decision-point`); see
`DECISION_POINT_IMPLEMENTATION_REPORT.md` for the change record. This document
is the authoritative description of what the decision point is, what it
signs, and what it explicitly does not mean.

---

## 1. Threat

Before this stage nothing in production decided anything before execution.
`POST /v1/evidence/generate` sealed caller-supplied tokens, decision text and
actions with a caller-supplied private key, and `POST /v1/evidence/verify`
accepted caller-supplied trust anchors. An agent could self-issue an admin
token, seal a packet exercising it, and have it verified `valid` at
`AUTHORITY_BOUND` by naming its own key as the trusted issuer
(CURRENT_SYSTEM §6). The agent was producer, signer and effective authorizer
of its own evidence — **I1** violated by construction.

Pinned by two characterization tests that pass against the unchanged code:
`weakness_packet_verifies_when_agent_is_its_own_root_issuer`
(`aip-protocol/tests/evidence_packet.rs`) and
`weakness_generate_then_verify_accepts_self_issued_authority`
(`aip-service/src/evidence.rs`). `verify_packet` is not wrong — it answers a
well-posed question about anchors it is given. The gap was the absence of an
independent *decision*.

## 2. Assumptions

| # | Assumption | Basis / limit |
|---|---|---|
| A1 | AIP authority semantics are correct: `expires_at` signed, encodings injective, domain-tagged (Skill 3). | `AIP_CORRECTNESS_REPORT.md`. The decision point *consumes* `verify_scoped_token`, `verify_delegation_chain`, `scope_permits`; it re-implements none of them. |
| A2 | `ExecutionBinding` identifies a process instance as defined in Stage 1, and is a self-report until observed. | `EXECUTION_BINDING.md`. The decision point checks the binding is well-formed and names the agent; it cannot check it is *true*. |
| A3 | The decision point's private key is held by a party the agent cannot read. | **Deployment assumption, not enforced by code.** The crate makes the agent-holds-key case *detectable* (§4) but cannot make it impossible. |
| A4 | The decision point's clock is honest for `issued_at`. | The decision point is the trusted party for its own timestamps, exactly as issuers are for token `issued_at`. No trusted time source exists (I21). |
| A5 | The operator's configured issuer keys are the right principals. | Same trust decision as `aip-verify --trust`; a mis-configured anchor is an operator error, not something the code can detect. |

## 3. Trust boundary

```text
PRINCIPAL ──signs ScopedToken──▶ (chain) ──▶ ORCHESTRATOR ──signs hop──▶ AGENT
                                                                          │
              AuthorizationRequest (no key material) ─────────────────────┘
                              │
                              ▼
┌─ DECISION POINT (aip-authorize) ── own Ed25519 key, operator-configured issuer anchors ─┐
│  consumes: verify_scoped_token · verify_delegation_chain · scope_permits (aip-core)      │
│  adds:     issuer trust · leaf == agent · binding well-formed · temporal adjudication    │
│  emits:    Authorized(ExpectedExecution signed by DP)  |  Denied(reason)                 │
└──────────────────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼  ExpectedExecution (decision_id, binding, action, params digest, window)
                            AGENT executes; later emits EvidencePacket with the same decision_id
                              │
                              ▼
                       VERIFIER: verify_expected_execution(ee, DecisionPointTrustAnchors)
                       (offline; distinguishes SignatureInvalid from UntrustedDecisionPoint)
```

What crosses the boundary **in**: agent id, signed tokens, requested action
and parameters, a binding claim, a requested TTL. What must never cross in: a
private key. `AuthorizationRequest` has no field that could carry one
(pinned by `request_type_carries_no_key_material`).

## 4. Authority

The decision point is an **independent signing authority** whose private key
is separate from the agent key, the observer key (Stage 3), the service API
keys and the service bundle-signing seed. Its authority is bounded:

- it can only *authorize what the AIP chain already permits* — it cannot widen
  scope, extend authority expiry, or bypass a missing issuer key;
- it can *refuse* anything;
- it cannot state that anything executed.

Self-authorization is refused at three points:

| Check | Where | Result |
|---|---|---|
| requesting `agent_id == decision_point.id` | `DecisionPoint::adjudicate` | `Denied(SelfAuthorization)` |
| `root_token.issuer_id == agent_id` (agent issued its own root) | `adjudicate` | `Denied(SelfIssuedAuthority)` — even if an operator trusts the agent key |
| `ee.decision_point_id == ee.agent_id` | `verify_expected_execution` | `Err(SelfAuthorization)` |
| anchor key for `decision_point_id` equals the agent's public key | `verify_expected_execution_for_agent` | `Err(DecisionKeyIsAgentKey)` |

Tests: `test_h_*` (three variants), `self_issued_root_authority_is_denied_even_if_the_agent_key_is_trusted`.

## 5. Input

```rust
pub struct AuthorizationRequest {
    pub agent_id: String,
    pub root_token: ScopedToken,             // principal-signed
    pub delegation_chain: Vec<DelegationToken>,
    pub action_kind: ScopeAction,
    pub parameters: ActionParameters,        // canonical, key-sorted, unique keys
    pub execution_binding: ExecutionBinding, // Stage 1; a claim to be checked
    pub requested_ttl_ms: u64,
}
```

## 6. Policy evaluation (in order; first failure denies)

| # | Check | Denial |
|---|---|---|
| 1 | `agent_id != decision_point.id`; `root_token.issuer_id != agent_id` | `SelfAuthorization`, `SelfIssuedAuthority` |
| 2 | root issuer has a **configured** key; `verify_scoped_token` passes | `UnknownIssuer`, `RootTokenSignatureInvalid` |
| 3 | `verify_delegation_chain` (aip-core: signatures, linkage, depth, scope attenuation, child ≤ parent expiry) | `UnknownIssuer` (hop key missing), `DelegationChainInvalid` |
| 4 | chain leaf grantee (or root `agent_id` when no chain) `== agent_id` | `ChainLeafNotAgent` |
| 5 | `scope_permits(effective_scope, action_kind)` | `ActionOutOfScope` |
| 6 | binding names `agent_id`; version 1; no zero pid/start/boot/exe hash | `BindingAgentMismatch`, `BindingMalformed` |
| 7 | temporal (§9) | `AuthorityNotYetValid`, `AuthorityExpired`, `InvalidTtl`, `TtlExceedsPolicy`, `TimeOverflow` |
| 8 | sign with the decision point's key | `SigningFailed` |

There is no risk score, no confidence, no `allowed: bool`. The outcome type is
`enum Decision { Authorized(Box<ExpectedExecution>), Denied(Denial) }`.

## 7. ExpectedExecution format

```rust
pub struct ExpectedExecution {
    pub version: u16,                       // EXPECTED_EXECUTION_VERSION = 1
    pub decision_id: [u8; 16],              // fresh per decision; THE join key
    pub decision_point_id: String,
    pub agent_id: String,
    pub authority: AuthorityRef,            // root_jti + chain_jtis (by identity, not by copy)
    pub action_kind: ScopeAction,
    pub parameter_digest: [u8; 32],         // SHA-256(ActionParameters::canonical_bytes)
    pub execution_binding: ExecutionBinding,
    pub issued_at: u64,                     // Unix ms, inclusive start
    pub valid_until: u64,                   // Unix ms, inclusive end; mandatory
    pub decision_sig: Signature,            // by the decision point
}
```

`decision_id` is reused as the correlation key (RECONCILIATION_MODEL §2); no
new correlation identifier was introduced. The agent must copy it into
`DecisionRecord.decision_id` in the packet it later produces.

`ActionParameters` is a `BTreeMap<String, Vec<u8>>` built through
`from_pairs`, which rejects duplicate keys. Same map, different insertion
order → same digest; any key/value difference → different digest; `("ab","c")`
vs `("a","bc")` differ (tests in `expected.rs`).

## 8. Signing preimage

```text
put_domain("GHOST/ExpectedExecution/v1")
put_u16(version)
decision_id                     16 bytes, fixed
put_str(decision_point_id)
put_str(agent_id)
authority.root_jti              16 bytes, fixed
put_u32(chain_jtis.len()) ‖ chain_jtis…   16 bytes each
encode_scope_action(action_kind)
parameter_digest                32 bytes, fixed
put_bytes(execution_binding.canonical_bytes())   (nested, itself domain-tagged)
put_u64(issued_at)
put_u64(valid_until)

decision_sig = sign_ed25519(dp_private_key, decision_point_id, preimage)
```

Every security-sensitive field is inside the preimage. Encoder:
`aip_types::canonical` (the single injective encoder from Skill 3). Domain
tag distinct from `AIP/ScopedToken/v1`, `AIP/DelegationToken/v1`,
`GHOST/ExecutionBinding/v1`, `GHOST/ExecutionIdentity/v1`,
`GHOST/ActionParameters/v1` (test `test_g_*`).

## 9. Temporal semantics

Adopted from the R10 contract established in Skill 3 — not newly invented:

| Question | Answer |
|---|---|
| Units | Unix milliseconds |
| Window | `[issued_at, valid_until]`, **inclusive at both ends** |
| Who supplies `T` at verification | the caller, explicitly (`temporal_status_at(t_ms)`); the crate never reads a clock to verify |
| Result type | `TemporalStatus::{NotYetValid, Valid, Expired}` — three states, not a bool |
| `issued_at` | the decision point's clock at adjudication (`authorize_at(req, now_ms)` makes it explicit and deterministic in tests) |
| `valid_until` | `now + requested_ttl_ms`, then **clamped to the authority chain's earliest `expires_at`** — an expectation never outlives the authority it rests on |
| Zero / missing | `requested_ttl_ms == 0` → `InvalidTtl`; `valid_until` is mandatory (no `None`) |
| Overflow | `checked_add` → `TimeOverflow` denial |
| `valid_until < issued_at` on a presented record | `InvalidWindow` (structural rejection) |
| Decision time vs authority | `now < any issued_at` → `AuthorityNotYetValid`; `now > earliest expires_at` → `AuthorityExpired`; `now == expires_at` is inside |
| Clock skew policy | **NOT DETERMINED** by the architecture; no tolerance is applied. Recorded as a limitation. |

Tests: `test_i_*` (three), `expectation_never_outlives_the_authority_chain`,
`ttl_policy_is_enforced`, `invalid_window_is_rejected_structurally`.

## 10. Key lifecycle

| Phase | Status |
|---|---|
| Generation | caller uses `aip_crypto::generate_ed25519_keypair` (or any Ed25519 source) and passes both halves to `DecisionPoint::new` |
| Provisioning to a separate process | **NOT IMPLEMENTED** — no binary, no service, no config loader |
| Storage / custody | **NOT IMPLEMENTED** — in-memory `Vec<u8>` for the life of the `DecisionPoint`; `Debug` redacts it |
| Rotation | **NOT IMPLEMENTED** — verifiers can anchor several ids; there is no key-version field in `ExpectedExecution` (see NEXORA_BOUNDARY / Skill 10 for versioning) |
| Revocation | **NOT IMPLEMENTED** — remove the anchor from `DecisionPointTrustAnchors` |
| Compromise / recovery | **NOT IMPLEMENTED** |

Nothing here is production key management. The single enforced property is
that the key enters through construction, never through a request.

## 11. Failure modes

Every failure yields `Decision::Denied(Denial { reason, detail })` with no
`ExpectedExecution` inside (test `a_denial_carries_no_expectation`). Signing
failure is a denial, not a partially populated record. Verification failures
are typed (`ExpectedVerifyError`) and distinguish *cryptographically invalid*
(`PayloadHashMismatch`, `SignatureInvalid`) from *not trusted*
(`UntrustedDecisionPoint`) from *structurally wrong* (`InvalidWindow`,
`BindingMalformed`, `SelfAuthorization`, …). Callers must not flatten these.

A denial says nothing about whether the agent executes anyway. That is a
question for observation and reconciliation.

## 12. Offline verification

```rust
verify_expected_execution(&ee, &DecisionPointTrustAnchors) -> Result<(), ExpectedVerifyError>
verify_expected_execution_for_agent(&ee, &anchors, agent_public_key)  // also rejects DecisionKeyIsAgentKey
```

Inputs: the record and the verifier's own anchor set (decision-point id →
public key). No network, no call back to the decision point. A JSON
round-trip followed by verification is tested
(`honest_request_is_authorized_and_verifies_offline`). Trust anchors are the
verifier's decision, exactly as issuer anchors are for `verify_packet`.

## 13. Relationship to AIP

The decision point **consumes** AIP: `verify_scoped_token`,
`verify_delegation_chain` (including the Skill 3 child-≤-parent expiry rule),
`scope_permits`, `random_jti`, `sign_ed25519`, the shared canonical encoder.
It adds no scope algebra, no token type, no second attenuation model (I18). A
tampered root token or hop is denied *because aip-core rejects it*
(`tampered_root_token_is_denied`, `tampered_delegation_hop_is_denied` — the
latter is the Skill 3 `expires_at` attack, now refused before execution as
well as at packet verification).

## 14. Relationship to ExecutionBinding

`ExpectedExecution.execution_binding` binds the authorization to one process
instance. `ExpectedExecution::covers(decision_id, agent_id, binding)` uses
`same_execution` (identity bytes: agent + pid + start + boot + exe hash), so
an expectation for one instance does not cover a PID-reused instance and
does cover a path-respelled one (`test_j_*`). The decision point checks the
binding is well-formed and names the agent; it does **not** and cannot check
the binding is true — that remains a self-report (A2).

## 15. Relationship to the Observer (Stage 3)

None yet, by design. The decision point never consumes an observation, and
an observer must never consume a decision to decide what it saw (I19). The
two will meet only in the reconciler. There is no `OBSERVED`,
`NOT_OBSERVED` or `OBSERVATION_UNAVAILABLE` concept in this crate.

## 16. Relationship to Reconciliation (Stage 4)

The reconciler will join `ExpectedExecution` (this stage), the agent's
`EvidencePacket` (with the same `decision_id` and a self-reported binding)
and `ObservedExecution` (Stage 3). `covers()` and `temporal_status_at()` are
the two pure predicates offered for that join; no result class is emitted
here. In particular this crate **never** produces `PHANTOM_CLAIM`: an
expectation with no matching observation is `CANNOT_PROVE` until an observer
with attested coverage of the window says otherwise (I8).

## 16a. Expected-side completeness (the coverage ledger)

The reconciler may name `UNATTRIBUTED_EFFECT` — an observed effect with no
expectation — only when the decision point signs that no expectation
*exists*, not merely that none was found. This crate produces that statement
(`DecisionPoint::coverage_statement`, `aip_authorize::coverage`) under four
rules:

1. **Derived, never supplied.** Every `ExpectedExecution` the decision point
   signs is appended to its own ledger (agent, decision id, validity
   window). A statement's decision list is computed from the ledger for the
   requested agent and window. A caller supplies only the agent, the window
   and the issue time; a producer that signed a caller's list would be a
   forgery oracle.
2. **Only what it can vouch for.** The ledger has a declared epoch
   (`with_coverage_ledger(since_ms)`); without one, no statement issues. A
   window starting before the epoch, or ending after the issue time, is
   refused (`WindowPrecedesLedger`, `WindowNotClosed`).
3. **Never falsified afterwards.** Once a statement is issued for an agent
   through `to_ms`, a later request to authorize that agent at or before
   `to_ms` is denied (`DenialReason::AttestedWindowClosed`). Closure is
   monotone per agent. The check, the signature and the ledger append happen
   under one guard, so a concurrent statement cannot