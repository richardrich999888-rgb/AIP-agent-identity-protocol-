# DECISION POINT IMPLEMENTATION REPORT

Skill 5 (`syntriass-decision-point`) / Orchestrator Stage 2.

## Status

**PASS** under Skill 5 §35, with the deployment, service-integration and
key-lifecycle items explicitly recorded as NOT IMPLEMENTED below. Nothing in
this stage claims that an execution occurred or was observed.

## Baseline

- Predecessors: Skill 3 PASS (`AIP_CORRECTNESS_REPORT.md`, `f78a599`);
  Skill 4 PASS (`EXECUTION_BINDING_IMPLEMENTATION_REPORT.md`, `f93f4bd`).
  Both treated as evidence only for what they state; every limitation they
  list is preserved (self-reported binding, no trusted time, caller-supplied
  anchors, plaintext key persistence, service duplicate model).
- Start of Stage 2: HEAD `f93f4bd`, working tree clean.
- Test baseline at start: aip-standalone 278 / 0 / 3 ignored; aip-service 38.
- Hard-stop checklist (Skill 5 §3): all clear. Temporal policy was resolved
  by adopting the R10 contract from Skill 3 (inclusive window, explicit `T`,
  Unix ms) rather than inventing one; the one undetermined item — clock-skew
  tolerance — is recorded as a limitation, not silently chosen.

## Repository state (decision semantics before this stage)

| Where | Finding |
|---|---|
| `aip-service/src/evidence.rs::generate_packet` | seals caller-supplied root token, chain, decision text, actions **and the agent's private key**; verifies nothing; `DecisionRecord` is produced after the fact by the acting party |
| `aip-service/src/evidence.rs::verify_request` | caller-supplied trust anchors → calculator, not an authority (documented in Skill 3) |
| `aip-protocol::verify_packet` | correct given anchors; has no rule that could require an independent decision |
| `aip-verify` | operator-supplied anchors; the correct verifier boundary; no decision either |
| `aip-core` | pure predicates (`is_scope_subset`, `scope_permits`, `verify_delegation_chain`) with **no invocation site that gates execution** |
| repository-wide | 0 occurrences of `ExpectedExecution`, `DecisionPoint`, `decision_point` in production code |

## Existing weakness demonstrated first (Skill 5 §24 spirit, user rule 4)

Two characterization tests pass against the unchanged code and pin the closed
loop:

| Test | What it shows |
|---|---|
| `weakness_packet_verifies_when_agent_is_its_own_root_issuer` (`aip-protocol/tests/evidence_packet.rs`) | agent self-issues an ADMIN token to itself, seals an ADMIN action, caller anchors the agent's own key → `valid = true`, `AUTHORITY_BOUND`, `authority_chain_verified = true`; no rule in the report can express "was an independent party involved?" |
| `weakness_generate_then_verify_accepts_self_issued_authority` (`aip-service/src/evidence.rs`) | the HTTP generate path seals the same self-issued authority; `verify_request` accepts it with the agent's key as `trusted_issuers` |

These are **not** defects in `verify_packet`/`verify_request` and are not
changed by this stage. They stay in the tree so the boundary the decision
point adds remains visible.

## Architecture decision

```text
DECISION:      Independent decision point as a library authority boundary (aip-authorize),
               constructed with its own key; agent-facing request carries no key material.
THREAT:        agent is producer, signer and effective authorizer of its own evidence (I1).
ASSUMPTION:    the DecisionPoint value lives in a process the agent cannot read (deployment).
MECHANISM:     consume aip-core authority checks; add issuer anchors, leaf==agent, binding,
               temporal adjudication; sign ExpectedExecution under GHOST/ExpectedExecution/v1.
IMPLEMENTATION: aip-standalone/aip-authorize/{lib,expected,decision}.rs
TEST:          35 tests (32 adversarial/integration + 3 unit) — see below.
LIMITATION:    deployment boundary, service integration, key lifecycle not implemented;
               binding remains a self-report; no clock-skew policy.
DEPENDENCIES:  Stage 0, Stage 1.
STATUS:        library IMPLEMENTED; process boundary DESIGN ONLY.
```

**Deployment boundary.** Not placed in `aip-service`: that process handles
`agent_seed_hex`-bearing requests, so co-locating the decision key would make
"agent compromise ≠ decision-key compromise" false by construction (Skill 5
§16). IMPLEMENTATION_PLAN §2.2 (require a verified `ExpectedExecution` in
`GenerateRequest`) is a breaking API change and is deferred to a versioned
endpoint. The interface is documented in `DECISION_POINT.md` §18 without
pretending the boundary exists.

## Files inspected

`docs/architecture/{SECURITY_INVARIANTS, CURRENT_SYSTEM, TARGET_ARCHITECTURE,
RECONCILIATION_MODEL, OBSERVATION_MODEL, EXECUTION_BINDING, GAP_MATRIX,
IMPLEMENTATION_PLAN, TRUST_BOUNDARIES, CRYPTOGRAPHIC_BOUNDARIES,
AIP_CORRECTNESS_REPORT, EXECUTION_BINDING_IMPLEMENTATION_REPORT}.md`;
`aip-core/src/{capability,delegation,execution_binding}.rs`;
`aip-crypto/src/lib.rs`; `aip-types/src/{lib,canonical}.rs`;
`aip-protocol/src/{evidence_packet,verification,verification_report}.rs`;
`aip-service/src/{evidence,test_support,keys}.rs`; `aip-verify/src/main.rs`;
`.github/workflows/ci.yml`; `aip-standalone/Cargo.toml`.

## Files changed

| File | Change |
|---|---|
| `aip-standalone/Cargo.toml` | workspace member `aip-authorize` |
| `aip-standalone/Cargo.lock` | new crate (no new external dependencies) |
| `aip-standalone/aip-authorize/Cargo.toml` | **new** |
| `aip-standalone/aip-authorize/src/lib.rs` | **new** — crate doc (what it is / is not), re-exports |
| `aip-standalone/aip-authorize/src/expected.rs` | **new** — `ExpectedExecution`, `AuthorityRef`, `ActionParameters`, preimage, `TemporalStatus`, `DecisionPointTrustAnchors`, `verify_expected_execution[_for_agent]`, `ExpectedVerifyError`; 3 unit tests |
| `aip-standalone/aip-authorize/src/decision.rs` | **new** — `AuthorizationRequest`, `Decision`, `Denial`, `DenialReason`, `DecisionPoint` (redacting `Debug`), `authorize_at` |
| `aip-standalone/aip-authorize/tests/adversarial.rs` | **new** — 32 tests |
| `aip-standalone/aip-protocol/tests/evidence_packet.rs` | +1 characterization test |
| `aip-service/src/evidence.rs` | +1 characterization test (tests module only) |
| `docs/architecture/DECISION_POINT.md` | **new** — 17 required items + deployment boundary |
| `docs/architecture/DECISION_POINT_IMPLEMENTATION_REPORT.md` | this report |
| `docs/architecture/GAP_MATRIX.md` | status of rows "Authorization decision point", "ExpectedExecution" |

No production code outside the new crate was modified. No observer,
reconciliation, warrant, containment, NEXORA or PQC code exists.

## Data model

See `DECISION_POINT.md` §5 (request), §7 (`ExpectedExecution`). Summary:

- `Decision = Authorized(Box<ExpectedExecution>) | Denied(Denial)`. No
  boolean, no score, no caller-settable `trusted`/`verified`/`authorized`
  flag anywhere in the crate's public types.
- `Denial { reason: DenialReason (15 variants), detail }`.
- `ExpectedVerifyError` (11 variants) separates cryptographic failure,
  trust failure and structural failure.
- `TemporalStatus = NotYetValid | Valid | Expired`.

## Canonical encoding and signature preimage

`DECISION_POINT.md` §8. Shared encoder `aip_types::canonical`; domain tag
first; fixed-width fields raw; variable-length fields length-prefixed;
nested binding wrapped in `put_bytes`; parameters digested from a
key-sorted, duplicate-rejecting map under `GHOST/ActionParameters/v1`.

## Domain separation

`GHOST/ExpectedExecution/v1` and `GHOST/ActionParameters/v1`, distinct from
all Stage 0/1 tags. `test_g_expected_execution_signature_cannot_verify_as_scoped_token`
transplants a genuine decision signature onto a field-mirroring
`ScopedToken` and shows `verify_scoped_token` rejects it.

## Temporal semantics

`DECISION_POINT.md` §9. Inclusive `[issued_at, valid_until]`; explicit `T`;
`valid_until` clamped to the earliest authority `expires_at`; decision at
exactly the authority expiry is inside; `+1` is `AuthorityExpired`;
`requested_ttl_ms` bounded by `max_ttl_ms` and `checked_add`.

## Trust anchor

`DecisionPointTrustAnchors` (decision-point id → public key), supplied by the
verifier. `UntrustedDecisionPoint` is reported separately from
`SignatureInvalid` so a valid signature from an unanchored signer is never
mistaken for trust (Skill 5 §29).

## Key lifecycle

`DECISION_POINT.md` §10. Only construction-time injection is implemented;
provisioning, custody, rotation, revocation, compromise handling are **NOT
IMPLEMENTED**.

## Adversarial tests (`aip-authorize/tests/adversarial.rs`)

| Skill 5 §24 | Test | Rejection |
|---|---|---|
| A expiry mutation | `test_a_valid_until_mutation_rejected` (extend to `u64::MAX`, +1) | `PayloadHashMismatch` |
| B issued_at | `test_b_issued_at_mutation_rejected` | `PayloadHashMismatch` |
| C action | `test_c_action_kind_mutation_rejected` (Standard→Admin, Standard→Custom) | `PayloadHashMismatch` |
| D parameters | `test_d_parameter_digest_mutation_rejected` (+ digest of altered params differs) | `PayloadHashMismatch` |
| E binding | `test_e_execution_binding_mutation_rejected` (start ticks, boot id, exe hash, path) | `PayloadHashMismatch` |
| F decision id | `test_f_decision_id_and_authority_mutation_rejected` (decision_id, root_jti, chain_jtis); `version_mutation_is_rejected_structurally` | `PayloadHashMismatch` / `UnsupportedVersion` |
| G domain | `test_g_expected_execution_signature_cannot_verify_as_scoped_token` | `verify_scoped_token == false`; tags pairwise distinct |
| H agent key | `test_h_agent_running_its_own_decision_point_is_denied` → `Denied(SelfAuthorization)`; `test_h_agent_key_under_a_fake_decision_point_id_is_not_trusted` → `UntrustedDecisionPoint`, and with a tricked anchor `DecisionKeyIsAgentKey`; `test_h_handcrafted_expectation_naming_agent_as_decision_point_rejected` → `SelfAuthorization` | as listed |
| I temporal | `test_i_window_is_inclusive_at_both_ends`, `test_i_decision_after_authority_expiry_is_denied` (boundary accepted, +1 denied), `test_i_decision_before_authority_issuance_is_denied` | `TemporalStatus`, `AuthorityExpired`, `AuthorityNotYetValid` |
| J transplantation | `test_j_expectation_covers_only_its_own_decision_and_execution` (other decision id, other agent, PID-reused instance, respelled path, transplanted decision id) | `covers == false` / `PayloadHashMismatch` |

Additional denials and properties: `unknown_root_issuer_is_denied`,
`unknown_hop_issuer_is_denied`,
`self_issued_root_authority_is_denied_even_if_the_agent_key_is_trusted`
(the CURRENT_SYSTEM §6 loop, refused), `tampered_root_token_is_denied`,
`tampered_delegation_hop_is_denied` (the Skill 3 `expires_at` attack, refused
pre-execution), `out_of_scope_action_is_denied`,
`chain_leaf_must_be_the_requesting_agent`,
`binding_for_another_agent_or_degenerate_binding_is_denied`,
`a_denial_carries_no_expectation`, `ttl_policy_is_enforced`,
`expectation_never_outlives_the_authority_chain`,
`invalid_window_is_rejected_structurally`,
`wrong_anchor_key_or_signer_id_is_rejected_distinctly`,
`each_decision_gets_a_fresh_decision_id`,
`decision_point_constructor_rejects_bad_material` (incl. `Debug` redaction),
`request_type_carries_no_key_material`,
`honest_request_is_authorized_and_verifies_offline` (JSON round-trip).

Unit tests (`expected.rs`): parameter order-independence and content
sensitivity incl. `("ab","c")`/`("a","bc")`, duplicate key → error, domain
tag leads encoding.

## Integration tests

- The decision point consumes real `aip-core` tokens and chains built by the
  same constructors the packet fixtures use; a hop with a forged expiry is
  denied by `verify_delegation_chain` inside the decision point
  (`tampered_delegation_hop_is_denied`).
- `covers()` is exercised against Stage 1 binding semantics (PID reuse vs
  path respelling).
- Service and packet characterization tests pin the pre-existing loop.
- No packet/service code path was wired to the decision point (deferred, see
  Remaining dependencies).

## Test results

| Suite | Before Stage 2 | After |
|---|---|---|
| aip-authorize (new) | — | **35** (3 unit + 32 adversarial) |
| aip-protocol tests/evidence_packet.rs | 35 | **36** (+1 characterization) |
| aip-core / aip-crypto / aip-types / aip-protocol unit / bundle / aip-test / aip-real-tests | 140 / 8 / 5 / 4 / 6 (1 ign) / 13 / 67 (2 ign) | unchanged |
| **aip-standalone total** | 278 / 0 / 3 | **314 / 0 / 3** |
| aip-service | 38 | **39** (+1 characterization) |

`cargo clippy --workspace --all-targets -- -D warnings` and
`cargo fmt --all -- --check`: clean in both workspaces. `cargo deny` is not
installed in this environment; the new crate adds no external dependency, so
the CI deny check has nothing new to evaluate.

## CANNOT_PROVE cases (what this stage cannot and does not assert)

| Situation | What the decision point / verifier can say | What remains `CANNOT_PROVE` |
|---|---|---|
| `Authorized(ee)` issued | the decision point signed an expectation | whether the process ran, whether the action happened, whether the parameters were used |
| `Denied(reason)` | the decision point refused | whether the agent executed anyway |
| `verify_expected_execution == Ok` | a trusted decision point signed exactly this record | anything about execution or observation |
| `ExpectedExecution` present, no observation | — | non-execution (never `PHANTOM_CLAIM` from this layer; I8) |
| Observation present, no `ExpectedExecution` | — | authorization (an observed action is not thereby authorized) |
| Binding well-formed and names the agent | the claim is consistent | that the binding is true (self-report; Stage 3) |
| `TemporalStatus::Valid` at `T` | `T` is inside the signed window | that `T` is the true time of anything (no trusted time, I21) |
| Anchor for `decision_point_id` present | the verifier trusts that key | that the key is actually held outside the agent's process (deployment) |

## Known limitations

1. **Deployment boundary is a design statement.** The crate cannot prove the
   `DecisionPoint` runs where the agent cannot read its key; it can only
   refuse the detectable self-authorization shapes.
2. **Not wired into `aip-service`.** `generate_packet` still seals
   unverified claims; the characterization test keeps that visible.
3. **Key lifecycle NOT IMPLEMENTED** (provisioning, custody, rotation,
   revocation, compromise).
4. **No clock-skew tolerance** — undetermined by the architecture.
5. **Binding is a self-report** (inherited from Stage 1).
6. **Issuer directory is static configuration**; no discovery, no revocation
   feed (packet-level revocation remains R9's job).
7. **`ExpectedExecution` is not embedded in `EvidencePacket`**; the link is
   `decision_id` equality, which the agent controls. Only reconciliation
   with an independent observation can make that link meaningful.

## Prohibited security claims after this stage

Do not claim: that any execution occurred or was observed; that an
`Authorized` decision proves the agent acted; that a `Denied` decision proves
the agent refrained; that a verified `ExpectedExecution` implies the
decision point is independently deployed; that the binding inside it is
true; process attribution; reconciliation results of any class; warrants;
containment; NEXORA commitments; post-quantum security; trusted time.

Correct statement: *the decision point is an independent signing authority
whose private key is outside the agent's control, subject to the documented
deployment and key-custody assumptions; an `ExpectedExecution` proves only
that the designated decision point signed an authorization expectation, and
execution requires independent observation and reconciliation.*

## Remaining dependencies

- **Stage 3 — Observer attestation** (`syntriass-observer-attestation`):
  produces `ObservedExecution` with an independent key; must never consume
  `ExpectedExecution` to decide what it saw.
- **Stage 4 — Reconciliation**: joins `ExpectedExecution` + packet +
  `ObservedExecution` on `decision_id` and `identity_bytes`, using `covers()`
  and `temporal_status_at()`; `CANNOT_PROVE` default.
- **Service integration** (IMPLEMENTATION_PLAN §2.2): versioned endpoint
  requiring a verified `ExpectedExecution`; removal of `agent_seed_hex`.
- **Key lifecycle / deployment topology**: architecture decision pending.

## Gate decision

Skill 5 completion criteria (§35) are met as evidenced above. Ready for
**SKILL 6 — OBSERVER ATTESTATION**, subject to explicit authorization.
