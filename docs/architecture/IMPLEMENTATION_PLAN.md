# IMPLEMENTATION_PLAN

Exact file-level sequence from the AIP repository at `377d5fc` to a **minimum
viable Ghost detection vertical slice**.

**Nothing in this document was implemented during the discovery run.**

## 0. What the first target is, and is not

**Target:** prove *one* execution end-to-end, cryptographically, with a
**synthetic observer** — an observer whose signing key the agent provably does
not hold, but which observes a simulated process rather than the kernel.

**Not the target:** eBPF, XDP, containment, NEXORA, PQC, performance.

**Why a synthetic observer first.** The hard part of Ghost is not reading the
kernel; it is the cryptographic contract that makes an observation *evidence* —
binding, attestation, reconciliation semantics, and the `CANNOT_PROVE` default.
A synthetic observer exercises 100% of that contract with zero kernel risk. If
the contract is wrong, an eBPF sensor produces attributable-looking telemetry
that cannot actually be attributed — which is precisely the failure mode of the
unmerged `aegis-quantum` work, whose `ConnectionKey` is a bare IPv4 4-tuple
with no process identity. Skill §23 places "synthetic observer" at step 7 and
"real kernel observer" at step 12; the evidence supports that order.

**Slice acceptance criterion (one sentence):** a reconciler returns
`VERIFIED_EXECUTION` for an honest run, `UNATTRIBUTED_EFFECT` when the observer
sees an effect with no authorization, and `CANNOT_PROVE` when observation is
unavailable — **and an adversarial test proves the agent cannot forge any of
the three, even holding its own key and re-sealing its own packet.**

---

## STAGE 0 — AIP correctness (blocking; no Ghost code yet)

One wire break. Bump `PACKET_VERSION` exactly once for Stages 0–1 combined.

### 0.1

**FILE** `aip-standalone/aip-core/src/capability.rs`
**CURRENT PURPOSE** scope lattice; `issue_scoped_token` / `verify_scoped_token`; `canonical_token_payload:208-230`
**PROPOSED CHANGE** add `expires_at: Option<u64>` as a parameter to `canonical_token_payload` and encode it with a presence tag; update `issue_scoped_token:130` and `verify_scoped_token:156` call sites
**WHY** the field is read by R10 (`verification.rs:495`) but not covered by the signature — the holder rewrites its own expiry. Copy the correct pattern already present at `aip-core/src/lib.rs:135-142`
**DEPENDENCIES** none
**SECURITY IMPACT** closes the P0 authority-extension defect; satisfies **I5**, **I6**
**COMPATIBILITY IMPACT** breaking — all existing tokens fail verification
**TEST IMPACT** new: mutate `expires_at`, re-seal with the agent's real key, assert `ROOT_TOKEN_SIGNATURE` fails
**MIGRATION IMPACT** re-issue tokens; no stored-data migration (tokens are ephemeral)

### 0.2

**FILE** `aip-standalone/aip-core/src/delegation.rs`
**CURRENT PURPOSE** delegation creation and chain verification; `canonical_delegation_payload:369-393`
**PROPOSED CHANGE** same treatment for `expires_at`; additionally enforce `child.expires_at <= parent.expires_at` inside `verify_delegation_chain:169-232` (currently only assigned at `:94,:149`, never checked)
**WHY** `AIP_SPEC.md:52` mandates it; nothing enforces it
**DEPENDENCIES** 0.1
**SECURITY IMPACT** a delegated agent can no longer outlive its grantor
**TEST IMPACT** new: child with later expiry than parent → `AttenuationViolation`

### 0.3

**FILE** `aip-standalone/aip-protocol/src/canonical.rs`
**CURRENT PURPOSE** injective length-prefixed encoder; **helpers are `pub(crate)`** (`put_u8:11`, `put_bytes:23`, `put_str:29`, …)
**PROPOSED CHANGE** promote to `pub`; re-export from `aip-protocol/src/lib.rs`. Optionally relocate to `aip-types` so `aip-core` can depend on it without a cycle
**WHY** every new signed Ghost type must use this encoder, not the non-injective `aip-core` pattern (**I14**). Today they cannot — visibility forbids it
**DEPENDENCIES** none
**SECURITY IMPACT** enables correct encoding everywhere; no behaviour change alone
**TEST IMPACT** **new file** `aip-protocol/tests/canonical.rs` — injectivity vectors, `Some("")` vs `None`, the `("ab","c")` / `("a","bc")` case. `canonical.rs` currently has **zero** tests

### 0.4

**FILE** `aip-standalone/aip-core/src/capability.rs`, `delegation.rs`, `lib.rs:119-161`
**PROPOSED CHANGE** replace raw `extend_from_slice(s.as_bytes())` with the length-prefixed helpers from 0.3
**WHY** `("ab","c")` and `("a","bc")` currently produce identical signed payloads
**DEPENDENCIES** 0.3
**COMPATIBILITY IMPACT** breaking (same wire break as 0.1/0.2)

### 0.5

**FILE** `aip-standalone/aip-crypto/src/lib.rs`
**CURRENT PURPOSE** `sign_ed25519:127` signs `SHA-256(alg ‖ signer_id ‖ ts ‖ nonce ‖ payload_hash)` — **no domain tag**
**PROPOSED CHANGE** add a `domain: &'static str` parameter folded into the preimage; define constants `DOMAIN_PACKET`, `DOMAIN_TOKEN`, `DOMAIN_DELEGATION`, `DOMAIN_EXPECTED`, `DOMAIN_OBSERVED`, `DOMAIN_BINDING`
**WHY** `ExpectedExecution` and `ObservedExecution` must not be confusable with a packet or token
**DEPENDENCIES** none (mechanical, wide blast radius)
**SECURITY IMPACT** eliminates cross-type signature substitution
**TEST IMPACT** new: a signature made under one domain must fail verification under another

---

## STAGE 1 — ExecutionBinding into signed evidence

### 1.1

**FILE** `aip-standalone/aip-types/src/lib.rs`
**PROPOSED CHANGE** add `struct ExecutionBinding` and `struct ProcessInstance { pid: u32, pid_start_time_ticks: u64, boot_id: [u8;16] }` per `EXECUTION_BINDING.md` §3. Data only, no logic (this crate has no dependencies beyond serde and must stay that way)
**WHY** PID alone cannot establish identity (**I3**); reuse must not transfer attribution (**I4**)
**TEST IMPACT** none directly — the crate has 0 tests today; add round-trip tests

### 1.2

**FILE** `aip-standalone/aip-protocol/src/evidence_packet.rs`
**CURRENT PURPOSE** `EvidencePacket:210-246`; `canonical_bytes:251-334`; `PACKET_VERSION`
**PROPOSED CHANGE** add `pub binding: Option<ExecutionBinding>`; encode it in `canonical_bytes` with `put_opt_*` helpers; **bump `PACKET_VERSION`** (covers Stages 0 + 1)
**WHY** the reconciliation join key must live inside signed evidence; today `EvidencePacket` has no runtime field at all
**DEPENDENCIES** 0.3, 0.5, 1.1
**SECURITY IMPACT** the binding becomes tamper-evident under R3/R4
**COMPATIBILITY IMPACT** breaking; keep a v1 verification path or state the break in `CHANGELOG.md`
**TEST IMPACT** tamper the binding, fix the hash → `AGENT_SIGNATURE` must fail

### 1.3

**FILE** `aip-standalone/aip-protocol/src/verification.rs`
**PROPOSED CHANGE** add rule **R15 `EXECUTION_BINDING`** — if present, the binding is well-formed and its `agent_id` equals `packet.agent.aip_id`. Add `ctx.verification_time: Option<u64>` and use it in R10 for absolute expiry
**WHY** R10 currently never consults a clock; `is_token_expired` (`capability.rs:175`) has no caller here
**DEPENDENCIES** 1.2
**TEST IMPACT** per `aip-protocol-change-guard` §4, a test pinning R15 by name via `assert_rule_failed` (`tests/evidence_packet.rs:163-173`)
**MIGRATION IMPACT** rule count 14 → 15; update `AIP_SPEC.md:149-173` and the report schema

---

## STAGE 2 — The decision point (this is the architectural centre)

### 2.1

**NEW CRATE** `aip-standalone/aip-authorize/`
**FILES** `src/lib.rs`, `src/expected.rs`, `src/decision.rs`
**PURPOSE** the authority that decides *before* execution — the component whose absence is the root finding of this audit
**PROPOSED CHANGE**
```rust
pub struct ExpectedExecution { /* per OBSERVATION_MODEL.md §4 */ }

pub trait DecisionPoint {
    /// Verifies the chain, checks scope, emits a SIGNED ExpectedExecution.
    /// The signing key belongs to the decision point, NOT the agent (I1).
    fn authorize(&self, req: &AuthorizationRequest)
        -> Result<ExpectedExecution, Denied>;
}
```
`authorize` must: verify the root token signature against a **configured**
issuer key (not one supplied in the request); call
`aip_core::delegation::verify_delegation_chain`; check the requested
`action_kind` against the effective scope via
`aip_core::capability::is_scope_subset`; then sign with its own key using
`DOMAIN_EXPECTED`
**WHY** today no component does any of this. `generate_packet`
(`aip-service/src/evidence.rs:220-300`) seals caller assertions using a private
key supplied in the request body (`:130`) and verifies nothing
**DEPENDENCIES** Stage 0, 1.1
**SECURITY IMPACT** the single change that satisfies **I1**
**TEST IMPACT** self-issued root token with an untrusted issuer → `Denied`; out-of-scope action → `Denied`; expired chain → `Denied`

### 2.2

**FILE** `aip-service/src/evidence.rs`
**CURRENT PURPOSE** `GenerateRequest:128-147` takes `agent_seed_hex`; `generate_packet:220` seals without verification; `VerifyRequest:157-172` takes caller-supplied `trusted_issuers`
**PROPOSED CHANGE** (a) require a valid `ExpectedExecution` in `GenerateRequest` and verify it before sealing; (b) rename the verify endpoint's semantics in code and docs to make clear it is a **calculator**, not an authority — or move caller-supplied anchors behind an explicit `?mode=calculator` flag; (c) plan removal of `agent_seed_hex` in favour of client-side signing
**WHY** closes the self-authorization loop (**I19**); (c) removes the service's custody of agent private keys
**DEPENDENCIES** 2.1
**COMPATIBILITY IMPACT** breaking API change — stage behind a version
**TEST IMPACT** HTTP test: generate without a valid `ExpectedExecution` → 403

---

## STAGE 3 — Observer contract + synthetic observer

### 3.1

**NEW CRATE** `aip-standalone/aip-observe/`
**FILES** `src/lib.rs`, `src/observed.rs`, `src/attest.rs`, `src/health.rs`, `src/synthetic.rs`
**PROPOSED CHANGE** `ObservedExecution`, `ObserverAttestor` trait, `SensorHealth` with the 5 continuity states from `OBSERVER_ATTESTATION.md` §5, and `SyntheticObserver` — a test/dev observer whose key is generated **outside** the agent process and injected, so the "agent does not hold the key" property is structurally true even in the slice
**WHY** without an independent trust root an observation is a second self-report (**I10**)
**DEPENDENCIES** Stage 0, 1.1
**SECURITY IMPACT** establishes the trust root interface; the *anchor* decision (remote collector vs TPM vs TEE) stays open and is documented as such
**TEST IMPACT** an observation signed with the agent's key must be **rejected** by the reconciler

---

## STAGE 4 — Reconciler

### 4.1

**NEW CRATE** `aip-standalone/aip-reconcile/`
**FILES** `src/lib.rs`, `src/result.rs`, `src/strength.rs`, `src/reconcile.rs`
**PROPOSED CHANGE** implement the contract in `RECONCILIATION_MODEL.md`:
join on `decision_id` + `ExecutionBinding`; emit
`ReconciliationResult` with `CANNOT_PROVE` as the `Default` impl; keep
`Severity` and `EvidenceStrength` as **separate** types with no `From` between
them (**I12**)
**WHY** this is the comparison that does not exist anywhere today
**DEPENDENCIES** 2.1, 3.1
**SECURITY IMPACT** first component able to distinguish authorized-and-observed from authorized-and-unobserved
**TEST IMPACT** the three acceptance cases from §0, plus: `PHANTOM_CLAIM` must be **unreachable** without attested coverage (**I8**)

---

## STAGE 5 — Adversarial proof of the slice

**NEW FILE** `aip-standalone/aip-reconcile/tests/adversarial.rs`

Mandatory cases, each modelling an agent that holds its own key and re-seals:

| # | Attack | Required outcome |
|---|---|---|
| 1 | agent extends `expires_at`, re-seals | R5/R6 fail (Stage 0.1/0.2) |
| 2 | agent forges an `ObservedExecution` with its own key | rejected — wrong signer for `DOMAIN_OBSERVED` |
| 3 | agent forges an `ExpectedExecution` with its own key | rejected — decision-point key required |
| 4 | PID reused by an unrelated process | binding mismatch → **not** attributed (**I4**) |
| 5 | observer silent for the window | `CANNOT_PROVE`, never `PHANTOM_CLAIM` (**I8**) |
| 6 | observer reports `DEGRADED` | `OBSERVATION_UNAVAILABLE`, no escalation (**I9**) |
| 7 | high severity + `Heuristic` strength | never reaches containment threshold (**I12/I13**) |

The slice is **not** complete until all seven pass.

---

## Sequence summary

```
STAGE 0  AIP correctness        capability.rs · delegation.rs · canonical.rs · aip-crypto/lib.rs
STAGE 1  ExecutionBinding       aip-types/lib.rs · evidence_packet.rs · verification.rs   [ONE version bump]
STAGE 2  Decision point         NEW aip-authorize · aip-service/evidence.rs
STAGE 3  Observer contract      NEW aip-observe (synthetic only)
STAGE 4  Reconciler             NEW aip-reconcile
STAGE 5  Adversarial proof      aip-reconcile/tests/adversarial.rs
─────────────────────────────────────────────────────────────────────────────
LATER    real kernel observer, warrant engine, containment, NEXORA, PQC
```

**Deviation from skill §23:** the skill lists ExecutionBinding (5) before the
ObserverAttestation *interface* (6) and the synthetic observer (7); this plan
agrees, but promotes the **decision point** to Stage 2 — earlier than the
skill's implied position — because discovery proved there is no
`ExpectedExecution` producer at all. Without it, Stages 3–4 have nothing to
reconcile against. This is the "repository evidence proves a different order"
case the skill permits, and the reason is recorded here.

## Explicitly out of scope for the slice

eBPF/XDP; containment; NEXORA/Merkle protocol; PQC; performance work; merging
`ot-sentinel` or `aegis-quantum`; deleting the `aip-service` duplicate authority
engine (P1, but not slice-blocking).
