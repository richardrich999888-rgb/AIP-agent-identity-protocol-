# PR3 GAP REVIEW — corrective review before reconciliation

Scope: everything Skills 3, 4, 5, 6 and Stage 6.5 left open, re-verified
against the repository at `1fc0152` (not against the reports), and classified
for one question only: **what must be true before a reconciliation layer can
produce a verdict that is not itself a fabrication?**

Classification key:

| Class | Meaning |
|---|---|
| **A** | MUST FIX BEFORE RECONCILIATION |
| **B** | CAN REMAIN CANNOT_PROVE BY DESIGN |
| **C** | DEPLOYMENT / TRUST-ROOT OBLIGATION |
| **D** | FUTURE HARDENING / POST-RECONCILIATION |
| **E** | DOCUMENTATION / TERMINOLOGY DEFECT |

Method note: the reports were treated as claims. Every classification below
cites the code or test that was checked. Where a report's claim did not hold
up, the section says so.

---

## 1. Executive summary

Three items are genuine prerequisites and are fixed in this pass, test-first:

| # | Item | Why it blocks reconciliation |
|---|---|---|
| A-1 | `aip_core::wellknown::verify_delegation_with_jwks` verifies the Ed25519 *envelope* only — it never recomputes the delegation payload hash. A hop with rewritten `expires_at`, scope or grantee still passes. | A public authority verifier that accepts the exact Skill 3 attack is a second, wrong answer to "is this hop valid" in the same tree the reconciler will live in. Not on `verify_packet`'s path, but any operator anchoring chain issuers through JWKS would be verifying nothing. |
| A-2 | `aip_crypto::verify_ed25519` accepts any `Signature.algorithm` label as long as the Ed25519 envelope verifies. A signature labelled `MlDsa65` produced with Ed25519 verifies as `Ok(true)`. | Every evidence type the reconciler consumes carries this label. A verified signature whose algorithm field lies is an I7 violation the reconciler would pass through as fact. |
| A-3 | Signed `SensorHealth` states coverage as a window but not **which mechanisms** covered it. A poll-only window and a connector-covered window are indistinguishable to a verifier. | `PHANTOM_CLAIM` requires attested coverage over the exact window by a source that would have seen the event. Without a signed per-mechanism coverage statement the reconciler would have to *infer* kernel coverage from the presence of kernel events — inferring coverage from content is exactly the I8 failure. |

Everything else is B, C, D or E. The most important B is that **the observer
cannot see actions**: `ObservedExecution` records process presence, lifecycle
and sockets, never `action_kind`/`parameter_digest`. `VERIFIED_EXECUTION` as
defined in `RECONCILIATION_MODEL.md` §4 (context match) is therefore
**unreachable** with the current sensors and must resolve to `CANNOT_PROVE`;
identity-level corroboration is the strongest positive statement available.

**Reconciliation readiness: READY WITH EXPLICIT CANNOT_PROVE BOUNDARIES**
(after A-1..A-3), with the boundary list in §10 as a binding part of the
Skill 7 contract.

## 2. Current architecture state after Skills 3–6 (+6.5)

| Layer | Crate / type | Signed by | Verified how | Stage |
|---|---|---|---|---|
| Authority | `ScopedToken`, `DelegationToken` (`aip-core`) | issuer | `verify_scoped_token`, `verify_delegation_chain` (payload hash + envelope; child ≤ parent expiry) | 0 |
| Execution identity | `ExecutionBinding` (`aip-types`), collected by `aip_core::execution_binding` | nobody standalone; agent via packet | R15 well-formedness; `identity_bytes` excludes path/time | 1 |
| Expectation | `ExpectedExecution` (`aip-authorize`) | decision point | `verify_expected_execution[_for_agent]` against `DecisionPointTrustAnchors` | 2 |
| Agent evidence | `EvidencePacket` v2 (`aip-protocol`) | agent | `verify_packet`, 15 rules | 0/1 |
| Observation | `ObservedExecution`, `KernelLifecycleEvent`, `ObservationBatch` v2 (`aip-observe`) | unsigned on host | — | 3/6.5 |
| Attestation | `AttestedBatch`, `SignedSensorHealth` | collector | `verify_attested_batch[_independent_of_agent]`, `verify_signed_health` against `ObserverTrustAnchors` | 3/6.5 |
| Reconciliation | — | — | — | not built |

Stage ↔ skill numbering (a recurring source of confusion, see E-5):
Stage 0 = Skill 3, Stage 1 = Skill 4, Stage 2 = Skill 5, Stage 3 = Skill 6
(+6.5), Stage 4 = Skill 7, Stage 5 (evidence strength) + 6 (warrant) = Skill 8,
Stage 8 = Skill 9, Stage 9 = Skill 10.

## 3–9. Gap inventory

Each row: classification · security property · existing evidence · missing
evidence · proposed minimal correction (A only) · why it is / is not a
prerequisite.

### Skill 3 — AIP correctness

**1. `aip-service` second scope/delegation model — D (+E).**
Property: I18 one authority model. Verified: `aip-service/src/{capability,delegation}.rs`
define their own `CapabilityScope::meet` and a SHA3-hex `DelegationToken`;
`handlers.rs:219` creates them. They are a *different Rust type* from
`aip_types::DelegationToken`; `generate_packet` accepts only `aip_core` tokens
(`evidence.rs:136-139`), so service-local tokens cannot enter an
`EvidencePacket` and cannot reach the reconciler. Two authorities can diverge
at the service API, not in the evidence chain. Not a prerequisite. Evidence:
`weakness_generate_then_verify_accepts_self_issued_authority` pins the
evidence-path behaviour. Missing: a test that a service-local token is
*rejected* by `generate_packet` — trivially true by type, no test added.

**2. `aip-protocol` payloads (packet canonical bytes, `ActionAttestation`,
`ReceiptBinding`) not domain-tagged — D.**
Property: I14 domain separation. Verified: packet bytes start with `AEP1` magic
+ version; action bytes start with `decision_id` (16 bytes) then
length-prefixed fields; receipt payload starts with `decision_id`. Cross-type
confusion needs a full byte string that parses as two structures; the
length-prefix discipline plus fixed leading fields make that a collision
search, not a structural hole, and every consumer recomputes the payload of
the type it expects. Reconciliation consumes packets only through
`verify_packet`. Batch into the next `PACKET_VERSION` bump; not a
prerequisite.

**3. `sign_ed25519` envelope has no domain tag — B for the envelope, A-2 for
the algorithm label.**
Envelope = `SHA-256(algorithm ‖ signer_id ‖ ts ‖ nonce ‖ payload_hash)`;
`signer_id` is the only variable-length element and is followed by 56 fixed
bytes, so it is injective. Cross-context transplantation is prevented **only**
if every verifier recomputes the payload and compares `payload_hash` before
calling `verify_ed25519`. Audit of every call site (`grep verify_ed25519(`):

| Site | Recomputes payload first? |
|---|---|
| `capability.rs::verify_scoped_token` | yes |
| `delegation.rs::verify_delegation_chain` | yes |
| `lib.rs` AID self-sig, lineage, grant, vote, liveness challenge | yes |
| `verification.rs` R4, R11, R13 | yes |
| `aip-authorize::verify_expected_execution` | yes |
| `aip-observe::verify_signature_over` | yes |
| **`wellknown.rs::verify_delegation_with_jwks`** | **no — A-1** |
| `aip-cli` verify command, `simulation.rs` | raw signature tools, payload printed / experimental — acceptable |

So the "no domain tag in the envelope" is B: the domain lives in the payload,
and the property holds wherever the discipline is followed. A-1 is where it
was not followed.

**4. Agent-controlled timestamps — B (+E).**
Three clocks exist and each is trusted only for its own party's statements:
agent (`decided_at`, `performed_at`, `bound_at_ms`), decision point
(`issued_at`, `valid_until`, `decision_sig.timestamp`), collector
(`emitted_at_ms`, `attestation.timestamp`), plus kernel `timestamp_ns`
(monotonic, boot-relative, user space cannot set it). What can be claimed:
R10 window consistency *as asserted by the agent*; DP window as asserted by the
DP; collector receipt order by sequence and an **upper bound** on when an
observation existed (`attestation.timestamp` is the collector's clock inside
the signed envelope); kernel ordering within one boot. What cannot: any
cross-clock equality, wall-clock truth, or "this happened at T". Reconciliation
must join on `decision_id` + identity and use time only as a consistency
filter with explicit tolerance supplied by the verifier, never as evidence.
No wall clock is introduced.

**5. Plaintext `KeyPair` persistence in `aip_core::store` — D.**
Verified: `store.rs` is not referenced from `aip-protocol`, `aip-authorize`,
`aip-observe` or `aip-service` evidence paths. Key custody quality does not
change what the evidence chain proves; it changes how easily a key is stolen,
which is C/D territory. Not a prerequisite.

**6. Caller-supplied trust anchors — C (+E).**
Inventory: `VerificationContext` (library verifier; correct — the verifier
decides), `VerifyRequest.trusted_issuers` (service calculator; documented in
Skill 3), `DecisionPoint::trust_issuer` (operator config), `ObserverTrustAnchors`
and `DecisionPointTrustAnchors` (verifier). The architecture intends the
*verifier* to hold anchors; none of these lets the *agent* choose anchors on
the evidence path. The reconciler will take anchors from its caller the same
way. Deployment obligation: anchors are distributed out-of-band; a verifier
that accepts anchors from the party under scrutiny recreates the Stage 0 loop.

**7. `MlDsa65`/`Hybrid` identifiers inert — A-2 for the label check, E for
claims.**
Verified: `verify_ed25519` does not check `signature.algorithm`;
`verify_signature_with_optional_verifier` dispatches on it but only the AID
path uses that. A custom signer can emit Ed25519 signatures labelled `MlDsa65`
that verify everywhere. Fix (A-2): `verify_ed25519` refuses non-Ed25519 labels
with `EvolutionRequired`. No PQC is implemented; nothing may claim it.

### Skill 4 — Execution binding

**8. `ExecutionBinding` is self-reported — B (+E).**
What reconciliation may infer from a packet binding: *the agent claims
instance X*. What it may infer when an observer's `ObservedProcess` matches
(`matches_process_of`): *the observer measured an instance with the same
(pid, start, boot, exe hash) as the agent claims* — corroboration under the
observer's own A4 limitation, never proof of truth. Test H
(`test_resealed_self_binding_swap_verifies_documenting_self_report_limit`)
pins the limit.

**9. PID reuse / reboot / start-time — verified, no gap.**
`same_pid_different_start_time_is_a_different_instance`,
`same_pid_same_start_different_boot_is_a_different_instance`,
`pid_equality_never_implies_same_execution`, and on the observer side
`t08_pid_reuse_never_transfers_identity_through_kernel_events`,
`pid_reuse_cannot_transfer_an_observation`. Residual: sub-tick recycling — B.

**10. Binary identity ≠ behavioural integrity — B, preserved.** Documented in
`EXECUTION_BINDING.md` §7.3; no code claims otherwise.

**11. Linux-only — C.** Non-Linux returns `UnsupportedPlatform`; nothing
degrades silently. A platform limitation, not an architecture blocker.

**12. cgroup / namespace context absent — D.** Reconciliation joins on
instance identity, which does not need it. It is needed to *scope* network
observations (which netns a socket table belongs to) and for containment
scoping — both later stages.

**13. Lifetime / lineage — B, now partially observable.** Kernel `Fork` events
(6.5) give observer-attested parent→child pids; lineage as *identity* still
needs both parent and child bound (`bound: Some`). `LINEAGE_VIOLATION` remains
`CANNOT_PROVE` unless both ends are bound; the reconciler must represent an
unbound fork as "kernel reported a fork of pid p from pid q", not as lineage.

### Skill 5 — Decision point

**14. Deployment isolation not proven — C.** Cryptographically enforced:
the DP key never enters via a request (type-level), self-authorization by id
is refused, an agent-keyed anchor is refused (`test_h_*`). Deployment-dependent:
that the `DecisionPoint` value lives in a process the agent cannot read.

**15. `aip-service` not wired to require `ExpectedExecution` — D.**
Reconciliation does not need the service; it needs an `ExpectedExecution`
from a trusted DP and a packet with the same `decision_id`. The boundary is
preserved explicitly: the service remains a signing oracle (pinned by
`weakness_generate_then_verify_accepts_self_issued_authority`), and a packet
whose `decision_id` has no verified `ExpectedExecution` reconciles to
`CANNOT_PROVE` on the expected side — never to `UNATTRIBUTED_EFFECT`, because
expected-side completeness is unknown.

**16. Key provisioning / custody / rotation / revocation — C (+D).**
Rotation and revocation exist at the anchor level for observers; the DP has
neither. None changes what a verified record proves.

**17. Trusted time / clock skew — B.** See item 4. The reconciler operates on
signed-time consistency with a verifier-supplied tolerance; it never claims
absolute time.

### Skill 6 / 6.5 — Observer

**18. Procfs vs root — B + C. Critical, and correctly bounded today.**
Verified against `aip-observe`: the collector attests *receipt and order*
(`AttestedBatch` docs, `OBSERVER_IMPLEMENTATION_REPORT.md` A4); kernel-pushed
events (`ProcConnector`) make existence/order/CPU/time kernel-generated, while
the *identity* behind an event still comes from procfs. Nothing in the crate
claims truth. The reconciler must therefore never assign a strength above
"attested receipt" to procfs-derived content. No stronger procfs parsing can
change this; the only escalation path is kernel instrumentation (D).

**19. Events between polls — A-3 for the coverage statement; B for the rest.**
With the connector present, exec/exit are pushed. Whether it *was* present
over a window is exactly what a verifier needs and cannot currently read from
signed health. Fix (A-3): probe declares its active sources per batch; the
collector carries the intersection over the coverage epoch into signed
`SensorHealth.covered_by`; `PHANTOM_CLAIM` requires a kernel-pushed mechanism
in `covered_by`. The declaration is a probe claim bounded by the registry —
same trust class as every other probe claim (C).

**20. Network, filesystem, syscall effects — B/D.** What Ghost 2.0 covers
today: process presence, kernel lifecycle (fork/exec/exit), socket-level
association. Not covered: packets, files, syscalls, exec arguments, tool
invocations. **Consequence for reconciliation:** `ObservedExecution` has no
`action_kind` or `parameter_digest`, so the context-match precondition of
`VERIFIED_EXECUTION` cannot be met by any current observation. The reconciler
must emit `CANNOT_PROVE` for action-level verification and may emit only
identity-level corroboration. This is the single most important honesty
boundary for Skill 7.

**21. Collector restart loses durable continuity — B (D for persistence).**
Verified: `t13_collector_restart_cannot_silently_continue_the_chain` — new
epoch, `ContinuityUnverified`, zero `prev_head`. Represented, not hidden.

**22. Collector trust root single point — C (+D NEXORA).** Verified:
`t17_a_stolen_collector_key_forges_history_until_revoked`. What is guaranteed:
forgery requires the key; what is assumed: the key is not stolen; what is
absent: threshold signing, external anchoring.

**23. Agent identity linkage is a claim — B (+E).** `AgentAttribution` has no
`Verified` variant (tested). Reconciliation must join `ExpectedExecution.agent_id`
to observation via **process identity**, and treat `Claimed(agent_id)` equality
as consistency of claims, never as identity proof.

### Cross-stage architecture

**24. Evidence contracts compatible — yes, with one asymmetry (E).**
`ExpectedExecution.execution_binding: ExecutionBinding` and
`ObservedProcess` compare via `ObservedProcess::matches_process_of(&ExecutionBinding)`
(structural: process tuple + exe hash). `ExecutionBinding::identity_bytes`
(`GHOST/ExecutionIdentity/v1`, includes `agent_id`) and
`ObservedProcess::identity_bytes` (`SYNTRIASS/GHOST/OBSERVED_PROCESS/v1`, no
agent) are **deliberately different digests** and must not be compared byte
for byte. The Skill 7 contract must say: compare process facts structurally;
compare agent claims separately.

**25. Identifier join — verified; one type-safety gap (D).** `decision_id`
appears as `[u8;16]` in `DecisionRecord`, `ExpectedExecution`,
`ObservedExecution.claimed_decision_id`, `KernelLifecycleEvent.claimed_decision_id`
— joinable. But `batch_id`, `probe_run_id`, `packet_id`, `action_id`, `jti`,
`root_jti`, `nonce` are all also `[u8;16]`: nothing at the type level stops a
reconciler passing a `batch_id` where a `decision_id` is expected. Skill 7
must introduce newtypes at its input boundary. Not a Stage 3–6 defect.

**26. Substitution of identity kinds — verified by test where it matters.**
Agent id vs process identity: `matching_a_process_never_matches_an_agent_identity`.
Authority id vs agent id: `ChainLeafNotAgent`, `SelfIssuedAuthority`. Observer
id vs agent id: `ObserverKeyIsAgentKey`. Decision-point id vs agent id:
`SelfAuthorization`. Remaining: the `[u8;16]` newtype gap above (D).

**27. Distinct states — verified.** `ObservationAvailability` (Covered /
Unavailable with 7 reasons), `ObserverState` (5), `ContinuityStatus` (4),
`TemporalStatus` (3), `Decision` (Authorized/Denied with 15 reasons),
`VerifyError`/`ExpectedVerifyError`/`AttestError` typed. Terminology drift on
`OBSERVATION_UNAVAILABLE` is E-3.

**28–31. Reconciliation cannot manufacture evidence / authorization /
coverage / PHANTOM from absence — contract, plus A-3.** No reconciler exists;
what exists is that no input type offers a "not executed" or "authorized"
predicate, that coverage is a signed collector statement, and — after A-3 —
that the *mechanism* of coverage is signed too. The Skill 7 tests listed in
its §28 (cases 2, 4, 17, 22) must pin these; they cannot be written before
Skill 7.

**32. Cryptographically valid but unrelated observation satisfying an
expectation — bounded, B.** Match requires `decision_id` (claimed on the
observation) **and** process identity match; an observation can carry any
claimed decision id, so `decision_id` equality alone is a claim. With no
action/parameter facts in observations, the strongest satisfiable relation is
"an instance matching the expected binding was observed"; the expectation's
action is unverifiable by observation. Skill 7 must not let identity match
imply action match.

**33. Replay / fork / rollback / gap / unavailable distinguishable — verified.**
`ContinuityFault::{Replay, Fork, Rollback, Gap, HeadMismatch, UnverifiableEpoch}`,
`ProbeStreamFault::{EventsLost, SequenceDiscontinuity}`,
`UnavailableReason` (7). Tests in `continuity::tests`, `adversarial.rs`,
`sniffer_dog.rs`.

**34. Domain separation & injectivity across the chain — verified per crate;
cross-crate audit added.** Sixteen tags exist (Stage 0: 6, Stage 1: 2,
Stage 2: 2, Stage 3/6.5: 6); per-crate tests assert distinctness within reach
of each crate's dependencies. No single test spans all crates. A cross-crate
test is added in this pass (`aip-test`) asserting all tags pairwise distinct
and each `put_domain` prefix is the first element of its preimage.

## 10. Things that MUST remain CANNOT_PROVE (binding on Skill 7)

1. Truth of any procfs-derived content on a root-compromised host.
2. Identity of an unbound kernel event (`bound: None`).
3. Action-level verification (`action_kind`, `parameter_digest`) from any
   current observation → `VERIFIED_EXECUTION` unreachable; identity-level
   corroboration is the ceiling.
4. Non-execution when coverage over the exact window by a kernel-pushed
   mechanism is not in signed `covered_by`.
5. Zero loss where `dropped_events` is `None`.
6. Execution continuity across observer or collector restart.
7. Absolute time; any cross-clock equality.
8. Truth of an `AgentAttribution::Claimed`.
9. Lineage as identity unless both parent and child are bound.
10. Expected-side completeness (an observed instance with no matching
    `ExpectedExecution` is not `UNATTRIBUTED_EFFECT` without an independent
    completeness statement).
11. Provenance under `ProbePolicy::Open`.

## 11. Deployment assumptions

Collector key, ledger and registry off-host; authenticated probe→collector
channel (registration bounds a genuine probe's claims, cannot stop an impostor
using a registered id without it); production collectors run `RegisteredOnly`;
connector needs `CAP_NET_ADMIN` in the initial netns; decision-point process
isolated from the agent; trust anchors distributed out-of-band to verifiers;
Linux procfs semantics as documented.

## 12. Future hardening (post-reconciliation)

Domain tags on `aip-protocol` payloads (next `PACKET_VERSION`); `[u8;16]`
newtypes; `aip-service` route through `aip_core` authority and require
`ExpectedExecution`; durable collector ledger; DP and observer key lifecycle;
cgroup/netns context; eBPF/tracepoint sources for syscall/file/exec-argument
effects and connection events; threshold signing / external anchoring
(NEXORA); non-Linux collectors; `KeyPair` at-rest protection.

## 13. Cross-stage contract audit (summary)

| Contract | Producer | Consumer | Status |
|---|---|---|---|
| `decision_id` | DP (`ExpectedExecution`) | packet `DecisionRecord`, observation claims | joinable; claim on the observation side |
| process identity | `ExecutionBinding` (agent), `ObservedProcess` (observer) | reconciler via `matches_process_of` | compatible; digests intentionally differ (E-1) |
| authority ref | `ExpectedExecution.authority` (jtis) | packet root/chain jtis | joinable by jti |
| coverage | `SignedSensorHealth` | reconciler | window signed; **mechanism missing → A-3** |
| provenance | `SourceMechanism` per observation/event | reconciler | signed, gated by registry |
| continuity | `ContinuityStatus`, `ObserverState`, faults | reconciler | explicit |
| strength | — | Skill 8 | not built; must be a separate type |

## 14. Reconciliation readiness decision

**READY WITH EXPLICIT CANNOT_PROVE BOUNDARIES** — conditional on A-1, A-2,
A-3 being fixed test-first in this pass (see §15 for before/after), and on
Skill 7 adopting §10 verbatim as preconditions.

## 15. Corrections made in this pass (before / after)

Filled in after the fixes; see the section of the same name appended below.

## 16. Documentation normalization

| Defect | Where | Fix |
|---|---|---|
| E-1 asymmetric identity digests | `EXECUTION_BINDING.md`, `SNIFFER_DOG.md` | state "compare structurally, never by digest" |
| E-2 `OBSERVER_MODEL.md` | Skill 4 §1 | → `OBSERVATION_MODEL.md` |
| E-3 `OBSERVATION_UNAVAILABLE` as result vs state | Skill 8 result list; `OBSERVATION_MODEL.md`, `RECONCILIATION_MODEL.md` | define: **availability state** (input), whose reconciliation result is `CANNOT_PROVE`; carried alongside the result so the warrant layer can refuse it |
| E-4 bare report filenames | Skills 6, 7, 8 | prefix `docs/architecture/` |
| E-5 stage vs skill numbering | `IMPLEMENTATION_PLAN.md` | add mapping line |
| E-6 stale "as of 377d5fc" headers read as current | `CURRENT_SYSTEM.md`, `TRUST_BOUNDARIES.md`, `OBSERVATION_MODEL.md` | status banner pointing at stage reports |
