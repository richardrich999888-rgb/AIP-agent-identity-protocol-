# AIRI Extension — Final Audit Report

**Scope:** the AI-stack extension added on
`claude/aip-security-architecture-audit-zpf9b3`, based on
`claude/codebase-production-readiness-wm6idp` (prod).
**Date:** 2026-09-06.
**Source of truth for security decisions:** the Six-Branch Forensic Audit
(`audit/2026-09-06-master-forensic/`). Branch summaries, README claims and
passing tests are not treated as proof of capability.

---

## A. Files changed

56 files, 6,434 insertions, 0 deletions of product code.

### New Rust crate — `aip-standalone/aip-airi` (1,731 LOC)

| File | Lines | Purpose |
|---|---:|---|
| `src/lib.rs` | 92 | Crate contract; states what an AIRI event does and does not establish |
| `src/event.rs` | 322 | `AiriEvent`, canonical preimage, sign, verify |
| `src/provenance.rs` | 297 | Payload bodies: model, tool, subprocess, framework, completion |
| `src/corroborate.rs` | 380 | Claim ⟷ observation comparison; the seal |
| `src/chain.rs` | 179 | Per-execution hash chain |
| `src/integrate.rs` | 129 | Annotation beside a reconciliation; never inside it |
| `src/error.rs` | 73 | AIRI's own error type |
| `src/ids.rs` | 45 | Newtype identifiers |
| `tests/` (7 suites) | 1,214 | Binding, chain, adversarial, integration, NEXORA, interop, parity |

### New Python SDK — `sdk/python/vanian_airi` (1,556 LOC)

| File | Lines | Purpose |
|---|---:|---|
| `canonical.py` | 128 | Prefix-free encoder, byte-identical to Rust |
| `events.py` | 386 | Event model and preimage |
| `emitter.py` | 268 | Signing, chaining, the nine event kinds |
| `context.py` | 268 | Execution context across four concurrency edges |
| `identity.py` | 165 | Fail-closed key loading |
| `commitment.py` | 58 | Domain-separated commitments |
| `errors.py` | 37 | Failure modes, all fatal |
| `adapters/framework.py` | 195 | Agent-framework adapter |
| `adapters/model.py` | 157 | Model / inference adapter |
| `adapters/tool.py` | 156 | Tool / API / effect adapter |
| `tests/` (4 suites) | 707 | Parity, boundary, context, end-to-end |

### Modified

| File | Change |
|---|---|
| `aip-standalone/Cargo.toml` | `aip-airi` added as a workspace member |
| `aip-standalone/aip-nexora/src/merkle.rs` | `LeafKind::AiriEvent = 0x09` appended; frozen codes untouched |
| `.claude/skills/11…15` | The five supplied skills installed project-level |

**No existing product logic was modified.** The NEXORA change is one appended
enum variant; `aip-reconcile`, `aip-observe`, `aip-warrant`,
`aip-containment`, `aip-authorize`, `aip-core` and `aip-protocol` are
byte-identical to prod.

---

## B. New protocols and types

### Domains introduced

| Domain | Use |
|---|---|
| `SYNTRIASS/AIRI/EVENT/v1` | Event signing preimage |
| `SYNTRIASS/AIRI/PARAM_COMMITMENT/v1` | Parameter, prompt, output, argv commitments |

Neither collides with the fifteen domains already present, asserted by test.

### Types

* `AiriEvent` — nine kinds, injective preimage, explicit version
* `AiriPayload` — `AgentStart`, `ModelProvenance`, `ToolInvocation`,
  `ToolReport`, `SubprocessReport`, `Completion`, `ContextPropagation`
* `Corroboration` — `NotEvaluated` / `Corroborated` / `Uncorroborated` /
  `Contradicted`, defaulting to `NotEvaluated`
* `CorroborationSeal` — `#[non_exhaustive]`; only `corroborate()` produces one
* `VerifiedChain` — `#[non_exhaustive]`; only `verify_event_chain()` produces one
* `AiriAnnotation` — counts beside a reconciliation, carrying no verdict
* `LeafKind::AiriEvent` — NEXORA leaf code `0x09`

### Result classes added

**None.** Every AI-stack outcome maps onto the existing vocabulary. Skill 15
permits new classes "only when the evidence semantics require a new epistemic
category", and none did: a claimed-but-unobserved AI action is
`PHANTOM_CLAIM`-shaped, and an unobservable one is `CANNOT_PROVE`.

---

## C. Security invariants

| # | Invariant | Enforcement | Status |
|---|---|---|---|
| I-A1 | An event cannot describe itself as independently observed | No constructor, field or variant exists | **HOLDS** (structural) |
| I-A2 | "Independent evidence agreed" is unforgeable by the agent | `#[non_exhaustive]` seal | **HOLDS** (compiler) |
| I-A3 | AIRI cannot move a reconciliation verdict | No expression producing `ReconciliationResult`/`EvidenceStrength` in `corroborate` or `integrate` | **HOLDS** (tested against the real engine) |
| I-A4 | AIRI cannot reach `Proven` | Same | **HOLDS** |
| I-A5 | An agent signs only for itself | `signature.signer_id == agent_id` | **HOLDS** |
| I-A6 | Every binding field is signed | 8-field mutation sweep | **HOLDS** |
| I-A7 | The preimage is injective | Length prefixes, presence bytes | **HOLDS** |
| I-A8 | AIRI's domain is distinct from all others | Tested against 8 named domains | **HOLDS** |
| I-A9 | Commitments are not bare SHA-256 | Domain-tagged construction | **HOLDS** |
| I-A10 | Replay/dup/drop/reorder/splice are detected | Hash chain | **HOLDS** |
| I-A11 | Deletion hidden by renumbering is detected | `prev_event_hash` | **HOLDS** |
| I-A12 | No framework is a trust anchor | 5-name sweep asserting identical outcomes | **HOLDS** |
| I-A13 | Sensor downtime never becomes an accusation | `NotEvaluated` on unavailable | **HOLDS** |
| I-A14 | A vocabulary gap never becomes an accusation | `ActionClassNotComparable` | **HOLDS** |
| I-A15 | Corroboration joins on process *instance*, not pid | Full `ProcessInstance` comparison | **HOLDS** |
| I-A16 | An unbound kernel event does not corroborate | `bound` required | **HOLDS** |
| I-A17 | Presence never corroborates an act | Exhaustive effect match | **HOLDS** |
| I-A18 | A model claim is never corroborated by a host observer | `is_externally_observable` | **HOLDS** |
| I-A19 | The SDK cannot self-prove or self-authorize | 14 forbidden names asserted absent | **HOLDS** |
| I-A20 | Identity loading fails closed, never regenerates | Tested: no key file created | **HOLDS** |
| I-A21 | Secrets never reach signed bytes | Commitments only | **HOLDS** |
| I-A22 | Context does not leak between concurrent tasks | `contextvars` | **HOLDS** |
| I-A23 | Context does not silently cross a thread | Explicit handoff required | **HOLDS** |
| I-A24 | The environment carries no key material | Identifiers only | **HOLDS** |
| I-A25 | Python and Rust preimages are byte-identical | 9 generated vectors, both directions | **HOLDS** |
| I-A26 | An AIRI leaf cannot be replayed as another kind | Kind code in the leaf preimage | **HOLDS** |

---

## D. Tests added

**117 total: 67 Rust, 50 Python.**

| Suite | Tests | Covers |
|---|---:|---|
| `aip-airi/tests/binding.rs` | 17 | Agent, execution, expectation, parameter, model, digest, framework and kind substitution; injectivity; domain separation; malformed keys; unsupported version |
| `aip-airi/tests/chain.rs` | 13 | Replay, duplicate, drop, reorder, splice (cross-execution and cross-agent), renumbering after deletion, genesis rules, empty run, broken signature, the documented truncation limit |
| `aip-airi/tests/adversarial.rs` | 23 | The Skill 15 matrix — each test names what the actor claims and what Vanian can establish |
| `aip-airi/tests/reconcile_integration.rs` | 7 | Composition against the **real** reconciler |
| `aip-airi/tests/nexora_commitment.rs` | 5 | Leaf-kind separation, order sensitivity, committed-bytes identity |
| `aip-airi/tests/python_interop.rs` | 1 | Rust verifies 5 Python-signed events, plus a bit-flip negative |
| `aip-airi/tests/parity_vectors.rs` | 1 (+1 ignored generator) | Vector stability and distinctness |
| `sdk/python/tests/test_canonical_parity.py` | 11 | Byte-identity against 9 Rust-generated vectors |
| `sdk/python/tests/test_boundary.py` | 17 | The forbidden surface; fail-closed identity |
| `sdk/python/tests/test_context.py` | 15 | Async, thread, process, subprocess propagation and isolation |
| `sdk/python/tests/test_adapters_e2e.py` | 7 | Full agent run through all three adapters |

### Skill 15 matrix coverage

| Required case | Covered by |
|---|---|
| valid identity + authority + matching action | `claim_corroborated_when_the_observer_saw_a_matching_kernel_event` |
| framework claims action, observer sees nothing | `framework_claims_a_tool_call_but_the_observer_saw_nothing` |
| observer sees action without matching expectation | existing `aip-reconcile` `UNATTRIBUTED_EFFECT` path (unchanged) |
| parameter substitution | `parameter_substitution_is_detected` |
| model substitution | `model_substitution_is_detected`, `model_digest_substitution_is_detected` |
| agent identity substitution | `an_event_does_not_verify_under_another_agents_key` + 1 |
| execution identity substitution | `an_event_cannot_be_moved_to_another_execution` |
| replay of a valid framework event | `a_replayed_event_is_detected` |
| event ordering violation | `reordering_is_detected` + `the_verifier_does_not_sort_its_way_out_of_a_reordering` |
| worker / process handoff | `a_handoff_binds_parent_and_child_executions`, `test_context.py` ×3 |
| subprocess handoff | `test_a_real_subprocess_restores_the_context` |
| duplicate event | `a_replayed_event_is_detected` |
| dropped event | `a_dropped_event_is_detected` |
| observer unavailable | `observer_unavailable_is_not_evaluated_and_is_not_a_finding` |
| observer continuity break | inherited from `aip-observe`; AIRI defers to its availability |
| stale ExpectedExecution | inherited from `aip-authorize` `TemporalStatus` |
| expired authority | inherited from `aip-core` |
| cross-framework transplantation | `a_claim_relabelled_to_another_framework_fails_verification` |
| forged adapter event | `a_forged_event_signed_by_a_key_the_verifier_does_not_anchor_fails` |
| malformed provenance commitment | `a_malformed_commitment_cannot_be_smuggled_in_as_a_foreign_digest` |
| tool response without observed effect | `a_successful_tool_response_is_not_evidence_of_the_external_effect` |

---

## E. Tests passed

| Run | Result |
|---|---|
| `cargo test --workspace` (baseline, prod merged, pre-AIRI) | **821 passed / 0 failed / 3 ignored / 81 suites** |
| `cargo test --workspace` (with AIRI) | **888 passed / 0 failed / 4 ignored / 90 suites** |
| `cargo clippy -p aip-airi --all-targets` | **0 warnings, 0 errors** |
| `python3 -m unittest discover -s tests` | **50 passed / 0 failed** |

**Baseline note.** The first full-workspace run showed one failure in
`aip-observe --test fanotify`. It passes in isolation and on a clean re-run;
it is a pre-existing flake in a live-kernel test racing filesystem activity
from other test binaries running in parallel. Not introduced by this work and
not fixed by it.

### Defects this work found and fixed in itself

| Defect | Found by | Fix |
|---|---|---|
| Python `identity_bytes` used the wrong domain tag | parity vectors | `GHOST/ExecutionIdentity/v1` |
| Python `identity_bytes` omitted the `version` field | parity vectors | added |
| Python `identity_bytes` length-prefixed a fixed-width digest | parity vectors | raw append |

All three would have produced Python signatures committing to different bytes
than the Python side believed it signed. The parity test caught them on its
first run, which is the argument for having it.

---

## F. Properties actually established

See `docs/architecture/AIRI_LIMITATIONS.md` §1 for all 34 with citations.
The load-bearing ones:

1. **An AIRI event that verifies proves authorship and integrity, never
   occurrence.** Enforced structurally, not documented.
2. **Cross-agent, cross-execution, cross-expectation, cross-model,
   cross-framework and cross-kind transplantation all fail.**
3. **Replay, duplication, drop, reordering and splicing are detected**,
   including deletion hidden by renumbering.
4. **AIRI evidence cannot change the reconciler's verdict or strength** —
   proven against the real engine, in every corroboration shape, at 150
   accumulated corroborations.
5. **Sensor downtime and vocabulary gaps never become accusations.**
6. **Python and Rust agree byte-for-byte**, proven in both directions.
7. **The SDK is structurally incapable of self-proving or self-authorizing.**
8. **Identity loading fails closed and never regenerates a key.**

---

## G. Properties still NOT_DETERMINABLE

| # | Not established | Why |
|---|---|---|
| N-1 | That any claimed action occurred | AIRI is self-report |
| N-2 | That a claimed external effect landed | The caller cannot know |
| N-3 | That a provider served the model requested | Hosted APIs return an unverifiable identifier |
| N-4 | That specific weights were loaded | A self-computed digest describes a file, not runtime memory |
| N-5 | That XLA, a kernel, or a GPU executed anything | Framework telemetry is framework telemetry |
| N-6 | That an agent reported everything it did | Silence leaves an intact chain |
| N-7 | That a chain was not truncated at the head | A prefix of a valid chain is valid |
| N-8 | That `runtime_binding` is true | Self-reported |
| N-9 | That a gateway's report is authoritative | Key lifecycle and transport undefined |
| N-10 | Any post-quantum property | **No PQC exists on this branch.** No such claim is made. |
| N-11 | That AIRI improves detection today | It contributes nothing to a verdict at this stage, by design |

N-11 is the honest headline. AIRI makes agent claims **specific, bound and
checkable**. It does not yet make the system detect more, because the step
that would — a `reconcile_airi_claim` entry point — is a new way to accuse and
was deliberately deferred (`AIRI_MIGRATION.md` §4).

---

## H. Existing forensic blockers remaining

**All ten remain OPEN.** AIRI closes none of them.

| ID | Blocker | Status |
|---|---|---|
| B-1 | Verifier clock semantics | **OPEN** |
| B-2 | Issuer/grantee binding | **OPEN** |
| B-3 | Real engine-produced containment path | **OPEN** |
| B-4 | Bundle signer trust | **OPEN** |
| B-5 | Private-key storage | **OPEN** (the SDK refuses to *read* a world-readable key; the writer is unchanged) |
| B-6 | Service key-regeneration behaviour | **OPEN** in `aip-service`; the SDK's own loader fails closed |
| B-7 | Private seed handling | **OPEN** |
| B-8 | Sealed reconciliation result construction (`Reconciliation` fields all `pub`) | **OPEN** |
| B-9 | Packet replay undetected | **OPEN** |
| B-10 | Service integration (`aip-service` in no workspace) | **OPEN** |

---

## I. Is production promotion permitted?

# NO.

Three independent reasons, any one of which is sufficient:

1. **Ten forensic blockers remain open**, including two P0s — the verifier has
   no clock, and delegation chains do not bind a hop's issuer to the previous
   hop's grantee. Both sit directly under the protocol's central claim about
   who authorized what and when. Building AI-stack accountability on top
   without closing them is building on sand.

2. **AIRI contributes nothing to a verdict.** Deploying it today yields
   signed, checkable claims and no additional detection. That is the correct
   staging, and it means there is nothing to promote *for*.

3. **No production evidence exists.** Every property here is CODE-PROVEN,
   TEST-PROVEN, or EXECUTION-PROVEN in a test harness. Corroboration rates
   against real traffic are unmeasured, and the false-positive behaviour of
   `uncorroborated` on real agent workloads is unknown. A detection signal
   whose false-positive rate has never been characterised should not be put in
   front of an operator.

**What promotion would require**, in order: close B-1 and B-2; close B-5 to
B-7 and B-10; resolve B-3 and B-8; run stages 1–2 of `AIRI_MIGRATION.md` §5
and characterise the false-positive rate; then build the §4 entry point with
an adversarial suite of comparable depth to the existing reconciler's.

No post-quantum claim is made anywhere in this extension, because no
post-quantum cryptography is implemented on this branch.
