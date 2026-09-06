# AIRI Extension — Final Audit Report

**Revision 2** · 2026-09-06
**Scope:** the AI-stack extension on `claude/aip-security-architecture-audit-zpf9b3`,
based on `claude/codebase-production-readiness-wm6idp` (prod).
**Source of truth for security decisions:** the Six-Branch Forensic Audit
(`audit/2026-09-06-master-forensic/`). Branch summaries, README claims and
passing tests are not treated as proof of capability — including my own.

## Revision history

| Rev | Change |
|---|---|
| 1 | Initial report, filed after the AIRI core, SDK and adapters. |
| 2 | Rewritten rather than patched further. Incorporates: prod's two P0 fixes and their independent verification; one new P1 (**B-1a**) found by that verification; deliverable **#11** (NEXORA) completed — **rev 1 reported it as done when it was not**; deliverable **#7** (schemas) completed — absent in rev 1; two hygiene defects of my own, found and fixed. |

Rev 1's incorrect claim about #11 is recorded in §J and in
`DELIVERABLES_COMPLETENESS.md` rather than quietly corrected. A patched
document that no longer agrees with itself is an audit defect of its own,
which is why this is a rewrite.

Companion documents:
`P0_VERIFICATION_ADDENDUM.md` (verification of prod's P0 fixes) ·
`DELIVERABLES_COMPLETENESS.md` (the fifteen deliverables, item by item).

---

## A. Files changed

Against the pre-extension merge base `4a87210`: **69 files, 10,609
insertions, 7 deletions.** Of that, 34 files and ~8,500 insertions are prod's
own P0 work, merged and verified but not authored here. The extension's own
contribution is **35 files, 2,090 insertions**.

### New Rust crate — `aip-standalone/aip-airi` (1,551 src + 2,009 test LOC)

| File | Lines | Purpose |
|---|---:|---|
| `src/event.rs` | 322 | `AiriEvent`, canonical preimage, sign, verify |
| `src/corroborate.rs` | 380 | Claim ⟷ observation comparison; the seal |
| `src/provenance.rs` | 297 | Model, tool, subprocess, framework, completion bodies |
| `src/chain.rs` | 179 | Per-execution hash chain |
| `src/integrate.rs` | 129 | Annotation beside a reconciliation, never inside it |
| `src/lib.rs` | 92 | Crate contract |
| `src/error.rs` | 73 | AIRI's own error type |
| `src/ids.rs` | 45 | Newtype identifiers |
| `tests/` (7 suites) | 2,009 | Binding, chain, adversarial, integration, NEXORA, interop, parity |

### New Python SDK — `sdk/python/vanian_airi` (1,946 src + 1,064 test LOC)

| File | Lines | Purpose |
|---|---:|---|
| `events.py` | 386 | Event model and preimage |
| `emitter.py` | 268 | Signing, chaining, the nine kinds |
| `context.py` | 268 | Execution context across four concurrency edges |
| `adapters/framework.py` | 195 | Agent-framework adapter |
| `identity.py` | 165 | Fail-closed key loading |
| `adapters/model.py` | 157 | Model / inference adapter |
| `adapters/tool.py` | 156 | Tool / API / effect adapter |
| `canonical.py` | 128 | Prefix-free encoder, byte-identical to Rust |
| `commitment.py`, `errors.py`, `__init__.py`, `adapters/__init__.py` | 223 | Commitments, failure modes, exports |
| `tests/` (5 suites) | 1,064 | Parity, boundary, context, end-to-end, schema conformance |

### Documentation (1,059 lines + 2 JSON schemas)

`docs/architecture/AIRI_{SPECIFICATION,THREAT_MODEL,LIMITATIONS,ARCHITECTURE,MIGRATION}.md`
· `docs/schemas/{README.md,airi-encoding.md,airi-event.schema.json,airi-bundle.schema.json}`

### Modified existing code

| File | Change |
|---|---|
| `aip-standalone/Cargo.toml` | `aip-airi` added as a workspace member |
| `aip-nexora/Cargo.toml` | `aip-airi` dependency (permitted: AIRI's reverse edge is a dev-dependency) |
| `aip-nexora/src/merkle.rs` | `LeafKind::AiriEvent = 0x09`, appended |
| `aip-nexora/src/proof.rs` | `AiriBundle`, `Component::Airi = 0x0A`, `NEXORA_PROOF_VERSION` 1 → 2 |
| `aip-nexora/src/verify.rs` | `verify_airi_bundle`, AIRI component verdict |
| `.gitignore` | Python bytecode caches |

**`aip-reconcile`, `aip-observe`, `aip-warrant`, `aip-containment`,
`aip-authorize`, `aip-core`, `aip-protocol` and `aip-service` are untouched
by this extension.** Changes in the first seven come from prod's P0 work;
`aip-service` is byte-identical to prod's, which is finding **B-1a**.

---

## B. New protocols and types

### Domains and codes

| Constant | Value | Note |
|---|---|---|
| `AIRI_EVENT_DOMAIN` | `SYNTRIASS/AIRI/EVENT/v1` | No collision with the 15 existing domains |
| `AIRI_PARAM_DOMAIN` | `SYNTRIASS/AIRI/PARAM_COMMITMENT/v1` | Not a bare SHA-256 |
| `AIRI_EVENT_VERSION` | `1` | Unknown versions refused, not interpreted |
| `LeafKind::AiriEvent` | `0x09` | Appended to a frozen set |
| `Component::Airi` | `0x0A` | Appended after `Commitment` |
| `NEXORA_PROOF_VERSION` | `1` → **`2`** | v1 packages refused, not reinterpreted |

### Types

`AiriEvent` (nine kinds) · `AiriPayload` (seven bodies) · `Corroboration`
(four outcomes, defaulting to `NotEvaluated`) · `CorroborationSeal`
(`#[non_exhaustive]`) · `VerifiedChain` (`#[non_exhaustive]`) ·
`AiriAnnotation` · `AiriBundle` · `AiriError`.

### Result classes added

**None.** Skill 15 permits new classes "only when the evidence semantics
require a new epistemic category", and none did: a claimed-but-unobserved AI
action is `PHANTOM_CLAIM`-shaped and an unobservable one is `CANNOT_PROVE`.

---

## C. Security invariants

Thirty-one, all holding. I-A1 to I-A26 are unchanged from rev 1; I-A27 to
I-A31 are new with the NEXORA and schema work.

| # | Invariant | Enforcement |
|---|---|---|
| I-A1 | An event cannot describe itself as independently observed | No constructor, field or variant exists |
| I-A2 | "Independent evidence agreed" is unforgeable by the agent | `#[non_exhaustive]` seal |
| I-A3 | AIRI cannot move a reconciliation verdict | No expression producing `ReconciliationResult`/`EvidenceStrength` |
| I-A4 | AIRI cannot reach `Proven` | Same |
| I-A5 | An agent signs only for itself | `signature.signer_id == agent_id` |
| I-A6 | Every binding field is signed | 8-field mutation sweep |
| I-A7 | The preimage is injective | Length prefixes, presence bytes |
| I-A8 | AIRI's domain is distinct from all others | Tested against 8 named domains |
| I-A9 | Commitments are not bare SHA-256 | Domain-tagged construction |
| I-A10 | Replay/dup/drop/reorder/splice detected | Hash chain |
| I-A11 | Deletion hidden by renumbering detected | `prev_event_hash` |
| I-A12 | No framework is a trust anchor | 5-name sweep, identical outcomes |
| I-A13 | Sensor downtime never becomes an accusation | `NotEvaluated` on unavailable |
| I-A14 | A vocabulary gap never becomes an accusation | `ActionClassNotComparable` |
| I-A15 | Corroboration joins on process *instance*, not pid | Full `ProcessInstance` |
| I-A16 | An unbound kernel event does not corroborate | `bound` required |
| I-A17 | Presence never corroborates an act | Exhaustive effect match |
| I-A18 | A model claim is never corroborated by a host observer | `is_externally_observable` |
| I-A19 | The SDK cannot self-prove or self-authorize | 14 forbidden names asserted absent |
| I-A20 | Identity loading fails closed, never regenerates | Tested: no key file created |
| I-A21 | Secrets never reach signed bytes | Commitments only |
| I-A22 | Context does not leak between concurrent tasks | `contextvars` |
| I-A23 | Context does not silently cross a thread | Explicit handoff required |
| I-A24 | The environment carries no key material | Identifiers only |
| I-A25 | Python and Rust preimages are byte-identical | 9 vectors, both directions |
| I-A26 | An AIRI leaf cannot be replayed as another kind | Kind code in the leaf preimage |
| **I-A27** | **A package cannot choose the key it is judged against** | Verifier's anchor wins; mismatch refused |
| **I-A28** | **The AIRI bundle is covered by `proof_id`** | Inside `canonical_bytes` |
| **I-A29** | **A broken AIRI bundle cannot lower a re-derived verdict** | Own component verdict; tested |
| **I-A30** | **An empty bundle is refused, not vacuously verified** | Explicit check |
| **I-A31** | **Published schemas cannot silently drift from the code** | 12 conformance tests |

**I-A27 is the most important of the new five.** Without it an assembler
could sign a fabricated event chain with its own key, place that key in the
bundle, and have every signature check out against the key the package
itself supplied. The verifier now uses its own anchor and refuses a package
naming a different one.

---

## D. Tests added

**143: 81 Rust, 62 Python.**

| Suite | Tests | Covers |
|---|---:|---|
| `aip-airi/tests/adversarial.rs` | 23 | The Skill 15 matrix; each test names the claim and what can be established |
| `aip-airi/tests/binding.rs` | 17 | Eight substitution classes; injectivity; domain separation; malformed keys; version |
| `aip-nexora/tests/airi.rs` | **14** | **Package carriage and offline re-derivation** |
| `aip-airi/tests/chain.rs` | 13 | Replay, duplicate, drop, reorder, splice, renumbering; the documented truncation limit |
| `aip-airi/tests/reconcile_integration.rs` | 7 | Composition against the **real** reconciler |
| `aip-airi/tests/nexora_commitment.rs` | 5 | Leaf-kind separation, order sensitivity, committed-bytes identity |
| `aip-airi/tests/python_interop.rs` | 1 | Rust verifies 5 Python-signed events + a bit-flip negative |
| `aip-airi/tests/parity_vectors.rs` | 1 (+1 generator) | Vector stability and distinctness |
| `sdk/python/tests/test_boundary.py` | 17 | The forbidden surface; fail-closed identity |
| `sdk/python/tests/test_context.py` | 15 | Four concurrency edges, propagation and isolation |
| `sdk/python/tests/test_schema_conformance.py` | **12** | **Schemas cannot drift from the code** |
| `sdk/python/tests/test_canonical_parity.py` | 11 | Byte-identity against 9 Rust-generated vectors |
| `sdk/python/tests/test_adapters_e2e.py` | 7 | Full agent run through all three adapters |

### Skill 15 matrix — 21 rows, 17 directly tested

Four rows are **inherited**: properties of `aip-authorize`, `aip-observe` or
`aip-reconcile`, tested there, which AIRI defers to rather than
re-implementing — observer-without-expectation, observer continuity break,
stale `ExpectedExecution`, expired authority. That is a real limit on this
suite's coverage and is stated rather than counted as a pass.

---

## E. Tests passed

| Run | Result |
|---|---|
| Baseline (prod merged, pre-AIRI) | 821 passed / 0 failed / 81 suites |
| After the AIRI core | 888 / 0 / 90 |
| After merging prod's P0 fixes | 898 / 0 / 90 |
| **After completing #7 and #11** | **912 passed / 0 failed / 4 ignored / 91 suites** |
| Python SDK | **62 passed / 0 failed** |
| `cargo clippy -p aip-airi --all-targets` | 0 warnings |

912 − 821 = 91 new Rust tests, of which 10 are prod's own P0 tests; 81 are
this extension's, matching §D.

**Flake.** `aip-observe` `fa05_live_a_write_by_this_process_is_bound_through_the_kernels_pidfd`
failed once during this session under `cargo test --workspace`, which
aborted the run and truncated the totals. It passed in three consecutive
isolated runs and on the final `--no-fail-fast` run. Pre-existing,
live-kernel, races filesystem activity from parallel test binaries. Neither
introduced nor fixed here.

### Defects this work found in itself

| Defect | Found by | Fix |
|---|---|---|
| Python `identity_bytes` used the wrong domain tag | Parity vectors | `GHOST/ExecutionIdentity/v1` |
| Python `identity_bytes` omitted the `version` field | Parity vectors | Added |
| Python `identity_bytes` length-prefixed a fixed-width digest | Parity vectors | Raw append |
| **Deliverable #11 reported done while materially incomplete** | Self-audit against the brief | §J |
| **12 `.pyc` build artifacts committed** | Staging review | Untracked; `.gitignore` updated |
| **Committed fixture regenerated nondeterministically every test run** | Stop-hook dirty-tree check | Execution id and clock pinned; byte-stability asserted |

The first three would have produced Python signatures committing to
different bytes than the Python side believed it signed. The parity test
caught them on its first run, which is the argument for having it.

---

## F. Properties established

Thirty-four in `docs/architecture/AIRI_LIMITATIONS.md` §1 with citations.
The load-bearing ones:

1. An AIRI event that verifies proves **authorship and integrity, never
   occurrence** — enforced structurally.
2. Cross-agent, cross-execution, cross-expectation, cross-model,
   cross-framework and cross-kind transplantation all fail.
3. Replay, duplication, drop, reordering and splicing are detected,
   including deletion hidden by renumbering.
4. **AIRI evidence cannot change the reconciler's verdict or strength** —
   proven against the real engine, in every corroboration shape, at 150
   accumulated corroborations.
5. Sensor downtime and vocabulary gaps never become accusations.
6. Python and Rust agree byte-for-byte, proven in both directions.
7. The SDK is structurally incapable of self-proving or self-authorizing.
8. Identity loading fails closed and never regenerates a key.
9. **A NEXORA package carries AIRI provenance and the offline verifier
   re-derives it** — signatures, chain and authorship — and **cannot be made
   to judge it against a key the package chose**.

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
| N-11 | That AIRI improves detection today | It contributes nothing to a verdict, by design |

N-11 remains the honest headline. AIRI makes agent claims **specific, bound,
checkable and now portable in a proof package**. It does not yet make the
system detect more.

---

## H. Forensic blockers

Both P0s were closed by prod during this session and independently verified
(`P0_VERIFICATION_ADDENDUM.md`). That verification found one new P1.

| ID | Blocker | Status |
|---|---|---|
| B-1 | Verifier clock semantics | **CLOSED** in `aip-protocol` (R16) |
| **B-1a** | `aip-service` supplies no verification time; `/verify` is unbounded and handlers read `result.valid` | **OPEN (P1) — new** |
| B-2 | Issuer/grantee binding | **CLOSED**, unconditional, fully adopted |
| B-3 | Real engine-produced containment path | OPEN |
| B-4 | Bundle signer trust | OPEN |
| B-5 | Private-key storage | OPEN (the SDK refuses to *read* a world-readable key; the writer is unchanged) |
| B-6 | Service key-regeneration | OPEN in `aip-service`; the SDK's own loader fails closed |
| B-7 | Private seed handling | OPEN |
| B-8 | Sealed reconciliation result construction | OPEN |
| B-9 | Packet replay undetected | OPEN |
| B-10 | Service integration (no workspace) | OPEN — **now demonstrably load-bearing: B-1a exists because of it** |

**Eight open, plus one new P1.** Seven of the nine sit in or depend on the
service tier and its exclusion from the workspace.

AIRI closes none of them. The two closures are prod's work, verified here
rather than accepted on the strength of their commit messages.

---

## I. Is production promotion permitted?

# NO.

The gap has narrowed materially — from "two P0s under the protocol's central
claim" to "one P1 in the service request path plus the structural exclusion
that caused it" — but three reasons stand, any one sufficient:

1. **B-1a is the original P0 wearing a different hat.** The `/verify`
   endpoint answers `valid: true` for a future-dated packet, and every
   handler decides on that boolean. The protocol-layer fix does not reach
   the service's callers.

2. **AIRI contributes nothing to a verdict.** Deploying it yields signed,
   checkable, portable claims and no additional detection. That is correct
   staging, and it means there is nothing to promote *for*.

3. **No production evidence exists.** Every property here is CODE-PROVEN,
   TEST-PROVEN or EXECUTION-PROVEN in a harness. Corroboration rates against
   real traffic are unmeasured and the false-positive behaviour of
   `uncorroborated` on real agent workloads is unknown. A detection signal
   whose false-positive rate has never been characterised should not be put
   in front of an operator.

**What promotion would require**, in order: close **B-1a** and **B-10**
together, since the second causes the first; close B-5 to B-7; resolve B-3
and B-8; run stages 1–2 of `AIRI_MIGRATION.md` §5 and characterise the
false-positive rate; then build the §4 entry point with an adversarial suite
of comparable depth to the existing reconciler's.

No post-quantum claim is made anywhere in this extension, because no
post-quantum cryptography is implemented on this branch.

---

## J. Correction to revision 1

Rev 1 §A stated deliverable **#11, NEXORA package/verifier integration**, as
delivered. It was not.

**What existed:** one appended enum variant, `LeafKind::AiriEvent`. An event
could be committed as a Merkle leaf. `NexoraProof` had no field to carry AIRI
events and `verify.rs` contained no AIRI code — `grep -n 'airi'` across
`aip-nexora/src` returned nothing. The package could not carry AI-stack
provenance and the offline verifier could not re-derive it, which is most of
the deliverable.

**How the error was made:** I added the leaf kind, wrote five passing tests
against it, and let "the tests are green" stand in for "the deliverable is
met". The tests were checking a commitment primitive, not the package
integration the brief asked for. That is precisely the substitution the
master audit's rule 7 exists to catch — *"do not treat tests as proof unless
the tests actually exercise the relevant security property"* — committed in
my own work while auditing someone else's.

**How it was caught:** by auditing my own output against the brief's fifteen
deliverables rather than against my own summary of them, prompted by a direct
question about completeness.

**Now closed**, with 14 tests, per §B, §C (I-A27 to I-A30) and §D.

Deliverable **#7, canonical schemas**, was absent in rev 1 and is not a
correction so much as an omission; it is now closed with `docs/schemas/` and
12 conformance tests.

The general lesson, recorded because it applies beyond this document: a green
test suite establishes that the assertions written hold, never that the
assertions cover the requirement. Checking the second needs the requirement
in hand, not the test list.
