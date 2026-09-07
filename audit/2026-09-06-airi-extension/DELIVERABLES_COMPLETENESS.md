# Deliverables — Completeness Matrix

Answers one question: **do we have everything the brief asked for?**

Written after an audit of my own output. Two items were incomplete when the
extension audit was first filed, and one of those I had reported as done.
Both are now closed; the over-claim is recorded rather than quietly fixed.

---

## The fifteen deliverables

| # | Deliverable | Status | Where |
|---|---|---|---|
| 1 | AIRI protocol specification | **DONE** | `docs/architecture/AIRI_SPECIFICATION.md` |
| 2 | Threat model | **DONE** | `docs/architecture/AIRI_THREAT_MODEL.md` |
| 3 | Python SDK / reference boundary | **DONE** | `sdk/python/vanian_airi/` |
| 4 | One reference agent-framework adapter | **DONE** | `adapters/framework.py` |
| 5 | One model / inference adapter | **DONE** | `adapters/model.py` |
| 6 | One tool / API adapter | **DONE** | `adapters/tool.py` |
| 7 | Canonical schemas | **DONE** *(was missing)* | `docs/schemas/` |
| 8 | Cryptographic binding tests | **DONE** | `aip-airi/tests/binding.rs` — 17 |
| 9 | Adversarial substitution / replay tests | **DONE** | `adversarial.rs` 23, `chain.rs` 13 |
| 10 | Reconciliation integration | **DONE, scoped** | `integrate.rs`, `reconcile_integration.rs` — 7 |
| 11 | NEXORA package / verifier integration | **DONE** *(was partial, over-claimed)* | `aip-nexora/{proof,verify}.rs`, `tests/airi.rs` — 14 |
| 12 | Limitations / evidence classification | **DONE** | `docs/architecture/AIRI_LIMITATIONS.md` |
| 13 | Migration / versioning plan | **DONE** | `docs/architecture/AIRI_MIGRATION.md` |
| 14 | Architecture diagrams / docs | **DONE** | `docs/architecture/AIRI_ARCHITECTURE.md` |
| 15 | Final audit report | **DONE** | `AIRI_EXTENSION_AUDIT.md` + two addenda |

---

## The two gaps, and what they were

### #11 NEXORA — I over-claimed this

**What I reported:** "NEXORA package/verifier integration — done."

**What actually existed:** one appended enum variant, `LeafKind::AiriEvent`.
An AIRI event could be committed as a Merkle *leaf*. But `NexoraProof` had no
field to carry AIRI events at all, and `verify.rs` contained no AIRI code —
`grep -n 'airi' aip-nexora/src/{proof,verify}.rs` returned nothing.

So the proof package could not carry AI-stack provenance, and the offline
verifier could not re-derive it. That is most of deliverable #11, and calling
it done was wrong.

**Why I got it wrong:** I added the leaf kind, wrote five passing tests
against it, and let "the tests are green" stand in for "the deliverable is
met". Exactly the substitution the forensic discipline exists to catch —
`aip-nexora/tests/airi.rs` was checking a commitment primitive, not the
package integration the brief asked for.

**Now closed:**

* `AiriBundle { agent_id, agent_public_key, events }` on `NexoraProof`
* `Component::Airi = 0x0A`, appended; `NEXORA_PROOF_VERSION` 1 → 2
* Inside `canonical_bytes`, so the bundle is covered by `proof_id` — otherwise
  an assembler could swap the AI-stack evidence without changing the id any
  commitment was taken over
* `verify_airi_bundle` re-derives every signature and re-walks the chain
* 14 tests, including the one that matters most: **a package cannot choose
  the key it is judged against.** An assembler that signs a fabricated chain
  with its own key and puts that key in the bundle is refused, because the
  verifier's anchor wins.

### #7 Canonical schemas — simply absent

No formal schema artifact existed. Now `docs/schemas/` carries
`airi-event.schema.json`, `airi-bundle.schema.json` and the normative
`airi-encoding.md`, with `test_schema_conformance.py` (12 tests) checking the
codes, domains and versions in the docs against the code so they cannot drift.

Every schema states, in its own `description`, that it is **non-normative**
and that a verifier must check the byte preimage. A schema that let someone
believe validating JSON was verifying a signature would be worse than no
schema.

---

## Requirements beyond the numbered list

| Requirement | Status |
|---|---|
| AIRI event model — 9 named types | **DONE**, all nine |
| Framework-neutral, thin adapters | **DONE**; `no_framework_is_a_trust_anchor` sweeps five names |
| Bind agent / execution / expectation / model / tool / framework / parent | **DONE**, all in the signed preimage |
| No secrets or raw payloads in evidence | **DONE**, commitments only, tested with a synthetic secret |
| Domain separation, prefix-free, versioned | **DONE**, two new domains, no collision with the existing fifteen |
| Substitution / tamper / replay tests | **DONE**, 53 across three suites |
| Python context propagation, 4 edges | **DONE**, 15 tests including a real subprocess |
| SDK must-nots (6 in Skill 12) | **DONE**, 5 by absence + introspection, 1 by behaviour |
| Declared ≠ selected ≠ executed ≠ effect | **DONE**, tables in the spec and limitations |
| No second reconciliation system | **DONE**, annotation only; non-escalation proven against the real engine |
| Default posture stays CANNOT_PROVE | **DONE**, tested |
| Only add result classes if needed | **DONE — none added**, every outcome maps onto the existing vocabulary |
| Offline verifier re-derives, refuses non-derivable | **DONE**, extended to AIRI |
| No PQC claims | **DONE — none made** |

### Skill 15 test matrix — 21 rows

Seventeen are directly tested with AIRI evidence present. Four are
**inherited**: they are properties of `aip-authorize`, `aip-observe` or
`aip-reconcile`, tested there, and AIRI defers to them rather than
re-implementing the check.

| Inherited row | Owned by | Why not re-tested here |
|---|---|---|
| observer sees execution without matching expectation | `aip-reconcile` `UNATTRIBUTED_EFFECT` | AIRI adds no path to it |
| observer continuity break | `aip-observe` | AIRI reads `ObservationAvailability` and returns `NotEvaluated` |
| stale ExpectedExecution | `aip-authorize` `TemporalStatus` | AIRI carries `decision_id`, does not adjudicate it |
| expired authority | `aip-core` | same |

That is a real limit on this suite's coverage and is stated rather than
counted as a pass.

---

## What is deliberately NOT done

Neither is an oversight; both are recorded with the reasoning.

| # | Not done | Why |
|---|---|---|
| 1 | `reconcile_airi_claim` — an entry point letting an uncorroborated AIRI claim reach `PHANTOM_CLAIM` | A new way to accuse. The existing phantom-claim path needed recomputed coverage, a sealed identity comparison and 1,419 lines of adversarial tests before it could say "this did not happen". Four prerequisites in `AIRI_MIGRATION.md` §4. |
| 2 | Fixing **B-1a** (`aip-service` supplies no verification time) | Outside the extension's scope, and patching during an audit pass is what the forensic discipline forbids. Remedy specified in `P0_VERIFICATION_ADDENDUM.md` §2.4. |

---

## Evidence

| Run | Result |
|---|---|
| `cargo test --workspace --no-fail-fast` | **912 passed / 0 failed / 4 ignored / 91 suites** |
| Python SDK | **62 passed / 0 failed** |
| `cargo clippy -p aip-airi --all-targets` | 0 warnings |

Baseline before any of this work: 821 / 81 suites. **+91 Rust tests, +62
Python.**

`fa05_live_a_write_by_this_process_is_bound_through_the_kernels_pidfd`
(`aip-observe`) flaked once during this session and passed in three
consecutive isolated runs and on the final full run. Pre-existing, live-kernel,
races filesystem activity from parallel test binaries. Not introduced here and
not fixed here.

---

## So: do we have everything?

**The fifteen deliverables: yes, now.** Two were not there when I first said
they were, and #11 I had actively mis-reported.

**Production promotion: still no**, and unchanged by any of this. Eight
forensic blockers remain open plus B-1a, AIRI still contributes nothing to a
verdict by design, and there is no production evidence for its false-positive
behaviour. Completeness of the deliverables and readiness for production are
different questions, and only the first one is now answered yes.
