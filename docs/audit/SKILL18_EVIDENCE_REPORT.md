# Skill 18 — Autonomous Execution Model: Evidence Report

**Branch** `claude/autonomous-accountability-skills-16-30`
**Specification** `docs/architecture/AUTONOMOUS_EXECUTION_MODEL.md`
**Threat model** `docs/architecture/AUTONOMOUS_EXECUTION_THREAT_MODEL.md`
**ADR in force** `docs/architecture/ADR-001-AUTONOMOUS-CONTAINMENT.md`
(PROVISIONAL / IMPLEMENTATION-GUIDING, untouched by this work)

---

## 1. Files

### Read before designing

`aip-authorize/src/expected.rs` (`ExpectedExecution`, `ActionParameters`,
`AuthorityRef`, `verify_expected_execution`), `aip-airi/src/event.rs` and
`src/provenance.rs` (`AiriEvent`, `ModelProvenance`, `ToolInvocation`,
`ToolReport`, `ReportedOutcome`), `aip-observe/src/observed.rs`
(`ObservedEffect`), `aip-types/src/lib.rs` and `src/canonical.rs`,
`aip-system/src/*` (Skill 17), `aip-reconcile/src/result.rs`.

### Changed

| File | Change |
|---|---|
| `Cargo.toml` (root) | +1 workspace member |
| `aip-standalone/aip-execution/**` | new crate: 5 source files, 3 test files |
| `docs/architecture/AUTONOMOUS_EXECUTION_MODEL.md` | new |
| `docs/architecture/AUTONOMOUS_EXECUTION_THREAT_MODEL.md` | new |

**No existing source file was modified.** No public structure changed, no wire
format changed, no existing serialized data is reinterpreted.

## 2. Reuse — what was deliberately not built

Nine of the twelve stages already had authoritative types. Building them again
would be the duplication the skill forbids, and a second definition is a second
place for the truth to drift.

| Stage | Reused from | Referenced how |
|---|---|---|
| ExpectedExecution | `aip-authorize`, DP-signed | `decision_id` |
| AI claim / model / tool / runtime report | `aip-airi`, agent-signed chain | `airi_chain_head` commitment |
| Process, container | `aip-types::ExecutionBinding` | inside `SystemExecution` |
| Device, platform | `aip-system` (Skill 17) | inside `SystemExecution` |
| Independent observation | `aip-observe` | referenced by `EffectEvidence` |
| Reconciliation, proof | `aip-reconcile`, `aip-nexora` | not referenced — this is their input |

Asserted mechanically: `no_primitive_is_duplicated` scans this crate's code for
redefinitions of `ExpectedExecution`, `ExecutionBinding`, `AiriEvent`,
`ObservedExecution`, `AttestedBatch` and `derive_aip_id`.

## 3. New types

Four, and only where nothing existed:

| Type | Why nothing covered it |
|---|---|
| `ExecutionStage` + `EvidenceOrigin` | The ladder existed only as prose across crate docs, so nothing checked it |
| `RequestedEffect`, `RuntimeAction`, `EffectEvidence`, `EffectDisposition`, `EffectOutcome` | `ObservedEffect` covers process presence and kernel sockets; there was **no model of an effect outside the host at all** |
| `RuntimeDeclaration` | Runtime was a single self-reported string with nowhere to record a measurement |
| `ExecutionProfile` | The composition, and the carrier of the DP binding |

## 4. Signed-carrier decision

**No new trust anchor was introduced.** The STOP condition was not reached.

Only the four Skill 17 identifiers were unanchored; `agent_id`,
`execution_id`, `execution_binding` and `decision_id` are already carried by a
DP signature or an agent signature. So the question narrowed to whether an
existing signer could legitimately attest system, platform, hardware and
mission — and one can.

`ExpectedExecution.parameter_digest` is the decision point's signature over
`ActionParameters`, an **open, key-sorted, domain-separated map**. A reserved
key `aip.execution_profile.v1` carrying the profile digest becomes part of what
the DP already signs.

- **No wire-format change.** `ActionParameters` was always an open map.
- **No new signer.** The DP's existing key does the work.
- **Correct authority.** The decision point decides what an agent may do, and
  "for this system, on this platform, for this mission" is part of that
  decision rather than a fact bolted on afterwards.
- **Versioned in the key**, so a v1 binding can never be read as a v2 one.

**TEST-PROVEN** against a real `DecisionPoint`, a real authority chain and a
real signature (`tests/binding.rs`, 7 tests) — not asserted in prose.

### What it does not establish

`the_binding_establishes_authorization_not_attestation` exists so this cannot
be quietly forgotten: the decision point signs a claim about hardware it never
measured. The signature is valid and the claim is unverified, both at once.
An execution authorized for platform P and running on Q is **not detected**.
That is T13, and it needs Skill 19 or Skill 20.

## 5. Trust boundaries preserved

| Boundary | How |
|---|---|
| self-report ≠ independent observation | Stages 4-7 are `SelfReported` by construction; `may_establish` refuses the crossing |
| tool success ≠ external effect | `Confirmed` unconstructible from a `RuntimeAction` |
| model claim ≠ runtime evidence | four runtime fields, no fallback between them |
| observation ≠ automatically Proven | this crate computes no strength; the word does not appear in its code |
| CANNOT_PROVE ≠ failure | `NotEvaluated` and `Unconfirmed` are distinct and neither asserts non-occurrence |
| AIRI stays application-layer | committed to by hash, never promoted |
| one reconciliation engine | no verdict vocabulary here, asserted by a code scan |
| no observer keys outside `aip-observe` | `EffectEvidence` is a *reference* for that model to resolve; it holds no key and verifies nothing |

## 6. Adversarial matrix

29 tests covering the skill's 25 cases; four cases were split where one
assertion could not carry the whole boundary.

Cross-agent (a01), cross-execution (a02), cross-platform (a03), cross-hardware
(a04), cross-mission (a05), cross-decision (a06), cross-model (a07),
cross-framework (a08), parameter (a09), temporal (a10), stale expectation
(a11), replay (a12), duplication (a13), reordering (a14), omission (a15),
claimed-without-observed (a16), observed-without-claim (a17), tool success
without effect evidence (a18, a18b, a18c), model claim without runtime evidence
(a19), malformed (a20), unsupported version (a21), canonical collision (a22,
a22b), forged binding (a23), transplantation (a24), serialization substitution
(a25, a25b).

**What these establish, precisely.** `ExecutionProfile` is unsigned. An
unsigned record cannot stop anyone writing what they like into it, and the
tests do not pretend otherwise. What they establish is that a substitution
changes the canonical bytes and the digest — so the DP signature no longer
matches and the substitution cannot be *silent*. Prevention is the DP
signature, exercised in `binding.rs`.

## 7. Mutation results

| Mutation | Expected to break | Result |
|---|---|---|
| A 200 response confirms the effect | the effect boundary | **3 fail** ✓ |
| Self-reports may establish occurrence | the ladder | **2 fail** ✓ |
| Runtime slots collapse to one encoding | claim vs measurement | **2 fail** ✓ |
| Effects encoded as an unordered set | duplication and ordering | **2 fail** ✓ |
| Profile digest omits the embedded execution | the binding | **3 fail** ✓ |

## 8. Errors found in my own work, and what was done

Three, recorded because a report that lists only successes is not evidence.

1. **A real defect in the implementation.** `EffectEvidence` derived
   `Deserialize`, so serde constructed it field by field and a JSON writer
   obtained a value the constructor refuses — an empty observer id was
   accepted. Found by probing rather than assumed absent. Fixed with
   `#[serde(try_from)]` and pinned by `a25b`.
2. **A test that miscounted its own boundary.** The over-long observer-id case
   hand-wrote 127 x's where it needed 129 and passed vacuously. It now computes
   the string and checks both sides of the limit.
3. **A test that would have degraded the code to satisfy itself.** The
   no-second-engine scan failed on the doc comment explaining that
   `EvidenceOrigin` is deliberately *not* `EvidenceStrength` — the single most
   important sentence in that module. Removing the sentence would have been
   exactly backwards; the test now strips comments and checks code.

## 9. Test results

```
cargo test -p aip-execution     43 passed, 0 failed
    boundary_attacks   29
    binding             7
    compatibility       7
cargo test --workspace         111 suites, 1099 passed, 0 failed, 6 ignored
cargo test -p airon-aip         79 passed, 0 failed
cargo clippy --workspace --all-targets   clean
cargo fmt --all -- --check               clean
```

Workspace members: 20 → **21**.

## 10. Compatibility

- No wire format changed; the binding rides an existing open map.
- No existing serialized data reinterpreted.
- Unknown versions refused, not guessed — and `check_version` also re-checks
  the embedded `SystemExecution`, because a profile is only as well formed as
  what it contains.
- Dependency direction asserted by test in both directions: no verdict-path
  crate depends on `aip-execution`, and `aip-execution` does not depend on any
  of them at runtime (`aip-authorize` and `aip-core` are dev-dependencies, for
  the binding test only).

## 11. B-3 interaction

**Not solved here, and its boundary is untouched.** ADR-001 remains
authoritative. Nothing in this work lowers an evidence threshold, bypasses
availability semantics, manufactures `Proven`, treats absence as proof, or
connects containment to AIRI claims.

The contribution is structural, not evidential. ADR-001 §Q13 identifies the
legitimate future path to a `Proven` workload violation as agent-side
cryptographic equivocation. The stage ladder makes the places such a
contradiction could arise explicit and nameable — stages 4-7 are all
agent-signed and chained — which is what a future evidence path would need in
order to be specified. It does not supply that path.

## 12. Remaining risks

1. **T13 — authorized ≠ attested.** The binding proves the DP authorized a
   context. Nothing proves the execution ran in it. This is the sharpest
   limitation of the skill and is stated in the model, the threat model, and a
   test.
2. **T15 — physical effects.** `EffectEvidence` exists; no independently
   anchored physical sensor does. Every physical-effect claim disposes to
   `NotEvaluated` today.
3. **T2 / T5 — model runtime.** `model requested ≠ served ≠ loaded ≠ executed`
   remains unproven at every rung. The evidenced slot exists; nothing fills it.
4. **`ExecutionProfile` is unsigned**, like Skill 17's descriptors. Its
   integrity comes entirely from the DP binding, so a profile that was never
   bound carries none.
5. **Nothing consumes this model yet.** The abstraction and its binding exist;
   no producer emits profiles and no reconciler input path reads them. The
   capability is the abstraction, not its use, and this report does not claim
   otherwise.
6. **Pre-existing load-sensitive flakes** unchanged: `live_freeze::f_p_a_*`
   and `aip-observe fa05_live_*`.
7. **PostgreSQL store** still never compiled or exercised.

## 13. Gate

| Criterion | Status |
|---|---|
| 1. Precise execution lifecycle | **MET** — 12 ordered stages, `ALL` swept by test |
| 2. AIP authority semantics intact | **MET** — no existing file modified |
| 3. ExpectedExecution distinct from AI intent and runtime claims | **MET** — separate stages, separate origins, `may_establish` refuses the crossing |
| 4. Runtime represented without claiming proof | **MET** — four slots, mutation-checked |
| 5. External effect separated from tool success | **MET** — `Confirmed` unconstructible from `RuntimeAction` |
| 6. Independent observation remains the evidence boundary | **MET** — `EffectEvidence` is a reference; no keys here |
| 7. One verdict engine | **MET** — code scan for verdict vocabulary |
| 8. No trust anchor introduced accidentally | **MET** — binding reuses the DP signature; asserted by test |
| 9. Substitutions rejected | **MET** — 29 tests, 5 mutations |
| 10. Canonical fields committed | **MET** — nothing security-relevant outside the preimage |
| 11. Versioning explicit | **MET** — refused, not guessed, including embedded records |
| 12. B-3 boundary untouched | **MET** |
| 13. All tests pass | **MET** — 1099 / 0 |
| 14. Production readiness unclaimed | **MET** |

**Skill 18: PASS.**

### Is Skill 19 permitted?

**Yes**, and it is the right next skill: T13 is the sharpest open risk in this
work, and Skill 19 (Edge Hardware Identity and Binding) is what closes it.

One condition, stated so it is not discovered late: Skill 19 will be tempted to
add a hardware signing key. That would be a new trust anchor. It may well be
the correct one — a hardware root of trust is a genuinely different kind of
thing from the anchors that exist — but it must be reached the way ADR-001
requires: documented as a missing trust boundary, with why existing artifacts
are insufficient, the minimum new primitive, and its security and migration
implications, *before* it is implemented.

**Production readiness is not claimed and nothing was merged to main.**
