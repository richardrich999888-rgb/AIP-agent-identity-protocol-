# Mutation Assurance — the Authoritative Reconciler and Verifier

**Baseline HEAD** `2f13b7788dd648aa3bd544e1a6f722171fbb51b3`
**Branch** `claude/skill-25-implementation-xbz0t3`
**Working tree at start** clean
**Harness** `validation/mutation/mutate_core.py`
**Machine-readable result** `validation/mutation/CORE_MUTATION_RESULTS.json`

Closes the gap `docs/SKILL_CONFORMANCE_27_FULL_RUN.md` §11.1 ranked first:

> Skills 7 and 10 are the sole authorities for their questions, they carry 351
> tests between them, and **nothing establishes that those tests would fail if
> the reconciliation or verification logic underneath them were broken.**

Something establishes it now.

---

## 1. Baseline implementation

| | `aip-reconcile` (Skill 7) | `aip-nexora` (Skill 10) |
|---|---|---|
| Role | the single authoritative reconciler | the single authoritative verifier |
| Source | 4,182 lines over 6 modules | 3,696 lines over 8 modules |
| Tests | 10 integration files, 8,960 lines | 16 integration files, 6,383 lines |
| Test count before this work | 173 | 178 |
| Public entry points | `reconcile_expectation`, `reconcile_observation`, `reconcile_lineage` | `verify_nexora_proof`, `verify_proof`, `verify_signed_head`, `HeadTracker::advance` |
| Mutation evidence before this work | **none** | **none** |

Both were exercised at HEAD before any change: 351 tests, 0 failures. That is
the state the exercise had to falsify — a suite that passes says nothing until
it has been shown capable of failing for the right reason.

---

## 2. Mutation methodology

The methodology Skills 11–27 established, unchanged. A result is
interpretable only once the mutation is proven to have been active. For every
mutation, in order:

1. the `old` fragment is located in the file and must occur **exactly once** —
   a fragment matching two sites is a harness defect, not a mutation, because
   the result would not say which site is covered;
2. the file is rewritten and its SHA-256 must differ;
3. the crate's test targets are **compiled** — a mutation that does not build
   was never active and is recorded as `HARNESS_DEFECT_DOES_NOT_COMPILE`,
   never as a kill and never as a survivor;
4. the crate's full test set is run with `--no-fail-fast`;
5. at least one test must **fail**, otherwise the mutation **SURVIVED**;
6. the file is restored from the bytes read in step 1 and the restored digest
   must equal the original.

Step 6 runs in a `finally`, and a whole-run restore runs in an outer `finally`,
so an interrupted run cannot leave a mutated tree. The final artifact records
`all_files_restored_byte_identical`, which is **true** for this run, and
`git diff` over `aip-standalone/*/src/` is empty at the end.

### What is and is not a target

Every mutation inverts, removes or downgrades **one security or correctness
invariant observable from outside the crate**. Formatting, logging,
unreachable branches and representation choices are not targets: killing those
would prove nothing and would pad the count.

Two consequences of taking that seriously, both visible in §3:

- **Where an invariant is stated at more than one entry point, each site is a
  separate mutation** (`R-11`/`R-11b`, `R-12`/`R-12b`, `R-13`/`R-13b`). A
  single mutation replacing every occurrence would have been killed by the
  expectation-path test and would have hidden that the lineage path was
  unguarded. Two of this run's findings are exactly that case.
- **A mutation that cannot be written is reported, not counted.** `N-01` was
  first drafted as "the bundle supplies its own signer key" (forensic blocker
  B-4). It does not compile, because `SignedHead` has no field for a key: the
  attack has no surface in the type. That is a stronger result than a kill,
  and it is recorded as such rather than as a mutation. `N-01` was re-aimed at
  the expressible half of the same invariant — key-version binding — which
  then survived and needed a test.


---

## 3. Mutation matrix

46 mutations: **24 against `aip-reconcile`**, **22 against `aip-nexora`**.

The *first pass* column is the result before any test was added — the honest
baseline (`baseline_mutations.json`). *tests failing* and *first killer* are
from the final pass against the code as it now stands.

### 3.1 `aip-reconcile` — 24 mutations

| # | file | invariant broken | first pass | tests failing | first killer |
|---|---|---|---:|---:|---|
| R-01 | `reconcile.rs` | a structurally or cryptographically invalid expectation cannot yield a verdict | killed | 1 | `t12_tampered_or_untrusted_expectation_is_can…` |
| R-02 | `reconcile.rs` | missing observer evidence is CANNOT_PROVE, never a verdict (absence is not evidence) | killed | 2 | `t22_no_observer_evidence_is_cannot_prove_wit…` |
| R-03 | `reconcile.rs` | an invalid observer signature is an integrity failure, not mere inability to prove | killed | 9 | `caller_cannot_assert_verification_through_th…` |
| R-04 | `reconcile.rs` | batches from a second observer cannot be mixed into one observer's chain | killed | 1 | `t16b_batches_from_a_second_trusted_observer_…` |
| R-05 | `reconcile.rs` | two validly signed batches at one sequence are a proven observer fork | killed | 1 | `t15b_forked_chain_signed_by_the_collector_ke…` |
| R-06 | `reconcile.rs` | a gap in the batch sequence is an incomplete observation set | killed | 1 | `t03b_withholding_the_batch_with_the_observat…` |
| R-07 | `reconcile.rs` | a broken prev_head linkage is an observer chain break | killed | 1 | `t15b_forked_chain_signed_by_the_collector_ke…` |
| R-08 | `reconcile.rs` | batches withheld from the tail of the chain are detectable against the health record | killed | 1 | `t16_health_and_chain_must_agree_on_the_head` |
| R-09 | `reconcile.rs` | a replayed batch is recorded as replay, not silently deduplicated | killed | 3 | `t15_replayed_batch_is_collapsed_and_flagged_…` |
| R-10 | `reconcile.rs` | I10 — an observer anchored to the agent's own key is not independent | **survived** | 1 | `t13d_an_observer_anchored_to_the_agents_key_…` |
| R-11 | `reconcile.rs` | reconcile_expectation: a quarantined observer yields SensorIntegrityFailure, never a positive verdict | *defect* | 1 | `t17b_quarantined_observer_is_integrity_failu…` |
| R-11b | `reconcile.rs` | reconcile_lineage: a quarantined observer yields SensorIntegrityFailure, never a positive verdict | *defect* | 1 | `lv18_a_quarantined_observer_stops_lineage_an…` |
| R-12 | `reconcile.rs` | reconcile_expectation: an observer whose integrity is unknown cannot support a positive verdict | killed | 1 | `t03d_integrity_unknown_state_is_cannot_prove…` |
| R-12b | `reconcile.rs` | reconcile_lineage: an observer whose integrity is unknown cannot support a positive verdict | **survived** | 1 | `lv17_integrity_unknown_blocks_lineage_exactl…` |
| R-13 | `reconcile.rs` | reconcile_expectation: a degraded observer cannot support a positive verdict | killed | 5 | `n13_counted_loss_around_the_action_is_cannot…` |
| R-13b | `reconcile.rs` | reconcile_lineage: a degraded observer cannot support a positive verdict | killed | 1 | `lv14_observer_gates_apply` |
| R-14 | `reconcile.rs` | matching and divergent observations together are ambiguous, not a match | killed | 2 | `t06b_matching_and_divergent_observations_tog…` |
| R-15 | `reconcile.rs` | ambiguous identity is CANNOT_PROVE | killed | 2 | `t06b_matching_and_divergent_observations_tog…` |
| R-16 | `reconcile.rs` | a stale health record settles nothing about the window | killed | 1 | `t11b_stale_health_is_cannot_prove` |
| R-17 | `reconcile.rs` | a forward-set collector clock cannot saturate staleness to age zero | killed | 2 | `r3_health_emitted_after_the_verification_tim…` |
| R-18 | `reconcile.rs` | reconcile_expectation: an Open-policy (unverified-provenance) mechanism label cannot support a match | killed | 4 | `n10_fabricated_evidence_under_open_provenanc…` |
| R-19 | `reconcile.rs` | action evidence that does not match the expectation is not a verified execution | killed | 4 | `xe02_the_path_never_enters_the_digest_only_t…` |
| R-20 | `reconcile.rs` | action evidence preceding its authorization does not verify the execution | killed | 6 | `xe08_spawn_before_the_decision_precedes_auth…` |
| R-21 | `result.rs` | a record read back from bytes is not engine-produced, however faithful (B-9 seal) | **survived** | 1 | `t22_a_record_read_back_from_bytes_is_never_e…` |

### 3.2 `aip-nexora` — 22 mutations


| # | file | invariant broken | first pass | tests failing | first killer |
|---|---|---|---:|---:|---|
| N-01 | `commitment.rs` | an anchor is bound to (signer_id, key_version): a head naming another key version is not verified by this key | *defect* | 1 | `x18_an_anchored_signer_at_an_unanchored_key_…` |
| N-02 | `commitment.rs` | the signature's signer_id must be the head's signer_id | **survived** | 1 | `x16_a_signature_naming_another_signer_is_ref…` |
| N-03 | `commitment.rs` | the signed payload hash must be the hash of the head's own preimage | killed | 3 | `x02_a_head_altered_after_signing_or_signed_b…` |
| N-04 | `commitment.rs` | a head whose Ed25519 signature does not verify is refused | killed | 2 | `x02_a_head_altered_after_signing_or_signed_b…` |
| N-05 | `commitment.rs` | a head declaring an unsupported NEXORA version is refused | **survived** | 1 | `x17_a_validly_signed_head_at_an_unknown_vers…` |
| N-06 | `commitment.rs` | a proof must name the same log as the head it carries | killed | 1 | `x07_a_proof_cannot_be_transplanted_to_anothe…` |
| N-07 | `commitment.rs` | the inclusion proof's tree size must be the head's size | killed | 1 | `x07_a_proof_cannot_be_transplanted_to_anothe…` |
| N-08 | `commitment.rs` | the record must actually be included under the head's committed root | killed | 2 | `g10_07_a_commitment_altered_in_transit_fails…` |
| N-09 | `commitment.rs` | a head tracker never accepts a rollback to a smaller tree | killed | 2 | `x10_rollback_is_refused` |
| N-10 | `commitment.rs` | two distinct heads at one size are a fork | killed | 1 | `x11_a_fork_is_refused` |
| N-11 | `commitment.rs` | an extension without a valid consistency proof is refused | killed | 2 | `x13_a_consistency_proof_that_does_not_fit_is…` |
| N-12 | `verify.rs` | a claimed verdict that the verifier cannot re-derive is refused (the package's own claim is never trusted) | killed | 3 | `t_altered_verdict_cannot_prove_never_becomes…` |
| N-13 | `verify.rs` | a refused package establishes no result and no strength | killed | 9 | `a_proof_substitution_a_package_is_evidence_o…` |
| N-14 | `verify.rs` | a structurally faulty package is refused before any component is credited | killed | 5 | `f_expected_execution_substitution_the_claim_…` |
| N-15 | `verify.rs` | a package whose components are not bound to one another is refused | killed | 9 | `d_identity_substitution_a_document_for_anoth…` |
| N-16 | `verify.rs` | a package declaring a version this verifier does not understand is refused | killed | 6 | `o_malformed_package_is_refused_rather_than_p…` |
| N-17 | `verify.rs` | a carried-but-unreached component is Unverifiable, never Absent (absence of evidence is not evidence of absence) | killed | 2 | `g_observation_substitution_an_edited_event_b…` |
| N-18 | `verify.rs` | independence is what THIS verifier checked, not what the package asserts (Defect #5) | killed | 2 | `d5b_independence_is_what_this_verifier_did_n…` |
| N-19 | `verify.rs` | a verified continuity break is reported as discontinuous, never softened | killed | 3 | `i_continuity_rollback_a_reported_break_never…` |
| N-20 | `verify.rs` | a declared parameter beyond the verifier's own bound is refused, not silently accepted | killed | 8 | `n_verifier_context_substitution_a_package_ca…` |
| N-21 | `verify.rs` | a verifier that bounds reconciliation age but holds no clock refuses rather than skipping the check | killed | 1 | `adv08_a_narrow_verifier_refuses_every_broad_…` |
| N-22 | `verify.rs` | an observer anchored to the agent's own key is not independent (I10, verifier side) | **survived** | 1 | `w_the_agent_as_its_own_observer_is_refused_o…` |

---

## 4. Mutation count

| | reconciler | verifier | total |
|---|---:|---:|---:|
| Mutations defined | 24 | 22 | **46** |
| Patch applied (fragment unique, digest changed) | 24 | 22 | **46 / 46** |
| Compiled under mutation | 24 | 22 | **46 / 46** |
| Killed, final pass | 24 | 22 | **46 / 46** |

Nothing was interpreted without all four. `all patch_applied: True`,
`all compiled: True` in the artifact.

## 5. Mutations killed

**46 of 46. Reconciler 24/24. Verifier 22/22.**

The number that matters is not that one, though — it is the first pass:

| | first pass | after regressions |
|---|---:|---:|
| Killed | 37 | **46** |
| Survived | 6 | **0** |
| Harness defects (never active, never interpreted) | 3 | **0** |

**Nine invariants of the two authoritative components were unguarded when
this work began.** Six survived outright; three were hidden behind harness
defects and surfaced only once those were fixed — which is the argument for
fixing a defect rather than writing it off as noise. Every one is now pinned
by a test that fails when the invariant is removed.

## 6. Survivors

**Zero in the final pass.** All nine first-pass gaps, and how each was closed:

| # | invariant left unguarded | why the suite missed it | closed by |
|---|---|---|---|
| R-10 | I10 — an observer anchored to the agent's own key is not independent | the per-batch check makes the same refusal, so the health-level check is shadowed whenever any batch is present | `t13d` — an observer that has attested nothing yet: sequence 0, no batches |
| R-11b | `reconcile_lineage`: a quarantined observer stops lineage | t17b covers the expectation path, lv14 covers `Degraded` on the lineage path; the pair left `Quarantined`-on-lineage untested | `lv18` |
| R-12b | `reconcile_lineage`: `IntegrityUnknown` stops lineage | same shape as R-11b | `lv17` |
| R-21 | a record read back from bytes is never engine-produced | pinned downstream in `aip-warrant` and `aip-nexora`; not in the crate that owns the invariant | `t22` |
| N-01 | an anchor is a `(signer_id, key_version)` pair | x02 covers an unanchored *signer*; nothing covered an anchored signer at an unanchored *version* | `x18` |
| N-02 | the signature's `signer_id` is the head's `signer_id` | `signature.signer_id` is not in the signing preimage, so editing it leaves hash and Ed25519 both valid — the mismatch check is the only guard | `x16` |
| N-05 | a head at an unsupported NEXORA version is refused | nothing constructed a head at another version | `x17` |
| N-22 | I10 on the verifier side | same shadowing as R-10, one level up | `w_the_agent_as_its_own_observer…` |
| R-11 | `reconcile_expectation`: a quarantined observer stops the verdict | *not a gap* — the first-pass mutation was a harness defect (a match guard made the match non-exhaustive). Once written to compile, t17b killed it immediately | already covered |

The three harness defects are reported as defects and never as kills. Of the
three, one (`R-11`) turned out to be already covered, one (`R-11b`) exposed a
real gap, and one (`N-01`) had to be re-aimed because the attack it described
is unrepresentable in the type.

**No implementation logic was weakened to make any mutation kill.** The only
production-adjacent change is a test helper (§7).


---

## 7. Tests added

**Eight tests, all appended to existing suites. No new test file, no new
crate, no new dependency.**

| test | file | pins |
|---|---|---|
| `t13d_an_observer_anchored_to_the_agents_key_is_refused_before_any_batch` | `aip-reconcile/tests/adversarial.rs` | R-10 |
| `t22_a_record_read_back_from_bytes_is_never_engine_produced` | `aip-reconcile/tests/adversarial.rs` | R-21 |
| `lv17_integrity_unknown_blocks_lineage_exactly_as_it_blocks_an_action` | `aip-reconcile/tests/lineage_violation.rs` | R-12b |
| `lv18_a_quarantined_observer_stops_lineage_and_accuses_only_itself` | `aip-reconcile/tests/lineage_violation.rs` | R-11b |
| `x16_a_signature_naming_another_signer_is_refused_even_though_it_verifies` | `aip-nexora/tests/nexora.rs` | N-02 |
| `x17_a_validly_signed_head_at_an_unknown_version_is_refused_on_the_version` | `aip-nexora/tests/nexora.rs` | N-05 |
| `x18_an_anchored_signer_at_an_unanchored_key_version_is_refused` | `aip-nexora/tests/nexora.rs` | N-01 |
| `w_the_agent_as_its_own_observer_is_refused_on_the_health_record_alone` | `aip-nexora/tests/adversarial.rs` | N-22 |

Verified against the diff: `git diff -U0 -- aip-standalone` contains exactly
eight added `#[test]` attributes and eight added `fn` items, matching this
table row for row, and the workspace total moved 2064 → 2072.

One test-only helper was added because a blind spot could not be reached
without it: `Observer::resign_health` in
`aip-reconcile/tests/lineage_violation.rs`, mirroring the helper the
`adversarial.rs` suite already had. It re-signs a health record the test has
edited, so the record is what an honest collector in that state actually
emits rather than a forgery. **No production file was changed.**

Each test asserts an observable security property and carries, in its
doc comment, the reason the existing suite missed it. Four also carry a
**control**: the same arrangement with the attack removed must fail for a
different, honest reason. Without a control, `t13d` would pass even if the
reconciler refused everything.

## 8. Security properties covered

The 46 invariants group as follows. Each row is proven non-vacuous: removing
it makes a named test fail.

**Reconciler — authority and expectation**
- an invalid, untrusted, self-authorized or structurally malformed expectation
  cannot yield a verdict (R-01)
- a record read back from bytes is not the engine's output, so a consumer that
  *acts* on a verdict cannot be handed one anybody could write (R-21)

**Reconciler — observer independence and integrity**
- I10, at the health record and with no batches present (R-10)
- an invalid observer signature is an integrity failure, not an inability to
  prove (R-03)
- batches from a second observer are not merged into one chain (R-04)
- two validly signed batches at one sequence are a proven fork (R-05)
- a sequence gap is an incomplete set; a broken `prev_head` is a chain break
  (R-06, R-07)
- batches withheld from the tail are caught against the health record (R-08)
- a replayed batch is flagged, not silently deduplicated (R-09)

**Reconciler — observer state gates, at each entry point**
- quarantined (R-11 expectation, R-11b lineage)
- integrity unknown (R-12 expectation, R-12b lineage)
- degraded (R-13 expectation, R-13b lineage)

**Reconciler — evidence and time**
- missing observer evidence is CANNOT_PROVE, never a verdict (R-02)
- matching and divergent observations together are ambiguous, and ambiguity is
  CANNOT_PROVE (R-14, R-15)
- a stale health record settles nothing; a forward-set collector clock cannot
  saturate staleness to age zero (R-16, R-17)
- an Open-policy mechanism label is unverified provenance (R-18)
- action evidence that mismatches, or that precedes its authorization, is not
  a verified execution (R-19, R-20)

**Verifier — the head**
- an anchor is a `(signer_id, key_version)` pair (N-01)
- the signature's signer is the head's signer (N-02)
- the payload hash is the hash of the head's own preimage (N-03)
- a failing Ed25519 verification is a refusal (N-04)
- an unsupported NEXORA version is refused before the key is consulted (N-05)

**Verifier — the commitment**
- a proof names the same log as its head; the inclusion size is the head's
  size; the record is genuinely included under the committed root (N-06, N-07,
  N-08)
- a head tracker refuses rollback, refuses a fork, and refuses an extension
  without a valid consistency proof (N-09, N-10, N-11)

**Verifier — the package**
- a claimed verdict the verifier cannot re-derive is refused: the package's own
  word is never trusted (N-12)
- a refused package establishes no result and no strength (N-13)
- structural and binding faults refuse the package before any component is
  credited (N-14, N-15)
- an unreadable declared version is refused (N-16)
- a carried-but-unreached component is `Unverifiable`, never `Absent` —
  absence of evidence is not evidence of absence, one level down (N-17)
- independence is what *this* verifier checked, not what the package asserts
  (N-18)
- a verified continuity break is discontinuous, never softened (N-19)
- a declared parameter beyond the verifier's own bound is refused (N-20)
- a verifier that bounds reconciliation age but holds no clock refuses rather
  than skipping the check it said it would make (N-21)
- I10 on the verifier side (N-22)

**CANNOT_PROVE remains fail-closed.** Six mutations (R-02, R-15, R-19, R-20,
N-12, N-13) attempt precisely the forbidden conversion — turning absent or
insufficient evidence into a positive result — and all six are killed.


---

## 9. Remaining blind spots

Stated as findings, not as reassurance.

1. **Mutation coverage is a floor, not a ceiling.** 46 mutations over ~7,900
   lines of source is a targeted sample of the invariants I could name from
   reading the code, not exhaustive coverage of its behaviour. A mutation
   nobody wrote proves nothing. What this establishes is that the 46 named
   invariants are genuinely tested — not that no unguarded invariant remains.

2. **`reconcile_observation` is under-sampled.** Of the three public entry
   points, the expectation path carries 18 mutations and the lineage path 3;
   `reconcile_observation` carries none of its own. Its observer-state gate is
   written differently (through `state_reason`) and its expected-side
   completeness checks — `ExpectedSideCompletenessUnknown`,
   `ExpectedSideStatementInvalid`, `ExpectedSideStatementDoesNotCover` — are
   the precondition for the only `UnattributedEffect` the engine can draw.
   **They are untested by mutation.** Given that R-11b and R-12b were both
   found on the *lineage* path for exactly this reason — an invariant covered
   at one entry point and unguarded at another — the same failure is likely
   here. This is the single highest-value follow-up.

3. **`aip-reconcile/src/action.rs` (894 lines) is unmutated.** `compare_action`
   and `derive_action` decide whether an observation is an instance of the
   expected action class. R-19 and R-20 mutate the *handling* of their
   outcomes; the derivation itself is untouched.

4. **`aip-nexora/src/proof.rs` (1,001 lines) is unmutated at the source of its
   faults.** N-14 and N-15 prove the verifier *acts on* structural and binding
   faults; nothing proves `structural_faults()` and `binding_faults()`
   correctly detect them. A mutation that made either return an empty vector
   would likely be killed by the same tests, but that is a prediction, not a
   result.

5. **`export.rs`, `replay.rs`, `capability.rs`, `merkle.rs` are unmutated.**
   Merkle is the most defensible omission — N-08 and N-11 exercise inclusion
   and consistency through the public verifier — but `replay.rs` (the
   `ProofSeen` ledger) and `capability.rs` (`VerifierCapability`) carry
   security decisions that only N-16, N-20 and N-21 touch indirectly.

6. **Kill strength is uneven — and thinner than the headline suggests.**
   **22 of the 46 mutations are killed by exactly one test** (median across
   the matrix: 2; maximum: 9). One failing test is sufficient to kill, so
   these are genuine results — but a single-test guard is one refactor or one
   `#[ignore]` away from becoming no guard at all, and half this matrix is in
   that position: R-01, R-04, R-05, R-06, R-07, R-08, R-10, R-11, R-11b,
   R-12, R-12b, R-13b, R-16, R-21, N-01, N-02, N-05, N-06, N-07, N-10, N-21,
   N-22. Seven of those are the tests added by this work, which is expected —
   a regression written for one blind spot guards one blind spot — but it
   means the newly closed gaps are the thinnest-guarded invariants in the
   system.

7. **This says nothing about the other twelve skills without mutation
   evidence.** Skills 3, 4, 5, 6, 8, 9, 16, 21, 22, 23 and 24 remain as
   `SKILL_CONFORMANCE_27_FULL_RUN.md` §11.1 described them.

## 10. Cross-architecture verification

Checked against the restored sources after the final pass.

| Invariant | Result |
|---|---|
| Exactly one reconcile implementation | **UPHELD** — `pub fn reconcile_*` in one file, `aip-reconcile/src/reconcile.rs` (3 entry points, one engine) |
| Exactly one verifier | **UPHELD** — `verify_proof` and `verify_nexora_proof` in `aip-nexora` and nowhere else; NEXORA remains authoritative |
| No new signing authority | **UPHELD** — `SigningKey::generate` appears once, in `aip-crypto`; no signer added |
| No new trust anchor | **UPHELD** — the tests consume existing anchor types; N-01/N-22's tests *narrow* anchors, never introduce one |
| No vertical-specific verifier | **UPHELD** — nothing added outside the two authoritative crates |
| No duplicate evidence semantics | **UPHELD** — one `EvidenceCeiling`, one `ObservationClass`, one `ReconciliationResult` |
| No wire/protocol change | **UPHELD** — see §12 |
| No production dependency expansion | **UPHELD** — `git diff` over every `Cargo.toml` and `Cargo.lock` is empty |

## 11. Validation totals

### 11.1 Targeted

| suite | before | after | delta |
|---|---:|---:|---:|
| `aip-reconcile` | 173 | 177 | +4 |
| `aip-nexora` | 178 | 182 | +4 |
| **combined** | **351** | **359** | **+8** |

0 failures in both, before and after. The +8 is the eight tests in §7:
`aip-reconcile` gains `t13d`, `t22`, `lv17`, `lv18`; `aip-nexora` gains `x16`,
`x17`, `x18`, `w_…`.

### 11.2 Mutation suite

| pass | mutations | applied | compiled | killed | survived | defects |
|---|---:|---:|---:|---:|---:|---:|
| First (baseline, before any test was added) | 46 | 43 | 43 | 37 | 6 | 3 |
| Final (against the code as it now stands) | 46 | 46 | 46 | **46** | **0** | **0** |

`all_files_restored_byte_identical: true` in both passes.

### 11.3 Full workspace

```
cargo fmt --all -- --check                                            EXIT 0
cargo clippy --workspace --all-targets --all-features -- -D warnings  EXIT 0
cargo test --workspace                                                EXIT 0
  2072 passed · 0 failed · 6 ignored   (182 result blocks, 0 FAILED blocks)
```

Baseline at `2f13b77` was 2064 / 0 / 6. **Delta +8**, matching the eight new tests exactly. No pre-existing
test changed status. The 6 ignored are the same pre-existing wall-clock and
root-privilege gates.

### 11.4 Structural and dependency guards

- `git diff` over `aip-standalone/*/src/` — **empty**
- `git diff` over every `Cargo.toml` and `Cargo.lock` — **empty**
- one reconciler, one verifier, one keypair primitive, one evidence hierarchy
  (§10)


## 12. Did the protocol or wire format change?

**No.**

| Constant | Value | Last modified |
|---|---|---|
| `AIP_VERSION` | `0x0004` | `2a6f156` |
| `PACKET_VERSION` | `2` | `4ff1f5c` |
| `EXECUTION_BINDING_VERSION` | `1` | `4ff1f5c` |
| `LeafKind::ALL` | 9 members, frozen | `df4ff70` |
| `RECONCILIATION_VERSION` | unchanged | — |
| `NEXORA_VERSION` | unchanged | — |

No canonical encoder, signing preimage, domain tag, enum discriminant or
serialized field was touched. `git diff` over `aip-standalone/*/src/` is
**empty**: every source file the harness mutated was restored byte-identical,
verified twice — by the harness (`all_files_restored_byte_identical: true`)
and by git.

## 13. Did the production architecture change?

**No.**

- **Zero production source files modified.** The complete change set is four
  test files and one new validation directory.
- No new crate, no new module, no new public type, no new dependency.
- No reconciler, verifier, evidence hierarchy, signer or trust anchor
  introduced; NEXORA remains the authoritative verifier and `aip-reconcile`
  the authoritative reconciler.
- No implementation logic was weakened to make a mutation kill. Where a
  mutation survived, a test was added; where a mutation would not compile, the
  mutation was rewritten — never the code under test.

---

## 14. How this relates to the 84/84 result

These are **two separate results over disjoint code**, and combining them into
a single headline would misrepresent both.

| | earlier result | this result |
|---|---|---|
| Scope | Skills 11–15, 17, 18, 19, 20, 25, 26, 27 | Skills 7 and 10 |
| Components | AIRI, the vertical profiles, the observation and execution models, the physical-AI adapter | `aip-reconcile`, `aip-nexora` |
| Mutations | 84, all killed | 46, all killed |
| Recorded in | the per-skill evidence reports and `validation/airi/MUTATION_RESULTS.json` | `validation/mutation/CORE_MUTATION_RESULTS.json` |

`docs/SKILL_CONFORMANCE_27_FULL_RUN.md` is the record of a run performed
against `8fe9ff4`, when this evidence did not exist. **It has not been edited
to suggest otherwise.** Its §11.1 correctly describes the state at that HEAD;
this document is the answer to it, and the conformance report should be
re-run — not retrofitted — if the combined position is wanted.

Stated jointly, and only as arithmetic: **130 mutations across the repository,
130 killed, 0 survivors.** Twelve of the 27 in-scope skills still have no
mutation evidence at all.

## 15. Evidence classification

| Class | What holds it |
|---|---|
| **TEST-PROVEN** | All 46 invariants in §8. Each is proven non-vacuous: a named test fails when it is removed. |
| **CODE-PROVEN** | The cross-architecture invariants in §10, by inspection of the restored sources; the wire constants in §12. |
| **EXECUTION-PROVEN** | That every mutation was genuinely active: fragment unique, digest changed, compiled, suite re-run — recorded per mutation with before/after digests. |
| **DOCUMENTED** | The blind spots in §9. |
| **UNKNOWN** | Whether unguarded invariants remain in the regions listed in §9.2–9.5. Mutation testing bounds what it samples and nothing else. |


---

## 16. Run integrity

| | |
|---|---|
| HEAD at start | `2f13b7788dd648aa3bd544e1a6f722171fbb51b3` |
| HEAD at end | `2f13b7788dd648aa3bd544e1a6f722171fbb51b3` (unchanged; no commit made) |
| Branch | `claude/skill-25-implementation-xbz0t3` |
| `git status --short` at start | empty |
| **Production files changed** | **0** |
| Test files changed | 4 (+383 lines, −1) |
| Files added | 3 — `validation/mutation/` (2) and this report |

Complete change set:

```
 M aip-standalone/aip-nexora/tests/adversarial.rs        +1 test
 M aip-standalone/aip-nexora/tests/nexora.rs             +3 tests
 M aip-standalone/aip-reconcile/tests/adversarial.rs     +2 tests
 M aip-standalone/aip-reconcile/tests/lineage_violation.rs +2 tests, +1 helper
?? validation/mutation/mutate_core.py                    the harness
?? validation/mutation/CORE_MUTATION_RESULTS.json        the result
?? docs/RECONCILER_VERIFIER_MUTATION_ASSURANCE.md        this report
```

Both mutation passes restored every touched source file byte-identically,
confirmed by the harness's own digest check and independently by `git diff`.
