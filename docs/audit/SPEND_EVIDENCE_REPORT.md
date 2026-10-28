# Spend Authority — Evidence Report

**Decision record** ADR-018 · **Crates** `aip-spend` (new), `aip-authorize`
(step 5c), `aip-aibom` (C5 limits) · **Baseline** `9f1b5e4`
**Branch** `claude/skill-25-implementation-xbz0t3`

Classes as in `AIBOM_EVIDENCE_REPORT.md`: CODE-PROVEN, TEST-PROVEN,
EXECUTION-PROVEN, DOCUMENTED, INFERRED, UNKNOWN. Nothing is promoted because
a fixture was built to show it.

---

## 1. The claim, and its class

> An agent authorised to spend $1,000 per payment asks to spend $5,000. The
> decision point refuses, and signs a record of the refusal carrying the
> amount. The agent's inventory shows its $1,000 limit as verified against
> the institution's signature, and the refusal from the decision point's
> signed bytes.

**TEST-PROVEN and EXECUTION-PROVEN** on the treasury example
(`cargo run -p aip-aibom --example treasury`), whose output the `aibom` CLI
reproduces byte for byte from the written files (exit 2: critical findings).
Every key in it is generated; every artifact is produced by the crate that
owns it; nothing is a hand-written fixture.

## 2. What exists that did not

| property | where | class |
|---|---|---|
| An institution-signed per-agent spend policy: per-action maximum and approval threshold, integer minor units, explicit currency and exponent | `aip-spend/src/policy.rs` | TEST-PROVEN |
| Strict amount parsing: ASCII digits only, ≤ 20 digits, checked arithmetic | `aip-spend/src/evaluate.rs` | TEST-PROVEN |
| Decision-point step 5c: above the maximum → refused; unreadable → refused; above the threshold → authorised and marked approval-required | `aip-authorize/src/decision.rs` | TEST-PROVEN |
| A signed `SpendRefusal` carrying the requested amount; a signed `SpendAttestation` bound to its expectation by digest, carrying no amount | `aip-spend/src/record.rs`, `aip-authorize/src/spend.rs` | TEST-PROVEN |
| No entry point skips 5c; no governed expectation exists without its attestation; configuration cannot roll a policy back | `aip-authorize/tests/spend.rs` | TEST-PROVEN |
| C5 limit `VERIFIED` against the signed policy, `CONTRADICTED` when it differs (value, currency or scale); approval threshold likewise; each approval-required decision checked for an agreeing approval | `aip-aibom/src/assess/spend.rs`, `assess/approvals.rs` | TEST-PROVEN |
| A decision point enforcing a superseded revision is reported; equivocating policies are not relied on; an issuer or decision point anchored under the agent's own key is refused | `aip-aibom/tests/assess_spend.rs` | TEST-PROVEN |

`ExpectedExecution` is unchanged: no signed field, preimage or wire format of
any existing artifact was modified.

## 3. Tests

| suite | tests |
|---|---|
| `aip-spend/tests/spend.rs` | 20 |
| `aip-authorize/tests/spend.rs` + `spend::tests` | 16 + 1 |
| `aip-aibom/tests/assess_spend.rs` | 24 |

Five tests were added *because* the mutation matrix or a pre-run review
showed an invariant had no test that could fail: `verify` re-validating a
policy it did not sign, a signer-id mismatch, an unknown record version, the
multiply-overflow case of amount parsing (SP-06 survived until it existed),
and foreign attestations. Two fixture tests were corrected after they failed
for the fixture's reasons, not the code's (§6).

## 4. Mutation testing

`validation/mutation/mutate_spend.py`, forensic runner shared with every other
matrix (`mutate_core.run_matrix`): unique fragment, changed digest, compile,
byte-identical restore.

| layer | mutations | killed |
|---|---|---|
| `aip-spend` | 20 | 20 |
| `aip-authorize` step 5c | 13 | 13 |
| `aip-aibom` limits and thresholds | 23 | 23 |
| **total** | **56** | **56** |

First run: 54 / 56. **SP-06** (`checked_mul` → `wrapping_mul`) survived: the
only overflow test was `u64::MAX + 1`, which overflows on the *add*. Closed
with `99999999999999999999`, which overflows on the multiply. **AS-14** was a
harness defect (an ambiguous `Result::or` that did not compile); the fragment
was corrected and the mutation then killed. Results:
`validation/mutation/SPEND_MUTATION_RESULTS.json`.

## 5. A defect in the previously committed evidence

The AIBOM matrix committed in `9f1b5e4` reported 63 / 63 killed. Re-checked
before this work: **five of its fragments did not occur in the committed
source** (AB-11, AB-37, AB-44, AB-46, AB-54). The run had been made on source
that `rustfmt` reformatted before the commit — the recorded `sha256_before` for
`assess/authority.rs` is `db227988…`; the committed file is `f22396a4…`. The
code was semantically identical, so the recorded kills were true of it, but
the matrix **did not reproduce** from the commit, which is the property a
mutation record exists to have.

All five were re-aimed at the committed text, two more (AB-59, AB-62) at the
approval code this work changed, and AB-14 at the limit logic's new home; the
whole matrix was re-run on the source being committed: **63 / 63 killed, all
files restored byte-identical.** Each mutation records the digest of the file
it ran against; comparing that digest with the committed file is how the
drift was found, and is the check to repeat on any future commit.

## 6. Failures during the work, and their causes

| failure | cause | resolution |
|---|---|---|
| `a_policy_cannot_be_rolled_back…` failed | the fixture minted a second agent; the stale policy named a different agent | test rewritten on one fixture |
| expected label `write` | the label format is `standard:Write` | test corrected |
| "different expectation" not rejected | swapping a decision id onto an expectation with the same amount and instant produces byte-identical signed content — the code was right | test uses a different amount |
| clippy `result_large_err` | `SignedSpendRefusal` inside the error type | boxed |
| `the_bundle_carries_no_trust_input` failed | the guard failed as designed when three bundle fields were added | reviewed — each is a signed artifact re-verified under the assessor's own anchors, none carries a key, anchor, revocation or clock — and updated deliberately |

## 7. What this does not establish

- **That every payment went through this decision point.** Records show
  enforcement for the decisions offered; completeness over a window is the
  decision point's coverage statement.
- **Cumulative limits.** Per-day and per-month limits are carried by no
  artifact and stay `SELF-REPORTED`.
- **Who the approver is.** A threshold is verified; the approver is not.
- **That the payment system applied the amount.** N-2, unchanged.
- **That a refusal was all the agent attempted.** A request that never
  reached the decision point leaves no refusal; it surfaces, if at all, as a
  gateway receipt with no matching expectation.
- **Key custody.** The decision point's and the policy issuer's keys are held
  wherever their operators hold them; nothing here proves the agent cannot
  read them (`DECISION_POINT.md`).

## 8. Validation

On `e2fbac2`, after `cargo clean` (an earlier run failed four `ghost-demo`
tests with `ENOSPC` — the disk had filled with mutation build artefacts,
`os error 28` in the nested `nexora-verify` build; environmental, not code):

```
cargo fmt --all -- --check                                            exit 0
cargo clippy --workspace --all-targets --all-features -- -D warnings  exit 0
cargo test --workspace --no-fail-fast   321 suites · 3156 passed · 0 failed · 7 ignored
```

3,156 = the previous 3,095 + exactly the 61 tests in §3. SoftHSM2 installed;
the `aip-hsm` custody tests ran.
