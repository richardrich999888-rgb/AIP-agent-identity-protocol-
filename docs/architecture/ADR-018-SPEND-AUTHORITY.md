# ADR-018 — Spend Authority: Make the Limit a Signed, Enforced, Provable Control

**Status** ACCEPTED
**Date** 2026-10-25
**Branch** `claude/skill-25-implementation-xbz0t3`
**Baseline** `9f1b5e4`
**Related** ADR-017 (AIBOM), ADR-016 (approval tier), R2 resource authority
(`aip-authorize/src/resource.rs`), R4 tool boundary (`aip-airi/src/boundary.rs`)

---

## Context

The AIBOM reports an agent's "$1,000 per payment" limit as `SELF-REPORTED`,
and says so truthfully: no artifact in this system carries an amount. The
consequence is that the flagship accountability story — *authorised $1,000,
attempted $5,000* — cannot be told from evidence. The limit is somebody's
word, enforcement happens (if anywhere) outside the system, and an attempted
overspend that a decision point refuses leaves **no signed record at all**:
`Denial` is unsigned and not serialisable.

Not every limit the AIBOM reports is of this kind. Three classes:

| class | example | what moves it |
|---|---|---|
| **physics** | a hosted model's identity (N-3); that weights were loaded (N-4); a remote effect, seen from the agent's host (N-2) | nothing in this repository. A provider that signs its responses, or the system of record signing what it applied, would — and neither is ours to build |
| **position** | spending limits; approval completeness | evidence collected where the truth is created rather than where the agent runs |
| **coverage** | lockfile discovery; CycloneDX export; key custody in the CLI | ordinary engineering |

This ADR takes the most valuable *position* limit and removes it.

## Decision 1 — the limit becomes an institution-signed artifact

A `SpendPolicy` is signed by the institution's policy authority, exactly as
its resource registry is: per agent, a rule per governed action naming the
parameter that carries the amount, its currency and scale, the per-action
maximum, and the threshold above which human approval is required. Verified
under anchors the verifier holds, never the policy's own.

## Decision 2 — the decision point enforces it, because it sees the amount

The decision point already reads request parameters in clear and already
refuses on policy (R2). Spend authority is its step 5c, after scope and
resource authority, before the expectation is signed:

- an amount above the maximum is **refused**;
- an amount the rule cannot read — missing, not a non-negative decimal
  integer, out of range — is **refused**, never read permissively;
- an amount above the approval threshold is authorised **and marked
  approval-required**.

A decision point with no spend policy for an agent performs no spend check,
and says so through `DecisionPoint::spend_policy_for` — the same stance as
resource authority. One authority engine; no second gate beside it.

## Decision 3 — both outcomes leave signed evidence

The decision point signs one of two records under its own key:

- **`SpendAttestation`** for an authorised decision: which policy revision
  (by digest) governed it, the verdict (`Within` or `ApprovalRequired`), and
  the limit applied — bound to the expectation by its digest. It carries **no
  amount**, consistent with the gateway receipt's rule that arguments never
  appear in evidence.
- **`SpendRefusal`** for a refused request: the policy, the reason, the
  **requested amount** and the limit. A refused request never executes; the
  number is what a supervisor needs, and it is the decision point's own
  record of what it was asked.

`ExpectedExecution` is **not changed**. Its signing preimage and its
parameter digest stay exactly what the reconciler and the tool boundary
recompute. The records are separate, domain-separated artifacts.

## Decision 4 — the chain is then provable end to end

| what happened | evidence | already existed? |
|---|---|---|
| agent asked to pay $5,000 against a $1,000 limit | signed `SpendRefusal` | **new** |
| agent was authorised $500 and sent $5,000 to the payments gateway | gateway receipt ≠ sealed parameter digest (`ReceiptDoesNotMatchAuthorization`) | yes |
| a payment above $500 executed with no human approval | `SpendAttestation { ApprovalRequired }` with no agreeing approval artifact | **new** (the join) |
| the manifest says $1,000; the institution's policy says $5,000 | signed policy contradicts the declaration | **new** |

Every row is arithmetic over signed bytes under anchors the verifier chose.

## Implementation

| piece | where |
|---|---|
| policy, evaluation, records — pure, no clock, no IO, no decision-point key | `aip-standalone/aip-spend` |
| step 5c, record signing under the ledger guard | `aip-authorize/src/decision.rs`, `aip-authorize/src/spend.rs` |
| C5 limits and approval thresholds against the policy and records | `aip-aibom/src/assess/spend.rs`, `aip-aibom/src/assess/approvals.rs` |

Rules the implementation adds, each with a test:

- **No rollback by configuration.** `DecisionPoint::with_spend_policy`
  refuses a revision not strictly newer than the one it holds for that agent.
- **No entry point skips 5c.** `authorize_at` enforces exactly as
  `authorize_spend_at`; it only drops the record.
- **No governed expectation without its record.** The attestation is signed
  before the decision enters the ledger; if it cannot be signed, the
  decision is denied.
- **Equivocation is not resolved.** Two different signed policies at the
  same highest revision: the assessor relies on neither.
- **A stale decision point is visible.** A verified record citing a policy
  other than the current signed revision is reported
  (`SpendPolicyMismatch`).
- **Independence.** A policy issuer or decision point the assessor anchors
  under the agent's own key is refused.
- **Amounts are strict.** ASCII decimal minor units only: no sign, no
  separator, no decimal point, no whitespace, no overflow. Different currency
  or exponent is a contradiction, never a conversion.

## What this does not establish

- **Decisions that bypass the decision point.** Those surface as gateway
  receipts with no matching expectation — a coverage finding, not a limit
  finding.
- **Cumulative limits** (per day, per month). The decision point would need a
  durable, amount-bearing ledger of its own decisions. Per-action only in this
  version; a declared daily limit stays the author's word, and says so.
- **That the downstream system applied the amount.** That is N-2, and stays
  N-2.

## Alternatives rejected

**Put the amount and the limit inside `ExpectedExecution`.** Rejected: a wire
change to the most widely verified artifact in the system, invalidating every
expectation, for information that can travel alongside it.

**A separate spend gate in front of the decision point.** Rejected: a caller
could reach the decision point without it. Enforcement belongs where
authorisation is already decided — the codebase has already paid once for
having two authority engines (`f4f0c7f`).

**Disclose the amount in every attestation.** Rejected for authorised
decisions: the limit and the verdict suffice for compliance, and the
receipt's privacy rule should not be broken one layer up. Kept for refusals,
where the requested number is the evidence.
