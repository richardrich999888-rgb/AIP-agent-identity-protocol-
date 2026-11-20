# ADR-002: Require the Delegate action to sub-delegate, and proof of possession at the decision point

- **Status:** Proposed. `aip-core` and `DecisionPoint` are **not** changed
  this weekend: the change alters verification of every existing chain (see
  `aip-protocol-change-guard`), and the loop does not change those cores
  under deadline, the same rule as ADR-001.
- **Date:** 21 Nov 2026.
- **Evidence:** `aip-standalone/aip-authorize/tests/delegation_identity_findings.rs`,
  5 passed / 0 failed; the whole `aip-authorize` crate 108/0/0.

## Finding 1: a holder without `Delegate` can sub-delegate (adversarial #5)

Setup: CFO → orchestrator (orchestrator scope, which includes `Delegate`) →
recon-reporter (`scope_submitter()`: Write only, **no Delegate**).

`create_sub_delegation(hop1, recon_key, grandchild, {Write})` succeeds.
`verify_delegation_chain` accepts the resulting three-link chain, and
`DecisionPoint::authorize_at` returns **Authorized** for the grandchild's
Write (`finding_holder_without_delegate_scope_can_sub_delegate_and_grandchild_is_authorized`).

The cause is in `aip-core/src/delegation.rs`. `create_delegation` and
`create_sub_delegation` check only that the scope is a non-empty subset of
the parent's and that the depth is within limit. `verify_delegation_chain`
checks signatures, linkage, depth, attenuation and lifetime. Nothing
requires the delegator's scope to contain `Action::Delegate`.

Attenuation itself holds: asking for Delete, which the parent lacks, gives
`AttenuationViolation` (`control_sub_delegation_cannot_exceed_the_parent_scope`).

**Recommendation.** In `verify_delegation_chain`, refuse hop *i* unless the
scope effective at hop *i−1* permits `Action::Delegate`, with a distinct
error. Also refuse it in `create_*` so that honest code fails early.
Migration: chains issued through a non-Delegate holder become invalid.
List them before enabling, and gate the change behind a version.

## Finding 2: no proof of possession for the agent id (adversarial #6)

`AuthorizationRequest` contains no requester signature, and
`DecisionPoint::authorize_at` checks that the chain's leaf equals
`agent_id`. It does not check that whoever submitted the request holds
that agent's key. A request naming recon-reporter, built with none of its
key material, is **Authorized**
(`finding_decision_point_takes_no_proof_of_possession_for_the_agent_id`).
Tokens behave as bearer credentials at this layer.

The pieces of a check do exist. `derive_aip_id` binds an id to a key
(`control_a_forged_key_does_not_derive_the_claimed_id`), and a chain
issued to one agent cannot authorize another
(`control_chain_leaf_must_be_the_requesting_agent`).

**Recommendation.** Add a request signature by the agent's key over the
request digest, plus a decision-point nonce or time window. Verify it, and
verify that the key derives `agent_id` under the presented provenance,
before adjudication. Deny with a distinct reason. The plan carries forward
"signed requests" at the P0-059 gateway. That claim is not re-verified here
(0.1), and even if it holds, it protects only that one entry point.

## When implemented

Flip both `finding_*` tests to expect refusal. Do not delete them. Keep
the `control_*` tests. Update ADVERSARIAL_RESULTS #5 and #6.
