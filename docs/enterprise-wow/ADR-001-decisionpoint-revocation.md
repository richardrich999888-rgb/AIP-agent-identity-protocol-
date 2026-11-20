# ADR-001: DecisionPoint must consult revocation

- **Status:** Proposed. Under the loop's rule, nothing in `DecisionPoint` is
  changed this weekend.
- **Date:** 20 Nov 2026
- **Scope:** `aip-standalone/aip-authorize` (`DecisionPoint`,
  `ExpectedExecution`) and `aip-standalone/aip-core` (`RevocationLog`).

## Context

`DecisionPoint::authorize_at` checks:

- issuer trust and token signatures;
- the delegation chain (through `aip_core::delegation::verify_delegation_chain`);
- the leaf agent, scope, binding, temporal validity and TTL;
- resource and spend policy.

It takes no revocation input, and `DenialReason` has no revoked variant.

**Measured, not inferred.** `aip-authorize/tests/revocation_gap.rs` (3 passed / 0 failed) shows:

| Test | Shows |
|---|---|
| `revocation_store_does_report_the_revoked_root` | `aip_core::revocation` knows. After revoking the root `jti`, `check_token_valid` and `check_delegation_valid` both return `IdentityRevoked`. |
| `gap_decision_point_authorizes_under_a_revoked_root` | `authorize_at` still returns `Authorized` with that root `jti` in `authority.root_jti`. |
| `gap_decision_point_authorizes_under_a_revoked_delegation_hop` | The same holds for a revoked hop. |

So a signed `ExpectedExecution` can be issued under revoked authority, and it
then verifies offline (`verify_expected_execution`) until `valid_until`.

The plan records a gateway revocation check carried forward from P0-059 and
says to keep it. **That check is not re-verified here:** the P0-059 commits
are not on the remote (item 0.1). Its existence does not close this gap.
Every other caller of `DecisionPoint`, and every offline verifier of its
expectations, sees authorizations that ignore revocation.

## Decision (recommended)

Give `DecisionPoint` an optional, verified revocation input. Use the same
pattern as the existing resource and spend policies: an explicit opt-in,
visible through an accessor, and never silently absent.

1. **Input.** `with_revocation_status(snapshot, max_staleness_ms)`. The
   snapshot is a `RevocationLog` view with three parts:
   - its `chain_tip()`;
   - its length;
   - the instant it was taken, `as_of_ms`.

   It is checked against an operator-provisioned signer key, the same way
   spend policies are verified against policy anchors. An accessor,
   `revocation_status()`, returns `None` when nothing is configured, as
   `resource_policy()` does.
2. **Check.** Run it in `authorize_at(req, now)` after the signature and chain
   checks and before signing. Deny with a new
   `DenialReason::AuthorityRevoked` when any of the following is revoked:
   - `root_token.jti`;
   - any `delegation_chain[i].jti`;
   - any `delegation_chain[i].parent_jti`.
3. **Fail closed on staleness.** When `now - as_of_ms > max_staleness_ms`,
   deny with a new `DenialReason::RevocationStatusStale`. A stale view is
   refused, never treated as "nothing revoked".
4. **Rollback.** Refuse a snapshot whose length is lower than the one held,
   or whose chain tip does not extend it. This mirrors `with_spend_policy`
   refusing a non-newer revision.
5. **Record what was checked.** Add `revocation_chain_tip` and
   `revocation_as_of_ms` to `ExpectedExecution`, so an auditor can see which
   revocation state a decision relied on. This changes the signed bytes:
   - bump `EXPECTED_EXECUTION_VERSION`, currently `1` in `expected.rs:43`;
   - follow the `aip-protocol-change-guard` rules for signed-field changes.
6. **Stay pure.** `DecisionPoint` takes time as a parameter. It must not call
   `check_token_valid` or `check_delegation_valid`, which read
   `SystemTime::now()` in `revocation.rs`. Use `RevocationLog::is_revoked`
   on the snapshot together with the caller's `now`.

## Alternatives considered

| Option | Why not |
|---|---|
| Gateway-only check (status quo) | Revocation becomes a property of one enforcement point. Expectations issued under revoked authority still verify offline, and other callers get no protection. |
| Check at `verify_expected_execution` time | Verifiers would need fresh revocation data, and issuance would still succeed. Useful as an addition, not a replacement. |
| Short TTLs only | They bound the exposure window but check nothing. Revoked authority still yields valid expectations inside the window. |

## Consequences

- Deployments that configure revocation get denials that cite it. Those that
  do not are visibly unchecked through the accessor, so nothing is silently
  lost.
- A new failure mode: a stale snapshot refuses everything. That is the
  intended fail-closed behaviour, and operators need a freshness feed.
- The format version bump means verifiers must accept v1 and v2 during
  migration, or be upgraded in lockstep.

## Related defect: unpersisted revocation is reported done (measured 21 Nov)

`RevocationLog::revoke` writes the entry in memory and then runs
`let _ = self.save();` (`aip-core/src/revocation.rs:127`), which discards
any persistence error. A revocation can therefore be reported as done while
it is not on disk, and a restart loses it: this fails open. Recommendation:
return the error, and treat a revocation as effective only once persisted.
**Measured** by `aip-core/tests/revocation_persistence_finding.rs` (2 passed / 0 failed). The log's path is made unwritable (its parent is a regular file). `revoke` then returns the entry, and `is_revoked` is true in memory. Nothing is written, and a `with_file` reload of the same path, as a restart does, no longer has the agent revoked. The control (a writable path) persists and survives a reload. This is out of scope for this loop. Record it as a tracking issue; none has been filed yet (that is an outward action).

## When implemented

Flip both `gap_*` tests to expect `DenialReason::AuthorityRevoked`. Do not
delete them. Then add tests for each of these:

- a stale snapshot is denied;
- an unconfigured decision point reports `None`;
- an older or forked snapshot is refused;
- the v2 expectation carries the chain tip;
- a v1 verifier rejects v2.
