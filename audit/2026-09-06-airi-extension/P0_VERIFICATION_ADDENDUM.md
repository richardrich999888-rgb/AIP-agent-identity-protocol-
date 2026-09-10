# Addendum — Independent Verification of the P0 Fixes

**Date:** 2026-09-06 (later than the parent report)
**Trigger:** `claude/codebase-production-readiness-wm6idp` advanced
`dc8caf3 → fdf380c`, claiming to close forensic blockers **B-1** (verifier
clock) and **B-2** (delegation issuer↔grantee binding).
**Method:** commit messages are claims. Each fix was read at source, its
adoption traced through every consumer, and the residual surface stated.

---

## 1. B-2 — delegation issuer must have held the parent

### Status: **CLOSED. Fully adopted.**

**CODE-PROVEN.** `aip-standalone/aip-core/src/delegation.rs`,
`verify_delegation_chain`:

```rust
// Who currently holds the authority being delegated. The root token's
// grantee holds it first; after each hop, that hop's grantee does.
let mut prev_holder: &str = &root_token.agent_id;
…
    if hop.issuer_id != prev_holder {
        return Err(AipError::LineageInvalid);
    }
    prev_holder = &hop.grantee_id;
```

This is exactly the check the master audit recorded as absent (finding L-5 /
B-2). The chain is now linked by identity as well as by `parent_jti` and
depth.

**TEST-PROVEN.** `p0_2_a_hop_issued_by_someone_who_never_held_the_parent_is_refused`
constructs the right attack: Mallory, a legitimate agent whose key the
verifier holds, signs a well-formed hop — correct `parent_jti`, correct
depth, attenuated scope, genuine signature over its own payload — off a root
token issued to Alice. Previously it verified. Now it is `LineageInvalid`.

### Why this one is fully closed

The fix is **unconditional**: a check inside `verify_delegation_chain`, which
every caller reaches. There is no opt-in, so no consumer can be left behind.
`aip-service` gets it without changing a line.

---

## 2. B-1 — verifier-supplied verification-time bound

### Status: **CLOSED in `aip-protocol`. NOT ADOPTED in `aip-service`.**

### 2.1 What was built, and it is well built

**CODE-PROVEN.** `aip-protocol/src/verification.rs` adds rule **R16
VERIFICATION_TIME_BOUND** plus two context fields:

```rust
pub verification_time_ms: Option<u64>,
pub future_tolerance_ms: u64,
```

Three design decisions are correct and worth naming:

1. **The time is supplied, never read from the system clock.** An offline
   verifier, an air-gapped verifier and a test all need to state what "now"
   means to them. Reading `SystemTime::now()` inside the verifier would have
   made the rule untestable and wrong for delayed verification.
2. **Absent a time, R16 is recorded as NOT EVALUATED, not as a pass.** The
   report carries `evaluated: bool` per rule, `verification_time_checked`,
   and `not_evaluated()`.
3. **The bound is not "the authority must still be valid now".** A historical
   packet stays verifiable after its tokens expire — offline verification
   depends on that — and whether the authority was valid *at decision time*
   remains R10's question. Conflating the two would have broken archival
   verification, and the test
   `p0_1_a_historical_packet_stays_verifiable_after_its_authority_expires`
   pins it.

`aip-verify` surfaces the gap to a human: `main.rs:224` prints
`note: <rule> was NOT evaluated — <detail>` for every unevaluated rule.

*(An earlier pass of this addendum provisionally recorded the CLI as silent.
That was wrong — the grep used the wrong symbol. Corrected here rather than
removed, because a withdrawn finding is itself a finding about the audit.)*

### 2.2 The residual, stated precisely

`valid` is computed as:

```rust
let valid = e.checks.iter().all(|c| !c.evaluated || c.pass);
```

An unevaluated rule therefore does not make a report invalid. Prod's own test
asserts this openly:

> `p0_1_without_a_bound_the_rule_is_not_evaluated_rather_than_passed`
> `assert!(report.valid);`
> *"Still valid — an unevaluated rule is not a failure — but a consumer can
> tell the difference, which is the whole point."*

**This is the right decision, not a defect.** Making `valid` false for an
unevaluated rule would conflate "could not check" with "failed", which is
precisely the `CANNOT_PROVE` / `FAILED` distinction the whole codebase is
built on. The obligation it creates is on the consumer: reading `.valid`
alone is misuse of the API, in the same way that reading
`Corroboration::is_corroborated() == false` as "nothing wrong" would be.

### 2.3 The finding: the service tier did not adopt it

**CODE-PROVEN.**

| Site | Construction | Verification time |
|---|---|---|
| `aip-service/src/evidence.rs:312` | `VerificationContext::new()` | never set |
| `aip-service/src/evidence.rs:428` | `VerificationContext::new()` | never set |
| `aip-service/src/evidence.rs:546` | `VerificationContext::new()` | never set |

`grep -rn 'verification_time_ms' aip-service/src/` returns **0 occurrences.**

And the handlers consume the bare boolean:

```
aip-service/src/handlers.rs:125   if result.valid …
aip-service/src/handlers.rs:132   if result.valid …
aip-service/src/handlers.rs:140   (result.valid, result.reason)
aip-service/src/handlers.rs:181   if !parent_result.valid …
aip-service/src/handlers.rs:249   if !root_result.valid …
```

`git diff origin/claude/codebase-production-readiness-wm6idp HEAD -- aip-service/`
is **empty**: the service is byte-identical to prod's, i.e. untouched by the
P0 work.

**Consequence.** The `/verify` HTTP endpoint applies no temporal bound. A
packet dated arbitrarily in the future returns `valid: true` through the API,
with `verification_time_checked: false` present in the report but not
consulted by any handler. The protocol-layer fix does not reach the service's
callers.

### 2.4 New blocker

| ID | Sev | Finding |
|---|---|---|
| **B-1a** | **P1** | `aip-service` never supplies `verification_time_ms`, so every service-side verification is unbounded, and `handlers.rs` decides on `result.valid` without consulting `verification_time_checked`. |

**Root cause is structural and already documented.** This is the same cause
as master-audit findings D-5 and B-10: `aip-service` is a member of no
workspace, so `cargo test --workspace` never compiles it and a fix landed in
`aip-protocol` does not propagate to it by default. B-1a is the first
concrete harm from that arrangement.

**Remedy** (not applied — this is an audit, and the service tier is outside
the AI-stack extension's scope):
1. Set `ctx.verification_time_ms` in `verify_request` from a service-supplied
   clock, with `future_tolerance_ms` from configuration.
2. Have the handlers refuse when `!verification_time_checked`, or make the
   absence explicit in the API response.
3. Bring `aip-service` into the workspace so the next protocol change is
   compiled against it (B-10).

---

## 3. Revised blocker register

| ID | Blocker | Before | **Now** |
|---|---|---|---|
| B-1 | Verifier clock semantics | OPEN (P0) | **CLOSED in `aip-protocol`** |
| **B-1a** | Service applies no temporal bound | — | **OPEN (P1), new** |
| B-2 | Issuer/grantee binding | OPEN (P0) | **CLOSED, fully adopted** |
| B-3 | Real engine-produced containment path | OPEN | OPEN |
| B-4 | Bundle signer trust | OPEN | OPEN |
| B-5 | Private-key storage | OPEN | OPEN |
| B-6 | Service key-regeneration | OPEN | OPEN |
| B-7 | Private seed handling | OPEN | OPEN |
| B-8 | Sealed reconciliation result construction | OPEN | OPEN |
| B-9 | Packet replay undetected | OPEN | OPEN |
| B-10 | Service integration (no workspace) | OPEN | OPEN — **now demonstrably load-bearing** |

**Both P0s are closed.** That is the significant change: the two defects
sitting directly under the protocol's central claim about *who* authorized
*what* and *when* are fixed, and fixed well.

Eight blockers remain, plus one new P1. Seven of the nine now sit in or
depend on the service tier and its exclusion from the workspace.

---

## 4. Effect on the AIRI extension

None. `aip-airi` does not consume `VerificationContext` and does not verify
packets; it verifies its own events and corroborates against observer
batches. Post-merge:

| Suite | Result |
|---|---|
| `aip-airi` | **67 passed / 0 failed** |
| Python SDK | **50 passed / 0 failed** |
| Workspace | see the parent report's E section, re-run post-merge |

The extension's own conclusion is unchanged, and its central caveat now reads
slightly differently: AIRI still contributes nothing to a verdict, but the
substrate it would eventually contribute to is two P0s sounder than it was.

---

## 5. Promotion

Still **NO**, and for a narrower reason than before.

The two P0s that made promotion obviously premature are closed. What remains:

1. **B-1a is a P1 in the request path.** A service that answers `valid: true`
   for a future-dated packet is the original P0 wearing a different hat, for
   any consumer that reads the boolean — which is every handler today.
2. **B-3 and B-8 remain**: containment is still unreachable from engine
   output, and `Reconciliation`'s fields are still all `pub`.
3. **B-10 is now demonstrably load-bearing** rather than theoretical. B-1a
   exists because of it.
4. **AIRI still has no production evidence.** Unchanged.

The gap has narrowed from "two P0s under the central claim" to "one P1 in the
service path plus a structural exclusion that caused it". That is real
progress and worth saying plainly.
