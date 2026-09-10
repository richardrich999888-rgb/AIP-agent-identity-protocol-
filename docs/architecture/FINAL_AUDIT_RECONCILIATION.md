# FINAL AUDIT RECONCILIATION

Directive §24 — the audit's findings re-run against the canonical branch at
the completion of Skill 10.

**Branch** `claude/codebase-production-readiness-wm6idp` · **at** `a56e5c1`
**Baseline for this programme** `82da7a6`

Every finding the audit raised is listed. Nothing is removed, and nothing
is marked fixed without a named test that fails if it stops being fixed.
Four classifications are used:

- **FIXED** — the defect is gone and a test proves it.
- **PARTIALLY FIXED** — the sharpest form is closed, a weaker form remains,
  and the remainder is stated.
- **REMAINING** — still open, with what it costs.
- **ACCEPTED / JUSTIFIED** — not a defect on inspection, or a deliberate
  boundary, with the reasoning.

---

## P0 findings

### P0-1 — the verifier had no trusted verification-time bound · **FIXED**

A packet dated a year in the future verified. Rule **R16**
(`VERIFICATION_TIME_BOUND`) now checks `decision.decided_at`, every
`action.performed_at`, the root token's `issued_at` and each hop's
`issued_at` against a verifier-supplied `verification_time_ms` plus an
explicit `future_tolerance_ms`.

The temporal semantics are explicit rather than ambient: when no
verification time is supplied the rule is recorded as **not evaluated**,
which is neither a pass nor a failure. `RuleResult.evaluated` carries that,
`failures()` excludes unevaluated rules, and `not_evaluated()` reports them
— so a verifier that applied no temporal bound says so instead of looking
like one that applied one and passed.

*Tests:* `aip-protocol` RED `e52437e` (the exploit), GREEN `fdf380c`.
`test_honest_packet_verifies_at_counterparty_floor` asserts the only
unevaluated rule is `VERIFICATION_TIME_BOUND`.

*Does not prove:* that any timestamp is true. There is still no trusted
time source; R16 bounds what a verifier will accept, and the values remain
the agent's assertions (limitation 1 of the correctness report, unchanged).

### P0-2 — a delegation issuer was not bound to the previous grantee · **FIXED**

Linkage by `parent_jti` alone let anyone whose key a verifier held mint a
hop off a token they never received. The signature check passed, because it
only proved the named issuer signed *this* hop — not that they were
entitled to issue it.

`verify_delegation_chain` now tracks `prev_holder`, starting at the root
token's grantee, and refuses a hop whose `issuer_id` is not that party.

*Tests:* RED `f856b7d` (Mallory delegating from Alice's root token), GREEN
`8daffe3`; re-checked end to end by
`aip-nexora/tests/audit.rs::a09_authority_cannot_be_issued_to_itself`,
which anchors Mallory's key so the failure cannot be an unknown-key
artifact.

### P0-3 (new, found by Gate 14) — a chain verified from an unauthenticated root · **FIXED**

Not in the original audit; found by the live demonstrator and recorded
here because §24 forbids losing findings.

`verify_delegation_chain` walked every hop but never authenticated the root
token it started from, while reading that token's `jti`, scope, expiry and
grantee as the starting truth. A package could therefore rewrite the root
and be told the chain verified. `aip-authorize`, `aip-protocol`,
`aip-agent` and `aip-reconcile` all called `verify_scoped_token` themselves
first; the offline NEXORA verifier did not.

The fix is in `aip-core`, not a fifth workaround: the function now verifies
its root under the root issuer's key, refuses an issuer whose key the
verifier does not hold, and covers the empty-chain path that returns the
root's scope.

*Tests:*
`aip-core::delegation::tests::the_root_token_a_chain_starts_from_must_be_authentic`;
`ghost-demo/tests/live_nexora.rs::g14_05` ("the expiry of the root token
extended").

---

## Findings from the directive's own sections

### §14 — reconciliation results were constructible downstream · **FIXED**

Any caller could build a `Reconciliation` and put `Proven` /
`VerifiedExecution` / `PhantomClaim` / `IdentityDivergence` /
`LineageViolation` in it. `Reconciliation` is now `#[non_exhaustive]` with
a crate-private `Provenance`; a downstream crate cannot write a struct
literal, and deserialisation yields `Provenance::Deserialized`.
`aip_warrant::evaluate` refuses anything that is not engine-produced with
`Refusal::ReconciliationNotEngineProduced` — refused outright rather than
lowered, because a ceiling would still be a response.

*Tests:* RED `4c712c2`, GREEN `30aafc6`;
`aip-nexora/tests/adversarial.rs::t` (T4) shows a record that arrived over
the wire warrants nothing.

*Does not prove:* that the engine's verdict is correct — only that nobody
else can author one. This is a language-level boundary, not a
cryptographic one; the register (IR-01) says so.

### §13 — containment could not be reached by real evidence · **ACCEPTED / JUSTIFIED**

Resolved as option **A**: autonomous containment of a workload is
intentionally unreachable in v1, and proved to be.

`Contain` needs a workload-targeted result **and** `Proven` **and**
Critical severity. Severity is the operator's; the other two are not
policy. The engine's guard emits every workload-targeted class only at
`Attested`, and the one result it emits at `Proven` —
`SensorIntegrityFailure` — caps at `Constrain` against the **observer**.
The sets do not intersect, and the observer target is deliberate: freezing
a workload because a sensor failed is the wrong response to the wrong
party.

Reaching B would mean either lowering what `Proven` means or adding an
evidence source a verifier can independently recompute for a workload
action. Neither was done, because §3 forbids weakening a predicate to make
a later gate reachable.

*Tests:* `aip-containment/tests/reachability.rs` (4 cases), which sweeps
the engine's whole producible set under the most permissive policy an
operator could write, and fails if a `Proven` workload finding ever
appears. `CONTAINMENT_MODEL.md` §10 records the reasoning.

**Consequence recorded:** the containment suite's `PhantomClaim · Proven`
fixture is a state the engine cannot produce. The tests are correct about
the gates, the actuator and the signed records, and the file now says at
the top and at the fixture that its input is not a capability. §13's
prohibition on using a hand-constructed record to demonstrate end-to-end
capability is met by not making that claim.

---

## Findings carried from AIP_CORRECTNESS_REPORT.md §"Remaining limitations"

### 1. Timestamps inside a packet are the agent's assertion · **REMAINING**

`decided_at` and `performed_at` are asserted, not witnessed. R16 now bounds
them against a verifier-supplied time, which is a real tightening, but
there is no trusted time source (I21). Kernel-observed events carry a
`BootClockAnchor`, which ties them to a boot-relative clock — not to
wall-clock truth.

*Cost:* an agent that lies about *when* within its authorised window is not
caught by time alone; it is caught, if at all, by the observer's
independent record.

### 2. Trust anchors are caller-supplied everywhere · **ACCEPTED / JUSTIFIED**

Verification proves consistency with the anchors, not that the anchors are
right. This is the correct shape for an offline verifier and is now stated
in the artifact itself: `AnchorFile` carries the sentence "a verifier that
takes them from beside the proof it is checking has verified nothing", and
`live_nexora.rs::g14_06` demonstrates the failure by shipping a forger's
anchors beside a forger's package and showing it "verifies".

The distinction the audit asked for — calculator versus authority — holds:
the service and the library verify, they do not authorise.

### 3. Only Ed25519 is implemented · **ACCEPTED / JUSTIFIED**

Unchanged, and now enforced rather than merely true. `MlDsa65` and `Hybrid`
identifiers are refused with an error rather than checked as Ed25519, at
both the primitive layer and the package layer, naming the component that
carried the label.

*Tests:* `aip-nexora/tests/audit.rs::a07`, `a08`.

No post-quantum claim is made anywhere.

### 4. Private keys at rest are plaintext JSON · **PARTIALLY FIXED**

`KeyPair`'s `Debug` redacts the private key, so logging or a panic message
cannot leak it, and that is tested. At rest in `aip_core::store` the
material is still plaintext JSON.

*Cost:* anyone who can read the store's files has the keys. **REMAINING**
for storage; the type documents that persisting a `KeyPair` anywhere else
is not supported.

*Not addressed here* because it is a key-management decision (OS keyring,
TPM, HSM, passphrase-wrapped file) with operational consequences, and
picking one silently inside a proof-layer programme would be the wrong
place to make it.

### 5. The service's second attenuation model · **REMAINING**

`aip-service` still carries authority logic of its own (I18). The Ghost
path does not run through it — `aip-standalone` is the canonical
implementation and `aip-service` is a separate root — but two authority
models in one repository remain two things to keep correct.

*Cost:* a divergence between them is a security bug that only shows up in
whichever path the caller took. Its 39 tests pass; that is not the same as
the two models agreeing.

*Explicitly not excluded*: §25's "service security addressed or explicitly
excluded" is answered here as **not addressed, and named** rather than
quietly dropped.

### 6. `test_chain_exceeding_max_depth_rejected` is vacuous · **REMAINING**

The test builds a chain by duplicating one hop, so it never exercises real
depth attenuation. Noted in the original audit and still true. It sits
directly beside code Gate 14 changed, which makes it more visible rather
than less.

*Cost:* `MAX_DELEGATION_DEPTH` is enforced (`chain.len() >=
MAX_DELEGATION_DEPTH` returns `LineageInvalid`) but the enforcement is not
covered by a test that could distinguish it from an accident.

---

## §25 checklist items not otherwise covered

### Bundle trust anchor · **ACCEPTED / JUSTIFIED, with the reasoning stated**

`verify_bundle_signature` checks the manifest against
`manifest.signer_public_key` — a key inside the bundle. That is not a trust
anchor and cannot be one.

On inspection it is not a false claim, because the code does not make one:
the failure message says "manifest not signed by the **embedded** key", the
report field is `authority_chain_verified: Not in this report` when no
`--trust` anchors are supplied, and the overall result degrades to
**NOT FULLY VERIFIED**. The security-relevant checks are on the evidence
*inside* the bundle, under caller-supplied anchors.

So the bundle signature is a container-integrity check, the same role JSON
plays for a NEXORA proof, and the wrapper is not a security boundary.

*What would be a defect, and is not present:* reporting `VALID` on the
strength of the embedded key alone.

*REMAINING sub-point:* the signer's identity is still unanchored, so the
bundle answers "this manifest matches this key" and not "this manifest came
from anyone in particular". A reader who stops at `BUNDLE_SIGNATURE: Pass`
learns less than the word "signature" suggests.

### Standalone roots tested · **FIXED**

`aip-standalone` — 925 tests, 0 failures. `aip-service` — 39 tests, 0
failures. Both run separately; `cargo test --workspace` does not cover the
service root.

---

## Summary

| classification | count | findings |
|---|---|---|
| FIXED | 5 | P0-1, P0-2, P0-3, §14, standalone roots |
| ACCEPTED / JUSTIFIED | 4 | §13 containment, caller-supplied anchors, Ed25519-only, bundle container signature |
| PARTIALLY FIXED | 1 | private key handling (Debug redacted; at rest plaintext) |
| REMAINING | 4 | packet timestamps, key storage, service second model, vacuous depth test |

Three findings in this document did not exist when the audit was written
and were found by the work itself: P0-3 (the unauthenticated root), the
verifier reporting a result on refused packages, and a carried component
reporting `Absent`. All three are fixed. They are recorded because a
programme that only ever closes findings it was handed is not auditing
anything.

**What this reconciliation does not establish.** That no further defects
exist. Every entry above is a statement about a specific, named property
with a specific, named test. The absence of a finding in this document is
not evidence that the corresponding property holds.
