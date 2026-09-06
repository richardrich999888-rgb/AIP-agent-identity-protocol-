# Skill 16 — Production Boundary and Blocker Closure: Evidence Report

**Branch** `claude/autonomous-accountability-skills-16-30`
**Base** `origin/claude/codebase-production-readiness-wm6idp` merged with
`origin/claude/aip-security-architecture-audit-zpf9b3` (commit `ec2c8db`, 0 conflicts)
**Range** `ef0877f..6ee8f73` — 8 commits, 40 files, +6618 / −1118

Source of truth: the revised AIP Six-Branch Forensic Audit, blocker register
B-1a … B-10. Where this report and a branch README disagree, this report is
subordinate to the code and the executed tests, in that order.

---

## 1. Blocker register — final state

| ID | Finding | State | Commit |
|----|---------|-------|--------|
| B-10 | `aip-service` outside the primary build/test boundary | **CLOSED** | `283c473` |
| B-1a | Service verification applied no temporal bound | **CLOSED** | `283c473` |
| B-9 | `Reconciliation` construction not sealed | **CLOSED (pre-existing)** | prod `30aafc6` |
| B-6 | Key load failure silently generated a new identity | **CLOSED** | `baf7343` |
| B-5 | Seed written then chmod'd; overwrite possible | **CLOSED** | `baf7343` |
| B-7 | Private agent seeds in HTTP request bodies | **CLOSED** | `ceca361` |
| B-4 | Bundle verifier trusted a key supplied by the bundle | **CLOSED** | `da5bbaa` |
| B-8 | No replay semantics, no anti-replay mechanism | **CLOSED** | `b6710aa` |
| B-3 | Reconciler → warrant → containment never driven end to end | **OBSERVATION CLOSED / FINDING OPEN** | `6ee8f73` |

B-3 is the one that did not close, and it did not close because closing it as
specified would have required asserting a capability the system does not have.
See §4.

---

## 2. Evidence class per closure

Using the skill's own vocabulary. Nothing below is upgraded past what was
actually executed.

### B-10 — one workspace
- **CODE-PROVEN** Repository-root workspace, 19 members, `aip-service` among
  them. `aip-standalone/Cargo.toml` and its `Cargo.lock` deleted; a stub
  `[workspace]` was tried first and *fails* — an empty workspace table makes
  that directory a root again with zero members and every crate under it stops
  resolving `workspace.package`. Verified by running `cargo metadata` from
  inside a member crate.
- **TEST-PROVEN** `aip-service/tests/build_boundary.rs` (3): the service
  compiles against the protocol crate, the temporal-bound API is reachable
  from it, and the root manifest lists `aip-service` as a member.
- **EXECUTION-PROVEN** `cargo test --workspace` compiles and runs the service
  tier: 102 suites, 1024 tests.

### B-1a — the temporal bound reaches the service
- **CODE-PROVEN** `verify_request` sets `ctx.verification_time_ms` from the
  caller's value or the service clock; `future_tolerance_ms` defaults to 0.
  No request value reaches unbounded verification.
- **TEST-PROVEN** `aip-service/tests/temporal_bound.rs` (13).
- **EXECUTION-PROVEN (mutation)** With the two-line fix reverted, 12 of 13
  fail. The thirteenth is the fixture-soundness guard and must pass either way.
- **Correction made during the work:** three of those tests initially passed
  under the revert, by reading `!pass` on a rule recorded NOT EVALUATED.
  `assert_refused` now requires `evaluated` first. Recorded because it is the
  exact epistemic error the forensic rule forbids, caught in my own tests.

### B-6 / B-5 — signing-key custody
- **CODE-PROVEN** `load_or_create` creates only on `KeyError::Absent`; every
  other outcome propagates. `main` logs, prints to stderr, exits non-zero.
  `write_new_seed_file` uses `O_CREAT | O_EXCL` with mode supplied at open
  time and never calls `set_permissions`.
- **TEST-PROVEN** `aip-service/tests/key_custody.rs` (10).
- **EXECUTION-PROVEN (mutation)** Reinstating generate-on-any-error fails 3;
  reinstating write-then-chmod fails 1.
- **NOT TEST-PROVEN, stated as such:** the *race window* itself. The umask test
  does not discriminate against write-then-chmod — the chmod lands before the
  assertion can read the mode. A racing-reader test would be
  non-deterministic, which the engineering standard forbids more strongly
  than it demands this coverage. The test says so in its own body.
- **NOT PROVEN:** that `main` exits. That is one `match`; testing it means
  spawning the binary. The property that decides it — `load_or_create`
  returning `Err` rather than a substitute keypair — is proven.

### B-7 — no private seeds in request bodies
- **CODE-PROVEN** The generate route is selected at router-build time. When
  managed signing is refused there is no body extractor, so a seed sent there
  is never deserialized. `GenerateRequest` and `ReceiptInput` have hand-written
  redacting `Debug`.
- **TEST-PROVEN** `aip-service/tests/managed_signing.rs` (8), including that a
  malformed body still returns 501 — proving nothing parsed it.
- **EXECUTION-PROVEN (mutation)** Routing generate unconditionally fails 3;
  restoring derived `Debug` fails 2.
- **OPEN RESIDUAL RISK:** on the opted-in path the seed is a `String` and does
  not zeroise. The bytes survive in the heap, and in a core dump, until
  reallocated. Closing this needs a secret-string type threaded through
  deserialization.

### B-4 — bundle signer anchored by the verifier
- **CODE-PROVEN** `BUNDLE_SIGNATURE` keeps its meaning (self-consistency) and
  says so in its detail. New `BUNDLE_SIGNER_TRUSTED` reads
  `ctx.trusted_bundle_signers`. No anchors ⇒ `Warning`, and `finalize` never
  reports `Pass` overall while any check warns.
- **TEST-PROVEN** `aip-protocol/tests/bundle.rs` (13, of which 7 new),
  including a genuinely forged bundle — real structure, real hashes, real
  signature under the forger's own key.
- **EXECUTION-PROVEN (mutation)** Making R5a unconditionally pass fails 4.
- **No new result class.** `BundleStatus` unchanged; `Warning` already carries
  "verified as far as this verifier could", and adding a variant to a
  serialized enum would change the wire format for every consumer.

### B-8 — replay semantics defined and enforced
- **CODE-PROVEN** R17 `ACTION_UNIQUENESS` (always evaluated) and R18
  `REPLAY_SCOPE` (evaluated only with a history, NOT EVALUATED otherwise).
  `ObservedHistory` maps each identity to the packet that established it, so a
  packet re-verified against a history containing it maps to itself.
- **TEST-PROVEN** `aip-protocol/tests/replay.rs` (10),
  `aip-service/tests/replay_ingest.rs` (6).
- **EXECUTION-PROVEN (mutation)** Building the history across all tenants
  fails 2; passing R18 without a history fails 1.
- **OPEN RESIDUAL RISK (performance):** the service walks the tenant's packets
  per request that asks. Adequate for the reference JSONL store, not at
  volume. A production store should answer "who recorded this decision id"
  from an index, which needs a new trait method.
- **OPEN ARCHITECTURAL GAP:** with managed signing off (B-7), the service has
  **no client-signed ingest endpoint**, so there is no boundary at which this
  is enforced automatically. `check_replay` is available to a caller; nothing
  makes a caller use it. See §5.

### B-9 — reconciliation construction sealed
- **CODE-PROVEN, pre-existing.** Verified present on this branch, not
  re-implemented: `Provenance::{Engine, Deserialized}`, `Reconciliation`
  `#[non_exhaustive]` with a private field, `evaluate` refusing
  `ReconciliationNotEngineProduced`.
- **TEST-PROVEN, newly against engine output** rather than a fixture:
  `a_reconciliation_that_travelled_as_bytes_is_refused_by_the_warrant_layer`
  round-trips a *genuine engine verdict* and confirms the refusal.

---

## 3. Test and check results

```
cargo test --workspace     102 suites   1024 passed   0 failed   5 ignored
cargo clippy --workspace --all-targets              clean
cargo fmt --all -- --check                          clean
```

Suites added: 8 files, 68 tests.

| Suite | Tests | Blocker |
|---|---|---|
| `aip-service/tests/build_boundary.rs` | 3 | B-10 |
| `aip-service/tests/temporal_bound.rs` | 13 | B-1a |
| `aip-service/tests/key_custody.rs` | 10 | B-5, B-6 |
| `aip-service/tests/managed_signing.rs` | 8 | B-7 |
| `aip-service/tests/replay_ingest.rs` | 6 | B-8 |
| `aip-protocol/tests/replay.rs` | 10 | B-8 |
| `aip-protocol/tests/bundle.rs` | +7 (13 total) | B-4 |
| `aip-containment/tests/engine_to_containment.rs` | 5 | B-3, B-9 |

Every security fix was mutation-checked: the defect was reintroduced and the
tests were confirmed to fail. A regression test that passes before the fix
proves nothing, and three of mine did until corrected.

### Pre-existing tests whose meaning changed

Three, each updated rather than the new rule weakened:

1. `test_bundle_build_and_verify_ok` reached `Pass` with issuer keys alone —
   exactly the state B-4 says must not be mistaken for attribution. It now
   anchors the signer, as a real verifier must.
2. `test_honest_packet_verifies_at_counterparty_floor` enumerates which rules
   may go unevaluated, deliberately, so the exemption cannot become a blanket
   skip. R18 is named alongside R16.
3. The service export test now anchors the service's own signer key and
   asserts `BUNDLE_SIGNER_TRUSTED` passes.

---

## 4. B-3 — the finding that did not close

The skill required: *"connect real reconciler output to warrant evaluation and
containment with a genuine end-to-end engine-produced path."*

The observation gap is closed. `engine_to_containment.rs` drives a real
`DecisionPoint`, a real `CollectorSigner`, the real engine, `evaluate`, and
`contain()` against a live process. Two crossings execute end to end on
engine-produced reconciliation.

What that turned up:

> **Actuation is unreachable from genuine reconciliation.**

Three independent closures, each sufficient alone:

1. `contain()` gate 5 requires `Proven`. Every workload-violation class the
   engine draws — `PhantomClaim`, `UnattributedEffect`, `IdentityDivergence`,
   `LineageViolation` — is capped at `Attested`, because the content behind
   them is read from the observed host and is root-forgeable.
2. `contain()` gate 6 requires a workload violation. The only class the engine
   draws at `Proven` is `SensorIntegrityFailure`, which gate 6 names and
   refuses.
3. Tightest: a `SensorIntegrityFailure` means the observer's evidence could not
   be trusted, so the record necessarily carries `Unavailable` availability.
   `evaluate` step 4 caps that at `Alert`, and gate 7 refuses it independently.
   The one verdict strong enough to clear the strength gate is by its own
   nature a verdict about missing observation.

The cgroup freezer can therefore be reached only by a `fixture_default()`
record. **This is not asserted to be a defect.** A fail-closed system observed
fully closed is behaving as designed; whether full closure is the intended end
state is an architectural decision, and it is not one to make while closing
blockers.

What was explicitly **not** done: manufacture a `Proven` `PhantomClaim` to make
the actuator fire. That verdict does not exist outside a fixture. A test that
invented one would assert a capability the system does not have, which is the
specific failure the forensic rule prohibits.

Against the skill's acceptance gate — *"at least one test crosses reconcile →
warrant → containment using engine-produced reconciliation"* — the crossing
exists and executes. It terminates in a refusal. That is the honest result.

### One prediction I got wrong

I expected the integrity verdict to warrant `Constrain`; the engine returned
`Alert`, because of closure 3 above, which I had not anticipated. The
assertion records what the engine does and the module doc explains why. The
observation makes the finding stronger, not weaker.

---

## 5. Remaining production risks

Ordered by consequence.

1. **No client-signed ingest endpoint.** With managed signing off by default,
   there is no endpoint at which a client-signed packet enters the service.
   `/v1/evidence/verify` calculates; it does not ingest. So B-8's replay
   mechanism has no boundary that enforces it, and the documented production
   shape ("agents sign client-side; the service verifies and ingests") is
   half-built. This is an architecture change, deliberately not made here.
2. **Actuation unreachable from engine output** (§4). Either the strength
   ladder must admit a workload violation at `Proven`, or containment must
   admit `Attested` under an explicit operator gate. Both are design
   decisions, not fixes.
3. **Agent seeds are not zeroised** on the opted-in managed-signing path.
4. **Replay history is O(tenant packets) per checked request.**
5. **PostgreSQL store untested here.** The `postgres` feature was not compiled
   or exercised; no database was available. Every claim in this report about
   the store is about `JsonlEvidenceStore`.
6. **`main`'s fail-closed exit is CODE-PROVEN, not TEST-PROVEN** (§2, B-6).
7. **Known pre-existing flake**, unrelated to this work:
   `aip-observe fa05_live_a_write_by_this_process_is_bound_through_the_kernels_pidfd`
   races parallel filesystem activity; passes in isolation.

---

## 6. Constraints honoured

- No work on `main`; nothing merged or promoted.
- **No second reconciliation engine.** No new engine, no new result class.
  `BundleStatus` and `ReconciliationResult` are unchanged.
- **No NOT_DETERMINABLE / CANNOT_PROVE / NOT EVALUATED converted into a
  successful assertion.** Two new rules (R17, R18) follow R16's established
  shape; R18 and `BUNDLE_SIGNER_TRUSTED` both report "did not check" as
  distinct from "checked and fine", and neither can reach a clean overall
  verdict without the input it needs.
- **No unsupported PQC claims.** None made; nothing touched.
- **AI/physical-effect boundary respected.** §4 is precisely a refusal to
  treat a gate's existence as proof that the effect it guards is reachable.
- Small commits, one blocker group each; the one unrelated change (a
  `cargo fmt` sweep over `aip-airi` and `aip-nexora`) was split out into
  `906d51f` and verified whitespace-only with `git diff -w`.
- No invariant silently weakened. Three tests changed meaning; all three are
  named in §3 with the reason.

---

## 7. Gate evaluation

The skill's acceptance gate, item by item:

| Criterion | Status |
|---|---|
| No open P0 findings under the central accountability claim | **MET** — B-1a, B-9 closed; no P0 remains open |
| All P1 production blockers have code-backed closure evidence | **MET for B-4, B-5, B-6, B-7, B-8, B-10.** B-3: the observation is closed with evidence; the finding it produced is open and is architectural |
| Service and standalone verification agree on temporal semantics | **MET** — both run R16 through `verify_packet`; the service always supplies a time |
| ≥1 test crosses reconcile → warrant → containment using engine-produced reconciliation | **MET** — 2 crossings execute. Both terminate in a refusal, for the structural reasons in §4 |
| Primary CI command compiles and tests the service tier | **MET** — `cargo test --workspace` covers 19 crates including `aip-service` |

### May Skill 17 begin?

**Yes, with one condition stated rather than assumed.**

Every blocker the skill listed is closed with code-backed, mutation-checked
evidence, except B-3 — where the required work was done and produced a finding
instead of a closure. Nothing in that finding blocks a *new domain
architecture* from being built on the accountability core; it constrains what
the core can be claimed to do today.

The condition: **§5.1 and §5.2 are decisions for the architecture owner, not
for the next skill to route around.** If Skill 17 or later needs packets
ingested, or needs containment to actuate, those are the two items to settle
first — deliberately, in the open, and not by widening a gate to make a test
pass.

Production promotion is **not** authorised by this report. The skill's own
rule applies: no promotion claim until every P0/P1 blocker is closed or
explicitly accepted by an authorized security decision record. §5.1 and §5.2
have no such record.
