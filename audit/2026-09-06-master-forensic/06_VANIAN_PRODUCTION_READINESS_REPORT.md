# Production Readiness Report

## 1. Verdict

| Branch | Classification | One-line basis |
|---|---|---|
| **prod** | **NOT PRODUCTION READY** — pilot-capable for the observation and reconciliation tiers only | Sound crypto core and verdict engine; unremediated P0 in packet verification; containment path unreachable and untested end-to-end; HTTP service untouched |
| **main** | **NOT PRODUCTION READY** | Signing payloads omit expiry; no verifier clock; every base-audit finding open |
| **audit** | not a product branch | tooling only |
| **importot** | **NOT ASSESSED AS PRODUCTION CODE** | four Rust roots and a Python SDK that no build or test run in this repository reaches |
| **valladder** | **PROTOTYPE** | oldest line; main-era crypto defects; unbounded circuit-breaker state; simulated PQC |
| **aipv4** | **PROTOTYPE** | strict subset of valladder |

No branch should be described as production ready. `prod` is materially
closer than the rest and the gap is specific and enumerable rather than
diffuse.

## 2. Blocking issues on `prod`

Ordered by severity. Each is CODE-PROVEN or EXECUTION-PROVEN; see the cited
report for the derivation.

| ID | Sev | Issue | Where | Report |
|---|---|---|---|---|
| **B-1** | **P0** | The verifier has no clock. A packet dated arbitrarily far in the future passes all 15 rules at `AuthorityBound` with `tampered = false`. | `aip-protocol/src/verification.rs:535` `check_temporal_validity`; `VerificationContext:29` has no time field | 03 I-7 |
| **B-2** | **P0** | A delegation hop's issuer is never bound to the previous hop's grantee. Any trusted key can substitute itself as issuer of a hop whose `parent_jti` matches. | `aip-core/src/delegation.rs:179-244` | 03 I-3 |
| **B-3** | **P1** | Containment cannot actuate on any engine-produced reconciliation, and no test crosses the reconcile→warrant→contain boundary. | `aip-containment/src/contain.rs` gates 3/5/6 vs `aip-reconcile/src/reconcile.rs:89-137` | 04 §3 |
| **B-4** | **P1** | A bundle is verified against a public key the bundle itself supplies. | `aip-protocol/src/bundle.rs:437` | 03 I-9, 05 §3 |
| **B-5** | **P1** | Private keys are written with default permissions; no `set_permissions`, no atomic replace. | `aip-core/src/store.rs:138` | 05 §4 |
| **B-6** | **P1** | The service mints a new identity when its key file is missing **or unreadable**, rather than failing to start. | `aip-service/src/keys.rs:130`, fall-through at `:144-154` | 05 §4 |
| **B-7** | **P1** | Private seeds are accepted in HTTP request bodies. | `aip-service/src/evidence.rs:125,130` | 05 §4 |
| **B-8** | **P2** | Packet replay is undetected — no nonce or JTI ledger at the packet layer. | `aip-protocol/src/verification.rs` (no replay rule among R1–R15) | 03 I-8 |
| **B-9** | **P2** | `Reconciliation`'s fourteen fields are all `pub`; any consumer can construct a verdict bypassing `precondition_holds`. | `aip-reconcile/src/result.rs:679-699` | 03 I-14 |
| **B-10** | **P2** | The primary test command does not reach the HTTP service. | `aip-service` is a member of no workspace, all branches | 02 §5 |
| **B-11** | **P3** | The two observer-directed verdicts have no structural precondition, only a strength threshold. | `aip-reconcile/src/reconcile.rs:129-131` | 04 §2.1 |

### 2.1 What B-1 and B-2 mean together

Individually each is serious. Together they compose: B-2 lets an attacker
holding *any* trusted issuer key insert themselves into a delegation chain,
and B-1 removes the time bound that would otherwise limit how long a
captured or forged chain remains usable. The system's central claim —
that an evidence packet establishes *who* authorized an action and *when* —
is not held by either half on any branch.

`prod` narrowed B-2's surface materially: because `expires_at` is now
covered by the hop signature, a forged expiry fails as `SignatureInvalid`
rather than being accepted. The identity substitution itself is untouched.

## 3. What `prod` demonstrably gets right

This is not a bad codebase and the report should not be read as saying so.
The following are EXECUTION-PROVEN or TEST-PROVEN:

1. **787 tests, 0 failures, 0 warnings across 78 test binaries.** The suite
   is 5.5× main's and includes dedicated adversarial files
   (`aip-observe/tests/adversarial.rs` 941 lines,
   `aip-reconcile/tests/adversarial.rs` 1,419 lines,
   `aip-authorize/tests/adversarial.rs` 671 lines).
2. **The signing payload rewrite is complete and correctly tested** — see
   Report 05 §2.2. The interior-NUL and adjacent-identifier collision tests
   show the authors understood the actual failure mode, not just its name.
3. **Temporal attenuation is enforced against a valid signature**
   (`test_legitimately_signed_hop_outliving_parent_rejected`). Enforcing a
   policy the signature cannot express is the correct shape.
4. **The reconciler fails closed through a single choke point** and the
   default verdict is `CannotProve`.
5. **Observer key locality is designed, not asserted**, with the deployment
   obligation stated explicitly in the module doc rather than glossed.
6. **Coverage claims from the observed host are re-derived, not trusted.**
7. **RFC 6962 Merkle construction with correct leaf/node domain separation.**

## 4. Test forensics — where passing tests do not establish the property

The brief's rule that tests are not proof unless they exercise the property
is load-bearing here. Three cases:

| Case | Test | What it actually proves | What it appears to prove |
|---|---|---|---|
| **Containment** | `aip-containment/tests/containment.rs` (1,032 lines) + `live_freeze.rs` (404) | Given a `Proven` workload violation, 17 gates behave as specified | That containment works end-to-end. It cannot: `proven_phantom()` at `:132` is a combination the engine cannot emit, and neither crate ever calls the reconciler. |
| **Circuit-breaker bound** | `aegis-quantum/stress-tests/tests/lru_exhaustion_test.rs` | That a `MockLruSessionMap`, defined at `stress-tests/src/lib.rs:19`, evicts to capacity | That `CircuitBreaker`'s state is bounded. It is not — `connections` is an unbounded `HashMap` with no eviction path. |
| **PQC exchange** | `aegis-quantum-userspace/src/pqc.rs` tests (12 of them) | That Kyber round-trips against itself in one process, at expected key sizes, within a wall-clock budget | That a quantum-safe session key is established with a peer. There is no peer. |

In all three cases the tests pass and are not themselves defective. The gap
is between what they assert and what a reader would take them to cover.

## 5. Coverage and reachability gaps

**CODE-PROVEN.** Roots that no test invocation in this repository reaches:

| Root | LOC | Reached by |
|---|---:|---|
| `aip-service` (all branches) | ~4,200 | a separate `cargo test` in that directory only |
| `importot/orbitaltrust-accountability/rust/ot-accountability-core` | — | nothing |
| `importot/…/ot-sentinel` | — | nothing |
| `importot/…/ot-verifier` | — | nothing |
| `importot/…/ot-mcp-gateway` | — | nothing |
| `importot/…/python-sdk` | — | nothing |
| `importot` TypeScript | 12,166 | nothing |
| `aipv4/aegis-quantum` | ~3,000 | nothing (not run in this audit) |
| `aegis-quantum-ebpf` (both branches) | 322 | excluded from the workspace; requires nightly + `bpfel-unknown-none` |

`importot` adds 35,673 lines and **zero tests to `aip-standalone`** — its
run is 143/0/1, identical to main's.

## 6. Operational hazards

| ID | Sev | Hazard |
|---|---|---|
| O-1 | P1 | `aegis-quantum-circuit-breaker` grows without bound under connection-tuple variation. Remote memory exhaustion in the component whose purpose is DoS defence. (valladder/aipv4) |
| O-2 | P2 | `CircuitBreaker::new` performs unchecked `window_ms * 1_000_000` and validates neither `window_ms` nor `threshold`. `threshold = 0` trips on the first event. |
| O-3 | P2 | Cryptographic dependencies are caret ranges, not pinned: `pqcrypto-kyber = "0.8"`, `pqcrypto-traits = "0.3"`, `sha2 = "0.10"`, `aya = "0.13"`. |
| O-4 | P3 | `aegis-quantum-ebpf` is excluded from its workspace and requires a nightly toolchain and a cross target. It is not built by any CI path visible in the repository. |
| O-5 | P3 | A wall-clock assertion inside a unit test (`test_kyber768_performance_under_5ms`) will flake on loaded CI. |

## 7. Recommended gating sequence

Not a remediation plan — the brief forbids fixing during the audit — but the
order in which the blockers must be cleared is itself a finding, because
some depend on others.

1. **B-1** (verifier clock). Independent; smallest change with the largest
   security delta. Add `now_ms` to `VerificationContext` and bound packet
   age in `check_temporal_validity`.
2. **B-2** (issuer↔grantee). Independent; one comparison per hop.
3. **B-3** (containment reachability). Requires a decision first — is
   autonomous containment intended to be reachable at all? Until that is
   answered, no code change is correct. The end-to-end test should be
   written *before* the answer, because it documents the current behaviour
   either way.
4. **B-5**, **B-6**, **B-7** (key handling). Independent of each other and
   of the above.
5. **B-4** (bundle signer key). Requires a trust-anchor design decision
   analogous to `VerificationContext::trust_issuer`.
6. **B-9** (verdict constructibility) should be resolved before, not after,
   B-3 — sealing `Reconciliation` changes what the containment integration
   test can express.
7. **B-10** (workspace membership) is a one-line manifest change and should
   precede all of the above, because it determines whether fixes to the
   service tier are exercised by the primary test command at all.
