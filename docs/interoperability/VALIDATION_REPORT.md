# Validation report — 2026-10-28

Overall: **PARTIALLY_VERIFIED. The requested first interoperability milestone is not achieved.** No new independently observed kernel execution or off-host signed observation archive is claimed.

Exact base: `e3aa195def7524d6ec84d37a934beebe18b6c794`, the existing draft PR #8 combining #6 and #7. The complete machine-readable [validation matrix](../../validation/interoperability/validation-matrix.json) records every inspected project. Exact upstream/release/model locks and license findings accompany it.

## Genuine executed workloads

| Integration | Actual workload and source authentication | Authorization / gateway / signatures | Coverage and status |
|---|---|---|---|
| Google ADK + A2A | Two real ADK agents, four Qwen inference calls, mTLS, pinned issuer/audience JWT and request-bound signed task credential | Provider selected a real tool through ContextForge; native gateway receipts verified offline | PARTIALLY_VERIFIED: single process, framework logical attribution, lab key custody, remote kernel unobserved |
| Microsoft ACS + ADK + A2A + ContextForge | Native Rust-backed SDK `run_tool`, actual pre/post Rego decisions around the model-selected gateway call | Native out-of-scope request denied before dispatch; two valid native governance results; gateway receipt verified | PARTIALLY_VERIFIED: same-process hook, no decision signature or verified institutional chain; exact ACS→gateway digest mapping not established |
| OPA | Real 1.21.4 service over mTLS, allowed research read and denied write | TLS-authenticated service reference, preserved native response/version; no signed ExpectedExecution | PARTIALLY_VERIFIED; separate run, not spliced into the combined agent run |
| SPIFFE/SPIRE | Actual pinned server attempted | Unit-tested JWT-SVID verifier; no locally issued SVID from successful service | BLOCKED locally by unavailable Unix sockets. CI is configured to attempt a genuine service on Ubuntu |
| OpenShell | Documented native OCSF parser contract tested | Imported events remain unauthenticated; no genuine sandbox run | IMPLEMENTED parser; workload BLOCKED by missing runtime/host capabilities |

The final combined run contains 28 gateway checks and 28 signed receipts. It also passes five live negative checks: native ACS out-of-scope denial, missing A2A bearer, wrong audience, altered delegated request, and missing TLS client certificate. The gateway suite additionally covers replay/restart, altered parameters, wrong keys, signature/sink/journal failures, timeout, denied operations and concurrent duplicates.

The harness's honest/mismatch ExpectedExecution files are explicitly **test fixtures for separate comparator cases**. They are not the institutional authorization for the model's operation. The model receipt is real; its complete identity→authority→kernel join is absent. No public archive contains signing keys, bearer tokens, raw model credentials or invented observations.

## Exact evidence locations

All paths below are under [validation/interoperability/results/20261028](../../validation/interoperability/results/20261028):

| Evidence | Relative path | Meaning |
|---|---|---|
| Combined workload summary and native ACS records | `combined/adk-a2a/result.json` | Real SDK interactions; explicit missing guarantees |
| Genuine model generations | `combined/adk-a2a/model-transcript.jsonl` | Untrusted model prose/tool choices; not execution evidence |
| Framework correlation | `combined/adk-a2a/framework-events.jsonl` | Application-reported metadata |
| Executed adapter source digests | `combined/adk-a2a/source-sha256.json` | Exact source bytes used for the workload |
| Gateway report and source/binary digests | `combined/report.json`, `combined/source-manifest.json` | 28 actual checks; exact existing signer and harness bytes |
| Signed gateway archive and lab public anchor | `combined/receipts.jsonl`, `combined/trust-anchor.json` | Existing Rust signatures; lab anchor authority remains external |
| Upstream received requests | `combined/upstream-events.jsonl` | Real MCP upstream events; application provenance |
| Actual MCP negotiated protocol | `combined/mcp-client-result.json` | Version `2026-07-28`; not all-spec conformance |
| OPA native references | `opa/result.json` | Separate actual mTLS run |
| Offline receipt verification | `checks/receipt-offline-final.log` | 28 verified signatures; changed commitment refused |
| Execution/uncertainty summary | `run-summary.json` | Honest same-run acceptance checklist and failed attempts |
| Integrity manifest | `SHA256SUMS.json` | Content hashes, not an independent signature or trust root |

The original RBI/enterprise archives remain untouched. Their successful historical observation cannot fill a new run's missing sensor or authorization.

## Tests actually run locally

| Command / check | Result | Qualification |
|---|---|---|
| `pytest integrations/interoperability/tests -q` | 47 passed | Contract/negative tests; no external integration status inferred |
| Scoped Cargo tests for authorize, spiffe, airi, mcp-gateway, reconcile | 446 passed, 1 ignored | Existing native cryptography and reconciliation regressions |
| `cargo test -p aip-airi --example interop_verify` | 3 passed | Role-key separation and native envelope refusal |
| Offline composition against real receipts + labeled fixture | 3 checks passed | No observation yields CannotProve; tampered receipt/expectation refused |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed | Full workspace compilation/lints; initial offline cache miss resolved by normal locked download |
| `cargo fmt --all -- --check` | Passed | No broad formatting rewrite |
| Existing Python SDK, clean prescribed environment | 76 passed | Model venv first failed metadata parity due installed PyTorch; clean environment result retained |
| TypeScript SDK | 2 passed | Native Node tests |
| Existing RBI control-flow tests | 17 passed | Explicitly fixture control-flow checks, not a new RBI kernel demonstration |
| Enterprise packaging, harness and SQL parity | Passed | Existing tests retained |
| Existing MCP client boundary tests | 9 passed | Executed using the pinned ContextForge MCP environment |
| Native Rego tests | 4 passed | Actual pinned OPA binary |
| Frozen uv dependency environment | 47 passed | Independently installed from committed `uv.lock` |
| Historical archive offline regression | Passed, including mutation refusal | Explicitly historical; no new live-agent or kernel claim |
| `cargo test --locked --workspace --no-fail-fast` | **Failed: 3078 passed, 161 failed, 8 ignored; 28 failed targets** | Full log retained; failures include unavailable `/proc` process metadata, host observation/cgroup facilities and SoftHSM prerequisites. No blanket green claim |

The complete workspace failure is not reclassified as a pass. The new code does not alter those host-dependent implementations. A clean supported runner is required to distinguish every environmental failure from other baseline defects. Release-mode, PostgreSQL runtime and privileged clean-host validation are NOT_EXECUTED locally.

## CI and reproduction

The new workflow pins actions and OPA/SPIRE release assets, and is configured for locked adapter tests, real OPA/SPIRE attempts and offline native verification. Existing repository workflows remain enabled. At code head `a1f4bfbc798c2bd7be734f75c8b3aa7eb7a7a3e3`, GitHub marked all four workflows failed: all 11 jobs had runner ID 0 and zero steps. Logs were unavailable (`BlobNotFound`). This is **BLOCKED CI execution**, not test failure evidence or a passing run. The provider cause was not exposed by the available connector. Exact run IDs and job records are in [ci-attempt.json](../../validation/interoperability/ci-attempt.json). SPIRE therefore remains unexecuted on CI too. See the PR for the current head's checks.

[Package instructions](../../integrations/interoperability/README.md) reproduce the model/native-framework run. The official A2A TCK was inspected and pinned but not run against this custom authenticated task profile. Full MCP conformance, AGNTCY credentials, NeMo, Cedar, OpenFGA, OpenTelemetry exports and CycloneDX schema export remain NOT_EXECUTED.
