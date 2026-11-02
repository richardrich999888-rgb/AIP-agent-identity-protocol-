# Enterprise integration validation — 28 October 2026

Source implementation: feature branch `feature/snifferdog-enterprise-integration`;
committed customer interface baseline `cdbd91781ac74e206f50131db20a755f91eadb29`
(also recorded in the retained final check report). Initial base `3a029aec83fa2aa57ea8bb0a2c28968f3be037a4` preserves
RBI `0991fb1eed1234403c1ff9683d010797ea073d39`; merge `d747a9fd` additionally
preserves concurrent swarm work through `f025a57`.

Host: Darwin/macOS arm64, Rust 1.91.1, Python 3.12.12, Node 25.2.1.
Privileged Linux sensors, a genuine separate collector host, live PostgreSQL
and a Kubernetes cluster were unavailable locally. Docker's daemon was not
running. Hosted Linux/PostgreSQL checks were subsequently executed as recorded
below; local absence is not a successful test, and institutional deployment
gates remain separate.

## Executed evidence

The final scoped checks are retained under
`validation/enterprise/results/20261028T102430Z/`. `report.json` records each
exact command, exit status, source commit, source-file SHA-256 values and host
scope; individual `.log` files contain the executable transcripts. The earlier
`20261028T101450Z` run is preserved rather than rewritten and includes the
console fixture screenshot. A Rust test suite's count does not establish that
Linux-only behavior ran on this host.

| Check | Result and scope |
| --- | --- |
| Scoped Rust suites | 620 passed, 0 failed, 3 ignored helpers/explicit live tests; service, gateway, AIRI, authorization, archive verifier, transport, collector and reconciler. The live API test was then explicitly executed separately. Kernel behavior is not asserted from Darwin tests |
| Service negative controls | Reader mutation/raw-export refusal; tenant hiding; strict pagination; real verifier; approved collector anchors; wrong keys/versions/tenants; malformed/tampered/duplicated archives; idempotency; persistence/restart; failed-append/readiness and console headers |
| Actual HTTP API + both SDKs + official evidence MCP client | Explicitly executed ignored Rust live fixture: authorized signed verdict/archive reads succeed; same IDs under another tenant fail; raw export and privilege-bearing MCP credential refused |
| OpenAPI contract | Actual read responses, unauthenticated/wrong-tenant errors and route alignment validated against the implemented source/JSON schemas |
| Python SDK/AIRI regressions | 76 tests passed in the first retained full run; final transcript records exact current count |
| SDK/MCP boundary negatives | 9 passed: bounded replies/frames, truncated HTTP replies, role/tenant change, rate limit, allowlisted schemas and pagination errors |
| TypeScript | Real API interoperability, 2 transport tests and strict source type-check with TypeScript 5.9.3 passed locally |
| Runtime package | 16 deterministic archive/configuration/staging install/uninstall tests; fixture ELF inputs are explicitly not executed Linux binaries |
| Agent harness fixes | 3 control-flow regressions plus shell syntax passed; fixes explicit package selection, build exit status, synced-clock default and stable stopped-writer verification |
| SQL source parity | 1 passed; PostgreSQL feature/tests compile. Database-executed RLS/grant/race controls remain unexecuted locally |
| RBI harness controls | 17 deterministic tests passed. They are simulated-command/control-flow tests, not a fresh privileged rehearsal |
| Browser console | Actual Rust router with genuinely signed test records: Reader login, health/explicit unavailable coverage, stored identity/activity and real integrity-only verifier displayed; disconnect cleared records/credential. Screenshot is labelled fixture evidence, not a live bank dashboard |

## Real ContextForge and genuine framework run

Canonical public evidence:
`validation/enterprise/results/CONTEXTFORGE_20261028T101836Z/RUN.md`.
It pins IBM revision `ff6a566a4b5c098093db90bbb4d5df483e108026`, CPEX
0.1.4, MCP SDK/types 2.3.0, protocol `2026-07-28`, uv 0.13.6 and the upstream
lock hash. All 28 checks passed. Exact source and built-binary hashes are in
its source manifest.

Actual ContextForge dispatched to a genuine MCP tool server reading synthetic
SQLite in read-only mode. Its 17 upstream invocations produced 15 final
receipts and two deliberately unresolved receipt cases. Twenty-eight signed
receipts in total include 13 refusals; all verify offline under the public
anchor. Duplicate/concurrent replay, restart, identity/header/malformed-input
refusal, missing decision ID, unsupported tools, Origin, real tool failure,
timeout, key/sink/journal failures and post-dispatch uncertainty were tested.

The real Rust comparator checked a preissued signed authorization against
actual gateway receipts, returning `Agrees` for matching parameters and
`ReceiptDoesNotMatchAuthorization` for the mismatch, with no agent claim.
Those authorization process bindings are test fixtures. They do not establish
the autonomous agent's measured Linux identity.

A genuine LangGraph graph called the actual local `llama3.2:1b` model, chose
a read, executed through ContextForge and received a signed gateway receipt.
The agent got no signer/collector/authority key. Its final output explicitly
states independent execution evaluation `NOT_RUN`; a random decision join
label is not a signed authorization. The earlier actual model JSON failure
is retained under `failures/`; schema-constrained bounded output fixed it
without a fabricated tool choice. The final framework dependency lock and
model digest are documented in the banking example.

Compatibility limitation: pinned ContextForge strips successful top-level
plugin metadata on `/mcp`. The official client succeeded and the test verified
the actual durable receipt sink independently. `/rpc` retains receipt
metadata. Successful MCP output alone must not be used as the receipt store.

## Offline observer verification and RBI boundary

The current standalone verifier accepted the repository's **historical**
LangGraph archive and rejected interior deletion, corruption, reordering,
duplication and altered content. Prefix/suffix removal can leave a valid
signed window; the separately retained checkpoint detects those mutations.
The transcript states this limitation instead of claiming universal truncation
detection.

The historical fixture health reports `ContinuityUnverified`, **zero coverage
records**, an unsynchronised collector clock and a 16,000,000 microsecond error
bound. Its signed bytes verify; this is not an `Active` or verified-execution
result. No old transcript was rewritten or relabelled as a new kernel run.

The RBI branch's actual hosted Linux rehearsal at `0991fb1` completed
successfully in [run 40409155305](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40409155305).
That historical VM result does not qualify the presentation computer or a
two-host institution deployment.

## Fresh hosted Linux, database and packaging evidence

The manual [RBI run 40672603812](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40672603812)
checked out feature head `e9da41314c3851a92388a8ce80f1db9a3a696520` and
passed both script regressions and the complete five-act rehearsal. Retained
public evidence is under `results/RBI_20261028T103930Z/` relative to
`validation/enterprise/`. The disposable Ubuntu 24.04 x86_64 VM ran kernel
`6.17.0-1022-azure` with real synchronized clock, tracefs and root privileges.
The control reported `Active` with coverage; the deliberate interference
reported `IntegrityUnknown` with unavailable coverage; recovery returned to
`Active` without backfilling the blinded interval. The checker passed. Current
offline verification accepted 77 signed batches containing 3,475 events and
four health records; deletion of interior record 39 was rejected.

Acts 1/2/5 ran the actual kernel/collector interference experiment. Act 3
executed 11 destination-comparison library tests; Act 4 executed 26 gateway
tests and Act 4b exercised two actual stdio gateway receipts. These are not
claims of a live loan transaction, the separate LangGraph workload, a fresh
ContextForge deployment on that VM, or independent collector administration.
Both processes remained on the disposable VM. The actual presentation host
and institutional two-host installation still require their own rehearsal.

The successful [enterprise run 40672558666](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40672558666)
executed the Linux contract/client checks, real pinned ContextForge checks and
built an actual x86_64 Linux runtime archive. The
[PostgreSQL job in run 40672558568](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40672558568)
explicitly executed all 14 restricted-role storage controls against PostgreSQL
16.15, including forced tenant isolation, artifact immutability, legal hold and
concurrent idempotency. The default test step's ignored controls were not
counted as execution; the separate `--ignored` invocation passed all 14.

The concise hosted manifests and filtered test transcripts are retained under
`results/CI_20261028T103950Z/`. Hosted ContextForge passed 27/27 checks; the
separate local 28/28 run additionally includes the genuine model-driven
LangGraph workload. The downloaded Linux artifact's ZIP hash matched GitHub's
published digest, its tar hash matched the public build transcript, and the
repository verifier accepted all eight payload hashes/modes and the three
x86_64 Linux ELF headers. The runtime tar SHA-256 is
`18c8ab104842eb9d806ea4952a5104c368a2f5344f6c0d21aa75a93a3d87a86a`.
These integrity/provenance checks are not an independent reproducible build
or an institution-approved release signature. Downloaded binaries stay in
ignored local storage rather than this evidence commit.

These pull-request jobs report head `e9da413` but actually checked out GitHub's
synthetic merge `076b22c27d663a87dfd62d91df20583f417b383a` (tree
`c2ea29de5e04487706aae9dd9d0f7f2a1ff91fb7`) with the concurrently advanced
development base `5489260b96124b95a7973233e69d9e5a44cb6bf5`. They must not be
described as tests of the feature head's standalone tree. The manual RBI run
above is a separate direct-head execution. Building/verifying the runtime
archive does not qualify installation, systemd startup or an OS support matrix.

The complete [workspace CI run 40672558568](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40672558568)
subsequently finished successfully: formatting, strict workspace/all-feature
Clippy, locked debug and release workspace tests, coverage generation,
adversarial RED suite, Python SDK, PostgreSQL and configured dependency
audit/policy checks passed. `results/CI_20261028T103950Z/workspace-final.json`
and its filtered transcript retain the final job/step outcomes. The configured
advisory exception remains an exception, not a claim of no known advisories.
These results still belong to the exact synthetic merge above. Later
documentation/evidence-only commits do not change the runtime implementation
or retroactively change the source attached to this test run; their automatic
reruns are separate and are not counted here as passed.

Pinned Helm 3.18.6 passed default/enabled lint and rendering, six expected
configuration refusals and static rendered-YAML assertions. Exact chart hashes,
commands, output and tool checksum are under `results/HELM_20261028T103133Z/`.
No cluster was contacted; example images/configuration are rendering fixtures,
not built or approved runtime images.

## Failures, remediation and remaining limits

Resolved defects include the unregistered ContextForge helper; misuse of the
echo demo as forwarding evidence; unsigned/silently missing receipt handling;
Reader role absence; RAM fallback and failed-append acknowledgement; missing
signed-artifact SQL provisioning/RLS; concurrent database insert handling;
the LangGraph harness's wrong package/diagnostic-based build gate; local-model
truncated JSON; SDK malformed/chunked-response errors; and duplicate oversized
MCP serialization. Each is grounded in source or a retained executable test.

Setup failures were kept distinct: initial SDK test imports/loopback sandbox
permission were corrected; the historical framework lock's unavailable wheel
led to a separate exact tested lock; an approval timeout was retried once;
no product failure or successful privileged test is inferred from these.

CPU/memory utilization, ingestion throughput, event loss, observation-to-
collector latency, collector signing latency, reconciliation latency, storage
growth and agent runtime overhead on institution hardware are **UNMEASURED**.
Local test durations and one historical offline-verification duration are
diagnostics only, not capacity/performance claims.

The complete same-run authorization/kernel/collector/gateway/reconciliation/
API/SDK/MCP banking milestone is not met by joining separate fixtures. Clean
Linux installation, independent host administration, additional real
framework/coding workload runs, bank HSM/KMS, HA/backup restoration,
Kubernetes/air-gap qualification, supply-chain release evidence and independent
security assessment remain open. Every hosted result above is scoped to its
exact run/commit and does not imply those remaining gates have passed.
