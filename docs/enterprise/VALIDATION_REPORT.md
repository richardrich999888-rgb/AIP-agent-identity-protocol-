# Enterprise integration validation — 28 October 2026

Source implementation: feature branch `feature/snifferdog-enterprise-integration`;
committed customer interface baseline `cdbd91781ac74e206f50131db20a755f91eadb29`
(also recorded in the retained final check report). Initial base `3a029aec83fa2aa57ea8bb0a2c28968f3be037a4` preserves
RBI `0991fb1eed1234403c1ff9683d010797ea073d39`; merge `d747a9fd` additionally
preserves concurrent swarm work through `f025a57`.

Host: Darwin/macOS arm64, Rust 1.91.1, Python 3.12.12, Node 25.2.1.
Privileged Linux sensors, a genuine separate collector host, live PostgreSQL
and a Kubernetes cluster were unavailable locally. Docker's daemon was not
running. Those facts are blockers, never passing/skipped acceptance results.

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
two-host institution deployment. A fresh complete run on authorized Linux
infrastructure is still required for those claims.

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
security assessment remain open. Current CI results, when available, must be
reported by exact run/commit, not inferred from workflow files.
