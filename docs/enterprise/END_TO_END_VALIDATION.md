# End-to-end validation record

Status: **HOSTED SOFTWARE PATH PASSED; DEPLOYMENT PARTIAL.** Combined-source
workflow [40854983596](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40854983596)
on `9ed1662` passed genuine model/tool execution, independently issued
authorization, signed receipts and task coverage, API/SDK/MCP/browser retrieval,
offline verification, actual observer interruption and fresh recovery. Positive
runs retain `CannotProve / ActionEvidenceUnavailable`; interruption retains
`CannotProve / WindowNotCovered`. See the current [acceptance report](../../validation/final_acceptance/REPORT.md)
for exact sources, original evidence, subsequent CI repairs and claim limits.
The entire assignment is not complete. Separate-host
administration, swarm qualification and production qualification have their own
status and cannot be inferred from a hosted software run.

## Source reconciliation

| Item | Verified revision |
| --- | --- |
| PR #6 | `65b6ff7fdad5ae70546a57216a497399091c7dc7` |
| PR #7 | `bd15b8e627e5ef67ba259559ed81feb6894cde48` |
| Common ancestor | `f025a57911f7daf473cdfdcbf98d2f911df2534e` |
| Combined merge | `e3aa195def7524d6ec84d37a934beebe18b6c794` |
| Integration branch | `integration/snifferdog-complete-enterprise-validation` |
| Integration PR | [PR #8](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/8), draft |

PR #6 had seven commits after the common ancestor and PR #7 had eight. Their
changed-file sets did not overlap, and the merge had no textual conflicts.
Both original PRs remain drafts. The dirty primary desktop checkout was not
modified. Later implementation and exact CI source revisions are recorded by
GitHub run metadata and the retained source/run manifests, rather than inferred
from a prior synthetic merge.

## First genuine workload

The reusable path is the existing LangGraph loan-document agent, actual pinned
ContextForge, a genuine MCP read subprocess, existing Sniffer Dog sensors and
existing enterprise clients. Synthetic customer records are safe test data;
model responses, tool requests, tool execution and kernel events must be real.
The task is to read synthetic loan 1 and recommend human review without issuing
an approval or modifying a banking record.

The local CPU model is `llama3.2:1b`, manifest SHA-256
`baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878`.
The bootstrap validates the exact public Ollama archive, model manifest and
every model blob. No cloud API key is used, cloud inference is disabled, and
the measured workload network has no external route. API spending is zero;
CPU, memory, process count and execution time remain bounded.

`same-run-validation.yml` records the source commit, actual model/task,
controller-measured process identities, signed expectation, signed gateway
receipts, original signed observation/health archives, external checkpoint,
actual signed reconciliation and separate evaluation annotations. It sends
that same bundle through the real API, both SDKs, official MCP client and
existing console. A returned model message is insufficient for success.

## Evidence and failure reporting

Public successful or failed run artifacts are under the workflow's
`same-run-evidence-<run-id>` artifact. Private keys, API tokens, provisioning
files and unrestricted service logs are excluded. Downloaded evidence and
final executed results are retained under `validation/enterprise/results/`.
The observer anchor and checkpoint are retained before/independently from
untrusted export and are never selected by submitted archive bytes. Their
GitHub provenance is not independent institutional custody.

Required output includes the actual same-run bundle, independent trust file,
offline archive/evaluation results, signed reconciliation, audit comparison,
negative verification results, model/operator manifests, SDK/MCP result and
browser result. Failed attempts retain a sanitized failure manifest and any
original signed partial archives; they are not rewritten as passing runs.

## Actual executions and retained failures

GitHub-hosted Linux allocation resumed after the repository became public.
These are actual attempts; their original artifacts remain preserved. Each
linked summary includes source/run provenance, GitHub artifact SHA-256 and
individual file hashes. Private keys, tokens and unrestricted logs are excluded.

| Source / run | Actual outcome | Original public evidence |
| --- | --- | --- |
| `64e3cd0` / `40740307858` attempt 2 | Bootstrap manifest mismatch; no agent | [Failure](../../validation/enterprise/results/E2E_40740307858_ATTEMPT2/summary.json) |
| `e2cd2d6` / `40745805805` | Model runtime ancestor permission failure; no agent | [Failure](../../validation/enterprise/results/E2E_40745805805/summary.json) |
| `3f025d2` / `40748072732` | Two model calls and real tool; strict coverage refused | [Partial archives](../../validation/enterprise/results/E2E_40748072732/summary.json) |
| `4ca5a4d` / `40749929151` | Genuine task completed; queued scheduler evidence in next batch caused strict coverage refusal | [Partial archives](../../validation/enterprise/results/E2E_40749929151/summary.json) |
| `e0f881e` / `40752840365` | Genuine task, binding, task coverage, signed join, offline checks and negatives passed; API correctly refused unwrapped signing-key custody | [Original evidence](../../validation/enterprise/results/E2E_40752840365/summary.json) |
| `a59fde4` / `40753922392` | Gateway account setup failed before agent; exact HTTP response not retained and remains unknown | [Failure](../../validation/enterprise/results/E2E_40753922392/summary.json) |
| `a6da6e5` / `40755309307` | Genuine task, signed coverage/join and API writer admission passed; Reader refusal transport check stopped client sequence | [Original evidence and separate verification](../../validation/enterprise/results/E2E_40755309307/summary.json) |

The capture fix drains real queued scheduler events once more after reading
connector notifications. Collector comparison rules remain unchanged; absent
evidence still refuses coverage. Each drain is bounded to 4,096 events (the
scheduler has two drains). Inverse races, backlog or limits can still cause a
conservative unknown. No signed records were moved, trimmed or re-signed.

The API harness now provides a random private wrapping passphrase, preserving
the existing production custody guard. The revised gateway password generator
has 256.7 bits of entropy and passed 2,000 actual upstream-validator trials;
the old generator independently failed 130/2,000 trials. That does not establish
which HTTP response the earlier failed run returned. The latest client issue
is handling an early Reader refusal; it does not require changing authorization.

### Supported finding and performance

At exact source `a6da6e590030a41b6b8ef025bc6c050f6fe03dfe`, actual run
`same-run-77b363755683fce54c6f36b7` retained 39 signed batches and 1,116 kernel
events. Another process on Mac, with original bytes and separately supplied
public trust/checkpoint configuration, verified zero archive findings and valid
authorization, receipt, checkpoint and original signed reconciliation. Process
identity was `Match` (four references); tool request comparison was `Agrees`.

The kernel finding remains **`CannotProve/ActionEvidenceUnavailable`** for the
application-level tool action. Full authorization-TTL availability remains
**`WindowNotCovered`** because the 30-second decision lifetime extends beyond
the task capture. Signed Active coverage for the actual task interval passed
separately. Neither TTL nor coverage requirements were reduced. The tool read
and gateway `Forwarded` receipt do not prove business success or delegation.

An actual changed-parameter stimulus received a signed gateway `Refused`
receipt without a second upstream read. Nine captured-record negative checks
and seven archive-mutation checks passed. These are controlled verifier tests,
not additional adversarial agent executions.

The retained `e0f881e` attempt measured 11.936 seconds task runtime; probe CPU
1.31 seconds and 4,888 KiB lifetime peak RSS; collector CPU 0.36 seconds and
24,180 KiB peak RSS; workload cgroup peak 2,619,273,216 bytes. Its 1,135 events
occupied 786,011 archive bytes over 47.439 seconds (23.925 events/second).
Event-to-attestation latency was 88 ms minimum, 1,085 ms median, 2,151 ms p95
and 2,292 ms maximum. CLI evaluate-and-sign/offline-evaluate wall times were
863.615/845.428 ms including startup and all verification. No matched baseline
exists, so causal observer overhead and task impact remain unknown. Original
`performance.json` records measurement scope and limits.

## CI evidence and unexecuted checks

Combined source passed all five CI/component workflows (14 jobs) at `3f025d2`,
`e0f881e` and `a59fde4`; `4ca5a4d` passed the four workflows run there. Exact
source, PR checkout tree, jobs, artifacts and scopes are in the retained
[3f025d2](../../validation/enterprise/results/CI_3f025d2/summary.json),
[4ca5a4d](../../validation/enterprise/results/CI_4ca5a4d/summary.json),
[e0f881e](../../validation/enterprise/results/CI_e0f881e/summary.json) and
[a59fde4](../../validation/enterprise/results/CI_a59fde4/summary.json) registers.
Those green checks do not erase failed genuine integration jobs. Further source
changes require final-head CI again.

Per debug invocation: 3,254 passed / zero failed / seven ignored. Per release:
3,256 / zero / five; each profile separately ran two passing and two ignored
doctests. Coverage reran debug. Do not sum profiles/jobs as unique tests.
`g14_04` passed 20/20 focused release repetitions; 4,096 startup-race trials
had zero pre-readiness identity changes, and wrong-process regression passed.
The fix waits for actual child readiness before binding, preserving identity
verification.

Executed checks include formatting, strict Clippy, Python SDK (76), PostgreSQL
(142 default passes plus 14 explicit storage controls), enterprise Rust (414
default plus two explicit HTTP tests), strict TypeScript and two tests, actual
ContextForge interoperability (27) and five policy tests, harness contracts
(37), real observer smoke, the existing five-act RBI rehearsal, staged package
lifecycle and supply-chain checks. Exact per-job counts remain in each register.

Ignored/blocked results are separate: PostgreSQL benchmark was not run; 14 of
its 17 default ignores run explicitly and two HTTP tests run in enterprise CI.
Parity/sample/timing helpers and two documentation examples remain ignored;
two debug timing skips pass in release. RED reports 43 runnable reproductions,
two notes and ten blocked rows, not re-execution of those privileged rows.
Cargo audit/deny retain existing policy and visible duplicate/wildcard warnings.
The separate Security workflow is `disabled_inactivity`; these runs did not
execute Gitleaks or Trivy.

## Acceptance register

| Property | Current evidence requirement/status |
| --- | --- |
| Combined source build and CI | PASS on retained revisions above; final-head rerun required after further changes |
| Genuine model/tool workload | EXECUTED: two model responses and actual synthetic read/output retained |
| Independent signed authorization | PASS on actual run under distinct decision keys in shared-root profile |
| Actual signed gateway receipt | PASS: actual Forwarded request and controlled Refused mismatch |
| Linux activity and coverage | PASS for actual task and measured processes; full authorization TTL remains WindowNotCovered |
| Same-run join and signed finding | PASS offline with original signed finding and canonical recomputation; kernel result remains CannotProve |
| API / SDK / MCP / console | PASS in separate actual-bundle client replay, including browser; fresh full Linux workflow retry pending |
| Separate collector administration | INCOMPLETE on one hosted VM |
| Genuine Agent Zero / DeerFlow / OpenHands swarms | Not established by the LangGraph run |
| Customer clean-host / Kubernetes / air-gap qualification | Separate unexecuted operational gates |
| Production or regulatory approval | Not established |

See [SECURITY_ACCEPTANCE.md](SECURITY_ACCEPTANCE.md) for A–G cases and
[PRODUCTION_GAPS.md](PRODUCTION_GAPS.md) for the remaining requirements.

The exact `a6da6e5` component CI rerun also passed all five workflows/14 jobs;
its [register](../../validation/enterprise/results/CI_a6da6e5/summary.json)
records source/checkout tree equality and exact counts. GitHub's separately
managed Advanced Security PR review passed that head. It is an AI review of
changed regions, not Gitleaks, Trivy, a whole-repository audit or certification.
Its historical `3f025d2` run failed because its monthly model quota was exceeded;
that failure is preserved separately from component results.

## Separate client replay over the actual Linux run

After correcting the client upload handling and replacing browser string-eval
waits with CSP-compatible locator assertions, the complete existing API, both
SDKs, official MCP client, exact raw-bundle retrieval, signed-verdict retrieval,
tenant/role refusals and actual Chromium console/logout checks passed on Mac.
The service CSP and authorization rules were preserved. The replay used the
original Linux run bundle, SHA-256
`44669786c5127422216b2586f40b5cf55f261c6d45c3938e02f5672b72eaf077`.
It did not execute another agent or model, create a new observation, or replace
any original signed record. [Report, screenshot and provenance](../../validation/enterprise/results/E2E_40755309307/independent-client-replay/)
identify the separate client host, binaries and pending client patch digest.
The original Linux workflow failure remains a failure. A fresh full workflow
must pass after the fixes; its planned sequence also exercises live interruption
and fresh-capture recovery without backfilling the interruption.

A manual `genuine_task=true` input on the existing Agent Zero build workflow
now provides a restricted zero-cloud-spend attempt at the actual Click issue
3652 using its existing launcher/harness and verified image. It stages the real
issue/repository/test dependencies before network isolation; no solution is
supplied. Memory recall is explicitly disabled through upstream configuration,
and embedding is unvalidated. A returned patch remains `REVIEW_REQUIRED` until
independent restricted patch/baseline/regression review passes. This source
record does not claim that the new task profile has executed or succeeded.
