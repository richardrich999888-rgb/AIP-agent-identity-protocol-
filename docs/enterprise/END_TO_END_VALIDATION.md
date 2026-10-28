# End-to-end validation record

Status: implementation and execution in progress. No complete same-run result
is claimed until a genuine model workload has executed and its actual records
pass independent verification and enterprise client checks. Separate-host
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

## Acceptance register

| Property | Current evidence requirement/status |
| --- | --- |
| Combined source build and CI | Re-run for exact integration source; older PR CI remains historical |
| Genuine model/tool workload | Fresh workflow must actually execute; no mock fallback |
| Independent signed authorization | Real scope evaluation and measured live binding required |
| Actual signed gateway receipt | Real final pre/post hooks, replay protection and parameter verification required |
| Linux activity and coverage | Original signed records, actual process binding, loss/integrity accounting required |
| Same-run join and signed finding | Original evidence plus external anchors/checkpoint; canonical recomputation required |
| API / SDK / MCP / console | Exact same bundle; role and tenant refusals required |
| Separate collector administration | INCOMPLETE on one hosted VM |
| Genuine Agent Zero / DeerFlow / OpenHands swarms | Not established by the LangGraph run |
| Customer clean-host / Kubernetes / air-gap qualification | Separate unexecuted operational gates |
| Production or regulatory approval | Not established |

See [SECURITY_ACCEPTANCE.md](SECURITY_ACCEPTANCE.md) for A–G cases and
[PRODUCTION_GAPS.md](PRODUCTION_GAPS.md) for the remaining requirements.
