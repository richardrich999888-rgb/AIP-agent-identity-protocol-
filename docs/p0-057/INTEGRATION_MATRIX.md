# P0-057 integration matrix

Status at baseline `61dd730`: existing connectors are retained; no fresh framework
integration acceptance is claimed. Import success and source inspection are not
task execution. Pins below identify different inspected/runtime profiles explicitly.

| Priority / integration | Pin and license record | Existing implementation / evidence / remaining guarantee |
|---|---|---|
| A — ContextForge / MCP | Runtime `ff6a566a4b5c098093db90bbb4d5df483e108026`, Apache-2.0; `integrations/mcp-gateway/contextforge.lock.json`; separate inspection `cea3b88aa4e34ce2e922e7073f6884c97f3fcb19` | Actual CPEX pre/post tool hooks and Rust receipts exist. Retained live gateway tests. Receipt is received request/dispatch evidence, not OS effect proof. |
| A — Google ADK | `34750dcb85f4cdefefe002f8c3f156c471d29b52`, Apache-2.0, interoperability lock | Plugin and A2A examples, genuine historical model/tool transcripts and negatives. Full conformance and current same-run kernel/logical-agent binding remain unqualified. |
| A — LangGraph | `langgraph==1.2.11` and exact package set in `integrations/agents/requirements.lock`; source revision/license closure pending for this installed profile | Existing graph subject and synthetic bank-agent workflow. Requirements version pins alone are not immutable source/wheel digest closure. Historical genuine same-run tool task still yields action uncertainty. |
| A — OPA | `ca660665cc95b0fce665b71192aac938889719c9`, Apache-2.0, interoperability lock | Existing actual HTTP/CLI policy example; later #8 governance adapter awaits reconciliation. Allow decision does not establish execution. |
| A — OpenTelemetry | GenAI conventions inspection `51a0f580f8a6ad804ca4de5e033683c6fbbe5906`, Apache-2.0; #8 owns `integrations/governance/otel.lock.json` | Later pinned SDK/collector work exists outside baseline. Controller instrumentation cannot promote independent observation. Full span/request/process joins pending. |
| A — AIP authority | In-repo baseline, LicenseRef-Proprietary | `aip-authorize`, native delegation/revocation and same-run authority reused. Institutional enrollment, current revocation authority and custody remain deployment gates. |
| A — Linux observers | In-repo baseline, LicenseRef-Proprietary | `aip-observe`, `aip-probe`, collector and offline verifier; ten hosted native assertions passed at base. Executable consistency, logical identity and load/custody gaps remain. |
| B — SPIFFE/SPIRE | `a33d43d3c1cd734b6eca0c6ec6582353a5d35eb0`, Apache-2.0 | Existing JWT-SVID/issuer bridge and native comparator. Parsed identity alone is not verified X.509 lifecycle or process-agent binding. |
| B — Microsoft toolkit | `4eca1f5b44d30ebe5e9745ac36ca394f887e617b`, MIT | Existing ACS receipt comparison. Content agreement does not authenticate policy source; current runtime/tenant-binding acceptance pending. |
| B — certificate lifecycle | Existing identity/transport configuration | Rotation, retirement, revocation freshness and independently administered launch binding unqualified. |
| C — Agent Zero | `ff2a5b9c9c4e490ba38dd7c313e779510bb2071a`, frameworks lock; license review in prior dependency inventory | Existing native launcher. Later #8 invoice task failed acceptance. No fresh workload or Shadow-AI recall credit. |
| C — OpenHands | SDK `46b1fa5cb91ada17e6ec938c7e8624a4fa19fa98`, frameworks lock | Native capability failure retained on #8. Package task/selected dependencies license closure and genuine acceptance remain open. |
| C — DeerFlow | `f79debed59ca6b1a31628e6b5ce55c8507793a4c`, frameworks lock | Native capability failure retained on #8; business task was not completed. |
| C — OpenShell | `44ef984b58f9badf79f2ff5b9982054017b01ca8`, Apache-2.0 | Adapter/inspection exists; actual supported host runtime qualification blocked. |

Full upstream source URLs, inspected files and license hashes are in the inherited
`integrations/interoperability/upstreams.lock.json` and P0-048 dependency matrix.
The all-branch P0-057 inventory also retains #8's later locks and licenses without
merging them. Fresh upstream API/advisory assessment for every framework is an
open gate; this table does not claim these versions are vulnerability-free,
production-compatible or vendor-endorsed. First engineering priority is native
attribution correctness, then exact same-run request/effect binding.

## Fresh P0-057 execution evidence

At `5be83a8`, the unchanged pinned ContextForge `ff6a566a` and its locked CPEX
0.1.4 / MCP 2.3.0 APIs ran locally against a real MCP upstream: 27 checks pass,
27 receipts independently verify, 16 upstream calls occur. This controller-driven
trial is not an AI-model/kernel test. `iteration-002/gateway-runtime` contains
original requests, receipts, public anchor, source/binary hashes and the report.

The separate hosted same-run model test used the existing real LangGraph,
local llama3.2:1b, authority broker, ContextForge and Linux observers at `5be83a8`.
Observed/interruption scenes retain CannotProve; the recovery scene fails on
missing Forwarded receipt. The native sensor workflow's ten assertions pass.
These outcomes do not close any mandatory integration as enterprise-qualified.
