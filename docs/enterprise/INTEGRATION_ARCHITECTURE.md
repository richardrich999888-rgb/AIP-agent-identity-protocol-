# Same-run execution assurance integration

The integration branch combines PR #6 at `65b6ff7fdad5ae70546a57216a497399091c7dc7`
and PR #7 at `bd15b8e627e5ef67ba259559ed81feb6894cde48`. Their common ancestor
is `f025a57911f7daf473cdfdcbf98d2f911df2534e`. Merge revision
`e3aa195def7524d6ec84d37a934beebe18b6c794` contains both sets of changes.
The subsequent integration wrappers reuse the existing signed record formats.

The implemented first-run topology uses one disposable Linux VM. Different OS
accounts and private directories isolate the model, agent, gateway and tool
from authority, collector and reconciler keys. All still trust the VM kernel,
host root and GitHub administration. Separate institutional custody remains a
separate acceptance gate. The enterprise two-host installer retains its stricter
separation requirement.

```mermaid
flowchart TB
  subgraph isolated[Loopback-only workload network; separate service UIDs]
    model[Pinned local Ollama CPU inference]
    agent[Genuine LangGraph agent]
    gateway[Actual ContextForge final dispatch hooks]
    tool[Restricted MCP read server and real read subprocess]
    agent -->|Actual inference requests| model
    agent -->|Authenticated tool request and decision reference| gateway
    gateway -->|Real upstream MCP invocation| tool
  end
  authority[Root-controlled AIP authority; independent issuer and decision keys]
  authority -->|Signed ExpectedExecution from narrow policy and measured binding| gateway
  agent -->|Unix socket with kernel peer credentials| authority
  probe[Host-side aip-probe; transport key only]
  agent -. independently observed effects .-> probe
  tool -. independently observed effects .-> probe
  collector[aip-collector; independent wrapped signing key]
  probe -->|Authenticated confidential Noise transport| collector
  collector --> archives[Original signed batches and signed health]
  gateway --> receipt[Original signed ToolReceipt]
  authority --> expected[Original signed ExpectedExecution]
  expected --> evaluator[Existing authorization/receipt/archive verifiers and reconciler]
  receipt --> evaluator
  archives --> evaluator
  checkpoint[Separately retained operator checkpoint and public anchors] --> evaluator
  evaluator --> verdict[Existing SignedReconciliation; separate tool-boundary annotation]
  verdict --> api[Existing tenant-scoped enterprise service]
  archives --> api
  api --> clients[Python SDK / TypeScript SDK / restricted evidence MCP / existing console]
  archives --> offline[Separate offline verification process]
  expected --> offline
  receipt --> offline
  verdict --> offline
```

`aip_mcp_gateway::assurance` joins original records under public anchors loaded
outside the submitted bundle. It invokes the existing authorization verifier,
`verify_tool_receipt`, archive verifier, `reconcile_expectation` and
`compare_tool_boundary`. It verifies optional original signed reconciliation
against the configured reconciler key and exact canonical recomputation.
It introduces no replacement signature or execution-verdict protocol.

The authority measures the actual ready agent process through host procfs,
checks binding stability, verifies issuer scope and checks an exact canonical
tool/resource/parameter policy. The agent supplies neither PID nor keys to the
Unix broker. The gateway independently checks the stored signed authorization
against its authenticated principal, actual received parameters and timestamp.
A random correlation ID cannot satisfy this path.

The same-run API stores the original bundle bytes and reevaluates them under
server-configured tenant/agent anchors and retained archive digests. Reader
credentials cannot submit or retrieve raw bundles. Existing evidence MCP tools
expose bounded metadata, evaluations and verified verdicts, with no additional
signing, shell, export or observer-control privilege.

The kernel cannot directly establish `ghost.tool.invoke.v1` business semantics
or in-process logical-agent identity. A truthful result may have verified
request-document agreement and a kernel `CannotProve` finding. File-write,
process and network records retain their individual process-instance bindings;
a tool-server child is not relabeled as the agent interpreter. A read-only
SQLite result is tool testimony and inspectable test output; fanotify does not
supply a file-read proof. See [SECURITY_ACCEPTANCE.md](SECURITY_ACCEPTANCE.md).
