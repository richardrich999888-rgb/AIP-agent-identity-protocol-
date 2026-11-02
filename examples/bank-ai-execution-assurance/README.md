# bank-ai-execution-assurance

This genuine LangGraph 1.2.11 workload uses a real local Ollama model to select
a permitted read, invokes the actual pinned ContextForge gateway, then asks
the model for a human-review recommendation. The MCP tool reads synthetic
loan documents from SQLite opened in read-only mode. It exposes no banking
write tool and operates on no production/customer data.

The independent gateway produces its normal Rust-signed ToolReceipt. The
agent has only a test gateway credential and public correlation identifiers;
it has no collector, gateway or authority signing key. Its process/framework
identity remains distinct from gateway-authenticated principal identity and
from independent kernel attribution. An in-process graph node is not a
kernel-proven independent agent.

## Reproduce the executed integration subset

Prepare ContextForge and the Rust binaries using
`integrations/mcp-gateway/README.md`. Create the separate framework environment:

```sh
python3.12 -m venv .local/bank-agent-venv
.local/bank-agent-venv/bin/python -m pip install -r examples/bank-ai-execution-assurance/requirements.lock
```

The historical `integrations/agents/requirements.lock` is preserved. Its
`orjson==3.12.0` was unavailable for this local setup's default index; this
example has its own exact tested environment, still LangGraph 1.2.11.

Use a running local Ollama instance with the reviewed local model
`llama3.2:1b`. The model observed in this run was Q8_0, digest
`baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878`.
Model tag contents may change; check the digest and never substitute a
cloud-backed model for this data-locality demonstration.

```sh
"$CONTEXTFORGE_SOURCE/.venv/bin/python" integrations/mcp-gateway/validate_contextforge.py \
  --contextforge-source "$CONTEXTFORGE_SOURCE" \
  --signer-binary target/debug/aip-tool-receipt \
  --agent-script examples/bank-ai-execution-assurance/loan_agent.py \
  --agent-python .local/bank-agent-venv/bin/python \
  --output /var/tmp/vanian-bank-evaluation-NEW-RUN
```

`CONTEXTFORGE_SOURCE` is the actual pinned source checkout from the gateway
guide. The harness provisions ephemeral test services and credentials, passes
only the allowed environment to the agent, checks a genuine upstream
invocation and signed receipt, then stops its own services. The model uses
bounded schema-constrained output; malformed/truncated output fails, with no
scripted substitute tool choice or fabricated recommendation.

The executed public evidence is in
`validation/enterprise/results/CONTEXTFORGE_20261028T101836Z/`. All 28 gateway
checks passed, including this workload. The final agent result correctly
states `independent_execution_evaluation: NOT_RUN` and issues no signed
execution verdict.

## Five requested scenarios: actual status

| Scenario | Executed evidence | Remaining acceptance |
| --- | --- | --- |
| Authorized execution | Actual model/framework read plus gateway receipt; separate preissued signed fixture intent agrees through real Rust comparator | This agent's actual Linux execution has not been joined to a measured binding and signed institution authority |
| Unregistered destination | Existing `aip-authorize` resource suite refuses unnamed destinations; real gateway also refuses unsupported tools | A current Linux banking-workload destination scenario is not represented by those library checks |
| Mismatched parameters | Actual pinned gateway receipt compared with preissued signed expectation returns `ReceiptDoesNotMatchAuthorization` without an agent claim | Production institutional decision integration remains separate |
| Observer interference | Preserved RBI harness and prior successful hosted Linux rehearsal | Current actual two-host/real-agent observer interference is blocked on approved Linux infrastructure |
| Independent audit | All captured gateway receipts verify with public anchor alone; historical observer archive verification/mutations rerun independently | Fresh bank-host collector archive and its agreed public anchor still need the real deployment |

The collector archive API, both customer SDKs and official evidence MCP client
are also tested together using genuinely signed collector fixtures. That
separate integration test does not attach those fixtures to this LangGraph
run. A complete observation/authorization/gateway/verdict/API/SDK/MCP join
remains an open acceptance gate, as does real multi-framework/coding-agent
Linux execution. Do not present this subset as that completed milestone.

## Same-run Linux integration

`validation/enterprise/same_run_validation.py` now connects this actual graph to
external measured authorization, the strict ContextForge hook, the real MCP
read subprocess, Linux observation, signed collector archives, retained
checkpoints, the offline evaluator and the enterprise clients. Its executable
workflow is `.github/workflows/same-run-validation.yml`. A successful historical
subset above does not establish that this newer workflow has executed.

The Linux controller starts the agent as UID 10001, tool server as 10002,
gateway as 10003 and cloud-disabled local model as 10004. The application
services share a fresh network namespace containing only loopback. An actual
UID output rule permits the agent to reach only the model and gateway ports;
the agent tests that direct upstream access, external access, administrator
operations and signing-file reads fail. Authority and collector secrets remain
under root-controlled paths. Kernel/audit observers remain in the initial host
network namespace. All those roles still trust the shared host root/kernel;
this is explicitly **local isolation**, with separate administrative collector
custody incomplete.

`prepare_local_model.py` verifies the pinned official Ollama archive, extracts
an explicit CPU runtime allowlist, then verifies the reviewed manifest and all
model blob hashes. It loads no account credentials and permits no cloud model
path. Actual model token counts and response content are supporting agent
reports; independent observer/gateway/authority signatures remain distinct.
The real read child includes an explicit three-second validation hold after
performing its SQLite read so the existing probe can bind its process before
it exits. This hold is instrumentation, never a substitute for the read.

A gateway parameter match cannot upgrade the kernel verdict. A logical
LangGraph node is not independently proven as a separate Linux agent. The
run's exact signed reconciliation and any `CANNOT_PROVE` reasons must remain
visible through the API, SDKs, restricted MCP and existing console.
