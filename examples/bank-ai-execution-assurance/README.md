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
