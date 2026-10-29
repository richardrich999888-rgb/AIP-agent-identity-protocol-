# Customer clients and optional evidence MCP

The customer SDK reads the implemented `/v1` service contract in
`openapi.yaml`. It is separate from `sdk/python/vanian_airi`, which emits
application telemetry. Neither SDK is required by the runtime sensor or is an
independent observation authority.

## Python

Python 3.10+; the read client itself uses only the standard library:

```sh
python -m pip install ./sdk/python
```

```python
import os
from vanian import VanianClient

client = VanianClient(
    "https://vanian.institution.example",
    credential_provider=lambda: os.environ["VANIAN_API_TOKEN"],
    timeout=10, retries=1,
    ca_file="/etc/institution/approved-ca.pem",
)
for agent in client.iter_agents(limit=25):
    print(agent["agent_id"], agent["identity_source"])
metadata = client.get_observation_metadata(approved_observation_id)
result = client.verify_observation(approved_observation_id)
signed_verdict = client.get_verdict(approved_verdict_id)

# A run artifact identifier is returned by an authorized /v1/runs admission.
run = client.get_run_metadata(approved_run_artifact_id)
evaluation = client.evaluate_run(approved_run_artifact_id)
# Returns 404 when no verified signed reconciliation was supplied.
run_verdict = client.get_run_verdict(approved_run_artifact_id)
agent_runs = client.get_agent_runs(approved_agent_id, limit=25)
```

Identifiers above come from admitted/stored records; they are not sample
evidence. Packet `verify_evidence` runs integrity-only verification without
institutional issuer anchors. Archive `verify_observation` uses separately
configured collector anchors and reports historical signature integrity.
Read each response's scope, limitations and unevaluated checks. A retrieved
signature or verifier success does not itself establish authorized execution.

Methods: `access`, `list_agents`, `iter_agents`, `get_agent`,
`get_agent_activity`, `get_verdict`, `get_evidence_metadata`,
`verify_evidence`, `get_observation_metadata`, `verify_observation`,
`get_run_metadata`, `evaluate_run`, `get_run_verdict`, `get_agent_runs`,
`get_coverage`, `get_health`. Pages have `items`, `limit`, `offset`,
`next_offset`. `ApiError` exposes redacted `status` and `code`.

TLS validation stays enabled, redirects are refused, timeouts and response
sizes are bounded, only GETs are retried and the credential callback is
re-evaluated for rotation. Plain HTTP is restricted to explicit loopback test
opt-in. No client logs record payloads or credentials.

## TypeScript

`sdk/typescript/src/index.ts` exposes the corresponding typed read methods.
This source distribution targets a TypeScript-aware bundler or Node 22.18+
with native type stripping. It is private and has not been published to npm.
Use institution trust configuration for Node TLS; never disable certificate
verification. The real service integration tests exercise both clients.

Same-run methods are `getRunMetadata`, `evaluateRun`, `getRunVerdict` and
`getAgentRuns`. They return the service's findings without promoting a signed
receipt or document agreement into verified kernel execution. The TypeScript
`RunMetadata` interface includes immutable bundle/archive hashes and a separate
`evaluation` object; signed protocol documents retain their original fields.

## Evidence MCP

Use a separate Python 3.12 environment with the tested dependency lock:

```sh
python3.12 -m venv .local/enterprise-venv
.local/enterprise-venv/bin/python -m pip install -r integrations/evidence-mcp/requirements.lock
PYTHONPATH=sdk/python .local/enterprise-venv/bin/python integrations/evidence-mcp/server.py
```

Provision `VANIAN_BASE_URL`, `VANIAN_API_TOKEN` (Reader only), and optional
`VANIAN_CA_FILE` through the MCP host's protected configuration. This is a
stdio subprocess, one process/credential per authorized institutional client.
OS process ownership authenticates the local launcher; the service credential
authenticates every evidence read. Never offer this process as a shared remote
server. HTTP MCP, Origin/OAuth/session management are not implemented here.

The official MCP SDK is pinned to 2.3.0, source commit
`2118f14f8a19bc158d8a1cf90af58d85d187f849`, negotiated protocol
`2026-07-28`. Eight tools are allowlisted in `server.py`. Metadata and
verification tools accept `kind: "packet"`, `"observation_archive"` or
`"run_bundle"`. For a run, pass its `run_artifact_id` as `evidence_id`:

```json
{"evidence_id":"<admitted run artifact identifier>","kind":"run_bundle"}
```

`vanian_get_evidence_metadata` returns run references and the reevaluation;
`vanian_verify_stored_evidence` returns the separate `RunEvaluation` directly.
`vanian_get_execution_verdict` also accepts
`{"verdict_id":"<admitted run artifact identifier>","kind":"run_bundle"}`
to retrieve the original configured-reconciler-signed finding. Its existing
`kind: "verdict"` behavior still reads an independently filed verdict. These
options reuse the eight existing tools; they add no signing or admission tool.
There are no arbitrary fetch, raw export, signing, shell, containment or admin
tools. Input frames are limited to 64 KiB, outbound replies to 256 KiB with
envelope allowance, pages to 25, calls to 120/minute and service calls are
serialized. A changed tenant/role or revoked credential fails subsequent
reads. The institutional service role remains the final authorization boundary.


## Same-run admission and interpretation

An authorized Machine or Admin submits the original `RunBundle` JSON to
`POST /v1/runs`. The customer SDK and evidence MCP remain read interfaces;
operators can use their approved HTTP client for admission. The service returns
`run_artifact_id`, `run_id`, `agent_id`, `bundle_sha256`, `batches_sha256`,
`health_sha256`, `verification_scope: "same_run_evaluation"` and `evaluation`.
The artifact identifier binds the tenant and exact submitted JSON bytes.
`run_id` is a run label; it does not impose a database uniqueness constraint.
An identical byte submission is idempotent. Formatting changes produce a
different artifact identifier even when the parsed fields are equivalent.

The administrator provisions `AIP_RUN_TRUST_PATH` separately as
`{tenants:[{tenant_id,trust:RunTrustConfig}]}`. Its public configuration contains
distinct agent, decision-point, gateway, observer and reconciler anchors, key
versions where required, accepted health/window bounds, and
`checkpoints[run_id].batches_sha256` / `health_sha256` retained outside the
workload's writable area. The request cannot choose those keys or checkpoint
values. No signing private key belongs in the service trust file.

The bundle carries `run_id`, `agent_id`, the original optional `expectation`,
`signed_receipt` and `signed_reconciliation`, the complete original
`batches_jsonl` and `health_jsonl` strings, and a retained historical
`verification_time_ms`. Protocol schemas and canonical signature rules remain
in the existing Rust crates. The service admits at most 16 MiB of serialized
run JSON; the evaluator admits at most 8 MiB of decoded archives together and
1..2048 complete records per archive. Other route body limits remain unchanged.
Full signed archives must be retained; discard neither records nor a degraded
health tail to fit the limit or improve a finding.

| Finding | Meaning |
| --- | --- |
| `archive_integrity_verified`, `checkpoint_verified` | Signed archives and their independently configured retained bytes verified. |
| `authorization_verified` | The supplied authorization signature and configured agent/authority relationship verified. |
| `gateway_receipt_verified`, `gateway_disposition` | The configured gateway signed this received request/disposition; downstream effects remain separate. |
| `receipt_within_authorization` | Whether receipt time falls inside the signed authorization window; null means the comparison was unavailable. |
| `tool_boundary` | Existing signed-document parameter comparison; it cannot upgrade `reconciliation`. |
| `reconciliation` | The unchanged kernel engine finding, including `CannotProve` and its reasons. |
| `signed_reconciliation_verified` | The original configured-reconciler signature verifies and its canonical verdict equals recomputation. |
| `limitations` | Explicit unevaluated or unsupported claims; retain them with every displayed finding. |

All metadata/evaluation/verdict reads reevaluate the immutable bundle under
current server configuration. A Reader can use
`GET /v1/runs/{run_artifact_id}/metadata`, `/evaluation` and `/verdict`, plus
`GET /v1/agents/{agent_id}/runs`. A Machine or Admin can retrieve the exact
original JSON at `GET /v1/runs/{run_artifact_id}` for independent offline
verification. Reader writes/raw reads return 403; wrong-tenant run identifiers
return 404 and wrong-tenant agent run listings return an empty page. Missing
configured trust returns 503; invalid signed inputs or checkpoint mismatch are
rejected rather than filed. An absent signed run verdict returns 404.

The existing console has a run-artifact lookup for the same authorized metadata,
evaluation and original verified signed verdict. It does not assert live
coverage, logical sub-agent attribution, separate administration or a banking
outcome from a successful read. The live coverage route still reports its
actual unavailable state.

`validation/enterprise/run_client_smoke.py` consumes an existing run bundle;
it creates no observations or signed authorization. It checks admission,
byte-identical retrieval, both SDKs, the official MCP client, tenant/Reader
boundaries and the OpenAPI contract. `--browser` additionally checks that the
existing console displays that same run. Signed empty fixtures used by local
contract tests remain fixtures. Only a fresh independently observed workload
with passing evidence verification can satisfy integration acceptance.
