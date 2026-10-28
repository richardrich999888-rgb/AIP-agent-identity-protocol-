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
`get_coverage`, `get_health`. Pages have `items`, `limit`, `offset`,
`next_offset`. `ApiError` exposes redacted `status` and `code`.

TLS validation stays enabled, redirects are refused, timeouts and response
sizes are bounded, only GETs are retried and the credential callback is
re-evaluated for rotation. Plain HTTP is restricted to explicit loopback test
opt-in. No client logs record payloads or credentials.

## TypeScript

`sdk/typescript/src/index.ts` exposes the corresponding typed read methods.
The installable package exports compiled JavaScript and type declarations.
It is private and has not been published to npm; see the engineering package
build/install procedure below.
Use institution trust configuration for Node TLS; never disable certificate
verification. The real service integration tests exercise both clients.

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
verification tools accept `kind: "packet"` or `"observation_archive"`.
There are no arbitrary fetch, raw export, signing, shell, containment or admin
tools. Input frames are limited to 64 KiB, outbound replies to 256 KiB with
envelope allowance, pages to 25, calls to 120/minute and service calls are
serialized. A changed tenant/role or revoked credential fails subsequent
reads. The institutional service role remains the final authorization boundary.
# SDK engineering packages

The current Python wheel is `vanian_sdk-0.1.0-py3-none-any.whl` (module
`vanian`); the TypeScript archive is `vanian-evidence-client-0.1.0.tgz`
(`@vanian/evidence-client`). They remain unpublished engineering packages,
subject to approved license terms, artifact approval and dependency review.

Build the TypeScript package with `npm ci --prefix sdk/typescript`,
`npm run build --prefix sdk/typescript`, then run `npm pack` from that directory.
The pinned TypeScript 5.9.3 compiler produces `dist/index.js` and
`dist/index.d.ts`. Package exports point to those files; `.ts` source is not
used as a runtime dependency inside node_modules. An isolated install caught
that earlier distribution defect; the retained failure and corrected install
test are in the delivery validation archive. The real HTTP smoke also uses
the compiled JavaScript.

Install institution-approved artifacts with `python -m pip install
/approved/vanian_sdk-0.1.0-py3-none-any.whl` or `npm install
/approved/vanian-evidence-client-0.1.0.tgz`. Verify the artifact origin/digest
before installation. These clients retrieve existing evidence; they do not
provide independent execution observation.
