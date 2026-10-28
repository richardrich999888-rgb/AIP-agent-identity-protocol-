# Bank integration guide

This is an engineering evaluation package. An RBI technical discussion is not
an approved banking pilot, regulatory certification or production acceptance.
Start with a non-production read-only workload and an institution-approved
collection/privacy scope. No automatic containment or banking transaction
gate is installed by the runtime package.

For repeatable CISO/onboarding scoping, review the [enterprise service delivery
model](SERVICE_DELIVERY_MODEL.md) and run the offline
[service manifest planner](../../integrations/service_delivery/README.md).
That planner validates the intended installation topology; it cannot establish
live coverage, signed authorization or pilot acceptance.

## Install and enroll

1. Review [architecture](ARCHITECTURE.md), [inventory](INVENTORY.md) and
   [security boundaries](SECURITY_AND_PRIVACY.md). Nominate separate workload,
   collector, gateway, authority and audit administrators.
2. Build/approve the verifiable runtime package and install its two roles on
   separate approved Linux hosts using
   `deploy/enterprise/linux/README.md`. Independently approve the package
   digest and key fingerprints. An installer confirmation flag is not proof
   of separate administration.
3. Provision probe transport enrollment, collector wrapped key/passphrase,
   pinned Noise transport key, allowed hosts/egress, selected sensors and NTP.
   Follow `deploy/enterprise/runbooks/OPERATIONS.md`; prove actual sensor
   startup and signed health. Process liveness alone is not coverage.
4. Build the existing service with `cargo build --release --locked -p
   airon-aip --features postgres`. Provision `deploy/sql/schema.sql` and
   `deploy/sql/hardening.sql` with separate owner/service roles. Use the
   hardened `aip_app` login and require the pre-provisioned schema. JSONL is
   suitable only for a single service process and controlled evaluation.
5. Configure `AIP_API_KEYS_PATH` with separate hashed Reader, Machine and
   Admin credentials per tenant. Keep managed agent signing disabled.
   Configure service signing custody and durable vault/artifact paths as in
   the existing service/runbook. Terminate TLS at the reviewed institutional
   ingress; do not expose the raw HTTP port to an untrusted network.
6. Optionally enable the existing service's private configuration registry with
   `AIP_DEPLOYMENTS_PATH` and register the reviewed kit through a separate Admin
   credential as described in [onboarding](CUSTOMER_ONBOARDING.md). This records
   declared topology only; actual host enrollment, independent key custody and
   verifier-anchor provisioning remain separate operator procedures.

## Admit collector evidence

Set `AIP_OBSERVER_TRUST_PATH` to an operator-owned JSON file:

```json
{"anchors":[{"tenant_id":"institution-evaluation","observer_id":"collector-evaluation","key_version":1,"public_key_hex":"REPLACE_WITH_INDEPENDENTLY_APPROVED_32_BYTE_PUBLIC_KEY_HEX"}]}
```

The placeholder is deliberately invalid. Provision the actual **public**
collector anchor through the institution's enrollment procedure. This file
cannot be changed through the read API or MCP tools. A configured missing,
malformed or ambiguous file refuses service startup. No configured anchors
means archive admission is unavailable; client-supplied keys are refused.

Take a stable snapshot of the signed batch and health archives on the
collector side. Do not fabricate a record or conceal a gap to make a snapshot
verify. With a Machine service credential injected by the institution's secret
manager and the Python SDK installed:

```sh
python integrations/evidence-api/upload_observations.py \
  --observer-id collector-evaluation --key-version 1 \
  --batches attested.archive.jsonl --health health.archive.jsonl
```

The tool reads `VANIAN_BASE_URL`, `VANIAN_API_TOKEN` and optional
`VANIAN_CA_FILE` from the environment. It requires HTTPS and does not print
credentials or raw records. Admission is idempotent for the same tenant and
snapshot. Decoded archive text is limited to 512 KiB and 2,048 records per
file. For larger histories, prepare a genuine signed window; do not split
arbitrary bytes or label separate windows continuous. This is an explicit
operator upload, not a live archive synchronization service.

Retrieve the returned `observation_id` through SDK or MCP metadata and
verification operations. A Reader cannot retrieve raw archives, packets or
exports. An approved Machine/Admin auditor can fetch
`GET /v1/observations/{id}`, recover the original archive strings and run
`aip-observe-verify` offline under independently approved public anchors.
The archive API does not prove that the approved key was physically off-host.

## Integrate tools and authorization

Follow [MCP gateway integration](MCP_GATEWAY_INTEGRATION.md) for the pinned
ContextForge profile. Configure gateway-admin principal/agent bindings and
explicit supported tools. Keep the gateway signer outside agent access.
The decision authority separately issues signed `ExpectedExecution` using
`aip-authorize`; `aip-airi::compare_tool_boundary` compares that signed intent
to the verified gateway receipt. The test fixture authority is not a production
bank authority. The local banking example's random join IDs are not signed
authorization.

Retrieve existing signed verdicts and ledgers through the original service
routes. Automatic collector/authority/receipt reconciliation scheduling,
independently authenticated running-workload inventory and a production signed-packet admission policy
are not delivered by this slice. Do not equate archived evidence retrieval
with the complete final acceptance milestone.

## Operate and audit

Use `/console` with a Reader credential for actual API metadata, historical
verification, signed verdicts and explicit unavailable coverage. Credentials
remain in memory; disconnect/reload clears them. The console refreshes every
15 seconds while visible, lists the first 25 packet identities and is not a
complete monitored-workload inventory. Optional deployment registrations appear
separately with unassessed execution status. Use SDK pagination for larger sets.

Agree retention, encrypted backups, data residency, anchor rotation,
revocation, incident handling and an independent security assessment before
bank deployment. Execute the acceptance runbook on the institution's actual
Linux hosts, then retain the exact source commit, transcripts, signed
evidence, public anchors and outstanding gaps.
