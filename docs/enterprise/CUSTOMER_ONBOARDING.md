# Institution-controlled onboarding

Start with [the preserved source inventory](DELIVERY_INVENTORY.md) and [installation](INSTALLATION.md). The onboarding planner from PR #10 remains the authority for topology/scope validation. The new kit composer connects that plan to actual runtime configuration and public probe enrollment without contacting proprietary VANIAN infrastructure.

1. The institution approves the tenant/deployment references, one low-criticality Linux workload host, separate collector administration and allowed integrations in `integrations/service_delivery/example.json`.
2. Install the approved role-specific software and bootstrap public probe records with `aip-probe enroll`. Approve those records and generate the collector allow-list with `enrollments.py`.
3. Configure/start the separate collector using institution-owned wrapped signing custody, clock discipline and the approved allow-list. Independently record its public Noise pin and observer-signing anchor. No collector private material belongs in a probe config or kit.
4. Prepare the real role configs with that collector pin and endpoint. Compose a non-secret, reproducible installation kit:

```sh
python3 integrations/service_delivery/onboarding_bundle.py \
  --manifest institution-plan.json \
  --runtime-archive approved-runtime.tar --expected-sha256 "$APPROVED_RUNTIME_SHA256" \
  --collector-config collector.env \
  --probe-config agent-linux-01=probe.env \
  --enrollment public-enrollment.json --retention-days 90 \
  --output institution-installation-kit
```

The kit contains exact role configs, native collector allow-list, public enrollment references, desired retention, software manifest, checksums, installation instructions, readiness and `deployment-registration.json`. That last file is an input to the optional existing-service registry described below. It does not contain private keys, API tokens, model prompts or bank transaction bodies. Host references must match the approved topology; unknown records, duplicate keys, colliding public keys, mismatched IDs, unsafe settings and invalid software digests are refused. The output directory is not overwritten. Keep operational metadata under the institution's access policy.

5. Review the kit and configure the services using the implemented commands in `INSTALLATION.md`. Runtime administrative separation, trust-anchor authority and public-key possession must still be independently established; a JSON record is not proof of them.
6. Run the same-run acceptance procedure: genuine agent/tool operation, independently signed authority, actual gateway receipt, supported kernel observation, separate collector evidence, native reconciliation, tenant-scoped API/SDK/MCP/console readback and independent offline verification.

| Stage | What establishes it | What this offline tool can claim |
|---|---|---|
| CONFIGURATION_VALID | Existing planner, package integrity and strict native role-config validation | Configuration valid only |
| INSTALLED | Actual host package/service-file checks and installation transcript | NOT_ASSESSED |
| OBSERVER_ACTIVE | Successful native sensors and fresh signed health/coverage | NOT_ASSESSED |
| SIGNED_EVIDENCE_AVAILABLE | Actual collector archive under independently approved anchor | NOT_ASSESSED |
| AUTHORIZATION_VERIFIED | Native authority/delegation/expectation verification in the actual context | NOT_ASSESSED |
| EXECUTION_RECONCILED | Existing native reconciler binds same-run inputs with adequate coverage | NOT_ASSESSED |
| PILOT_ACCEPTED | Institution and independent assessor accept the measured scope and remaining gaps | NOT_ASSESSED |

These stages are distinct evidence requirements, not automatic promotions from a customer-configured flag. A valid signature does not by itself establish Active coverage, actual execution or completed banking effects. Desired retention in the kit does not configure backend deletion, export permissions or legal hold; enforce these separately through the institution's storage/API policy.

## Optional service registration

The existing `aip-service` can retain administrator-approved deployment configuration. It is disabled by default. The service operator creates a private, durable directory owned by the service account, sets `AIP_DEPLOYMENTS_PATH` to an absolute JSONL path within it, and restarts the service through its existing deployment procedure. A new journal is created mode 0600; an existing journal must be a private regular file. Missing parents, corruption, an incomplete final line, duplicate records or a second writer refuse startup. Keep the directory and all parent components under trusted operator control. Do not share this file between replicas or replace/edit it while the service runs.

Use a separately provisioned, tenant-bound **Admin** credential for registration. Reader and Machine credentials cannot register. The SDK preserves TLS validation and reads credentials through the supplied callback:

```python
import json
from pathlib import Path
from vanian import VanianClient

# Institution-supplied callback; never embed credentials in the kit.
admin = VanianClient(service_url, credential_provider=get_admin_credential,
                     ca_file=approved_ca_file)
definition = json.loads(Path("institution-installation-kit/deployment-registration.json").read_text())
registration = admin.register_deployment(definition)
assert registration["configuration_status"] == "CONFIGURATION_VALID"
assert registration["observer_active"] == "NOT_ASSESSED"
```

The tenant and registering key ID come from the authenticated service principal. Requests cannot set tenant, assurance, private keys or trust anchors. HTTP returns 201 for a new name, 200 for an identical resubmission and 409 for a different configuration using an existing name. A caller must explicitly decide whether to retry a failed POST; SDKs never retry it automatically. Read back the name first after an uncertain response. Register a new name for a revised plan. There are no update/delete or remote installation operations.

Reader clients use `list_deployments` / `get_deployment`; TypeScript uses `listDeployments` / `getDeployment`. The existing `/console` displays the first 25 summaries and retrieves a named registration. Packet-derived `/v1/agents` inventory remains a separate source. The posture report still reads packet identities; it does not become a complete registered-host report.

Registration stores **unsigned configuration** and a service-clock timestamp, not cryptographic enrollment. Public keys and administrator-group names remain declarations: their possession and actual administrative separation are unverified. The registry cannot change probe allow-lists, verifier anchors, identity issuers, delegated authority, evidence stores, live coverage or retention enforcement. Every stage above configuration remains `NOT_ASSESSED`, identity binding remains `NOT_ESTABLISHED`, and `/v1/coverage` remains unavailable without its own live evidence source. An operator who can rewrite the journal can rewrite these configuration records; this is not a tamper-evident audit archive.

This single-process JSONL evaluation profile is limited to 500 registrations per tenant, 10,000 overall and a 64 MiB journal. Definitions are at most 24 KiB; HTTP bodies at most 32 KiB. Lists return bounded summaries with the existing pagination contract. An append/fsync failure makes subsequent registry reads and writes unavailable until operator recovery; it does not acknowledge an in-memory registration. Back up only a stopped or otherwise consistent journal under institutional retention controls. A corrupt/incomplete journal requires reviewed recovery from a known-good backup; no automatic repair is provided. No PostgreSQL registry, distributed lock, HA, capacity qualification or assured crash/power-loss recovery is claimed. The evidence backends keep their existing independent configuration.

Use the existing [SDK guide](SDK_GUIDE.md), [OpenAPI](openapi.yaml), [MCP gateway guide](MCP_GATEWAY_INTEGRATION.md) and read-only console. The evidence MCP server retains its eight Reader-only tools; registration is not an MCP control path into the observer. Reproducible real HTTP tests exercise enabled registration and both SDKs, plus disabled-registry behavior in the existing signed-record/MCP fixture. These tests do not establish sensor execution or bank deployment acceptance.
