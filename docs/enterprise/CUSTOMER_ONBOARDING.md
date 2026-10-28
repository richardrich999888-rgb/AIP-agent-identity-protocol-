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

The kit contains exact role configs, native collector allow-list, public enrollment references, desired retention, software manifest, checksums, installation instructions and readiness. It does not contain private keys, API tokens, model prompts or bank transaction bodies. Host references must match the approved topology; unknown records, duplicate keys, colliding public keys, mismatched IDs, unsafe settings and invalid software digests are refused. The output directory is not overwritten. Keep operational metadata under the institution's access policy.

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

Use the existing [SDK guide](SDK_GUIDE.md), [OpenAPI](openapi.yaml), [MCP gateway guide](MCP_GATEWAY_INTEGRATION.md) and read-only console. The posture report now has a real HTTP service/SDK/MCP fixture smoke test; it remains a bounded Reader summary of stored records and API-reported status. There is no new enrollment backend, independent identity issuer or competing console in this increment.
