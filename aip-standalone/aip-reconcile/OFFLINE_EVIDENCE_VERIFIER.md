# Offline AIP + Sniffer Dog evidence verifier

`aip-evidence-verify` verifies a serialized `ExpectedExecution`, collector-attested batches, and signed sensor health without an agent, observer process, private key, or network connection. It uses the existing AIP verification APIs, `aip-observe-verify::verify_archives`, and `aip-reconcile::reconcile_expectation`.

## Usage

From the repository root:

```sh
cargo run -p aip-reconcile --bin aip-evidence-verify -- \
  --bundle ./evidence-bundle.json \
  --anchors ./trusted-anchors.json
```

### Export the synthetic integration fixture

The integration test exposes a dedicated, ignored exporter. Choose an output
directory and run only that test explicitly:

```sh
mkdir -p /tmp/aip-snifferdog-evidence
AIP_SNIFFER_DOG_EXPORT_DIR=/tmp/aip-snifferdog-evidence \
  cargo test -p aip-reconcile --test send_evidence \
  export_synthetic_bundle_to_user_directory -- --ignored --exact --nocapture
```

It writes `evidence-bundle.json` and `trusted-anchors.json` using the same
synthetic authorization and observer fixture as the integration test. The
bundle retains `SYNTHETIC_TEST_FIXTURE` provenance. The exporter refuses to
overwrite either named file; use a new or empty directory for each export.
Normal test runs skip this ignored test and do not create persistent files.
The fixture creates fresh signing material when run, but exports public
verification inputs only; the JSON output is suitable for transfer to another
machine with the CLI and anchors whose authenticity is established separately
from the bundle (for example, via a trusted deployment channel).

Verify the exported files offline with:

```sh
cargo run -p aip-reconcile --bin aip-evidence-verify -- \
  --bundle /tmp/aip-snifferdog-evidence/evidence-bundle.json \
  --anchors /tmp/aip-snifferdog-evidence/trusted-anchors.json
```

For the matching fixture, the report should contain `status: "INPUTS_VERIFIED"`,
`evidence_origin: "SYNTHETIC_TEST_FIXTURE"`, and
`reconciliation_result: "VerifiedExecution"`.

The anchors file is held independently of the evidence bundle:

```json
{
  "decision_point": {
    "id": "<decision-point-id>",
    "public_key": "<64 hex characters>"
  },
  "observer": {
    "id": "<observer-id>",
    "key_version": 1,
    "public_key": "<64 hex characters>"
  }
}
```

The bundle has `bundle_version: 1`, an `evidence_origin`, serialized `expected_execution`, `observer_batches`, `signed_sensor_health`, informational `trust_anchors`, and `verification_context`. The informational public anchors must match the separate anchors file; they are never used as the trust source. This version supports `expected_side_coverage: "unknown"` only. Unsupported settings and missing anchors are refused.

The JSON report includes signature checks, observer archive chain findings, signed health and coverage, the reconciler's availability, result, strength and reason, plus limitations. `INPUTS_VERIFIED` means the supplied signatures and observer archive were verified; it does **not** mean the execution was verified. Check `reconciliation_result` separately. A valid but degraded bundle can have `INPUTS_VERIFIED` and `reconciliation_result: "CannotProve"`. Invalid inputs produce `REJECTED`; absent batches produce `INCOMPLETE`. Both exit nonzero. A zero exit status never upgrades the reconciler's result.

## Limits

An observer signature proves that the trusted collector signed those bytes, not that an observation is true. `SYNTHETIC_TEST_FIXTURE` is preserved as a self-asserted origin label and is never presented as live kernel evidence. The agent public key is included in the bundle for key-independence checks, not independently anchored by this CLI. AIP authorization is permission, not proof of action. Kernel evidence cannot reveal encrypted TLS payloads, MCP tool names, or arguments. Business effects require separate independent evidence.
