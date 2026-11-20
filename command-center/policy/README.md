# Gate policy bundle (item 3.1a)

The bundle is `gate.rego` plus `data.json`. `gate_test.rego` holds the
policy's own tests and is excluded from the bundle and from its hash.
`command-center/server/opa_gate.py` evaluates the bundle with `opa eval`,
once per call, and records `bundle_sha256` and `input_sha256` with every
decision.

| Check | Command | Result |
|---|---|---|
| Strict compile | `opa check --strict command-center/policy` | ok |
| Policy tests | `opa test command-center/policy` | 17/17 PASS |
| Adapter tests, live | `VANIAN_OPA_BIN=…/opa python3 -m unittest test_opa_gate` (in `command-center/server`) | 23 passed / 0 failed / 0 skipped |
| Adapter tests, no binary | `python3 -m unittest test_opa_gate` | 16 passed / 0 failed / 7 skipped |
| Mutations of the adapter | `command-center/server/mutations-opa-gate.txt` | 6/6 caught, after strengthening one test that G3 had survived |

OPA is the pinned `v1.22.4` from item 1.2 (`research/oss/opa/README.md`).

The `data.json` contents are a lab fixture. Real agents, revocations and
allowlists come from the inventory and signed revocations in item 3.1b.

Not yet done (3.1b, blocked on 0.1):

- call this from the gate's step 7;
- feed `revoked_jtis` from signature-verified revocations;
- run the parity tests against P0-059's existing allowlist cases.

Until then this is a decision component, not an enforcement point.
