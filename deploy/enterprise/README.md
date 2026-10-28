# Enterprise deployment package

Current customer workflow: [installation](../../docs/enterprise/INSTALLATION.md)
and [onboarding](../../docs/enterprise/CUSTOMER_ONBOARDING.md). The Debian
packages and native public-key enrollment extend the existing tar/systemd
path. Clean-host/runtime qualification and release approval remain open.

This directory packages the existing `aip-probe`, `aip-collector` and
`aip-observe-verify`. The package runs in **OBSERVER_ONLY** mode. It has no
actuator, transaction gate, firewall change, or automatic containment.

For customer onboarding, see the [enterprise service model](../../docs/enterprise/SERVICE_DELIVERY_MODEL.md)
and the [offline service manifest planner](../../integrations/service_delivery/README.md).
The preflight report is a plan, not proof that any security control was deployed.

The installer and verifier are Python standard-library programs. Their
deterministic tests install fixture files into a temporary directory; they do
not establish that a Linux sensor opens or that a live deployment works.
Clean Linux installation, runtime startup, observation, and uninstall remain
**BLOCKED_BY_INFRASTRUCTURE** until exercised on approved Linux hosts.

Start with [linux/README.md](linux/README.md), then
[runbooks/OPERATIONS.md](runbooks/OPERATIONS.md). The
[Kubernetes template](kubernetes/README.md) is deliberately unvalidated and
requires explicit enablement. [airgap/README.md](airgap/README.md) describes
offline dependencies and the independent artifact trust step.

The monitored host and collector require separate administrative boundaries.
Two containers sharing an administrator-controlled host do not establish that
separation. Runtime observation operates without a customer SDK or MCP server.

This package does not synchronize the collector's archive to the evidence API
automatically. A stable signed snapshot can be admitted through the new
tenant-anchored `POST /v1/observations` path described in
`docs/enterprise/BANK_INTEGRATION_GUIDE.md`. The existing signed-verdict
filing interface remains separate; the complete same-run authorization,
observation, receipt and reconciliation join is still an acceptance gate.

Run the packaging and harness regressions from the repository root:

```sh
python3 -B validation/enterprise/test_packaging.py
python3 -B validation/enterprise/test_agent_harness.py
bash -n integrations/agents/run.sh
```
