# Enterprise deployment package

This directory packages the existing `aip-probe`, `aip-collector` and
`aip-observe-verify`. The package runs in **OBSERVER_ONLY** mode. It has no
actuator, transaction gate, firewall change, or automatic containment.

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

This package does not connect the collector's archive to the evidence API
automatically. The existing authenticated evidence and verdict ingestion
interfaces remain separate; submitting a verdict still requires the existing
signed authorization, observation and reconciler trust anchors.

Run the packaging and harness regressions from the repository root:

```sh
python3 -B validation/enterprise/test_packaging.py
python3 -B validation/enterprise/test_agent_harness.py
bash -n integrations/agents/run.sh
```
