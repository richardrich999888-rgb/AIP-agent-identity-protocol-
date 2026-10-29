# Installed distribution provenance

Validated source: `42d0d96c9cc9d3075c792a195cc74e4171b0e817`.

`sdk-wheel-regression.log` records the real offline wheel/source-egg-info pollution regression. `sdk-wheel-old-verifier-control.log` records the expected import failure when the same regression uses the historical unisolated child Python behavior. The fixture is a packaging fixture only and is never used as a service SDK or banking workload.

`wheel-provenance-diagnosis.json` retains the concrete prior reproduction: pip exits zero and reports already installed under inherited `PYTHONPATH`, then the temporary-environment probe cannot import `vanian`. The isolated child path actually installs it and passes.

`sdk-distributions-isolated-positive.log` records the actual built customer wheel and TypeScript tarball verification with `PYTHONPATH=sdk/python`, matching the failing CI step. Both distributions install and import, expose all seven required methods, and Python imports beneath its temporary environment prefix. The local npm cache was explicitly placed under this workspace because the default user cache is unwritable. No network registry publish or evidence-service call occurs in this check. Live CI results are recorded separately in `../ci/`.
