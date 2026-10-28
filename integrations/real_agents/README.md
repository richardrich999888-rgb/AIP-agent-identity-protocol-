# Real-agent validation — implementation in progress

This directory adds source-pinned launchers for **Agent Zero, DeerFlow and the
OpenHands SDK**, a Linux controller, an off-host collector control helper,
offline archive checks and a loopback status viewer. **None of these three
frameworks has yet executed under this harness.** Image builds, live model
calls, deployment and complete end-to-end validation remain untested.

See [VALIDATION.md](VALIDATION.md) for the current results and missing gates.
A local unit-test pass or a historical signature check is not a real-agent run.

## Source and runtime choices

The full source commits and actual upstream entry points are in
[frameworks.lock.json](frameworks.lock.json). All three upstream LICENSE files
identify MIT licensing; retain their notices and inspect dependencies when
building redistributable images.

| Runtime | Inspected upstream API | Execution and logical agents |
| --- | --- | --- |
| [Agent Zero](https://github.com/agent0ai/agent-zero/tree/ff2a5b9c9c4e490ba38dd7c313e779510bb2071a) | `AgentContext.communicate(...).result_sync()` | Real model/tool loop, subordinate calls can share the Python process. Settings are supplied by the operator. |
| [DeerFlow](https://github.com/bytedance/deer-flow/tree/f79debed59ca6b1a31628e6b5ce55c8507793a4c) | `DeerFlowClient(..., subagent_enabled=True).stream()` | Embedded orchestrator and local sandbox inside the outer disposable container. Native remote/multi-container sandbox provisioning is not wired here. |
| [OpenHands SDK](https://github.com/OpenHands/software-agent-sdk/tree/46b1fa5cb91ada17e6ec938c7e8624a4fa19fa98) | `Conversation` with terminal, editor and task-tracker tools | Python software engineering agent. The current OpenHands/OpenHands repository is the control interface; this SDK owns execution. |

CrewAI, CAMEL/OWL, Deep Agents, Microsoft Agent Framework, Eigent, Agno,
SWE-agent and Browser Use were identified as alternatives. No adapter or live
validation is claimed for them. The three priority runtimes were selected to
avoid expanding scope before a first real run.

## Trust and attribution

The controller executes on a **dedicated disposable Linux host**. It launches
the existing `aip-probe` outside the agent containers. A separately provisioned
collector host runs `aip-collector` with its existing wrapped institutional key
and strict continuity/clock policy. Noise transport and all Rust signature
verification remain unchanged. The agent sees only the task, its disposable
workspace and restricted model configuration. It has no collector key,
evidence archive, Docker socket, host PID namespace or AIP source mount.

The controller measures the launched process through host `/proc`: boot ID,
PID, start ticks, PID namespace and mount namespace. After the Rust verifier
accepts the archive, the report selects signed events with the same probe,
boot and workload namespaces. It counts the precise launching instance using
PID **and start ticks**. Unbound events remain unknown; unrelated host events
cannot satisfy the workload gate. `aip-lineage` derives verified process edges;
the controller does not infer edges from PID numbers or agent messages.

This is process/container attribution under the observer's existing host-kernel
trust boundary. It is **not logical identity or authorization**. Every adapter
record is `SELF_REPORTED`. Logical agent attribution, authority and reconciliation
remain `CANNOT_PROVE`; gateway receipts are `NOT_SUPPLIED`. The merged
`aip-placement` and `aip-reconcile` code supports stronger signed placement,
but its decision/gateway integration is not yet connected to these launchers.
Missing authorization is never labeled unauthorized execution.

The existing `aip-sentinel-feed` verifies AIP signatures before converting
effects for the original OT sentinel. Its scope report is retained, including
unrenderable events. Starting an OT patrol or creating institutional gateway
receipts is not part of this first controller implementation.

## Prepare the two Linux hosts

Do this on disposable validation infrastructure. The workload host needs
cgroup v2, tracefs, scheduler/cgroup/socket tracepoints, connector, fanotify,
root privileges for the probe, Docker, bpftrace, Python 3.12+, synchronized
time, and the built AIP binaries. There is no macOS fallback or fake probe.

Build from this feature branch using the root Cargo workspace:

```sh
cargo build --release --locked -p aip-probe -p aip-collector \
  -p aip-observe-verify -p aip-reconcile -p aip-sentinel-feed -p aip-corroborate
```

On the collector host, provision a dedicated systemd unit named
`aip-collector-validation.service` (or a distinct instance per concurrent run).
Use the existing collector configuration requirements: `AIP_COLLECTOR_OBSERVER_ID`,
`AIP_COLLECTOR_KEY_VERSION`, wrapped `AIP_COLLECTOR_KEY_PATH`,
`AIP_COLLECTOR_PASSPHRASE_FILE`, `AIP_COLLECTOR_NOISE_KEY_PATH`,
`AIP_COLLECTOR_PROBES_PATH`, `AIP_COLLECTOR_LISTEN`, and `AIP_COLLECTOR_STATE_DIR`.
Set `AIP_COLLECTOR_CONTINUITY=strict`, `AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=1`.
Register the existing probe transport public key and pin the collector Noise
public key in the probe environment. Provision verification anchors separately.
Do not generate or copy the collector signing key on the workload host.

Install `collector_control.py` on that host and a root-owned config:

```json
{"unit":"aip-collector-validation.service","state_dir":"/var/lib/aip-validation/run-001"}
```

Use a fresh state directory per experiment. Existing archives are refused,
never erased. The helper claims an exclusive run lease, starts/stops only its
dedicated unit and exports only two public archives over pinned-host-key SSH.
A failed export leaves its lease in place for operator inspection. Do not
reuse a production collector service. The controller requires a different
machine ID; this check is inventory, not hardware attestation.

The operator must provision an **internal Docker bridge** and a separate
allowlisted egress proxy. Block host/collector/metadata/private destinations;
permit the selected public sources and restricted model endpoint. Model
credentials must have an externally enforced spend cap and expiry. Supply a
root-owned `policy_check` executable that actually checks those controls and
exits nonzero on failure. This deployment-specific check is deliberately not
replaced by an `approved=true` setting. Network rules, quotas and proxy setup
are still a deployment prerequisite, not an implemented universal provider.

Build each runtime with `build_image.py`, supplying a digest-pinned Python 3.12
Debian image, exact uv version and local tag. It checks out the exact framework
commit and uses the upstream frozen uv lock where available. Agent Zero's
requirements do not fully lock transitive packages: retain the built image by
digest and its dependency inventory. Image installation has not run here.

Create root-controlled model configuration readable only by the workload UID
10001: `agent-zero.json` containing upstream settings, or `deerflow.yaml`
containing model and local-sandbox settings. Set `DEER_FLOW_HOME` under `/work`.
OpenHands uses `LLM_API_KEY` and `LLM_BASE_URL` from its restricted env file.
Use upstream field names from the pinned source, not guessed provider settings.
Do not mount general personal configuration directories. `/tmp` and Agent
Zero's `usr` are ephemeral; `/work` is the only persistent agent-writable mount.
Use a quota-limited filesystem for workspaces; host storage quotas are not
automatically provisioned by this controller.

## Run, inspect and verify

Copy `example.config.json` into root-controlled deployment configuration and
replace every placeholder with provisioned paths, model ID, image ID and
independently held public anchor. `probe_env` is plain `AIP_PROBE_*=value`
data, never a sourced shell file. Configure a fresh dedicated collector state.

```sh
python3 integrations/real_agents/harness.py preflight --config /etc/snifferdog/agent_zero.json
python3 integrations/real_agents/harness.py run \
  --config /etc/snifferdog/agent_zero.json \
  --out /var/lib/snifferdog/runs/experiment-001 \
  --checkpoint /var/lib/snifferdog/checkpoints/experiment-001.json
```

The research task retrieves actual Linux documentation and asks for subordinate
research/review. The coding task uses [Click issue 3652](https://github.com/pallets/click/issues/3652)
with an independently reproduced baseline. No solution is supplied. Use the
DeerFlow research task after Agent Zero, then OpenHands with the coding task.
The current research workload satisfies neither a live browser-navigation
claim nor a demonstrated multi-container claim until those actions execute.

The controller verifies fresh signed health before launching, starts an
independent bpftrace observer, bounds resources/runtime, records controller
identity and status, waits for signed end coverage, stops writers and exports
stable archives. bpftrace shares the scheduler mechanism: it is an independent
implementation, **not an independent kernel**. Agreement must include every
bound workload exec, not just background host processes. All gaps remain in
the comparison report. Auditd remains available via the existing corroborator
but this launcher does not install or remove machine-wide audit rules.

`run` currently ends `REVIEW_REQUIRED` with exit 1 even if the observation gate
passes: task acceptance, authenticated delegation and the remaining assignment
gates are not automated. Failed preflight exits 2. No live CI run can turn green
merely because an LLM returned. Inspect results and complete the missing gates
before changing that contract. Unit CI never substitutes for privileged CI.

The checkpoint must stay outside the exported run directory under independent
controller/institution custody. It contains SHA-256 hashes of the exact two
archives received over authenticated SSH; it is not a new signature format.
A sender-supplied checkpoint cannot establish completeness. The Rust verifier
accepts valid chain windows; a valid prefix/suffix alone cannot reveal deletion.

```sh
python3 integrations/real_agents/harness.py verify --archive /evidence/run \
  --tools /opt/aip/bin --anchor /trust/observer.json --checkpoint /trust/run.json
python3 integrations/real_agents/harness.py tamper --archive /evidence/run \
  --tools /opt/aip/bin --anchor /trust/observer.json --checkpoint /trust/run.json
```

The tamper command checks modification, middle/edge deletion, reordering,
duplication and corruption. It requires at least three actual captured batches.
It reports signature/chain rejection separately from checkpoint rejection.

```sh
python3 integrations/real_agents/monitor.py /var/lib/snifferdog/runs --port 8765
```

The viewer binds only `127.0.0.1`; use an SSH tunnel for a remote host. It shows
controller state, verified snapshots and explicit uncertainty. It uses text
nodes for event rendering and serves only status JSON, never arbitrary files,
agent logs or credentials. The view itself is not signed evidence.

## Regression checks

```sh
python3 -m unittest discover -s integrations/real_agents/tests -v
python3 integrations/real_agents/tests/offline_archive_check.py \
  --repo . --tools target/debug
python3 -m unittest discover -s validation/rbi_demo -p 'test_*.py' -v
```

The archive regression intentionally uses preserved historical evidence. It
does not rename that evidence or claim it was captured by these launchers.
The manual privileged workflow requires a protected `snifferdog-validation`
environment and a dedicated `snifferdog-disposable` Linux runner. Do not
dispatch it until that runner's root-controlled deployment matches the reviewed
commit. Model logs and workspaces are not automatically uploaded to GitHub.
