# Bank engineering evaluation deployment

This is an engineering installation/runbook, not regulatory approval, a bank
certification or production qualification. Preserve the existing RBI five-act
rehearsal and its recorded library/full-system scope. No historical result is
reclassified as a new autonomous same-run execution.

## Topology and access

For separate-host acceptance, supply a disposable workload Linux VM and a
separately controlled collector Linux host or equivalent independent trust
domain. Synchronize both clocks and approve kernel features/privileges,
authenticated routing, probe enrollment and independent public anchors.
The workload cannot access the collector signing key. Institution-owned
release/key/storage approval and retention are required for institutional
custody; ephemeral GitHub keys do not satisfy that condition.

The initial automated local-isolation profile runs on `ubuntu-24.04` in GitHub
Actions. It proves software interfaces only to the extent supported by its
actual artifacts, with host root/kernel and the GitHub account trusted. SSH is
not needed for that profile. The public repository now receives allocated
GitHub runners; each execution must still pass its own capability and evidence
checks. A separately controlled collector is needed to establish independent
custody and the stronger workload-host-compromise boundary. No
separate-administration assertion is made for the hosted profile.

The hosted profile requires all of the following on the actual runner:

* Root for provisioning tracefs, a dedicated workload mount, network namespaces,
  UID-based firewall rules, audit rules and cgroup limits; the agent, model,
  gateway and tool subsequently run as distinct unprivileged accounts.
* cgroup v2 with enabled `cpu`, `memory` and `pids` controllers. The workload
  group is limited to two CPUs, 8 GiB and 512 tasks, with a 360-second agent
  deadline and a 45-minute workflow timeout.
* Accessible tracefs and working perf tracepoints for scheduler fork/exec,
  cgroup creation/removal/task attachment, `sock/inet_sock_set_state` and
  `sock/sock_send_length`. Perf observation requires `CAP_PERFMON` or an
  equivalent host policy; unavailable requested sensors fail startup.
* Kernel process-connector support (`CONFIG_CONNECTOR` and
  `CONFIG_PROC_EVENTS`), `CAP_NET_ADMIN` in the initial network namespace,
  and fanotify support with `CAP_SYS_ADMIN` and access to the workload mount.
  The probe and collector remain in the host network namespace while the
  model, agent, gateway and tool use an isolated loopback-only namespace.
* A synchronized host clock, working chrony checks, and auditd with permission
  to add and export the independent agent/tool execution rules. Retain actual
  loss, integrity, binding and signed coverage results; having privileges does
  not establish healthy observation.

The current profile selects `sched,cgroup,connector,fanotify,sockstate,socksend`.
It does not select AF_PACKET. A kernel feature absent from a runner image
cannot be supplied by granting additional capabilities.

## Reproduce the initial run

1. Check out the exact reviewed integration revision and retain its SHA and
   dirty-state report. Use the pinned framework/model/dependency locks.
2. Run the `Genuine same-run execution assurance` workflow on that branch.
   It downloads public pinned local inference software/model before isolating
   networking. It uses no paid-model or production credentials.
3. Require genuine model selection, independent policy authorization, actual
   ContextForge dispatch, actual MCP subprocess execution and real sensor
   coverage. A model failure, lost audit record, missing binding, invalid
   signature or unsupported client result must fail visibly.
4. Download the public run artifact and retain its GitHub digest/source/run
   metadata. Supply the public trust file and retained checkpoint separately
   to another process. Never derive trust from the submitted bundle itself.
5. Execute `aip-execution-assurance evaluate` with `AIP_RUN_TRUST_FILE` pointing
   to the independently approved public configuration and the original bundle
   on stdin. Run `aip-observe-verify` independently on the two original archive
   files using the approved observer ID/version/public key.
6. Inspect the signed runtime verdict, tool-boundary comparison, process
   references, coverage/loss/integrity states, actual output and limitations.
   API/SDK/MCP/console output must match this same immutable run.

The workload is a read-only synthetic document evaluation. Human review is
its only permitted recommendation. It cannot approve loans, move funds or
write institution/customer systems. Its gateway token is limited to the
allowlisted tool profile, not gateway administration.

## Institution installation

Use the existing [Linux package runbook](../../deploy/enterprise/linux/README.md).
Build actual Linux binaries from the reviewed source, obtain the package
SHA-256 through an independently approved release channel, and verify before
executing installer code. The archive is checksum-anchored; an institutional
release signature remains a separate requirement.

Install the probe and collector roles on the genuinely distinct hosts using
reviewed configuration and the existing `--confirm-separate-host` guard.
Never provide that confirmation merely to run both roles on one disposable VM.
Provision wrapped signing/passphrase and Noise keys only through the approved
operator/secret process. The installer does not start services automatically.
Complete the existing preflight, enrollment, resource-limit and coverage checks.

The installer currently refuses a configuration containing `fanotify`: its
shipped systemd restrictions do not grant `CAP_SYS_ADMIN` or the required host
mount view. Reproducing the full hosted six-sensor profile as an installed
service therefore requires a reviewed deployment change that supplies those
permissions and mount visibility, followed by actual startup and coverage
validation. A manual override alone does not bypass the installer's config
refusal. A package installed with fewer sensors has a different coverage
profile and cannot be reported as qualification of the full hosted profile.

Package CI also installs actual Linux binaries into staged filesystems,
executes the installed verifier, uninstalls/reinstalls and checks retained
operator data. That is an executable packaging test; it does not satisfy a
live clean-host installation or component restart/continuity gate.

Before customer acceptance, run the genuine workload through the installed
services, query its evidence via tenant-scoped clients, verify offline, restart
and recover with no silent backfill, test loss/backups/capacity and uninstall
software while preserving institution-owned state. Kubernetes, air-gap and
production ingress remain unvalidated until executed on the intended platform.

## Independent review of retained evidence

For example, `validation/enterprise/results/E2E_40755309307/` retains original
public bytes, GitHub source/run/artifact digest and separate local-verifier
outputs. Approve public authorities and checkpoint separately from the bundle;
check GitHub metadata and the file inventory. GitHub/controller provenance is
not institutional administrative separation.

With reviewed binaries and approved public trust copies, another process can
run (no model, live agent or API is needed):

```sh
aip-observe-verify --observer-id collector.same-run --key-version 1 \
  --pubkey-file /approved/observer.pub \
  --batches /evidence/attested.archive.jsonl \
  --health /evidence/health.archive.jsonl --json
AIP_RUN_TRUST_FILE=/approved/run-trust.json \
  aip-execution-assurance evaluate < /evidence/run-bundle.json
```

Require zero archive findings and inspect authorization, receipt, checkpoint
and signed-reconciliation flags. Inspect identity, action, availability, reason
and tool-boundary annotations separately. Successful verification preserves a
supported `CannotProve`; it does not upgrade it to `Verified`. Preserve original
bytes separately from review notes and check which client gates the run reached.

The latest complete hosted positive/interruption/fresh-recovery evidence package
is `validation/enterprise/results/E2E_40875323001/` at execution source 8d38d77;
the earlier 7625b1d and d6eb35e packages are retained separately as well. Each
profile has its own original public trust/checkpoint and bundle; use matching
material when verifying. This is the runnable engineering package for the
local-isolation demonstration. It does not satisfy the separate-host installer,
institution-owned custody or production deployment acceptance gates above.


The subsequent e4cd07d core positive and interruption paths passed, but its
recovery lacked a Forwarded receipt and remains failed. A controlled pinned
CPEX reproduction exposed UUID-local context loss on manager replacement.
The integration now uses owned request-global handoff and a one-use durable
post-callback transition, preserving cache invalidation and authorization.
Missing state remains CannotProve. The subsequent 8d38d77 core repeat in
workflow 40875323001 passed all three profiles, including fresh recovery, all
enterprise clients and separate offline verification; it does not reconstruct
the older missing receipt. See [the execution record](END_TO_END_VALIDATION.md)
for original failed evidence, the successful fresh repeat and the separate
Agent Zero timeout.

The genuine core repeat for source
`8d38d77fa3bf1c3b0670f584feaf75f34bf69a07` passed all three profiles and
independent offline checks of their original bundles. All five component-CI
workflows / fourteen jobs also passed that source, confirmed 2026-10-29
16:04 UTC. Final-HEAD CI remains required after the documentation/evidence-only
snapshot. The three failed Agent Zero tasks are separate from
historical component-CI successes. Its latest attempt made six model requests
but timed out after 900 seconds, with no accepted tool protocol, patch or full
coverage; this is not an accepted framework or installed-service test.

Read-only GitHub API inspection at 2026-10-29 12:43 UTC, rechecked at 12:44 UTC,
showed no repository secret names. The named `snifferdog-validation` environment
still had no protection rules or branch restriction and allowed administrator
bypass. The failed public local-model tasks used no model API credentials.
Remote inference would additionally require approved restricted model secrets,
exact endpoints/models, expiry, tested hard spend limits and controlled egress.
A suitable model/task configuration and retained incremental diagnostics also
need validation; credentials alone do not establish task acceptance.


The subsequent d5c39dd publication check passed all fourteen component-CI jobs
and the complete three-profile genuine core workflow, with separate offline
verification. Its originals and exact CI register are linked in
[the later publication and diagnostic record](END_TO_END_VALIDATION.md#later-publication-check-and-diagnostic-repair).
A further bounded incremental Agent Zero diagnostics repair passes 60 portable
component tests; fresh image smoke and genuine task acceptance remain separate.
The original 900-second deadline and security/evidence controls are unchanged.
Derived image size/origin annotations were corrected without changing signed
records or historical outcomes. The existing Security workflow was restored
from its inactivity pause; its next-revision scans and all exact-final-HEAD CI
still require actual results. Separate collector custody, successful framework
repairs/swarms and installed-customer qualification remain incomplete.
