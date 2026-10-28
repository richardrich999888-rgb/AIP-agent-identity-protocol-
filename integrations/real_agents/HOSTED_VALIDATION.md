# Disposable GitHub-hosted validation

GitHub-hosted Ubuntu 24.04 is a viable initial integration target. SSH to a
user-managed machine is not a prerequisite for image builds, ordinary tests,
container isolation, kernel observation, or offline verification. This does
not make a completed component test a completed autonomous integration.

GitHub documents a fresh VM, passwordless sudo, 4 CPUs / 16 GB RAM / 14 GB SSD
for standard public Linux runners. Kernel features and audit configuration
must still be checked on each VM; runner labels are not capability evidence.
Sources: [runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[environment protection and secrets](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

## What the automated jobs exercise

`agent-zero-build.yml` builds the exact upstream commit in `frameworks.lock.json`
using a digest-pinned Python base and CPU-only tensor packages. It records the
resulting image ID and installed dependency versions. The image runs as UID
10001, without capabilities or Docker socket, with a read-only root filesystem.
Only its temporary state and task workspace are writable. Network-disabled
smoke tests exercise the actual upstream context/model configuration and local
terminal, without invoking a model. No mock model response is substituted.

`hosted-observer-capabilities` starts the actual probe and wrapped-key collector,
requires synchronized clocks and all six requested sensors, waits for verified
signed Active coverage, runs a real OS component test, checks independent
Linux audit, stops the daemons, verifies the archives, and runs seven tamper
mutations. It exports public evidence only. Its output explicitly says
`autonomous_workload_executed: false`.

The separate RBI workflow runs all five existing demonstration contracts. Its
success is regression evidence, not Agent Zero / DeerFlow / OpenHands acceptance.
See [VALIDATION.md](VALIDATION.md) for executed results, including failed attempts.

## Signing boundary

The default harness mode remains `off-host`: strict host-key SSH, a distinct
collector machine ID, independently provisioned public anchor, synchronized
clock, strict continuity and the existing Rust signature verifier.

An explicit collector configuration `"mode": "local-isolated"` instead invokes
the same root-owned collector-control helper on the disposable VM. The helper,
configuration, service, wrapped key, passphrase and evidence directories must
remain outside the workload mounts. The workload runs with separate PID/mount/
network namespaces, UID 10001, no capabilities and no privilege escalation.
Its only configuration credential is the approved restricted model credential.

This boundary protects the signing key from the unprivileged workload under a
trusted host kernel. It **does not protect against compromised host root or a
kernel escape**. Reports identify it as `ISOLATED_FROM_CONTAINER`, never off-host
or institutional custody. The public anchor is retained before launching the
workload. The checkpoint is retained separately from the evidence export.
Artifact transport through the same GitHub account is not independent
institutional custody or a third-party timestamp.

## Independent cross-check

The runtime now uses Linux audit, scoped to UID 10001 `execve`/`execveat`, with
a fresh rule key per run. It deletes only that rule, requires an active audit
daemon, and refuses increased loss counters, daemon restart, undrained backlog
or no matching syscall records. It never clears the host's audit rules.

The disposable VM setup removes only a packaged exact `-a never,task` opt-out
if present, before starting the controller. The harness refuses that rule on
an unprepared host. See the [upstream auditctl manual](https://github.com/linux-audit/audit-userspace/blob/master/docs/auditctl.8).

Do not attach the old bpftrace cross-check to the monitored scheduler tracepoint
and waive Sniffer Dog's resulting integrity warning. The probe's foreign-program
gate correctly withdraws coverage for that attachment. Linux audit uses a
different mechanism but still trusts the same kernel; it is not complete ground
truth, and unbound or missed events remain visible.

## Remaining access for a genuine workload

The repository secret-name listing and environment listing on 2026-10-28 both
returned zero entries. No secret values were requested, read or invented.
Before the genuine Click issue run, provision:

1. A protected GitHub environment named `snifferdog-validation`, limited to the
   reviewed feature branch and requiring the appropriate reviewer approval.
2. Test-only model credentials through approved environment secrets. Supply
   the secret **names**, provider, exact chat/utility/embedding model IDs,
   approved endpoints, expiry and enforced expenditure limit outside the
   secret values. A model identifier alone is insufficient.
3. A restricted model gateway or provider credential with a demonstrable hard
   budget. Provision a policy check that exercises denial and exhaustion; a
   boolean claiming a spending cap, or a client timeout, is not a hard cap.
4. An internal Docker bridge and a separately controlled egress proxy allowing
   the approved model endpoint and the public sources needed for the task
   (GitHub and dependency indexes). Test that direct egress, host services,
   metadata addresses and unrelated destinations are blocked. No repository
   token, personal files, observer key or Docker socket enters the container.
5. Root-controlled collector unit/configuration, probe transport registration,
   independently retained verification material, and a quota-limited disposable
   workspace. These can be provisioned in a hosted VM; the current capability
   test's ephemeral collector is not a deployable institutional signing service.

The pinned Agent Zero runtime uses `agent-zero.json` with `settings` and a
complete `preset` named `Default`. Each `chat`, `utility` and `embedding` slot
must explicitly include `provider`, `name` and `api_base`. The adapter reads back
the upstream resolved model configuration and rejects fallback to another model.
Use approved restricted credentials in upstream `settings.api_keys` or the
restricted env file. Never put values in the repository or action inputs.

The real task is [Click issue 3652](https://github.com/pallets/click/issues/3652),
at source `2247b35ea1c47c727d7a06e51fa280e12a863ff6`; the task prompt contains no
solution. After execution, independently inspect the patch and baseline/new
regression tests in another credential-free sandbox. A returned LLM message
cannot satisfy task acceptance. Logical delegation remains self-reported until
authenticated orchestration/gateway evidence is connected.

## Capabilities that need controlled external infrastructure

| Capability | Required infrastructure beyond an ordinary disposable runner |
| --- | --- |
| Signing remains trustworthy after workload-host root/kernel compromise | A collector in a genuinely separate trust domain, with independently provisioned keys and authenticated connectivity. A dedicated second Linux host or equivalent managed signing service is required; the local-isolated mode cannot establish this. |
| Institution-owned persistent keys, HSM custody, independent checkpoint retention, restart/rollback experiments across VM replacement | Institution-controlled key/storage service and access policy; usually dedicated collector infrastructure. SoftHSM on a runner is a software interface test, not hardware custody. |
| Fixed/custom kernel, lockdown/secure-boot policy, deliberate reboot, host-compromise experiments, cross-host container migration | Disposable machines whose kernel/boot/network policy is under the validation operator's control. Dedicated self-hosted VMs are suitable; do not perform these experiments on persistent production runners. |
| Reproducible overhead/soak/concurrency or local GPU model performance beyond standard resources | Controlled resource allocation and persistent measurement windows. A suitably sized hosted runner can suffice; self-hosting is not intrinsically required. |
| Private institutional model/gateway endpoints | Approved network connectivity, such as a dedicated validation network or managed private connectivity. Ordinary public runner egress alone does not establish access. |

Three-framework execution, delegated work, software-task acceptance, browser/
research execution, concurrency, degradation during genuine agent execution,
and a measured performance run remain acceptance gates until actually executed.
