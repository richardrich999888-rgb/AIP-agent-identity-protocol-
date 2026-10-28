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
not needed for that profile. No separate-administration assertion is made.

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

Package CI also installs actual Linux binaries into staged filesystems,
executes the installed verifier, uninstalls/reinstalls and checks retained
operator data. That is an executable packaging test; it does not satisfy a
live clean-host installation or component restart/continuity gate.

Before customer acceptance, run the genuine workload through the installed
services, query its evidence via tenant-scoped clients, verify offline, restart
and recover with no silent backfill, test loss/backups/capacity and uninstall
software while preserving institution-owned state. Kubernetes, air-gap and
production ingress remain unvalidated until executed on the intended platform.
