# Customer pilot qualification

Status: **NOT READY — local software checks passed; Linux CI and deployment gates remain.**
This report covers the new customer-pilot changes. The earlier genuine Linux
Q&A capture remains preserved separately; it is not a test of this new deployment.

## Implemented candidate

- Process-instance retention filtering before serialization, queueing and export.
  Signed protocol 14 records state the targets and excluded/unassigned counts.
  Labels remain claims; filtered health grants no host-wide completeness.
- Private bounded durable buffering, continuous collection while delivery retries,
  pinned-recipient binding, and collector replay receipts reconstructed from
  verified signed archives. Original observation timestamps and bytes are retained.
- Collector startup coverage floor: historical backlog cannot backfill a
  collector interruption. Strict clock, identity, continuity and signature checks
  remain required.
- Key-only enrollment, filter enrollment/validation commands and offline reports
  that expose scoped retention. Sealed protocol 12/13 evidence stays verifiable.
- Installer configuration/preflight checks and an inactive full-sensor service
  profile. Full-sensor activation is still refused by the installer.

See [filtering](../../deploy/enterprise/linux/FILTERING.md),
[buffering and recovery](../../deploy/enterprise/linux/BUFFERING.md), and the
[full-sensor profile and Linux qualification procedure](../../deploy/enterprise/linux/FULL_SENSOR_REVIEW.md).

## Outstanding deployment gates

1. **Privilege approval and actual service qualification.** Automatic approval
   review rejected enabling the expanded Linux capabilities and host mount view.
   The exact candidate is retained for review. Approval for a disposable Actions
   runner was requested but has not been received. No service was activated.
   Install/start/restart/outage recovery/uninstall and negative privilege tests
   must actually pass under the service account before enabling this profile.
2. **Separately administered Linux collector.** The available configuration has
   no SSH host alias, registered self-hosted runner, or approved validation secret
   names. Provide connection/configuration names for the workload and collector
   hosts plus their responsible administrators; do not paste secret values.
   The workload administrator must not control the collector signing key,
   continuity storage or independently held checkpoints. Two runners under the
   same administrator do not establish this boundary.
3. **Real workload, fresh signed evidence and offline verification on those
   hosts.** This pilot run has not occurred. It must include selected and
   unselected processes, an interrupted collector route, unchanged replayed
   payloads, restart boundaries and independently retained public trust/checkpoints.
   No model result or customer action is inferred from a valid signature.
4. **Capacity and customer acceptance.** Qualify sensor loss/overhead, queue
   capacity and collector replay retention with the intended customer workload.
   The current 1,000,000-receipt limit, process reenrollment and unsupported
   automatic archive/key rotation are documented operational limits.

The existing draft PR must remain draft until its required acceptance gates
are satisfied. Software tests and the earlier hosted demo do not close these
customer deployment gates.

## Local software validation

The combined probe, collector, observation, offline-verifier and transport run
passed **350 tests**, with **0 failures** and **1 ignored**.
Sensor-dependent cases on macOS report unavailability; these totals do not
represent live Linux sensor qualification. The completed queue checkpoint
coverage includes 26 passing tests. Collector release tests passed 25; these
counts overlap the combined run and must not be added to it.

Python agent harness: 138 passed. Installer packaging: 24 passed. Build harness: 3
passed. Formatting and patch checks passed. Changed-package Clippy passed with
all Clippy lints denied; existing Mac-only compiler warnings remain visible.
The final offline report preserves the legacy JSON shape while declaring scoped
batches for new filtered archives.

[Local receipts](local-checks/) retain the initial Python 3.9 mismatch, the
Mac-only workspace compile failure and startup-diagnostic test failures, alongside
the corrected runs. The project requires Python 3.12; tests were rerun with it.
Unsupported-platform diagnostics were corrected without opening any sensor or
changing the Linux sensor path. Full workspace validation awaits Linux CI.
