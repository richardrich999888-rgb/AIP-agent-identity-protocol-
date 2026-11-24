# Customer pilot qualification

Status: **NOT READY — filtering and durable delivery are implemented; CI security and customer deployment gates remain.**
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
   names for an independent collector. The existing disposable GitHub Actions
   runner can remain the workload host for initial integration. The missing
   infrastructure is a reachable Linux collector controlled by a different
   administrator, its connection/configuration name, and approved secret names
   for access; do not paste secret values.
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
   Disposable Actions runners cannot qualify persistent customer storage, actual
   host restart/power-loss behavior, long-duration capacity or customer deployment.
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
changing the Linux sensor path. Linux results are recorded separately below.

## Current Linux candidate and retained evidence

Implementation source: `32619a16b102d14d9cca667699a3b64394ca644f`.
All seven configured workflows and 22 jobs finished: **16 successful, three
security-gate failures and three gated skips**. The overall CI result remains
failed because the security gates are unresolved. The tested PR merge checkout
was `e004eb0e49d39647c6e509909b0264c023416a9d`.

| Functional check | Exact result |
| --- | --- |
| Formatting and workspace Clippy with warnings denied | Passed |
| Workspace debug tests | 3,322 passed, zero failed, seven ignored |
| Workspace release/performance tests | 3,324 passed, zero failed, five ignored |
| Doctests, each profile | Two passed, zero failed, two ignored |
| Coverage execution | 3,322 passed, zero failed, seven ignored |

The two new Linux binary-location regressions passed in debug, release and
coverage. The [complete job matrix and ignored-test details](ci/32619a1-FINAL-OUTCOMES.md)
retain the scope of these results. Coverage was 82.893% of lines; no minimum
percentage gate is configured. The RED ledger reproduced 43 runnable cases,
with ten blocked cases and two notes. Two real-client tests ignored in the
general workspace suite ran explicitly in enterprise integration.

The three gated jobs were the separate Qwen evidence-agent Linux/offline jobs
and the Agent Zero genuine-task job. Agent Zero image/API component success
does not validate its genuine workload; no claim is made that all three
open-source agent integrations have executed.

- The exact release regression
  `g14_04_a_live_execution_that_did_not_happen_is_cannot_prove_offline_too`
  passed all **20 repetitions**; its verdict assertions were not changed.
- The real Linux interference rehearsal passed with **85 signed batches, 3,696
  kernel events and four signed health records**. Honest, interfered and recovery
  behavior remained distinct; coverage was withdrawn for interference. The
  offline verifier accepted the originals and rejected deletion of one middle
  record with exit code 1. This is a controlled workload, not an AI-model run.
- The original [public rehearsal artifact](evidence/32619a1/rbi-public.zip) was
  downloaded with its GitHub digest checked. A separate local verification
  process ran with networking denied and accepted all 85 batches/four health
  records with zero findings. Its deletion control was rejected again. The
  [local receipt](evidence/32619a1/rbi-offline-local.json) records the binary hash
  and actual network-denial check.
- The [genuine hosted AI-agent workflow](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/44916522554)
  passed normal execution, observer interruption and fresh recovery. Its original
  [public evidence ZIP](evidence/32619a1/genuine-agent-public.zip) is retained with
  its GitHub digest checked. All three archives also passed the current local
  verifier with networking denied and exact controller checkpoint hashes checked:

  | Profile | Signed batches | Signed health | Controller-reported model calls | Workload observation coverage |
  | --- | ---: | ---: | ---: | --- |
  | Normal genuine execution | 47 | 4 | 2 | Signed Active for the task window |
  | Observer interrupted | 18 | 3 | 2 | Unavailable; archive integrity does not prove unobserved work |
  | Fresh recovery | 46 | 4 | 2 | Signed Active for the new task window |

  The [local offline receipt](evidence/32619a1/genuine-agent-offline-local.json)
  records zero verification findings and rejection of a deleted middle record
  for each profile. Model-call counts and workload success are controller
  observations, not conclusions inferred from archive signatures. These runs
  used one GitHub administration; they do not establish independent collector
  custody or the still-unrun scoped customer pilot.

Security gates remain failing: **217 Gitleaks findings**, **four HIGH Trivy
configuration findings** in retained Helm example evidence, and cargo-deny's
unmaintained Chrono alert. The audit also reports a rustix unsoundness warning.
These are scanner findings, not a claim that all are exploitable defects. No new
ignore, scan exclusion or security waiver was added. Safe exact-source scanner
receipts are under [CI records](ci/). The dependency review identified
[Chrono RUSTSEC-2026-0543](https://rustsec.org/advisories/RUSTSEC-2026-0543.html)
(no patched version) and
[rustix RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html)
(patched in 1.1.6); neither dependency was changed by this pilot feature work.

Earlier failed candidates and corrected harness checks are retained in the CI
records. The final artifact lookup uses Cargo's current compiler-artifact paths
instead of assuming its output-directory layout, and refuses failed builds
rather than reusing a stale executable. Rehearsal readiness requires an actual
authenticated collector acknowledgement. Public diagnostic export keeps private
state permissions unchanged and cannot upload a preexisting output directory.

No full-sensor service was installed, and no separately administered collector
was contacted. Per-agent filtering and delivery crash/replay checks remain
component validation until the scoped workload and outage/restart acceptance
procedure has actually run on the approved pilot hosts.
