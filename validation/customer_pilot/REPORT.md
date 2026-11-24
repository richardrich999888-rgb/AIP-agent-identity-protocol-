# Customer pilot qualification

Status: **NOT_READY for a customer pilot. Disposable full-sensor service qualification and fresh genuine AI execution passed; independent collector custody and persistent customer-host acceptance remain untested. PR #8 stays draft.**

These results bind to runtime source `c683134c59b50950e4eab176d37292683c61930d`.
The report publication commit records that tested source; it is not a new runtime
qualification. The previous [report](historical/32619a1/REPORT.md) and
[acceptance record](historical/32619a1/acceptance.json) are preserved byte-for-byte.
Historical approval refusals and failures in those records are not current status.

## What changed

The probe retains only explicitly enrolled process instances before serialization,
queueing and export. Protocol 14 signs the scope and excluded/unassigned counts.
PID reuse, mismatched event subjects, altered scope and scope added to legacy
formats are rejected. Labels remain claims, and filtered health grants no
host-wide completeness. Sealed protocol 12/13 evidence remains verifiable.

A bounded durable spool continues collecting while delivery retries. Replays
retain original timestamps and payloads; the pinned collector returns the
original durable receipt after strict archive verification. A collector restart
cannot backfill an interruption. A fatal sensor read now stops collection before
a batch can be signed as a quiet interval; the sensor set remains poisoned until
restart, with committed spool data preserved. No signature, identity, clock,
coverage or continuity requirement was relaxed.

The full-sensor installer remains disabled by default. The approved disposable
path binds activation to exact unit, configuration and AppArmor policy digests,
requires an enforcing policy, and never starts automatically. Enforced AppArmor
closes the reproduced host-root write escape. State-only hardlinks permit atomic
spool publication without allowing outside targets. Packet interface lookup uses
the existing packet descriptor rather than opening an additional socket. A
read-only disconnected-path prefix permits fanotify metadata reads without
matching writable state paths. Broad read access and sensor capabilities remain
explicit residual privileges, not a customer-data isolation guarantee.

See [filtering](../../deploy/enterprise/linux/FILTERING.md),
[buffering](../../deploy/enterprise/linux/BUFFERING.md), and
[installation and full-sensor review](../../deploy/enterprise/linux/FULL_SENSOR_REVIEW.md).

## Actual full-sensor Linux qualification

[Run 45433545896](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/45433545896)
passed both the installed-service job and a separate Linux offline-verification
job. This run used controlled file, process, cgroup and TCP operations, **not an
AI agent**. The genuine AI capture below is a different workload and archive.

The disposable x86_64 runner used kernel `7.0.0-1014-aws`, systemd 255 and a
synchronized clock. The actual service ran as UID 999 with
`aip-probe-full-sensor (enforce)`, `NoNewPrivs=1` and seccomp enabled.
The collector had another nonroot UID but the same host administrator.

| Executed check | Result |
| --- | --- |
| Seven sensor mechanisms, baseline | Sched 6; Cgroup 12; SockState 30; SockSend 6; AF_PACKET 60; Fanotify 6; process connector 6 controlled positive events |
| Final signed archive | 59 batches, five health records, 721 kernel events; 32 scoped batches; zero verifier findings |
| Baseline subset | 27 batches, two health records, 637 kernel events; zero findings; overlaps final archive, do not sum |
| Selected process retention | 14 each of spawn, cgroup create/remove, socket state/send and file events; unselected workload excluded |
| Scope accounting | 648 excluded and 538 unassigned records; aggregate coverage and logical agent identity remain CANNOT_PROVE |
| Outage, lost authenticated acknowledgement and restart replay | 14 unique original queued payload snapshots replayed, zero duplicate batch identities, two filtered probe run IDs; no reply fabrication |
| Uninstall/reinstall and collector restart | Stopped spool and credentials preserved; signed archive prefix and signing anchor preserved; strict continuity |
| Forbidden-operation controls | All nine refused: direct outside write, host-root write, other-process-root write, state symlink write, outside hardlink, mount, unshare, ptrace and process_vm_writev |
| Offline verification | Both snapshots accepted with zero findings in a separate Linux Docker process with networking disabled, read-only files, no capabilities and no privilege escalation |
| Tamper controls | All seven rejected by the retained checkpoint policy: modification, middle deletion, suffix deletion, prefix deletion, reorder, duplicate and corruption |

A valid signed prefix or suffix can still have valid individual signatures.
Those two truncation controls were rejected by the retained checkpoint, not by
claiming signatures alone prove archive completeness. Original trust anchors and
checkpoints came from this same administration; their preservation does not
establish independent custody. A dummy root-owned read canary remained readable,
confirming the documented broad-read residual privilege.

The [original public ZIP](evidence/c683134/full-sensor-public.zip) contains signed
archives, public anchor, checkpoints, effective installation records and results.
The [original offline ZIP](evidence/c683134/full-sensor-offline.zip),
[readable verification](evidence/c683134/full-sensor-offline-verification.json),
[negative controls](evidence/c683134/full-sensor-negative-controls.json) and
[artifact manifest](evidence/c683134/manifest.json) retain exact GitHub artifact
IDs and SHA-256 checksums. The public ZIP checksum is
`31b7a0901c57c79def5035c6e08a2ce8f9a6ae34e6be50bcf3503b4aa7fcaaf2`.
Its final signed head is
`9cc6e8c46323e97c3a01d66dd057bf140b82f4dfeb6731776c73f3817acc1cd0`.

## Failed attempts remain evidence

| Source / run | Actual outcome |
| --- | --- |
| [3622b85 / 45331122159](evidence/3622b85/manifest.json) | All seven sensors and offline integrity worked, but host-root write succeeded: FAIL |
| [ae79431 / 45332571742](evidence/ae79431/manifest.json) | Eight forbidden operations refused, but state hardlink publication was denied; no accepted archive: FAIL |
| [b6252bb / 45333418148](evidence/b6252bb/manifest.json) | Nine forbidden operations refused, but interface lookup opened a forbidden extra socket; no accepted archive: FAIL |
| [6d6ef35 / 45381506440](evidence/6d6ef35/manifest.json) | Nine forbidden operations refused and signatures verified, but fanotify had no positive events after a metadata-read denial: FAIL |
| [c683134 / 45433545896](evidence/c683134/manifest.json) | Seven positive mechanisms, nine forbidden controls, lifecycle, replay and offline checks: PASS within disposable controlled-workload scope |

The fourth failure exposed a swallowed sensor-read error; the final code refuses
that interval instead of emitting a counted-zero successful batch. Original
archives from failures are preserved, never repaired or re-signed.

## Fresh genuine AI workload

[Run 45433546227](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/45433546227)
executed the pinned local-model agent against a synthetic read-only loan review
task, through the actual tool and client integrations. It made two model calls
and produced two signed tool receipts in each phase. This is real model execution,
not the Agent Zero component smoke and not the full-sensor installed service test.

| Phase | Signed batches / health | Identity and evidence conclusion |
| --- | --- | --- |
| Normal | 44 / 3 | Match with four observations; CannotProve(ActionEvidenceUnavailable) |
| Observer interrupted | 18 / 4 | NoReference; CannotProve(WindowNotCovered) |
| Fresh recovery | 46 / 4 | Match with four observations; CannotProve(ActionEvidenceUnavailable) |

All three workflow archive, checkpoint and signed-reconciliation verifications
passed. Model-call counts and task success are controller observations, not
conclusions inferred from signature validity. Missing action evidence and the
interruption remain CannotProve. Separately administered custody is incomplete.
The [original public evidence](evidence/c683134/genuine-agent-public.zip) and
[manifest](evidence/c683134/genuine-agent-manifest.json) preserve this fresh run.
A separate local process rebuilt the verifier from current source and replayed
all three original archives under an enforced network-denial policy, with an
actual denied-socket check. All originals returned zero findings and matched
the retained anchor/checkpoint hashes; deleting a middle record was rejected in
every profile. The [offline receipt](evidence/c683134/genuine-agent-offline-local.json)
records binary/source hashes and 993 / 307 / 930 kernel events respectively.
This local replay is independent execution, not independent administrative custody.

## Complete CI and security scope

All eight configured workflows completed for runtime `c683134`: **22 successful
jobs, zero failed jobs and three gated skips**. Ordinary PR jobs checked out
merge commit `d550820723cc3af85bae2fb0556e425f4208e7c1`; the genuine AI and
full-sensor jobs explicitly checked out the runtime head. The exact matrix is in
[functional CI results](ci/c683134-results.json) and
[security results](ci/c683134-security.json).

| Completed check | Result |
| --- | --- |
| Workspace debug | 3,329 passed, zero failed, seven ignored |
| Workspace release/performance | 3,331 passed, zero failed, five ignored |
| Doctests, each profile | Two passed, zero failed, two ignored |
| Coverage execution | 3,329 passed, zero failed, seven ignored; 82.9259% lines |
| Formatting and workspace Clippy, warnings denied | Passed |
| Fatal sensor-read and poisoned-sensor-set regressions | Both passed in debug, release and coverage |
| Original g14_04 CannotProve release regression | 20 repetitions passed; assertions unchanged |
| Installer packaging | 36 passed |
| Python SDK / real-agent contracts / OPA-OTel controls | 76 / 138 / 21 passed |
| RED adversarial ledger | 43 reproduced, ten blocked, two notes; blocked cases are not passes |

These suite counts overlap where workflows rerun packages; do not add them into
one unique-test count. Component and ignored-test scope remains in the matrix.

All four Security jobs passed. Exact PR history scanning covered all 48 ancestors
in the base-to-head range (46 nonmerge diffs and two merges), followed by an
independent full working-tree scan; both found zero issues. The scanner no longer
uses a truncated API history page. Ten real-engine controls include a 40-commit
history regression and positive credential detection alongside exact proven
nonsecret exceptions. A previous local scan using first-parent/no-merges was
incomplete and has been superseded by the full-ancestry result.

Chrono was removed and rustix updated to 1.1.6. Cargo audit/deny passed with 312
dependencies under the **existing RUSTSEC-2026-0097 exception**; no new advisory
waiver was added. Trivy found zero current HIGH/CRITICAL results. The unsupported
Kubernetes host-probe option now refuses rendering; its historical insecure
render remains byte-identical inside a clearly nondeployable archive. Historical
source-hash exceptions are limited to independently recovered exact bytes and
field/path matches, with credential-positive controls; signed records and
original inventories were not modified.

A broader local scan of all **423 ancestors of c683134** still reports **one
historical github-pat finding** at `aip-standalone/aip-aibom/tests/discovery.rs:12`
in commit `9f1b5e407b88b6a3a6d925746052e49f722678ff`. It is a hardcoded parser/redaction
test value, and current source already uses an unmistakable noncredential.
Available origin and offline checksum evidence support synthetic intent but do
not conclusively establish issuance history. No provider exception, credential
network test or history rewrite was used. This remains an unresolved security
finding; green PR CI is not a clean all-history result. Security-owner provenance
or revocation confirmation is required to close it safely. The local check is
scheduled-mode HEAD ancestry, not a claim that every repository ref was scanned.

## Exact remaining pilot requirements

1. A reachable **separately administered Linux collector**, with its connection
   or runner configuration name and approved access-secret names. Its operator
   must exclusively control signing keys, passphrase delivery, durable continuity
   storage and independently retained public checkpoints. A second UID or another
   GitHub runner under the same administrator does not meet this requirement.
   Current discovery found zero registered self-hosted runners, no repository
   secrets and no local SSH configuration. The user's acknowledgement supplied
   no collector configuration. Secret values must not be placed in chat or evidence.
2. A fresh selected/unselected **genuine customer workload across those hosts**,
   with authenticated outages, unchanged replay, probe and collector restarts,
   independent anchor/checkpoint approval and network-disabled verification.
   Neither of the separate disposable captures above closes this combined gate.
3. Persistent customer-host qualification: actual power-loss/reboot recovery,
   storage failure/corruption/queue-full behavior under the installed service,
   long-duration sensor loss and overhead, capacity and receipt-retention limits.
   Component tests do not establish these host-level properties. The current
   one-million-receipt limit, manual process reenrollment and unsupported automatic
   archive/key rotation remain operational limits.
4. Customer security-owner acceptance of broad read access and the required
   capabilities, and resolution of the remaining historical provider finding.
   Disposable activation is not authorization for customer installation.

Agent Zero image/tool component checks make zero model calls; its genuine-task
job remains gated. The separately dispatched Qwen Linux/offline jobs are also
skipped in ordinary PR CI. These checks do not validate all three open-source
agent integrations. No production approval, independent audit, customer
acceptance or customer pilot completion is claimed.
