# P0-048 — removing native-test host blockers

Iteration 004. Parent: `9e7e9eec13f58a2b7689b66ca1e76ff65fb8bc8d`.
Selected single item: execute the nine previously blocked native checks and the
BPF verifier check on a capable disposable host, with strict result accounting.
The user's current request prioritizes blockers over the earlier planned image-read
race item. No production observer or verifier predicate is changed by this item.

## Acceptance

All ten exact native tests must execute their assertions and pass, with no ignored,
missing, filtered-out or early-return substitute. Retain exact commands, original
output, source and executable hashes, actual host/kernel/capabilities and fresh
signed originals. Verify the short-lived-process and event-loss archives through
the separate native offline CLI. A missing archive or failed signature prevents
qualification. A timing benchmark is separate from these security assertions.

## Mechanism

[The dedicated workflow](../../.github/workflows/p0-048-native-qualification.yml)
uses a GitHub-hosted Ubuntu 24.04 VM, never a self-hosted runner. It is limited to
same-repository PRs or explicit manual dispatch, uses read-only repository
permissions, and does not retain checkout credentials. It mounts tracefs only in
that disposable VM and runs already-built tests with the needed host privilege.
No local workspace restriction, kernel sysctl or production enforcement is changed.
The XDP tests use test-run syscalls and never attach a program to an interface.

[The runner](../../validation/p0_048/native_qualification.py) reads Cargo's actual
executable manifest, checks source paths and required cases, and launches each
exact test serially with a deadline. `SKIP`, `UNAVAILABLE`, missing private fanotify
mounts, zero matching tests, ignored tests, timeouts, missing results and nonzero
exits cannot become PASS. The result records the distinction between BLOCKED and
FAIL. It does not reinterpret a skipped test as proof of sensor behavior.

Only optional retention was added to the existing process-capture and event-loss
tests. The originals are signed by their existing synthetic fixture collector;
the private key stays in memory. Their host observations are real, while their
claimed wall-time windows remain fixture values. This does not establish a
production execution verdict, full coverage or independently administered custody.
The loss archive must retain the collector's degraded state and absent coverage.

Compiler/component downloads are checked against the already audited version and
hashes before extraction or installation. Each component's own licence files are
hashed; Cargo's licence text differs from the compiler's text. Checkout and upload
actions are pinned to immutable revisions. [Pins and licences](../../validation/p0_048/native_ci_pins.json)
also state that the hosted VM image itself is measured, not reproducibly pinned.
This is evaluation infrastructure, not an air-gap runtime installer.

## Local results and hosted evidence

The qualification gate's 15 positive/negative tests pass. The actual restricted
workspace run correctly returns exit 1 for nine BLOCKED cases, one BPF FAIL and
two missing live archives. Those results remain blocked locally.

The [dedicated hosted run](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43167021649)
passed **all ten exact native tests**, without skips, at source
`ea5fe9e9ad10da0b490b411afc9f757e01259c73`. Both archive checks also passed.
The actual host was Ubuntu 24.04.5, x86_64, kernel `7.0.0-1017-azure`, image
`20261101.360.1`, with root capabilities and the VM PID 1 network namespace.
This resolves these ten environment-dependent qualification gaps on this host;
it does not make the restricted workspace capable of those kernel operations.

| Native assertion | Executed result |
|---|---|
| Exec sample carries the task's cgroup ID | PASS |
| Fanotify binds a live writer through its kernel pidfd | PASS |
| Exited fanotify writer remains unbound | PASS |
| Kernel loads/runs the XDP parser without attaching it | PASS |
| Kernel verifier refuses the unsafe BPF program | PASS |
| Connector captures a short-lived process | PASS |
| Connector delivers exec replacement | PASS |
| Real connector loss degrades health and removes coverage | PASS |
| Loopback send records the sender PID and byte count | PASS |
| Loopback packet capture records kernel timestamps and loss counters | PASS |

The 19,870-byte original provider ZIP is retained alongside extracted bytes.
Its SHA-256 matches the provider's published digest:
`cd0e919510fc5922de8638dacf98d11e22d82e84f6d6e5c1c3a8890ac1cca29c`.
Local re-verification checked all 19 entries in the native evidence manifest and
nine recorded source hashes against both the tested commit and current files.
The hosted checkout was clean. `GITHUB_SHA` records the PR's synthetic merge ref;
the workflow deliberately checked out and measured the exact head above.

Six local offline CLI checks pass: both originals are accepted; one-byte-modified
copies and a different valid public trust anchor are rejected for each archive.
The short-lived-process archive contains three kernel events, with
`ContinuityUnverified` health and no coverage. The loss archive records a dropped
event, `Degraded` health, and no coverage. Signature acceptance does not upgrade
either archive to a VERIFIED execution verdict.

The first local tamper setup aborted before invoking the verifier because it
incorrectly required the probe ID to occur only once. Kernel events repeat that
ID. The helper now changes exactly one byte in the first occurrence of a copy;
three regression controls cover unique/repeated IDs and refusal of a missing
target field. The initial failure and successful rerun are both retained.

Local sensor regression reported 95 successes, of which 92 actually executed and
three were blocked connector checks. Those three were executed separately in the
hosted gate; overlapping suites are not summed. Workspace formatting and scoped
all-target Clippy with warnings denied pass.

## Separate timing observation

The previously ignored throughput test was explicitly executed in release mode
and passed once. It measured 2,000 small synthetic batches after 100 warmups on
kernel `6.18.57`, nine visible CPUs, AMD EPYC 9V74. Offline verification measured
21,948 batches/s (mean 45.6 microseconds; p50 36.5, p95 86.9, p99 121.9).
This is an in-process component timing measurement. It excludes sensor sampling,
transport and archive storage, and establishes no capture rate, false-negative
rate, concurrent-agent capacity or supported host count. The legacy benchmark's
printed host-capacity extrapolation is not a measured or accepted result.

Exact results, including any hosted failure and subsequent correction, are in
[iteration-004](../../validation/p0_048/iteration-004/README.md). Native source checks
and the strict gate's checks are different evidence and must not be added together
as a count of kernel assertions. A successful component run cannot establish a
framework task, independent administration or full enterprise acceptance.

## Other blockers

At the parent head, full CI (including debug/release, coverage upload and database
checks), same-run assurance with artifact upload, RBI rehearsal and harness
contracts have now completed successfully. Their provider receipts supersede the
previously pending status; this does not erase historical failed artifact uploads.

The existing Gitleaks tokenizer-checksum matches and Trivy findings in retained
Helm output remain a separate open security-CI item. Historical evidence is not
deleted or rewritten. Separate collector administration, clean-machine air-gap
deployment, actual high-load attribution and final demo/release acceptance remain
unqualified. No certification or complete enterprise-readiness claim follows.

At the tested implementation head, the native gate, same-run assurance, RBI
rehearsal and harness-contract workflows passed. Full CI was still running when
the retained provider snapshot was taken. Security CI failed on the same two
tokenizer-checksum matches and four retained Helm findings (`KSV-0009`,
`KSV-0010`, `KSV-0118`, `KSV-0121`); the current SARIF and provider receipts are
retained. These results are not represented as a clean release gate.
