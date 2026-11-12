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
two missing live archives. Those results stay blocked locally. They will only be
qualified on the external host after the ten assertions and archive checks pass.

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
