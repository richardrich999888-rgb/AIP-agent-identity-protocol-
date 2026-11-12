# P0-048 checkpoint — iteration 004

Branch: `codex/p0-048-snifferdog-enterprise-assurance`.
Integration base: `fix/vanian-end-to-end-green`, `4d0ce1e32c8dedde4e3a930abc2becf1f56b864e`.
Parent: `9e7e9eec13f58a2b7689b66ca1e76ff65fb8bc8d`.
12 November 2026 (Asia/Kolkata).

All remote branches were fetched and the prior checkpoint/CI reviewed. The user
asked to remove blockers, so the single selected item is supported-host execution
of the ten native tests previously blocked by local kernel permissions.

## Acceptance

All ten exact tests execute and pass with no early-return, ignored or zero-test
substitute. Retain host/source/binary/log provenance and fresh signed originals
for process capture and event loss; verify them through the separate native CLI.
Keep the local restrictions and all product checks intact. Commit/push on the
approved branch, inspect actual CI, retain results, update this checklist and stop.

## Completed item

The strict runner and its 15 positive/negative controls are implemented. The local
restricted-host attempt correctly refuses qualification (nine BLOCKED, one FAIL,
no live archives). A pinned dedicated workflow prepares a disposable GitHub-hosted
Linux VM and executes the actual tests as root. Hosted acceptance **passed** at
`ea5fe9e9ad10da0b490b411afc9f757e01259c73` in run `43167021649`: ten executed
native tests, zero blocked/ignored, and two native archive-verification checks.
The original provider ZIP, logs, host/source/binary hashes and signed originals
are retained. Six local archive/tamper/wrong-anchor checks also pass, with no
upgrade of missing coverage. Three tamper-harness regressions pass after fixing
an initial setup assumption; the failed setup transcript remains available.

Local regression: 92 executed passes plus three blocked cases, never counted as
passed locally. Formatting and scoped Clippy pass. The separately requested
ignored throughput test was explicitly executed once in release mode; its timing
is a component measurement, not the high-load or concurrent-agent benchmark matrix.

The native product is unchanged. Only optional retention was added to two existing
live tests; original signatures and absence of coverage after loss are preserved.

- [Native host qualification report](P0-048-NATIVE-QUALIFICATION.md)
- [Iteration commands and evidence](../../validation/p0_048/iteration-004/README.md)
- [Prior checkpoint](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/9e7e9eec13f58a2b7689b66ca1e76ff65fb8bc8d/docs/research/P0-048-CHECKPOINT.md)

## Checklist

| Workstream | Current state |
|---|---|
| A — audit | Completed to the recorded structural and targeted-review scope |
| B — sensor correctness | Socket multiplicity and delayed connector-event/cache corrections complete; ten native kernel assertions now pass on the recorded disposable host; executable/descriptor consistency, namespaces, concurrent attribution and broader interruption qualification incomplete |
| C — SPIFFE/SPIRE | Existing adapter qualification and lifecycle/binding guarantees pending |
| D — OTel GenAI | Existing cross-branch telemetry and full GenAI correlation pending |
| E — Tetragon | Optional evaluation on a supported host pending |
| F — policy/gateway | Complete fresh negative matrix pending |
| G — frameworks | Full framework task acceptance pending; historical failures remain |
| H — custody | Fresh socket/lifecycle and live connector/loss signatures and tamper checks complete; independent administration and full custody matrix pending |
| I — air gap | Complete bundle and clean-host/firewall qualification pending |
| J — performance | Bounded churn and one explicit component timing run retained; required performance matrix pending |
| K — demo | Full retained nine-scene demo acceptance pending |
| L — release | NOT MET: full regression/security CI, clean installation, independent custody and ten full rehearsals remain open |

## Updated CI baseline and remaining gates

Parent 9e7e9ee's full CI, coverage upload, same-run assurance and artifact upload,
RBI rehearsal and harness contracts have now passed. Provider receipts are in
`iteration-004/parent-ci.json`. Historical failed uploads remain in their original
records; a current successful upload does not reconstruct an earlier missing one.

Security CI still reports the known tokenizer-checksum matches and retained Helm
findings. These are a separate item; this work adds no scanner suppression and
removes no historical evidence. Independent collector administration, clean-machine
air-gap deployment, broader attribution/load and final demo acceptance remain open.

## Next item

The native-host gate is complete for the recorded Linux environment. Stop after
publishing this evidence update and inspecting CI. The next single incomplete
item is security-CI finding classification and remediation while preserving
original archives and scanner coverage. No merge or production enforcement.
