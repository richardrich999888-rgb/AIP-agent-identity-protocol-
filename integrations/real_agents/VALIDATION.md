# Validation record — 2026-10-28

**Assignment incomplete. Zero of the three new framework integrations has
executed under Sniffer Dog. No readiness-level, external-assessment or
institutional-pilot advancement is claimed.**

## Source baseline and branch discovery

Discovery covered all 11 advertised remote branches, 16 local/remote branch
references, 395 reachable commits, 3,450 distinct historical blobs and
1,158,501 text lines, including 705,435 code lines. This was an automated
content/inventory scan, not a manual security review of every line. The binary
inventory included nested/excluded Cargo workspaces and local compiled files.
No unidentified binary was executed.

The original OT sentinel is in `orbitaltrust-accountability/rust/ot-sentinel`,
on `import/orbitaltrust-accountability-layer` at
`6cc439f190161ba28e76d46cea1901de8dd527ea`. It reads JSONL sensor feeds and uses
hash-chained patrol records. It is not itself the Linux probe or an off-host
signer. The modern independently signed path is `aip-probe` → Noise transport
→ `aip-collector` → verification/reconciliation → `aip-sentinel-feed` → OT.

This branch combines:

- RBI safeguards at `0991fb1eed1234403c1ff9683d010797ea073d39`.
- Signed placement/attribution at `061cebc975d81c8126d5f66d96f5384d11be0620`.
- Merge commit `3a029ae` preserving both, with the CI conflict resolved to keep
  delegated cgroup execution, locked dependencies and independent test stages.

The new harness source and report are committed after that merge. Test logs
and the exact tested file hashes are in [checks](checks/). Historical archives
and their reported limitations were not rewritten. The user's original dirty
checkout was not changed.

## Executed checks

| Check | Result and scope |
| --- | --- |
| Portable Rust observer, verifier, protocol, reconciler, corroborator, sentinel-feed, feed-conformance and OT sentinel suites | **701 passed**, 2 explicitly ignored. Includes unit/integration/doc tests. Linux-specific cfg-disabled tests are not live passes. |
| New harness policy and import-mutation tests | **28 passed**. Ordinary unit fixtures, not execution evidence. |
| Existing RBI control-flow tests | **17 passed**. These exercise harness control flow, not the five live demonstrations. |
| Formatting and whitespace | Passed. |
| Complete workspace `cargo test --workspace --locked` | **Failed to compile on macOS**: `aip-placement` references Linux `libc::SYS_clone3`. The original RBI baseline also failed in Linux-only ghost-demo imports on macOS. No complete-workspace green result claimed. |
| Historical offline archive regression | Existing `collector.phase1` archive: two signed batches, 556 kernel events; signatures/chains accepted. Its one health record is `ContinuityUnverified`, has no coverage, and states an unsynchronized clock. It does **not** pass new real-workload acceptance. |
| Offline corruption tests | Existing nine-batch corroboration archive: modification, middle deletion, reordering, duplication and corruption rejected by Rust. Prefix/suffix deletion remained valid signed windows and was detected by the separately retained checksum. Seven mutations accounted for. |
| Original import integrity | Initially failed due to an existing RBI clippy refactor in `registry.rs`. The original manifest is retained; all three reviewed deviations are now pinned by full SHA-256. A further source mutation fails. |
| Selected issue baseline | Click `2247b35ea1c47c727d7a06e51fa280e12a863ff6`, issue 3652: a repeatable `--foo` option renders `--foo TEXT`, without an ellipsis. Reproduced locally; no solution was supplied to the agent task. |
| Linux preflight on this machine | Correctly blocked with exit 2: host is Darwin. No model request or workload started. |
| Local status interface | Browser displayed the actual blocked run and `assignment_complete: false`. `/` and `/status` returned 200; arbitrary file/log paths returned 404. No synthetic activity was rendered. |

The ignored Rust tests are `observer_path_throughput` (explicit release timing
measurement) and `emit_sample_bundle` (fixture generation). The approximately
0.02-second historical archive verification timing is a local regression
measurement, not observer overhead or agent-task performance.

## CI follow-up

The first PR run at `faf5ed0` passed the harness-contract, Python SDK,
RBI script-regression and RED-suite jobs. The PostgreSQL test stages passed,
but the job failed its strict lint stage: Rust 1.99 requires `as_chunks::<2>`
for the new placement-name parser. The parser was updated without a lint
suppression; its 11 existing tests and local strict clippy check passed.
The full Linux quality, coverage, supply-chain and live RBI jobs were still
running when this follow-up was recorded. They are not counted as passes.
See [the CI run](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40650571944)
and the PR's current checks for subsequent results. This does not change the
blocked status of the three new real-agent workloads.

## Per-framework execution record

| Framework commit | Model/task | Agents/processes/effects | Result |
| --- | --- | --- | --- |
| Agent Zero `ff2a5b9c9c4e490ba38dd7c313e779510bb2071a` | Model unavailable; public Linux documentation research task prepared | Not executed; all counts unknown | Source/API inspected; launcher written; image build and integration blocked |
| DeerFlow `f79debed59ca6b1a31628e6b5ce55c8507793a4c` | Model unavailable; same task with subagents enabled | Not executed; all counts unknown | Source/API inspected; launcher written; multi-container deployment unimplemented |
| OpenHands SDK `46b1fa5cb91ada17e6ec938c7e8624a4fa19fa98` | Model unavailable; public Click issue 3652 prepared | Not executed; all counts unknown | Source/API inspected; launcher written; issue resolution unexecuted |

No new signed execution archive exists for these frameworks. No live process
lineage, delegated logical-agent identity, tool receipt, independently accepted
patch, real research report or browser-navigation result is claimed.

## Limitations and remaining acceptance gates

1. **Infrastructure and access:** the user selected an existing Linux host,
   but its connection alias/hostname, user and restricted model configuration
   location have not been supplied. Docker is stopped locally, and no model
   API credential was available in this session. No guessed host was contacted.
2. **Runtime installation:** Docker images have not built. Source pins and APIs
   were inspected; additional upstream native/system dependencies or settings
   may require corrections after the first actual image build. Agent Zero's
   transitive dependency lock is incomplete upstream.
3. **Provisioning:** institution-controlled collector units/keys, probe trust,
   egress policy, model budget enforcement, image digests and workspace quotas
   must be deployed. The controller does not manufacture these trust controls.
4. **Attribution/authority:** adapters preserve self-reported framework records.
   Authenticated logical delegation and real decision/gateway receipt plumbing
   are not connected. Kernel attribution never identifies an in-process agent.
5. **Workload acceptance:** the runner deliberately ends `REVIEW_REQUIRED` after
   observation checks. Independent task acceptance and logical delegation
   remain open; no automatic green result is available for an unreviewed task.
6. **Concurrency and deployment coverage:** one controller runs one isolated
   container. Separate configurations/collector instances can be provisioned,
   but concurrent multi-agent experiments, multi-container DeerFlow sandboxes
   and native non-container Linux launches have not been implemented/validated.
7. **Degradation:** RBI control-flow regressions pass, but no new live observer
   degradation experiment ran. No new interference outcome is claimed.
8. **Performance:** bounded resource sampling exists, but observer CPU/RSS,
   ingestion rate, collector latency, reconciliation latency, storage growth
   and matched observed/unobserved agent-task overhead are not measured.
9. **Coverage:** bpftrace shares the scheduler tracepoint. Auditd comparison
   and independent ground truth remain open; no complete-coverage percentage
   is reported. Namespace selection can leave nested/unshared sandboxes unknown.
10. **Archive completeness:** signatures bind supplied records. Independent
    checkpoint custody is required for edge-deletion detection; a checkpoint
    supplied by an untrusted archive sender provides no such guarantee.
11. **Assessment and pilot:** no independent assessor or institutional pilot
    participated. Production/pilot approval is not established by local tests.

## RBI demonstration contracts

The existing five contracts and their scopes are preserved: authorized
execution; interference with uncertainty; unregistered destination refusal;
parameter mismatch detection; offline verification. Existing acts 3 and 4
include library-level checks and must retain that qualification; the newer
real gateway subcase remains distinct. The 17 tests above establish control
flow preservation only. Run the existing complete RBI rehearsal on its
authorized disposable Linux environment before claiming current live results.

The next concrete gate is a successful pinned image build and Agent Zero
delegated research run on the specified Linux infrastructure, with an off-host
collector and independent task review. Only then proceed to DeerFlow and the
OpenHands issue run, followed by concurrency, degradation and performance.
