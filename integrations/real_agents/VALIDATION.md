# Validation record — original 2026-10-28, updated 2026-10-29

**Assignment incomplete.** The third actual attempt at e4cd07d (40857993677)
made six model requests but exceeded 900 seconds, produced no patch and has
unestablished final coverage/task acceptance despite valid archive signatures.
Its underlying framework/model cause is UNKNOWN. Agent Zero's second attempt at
7625b1d (run40854020439) made five real model requests. Its original signed
archives/checkpoint verify and cover the task, including a bound file event,
but no bound successful ProcessExec or patch was produced. Its retained
framework log records five unusable plain-text responses before stopping.
The first failed attempt remains preserved separately. DeerFlow and OpenHands
remain unexecuted; no framework-swarm or institutional-pilot advancement is
claimed. See [latest original evidence](../../validation/enterprise/results/AGENT_ZERO_40854020439/summary.json)
and the [integration register](../../docs/enterprise/END_TO_END_VALIDATION.md).
Historical checks below retain their original dates and scope.

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
and the original implementation file-hash snapshot are in [checks](checks/).
Subsequent executions below are identified by immutable commit and CI run; the
original hash snapshot is historical, not a claim about later files. Historical archives
and their reported limitations were not rewritten. The user's original dirty
checkout was not changed.

## Executed checks

| Check | Result and scope |
| --- | --- |
| Portable Rust observer, verifier, protocol, reconciler, corroborator, sentinel-feed, feed-conformance and OT sentinel suites | **701 passed**, 2 explicitly ignored. Includes unit/integration/doc tests. Linux-specific cfg-disabled tests are not live passes. |
| New harness policy, audit and import-mutation tests | **37 passed**. Ordinary unit fixtures, not execution evidence. |
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

## Current CI and container follow-up

The reported release failure at `f025a57` is confirmed in
[run 40651335714](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40651335714):
`g14_04` returned `IdentityDivergence` while its debug run returned `CannotProve`.
The idle path had no child-readiness handshake, unlike the other scenarios.
It now waits for userspace readiness before independently measuring the binding;
no identity, signature, coverage or reconciliation predicate was relaxed.
The test additionally requires matching identity and `ActionEvidenceUnavailable`.
The offline verifier helper now builds the same profile it executes, fixing its
previous debug-build/release-binary mismatch.

The original failing log omitted the differing identity fields. The longer
[diagnostic at c980449](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40676428606)
reproduced the race **38 times in 4,096 release starts**: before readiness,
`/proc/<pid>/exe` identified the parent test executable; after readiness it
identified `ghost-demo-agent`. PID, start ticks and boot ID stayed the same,
but the executable hash changed. The reconciler's `IdentityDivergence` was
correct for that raced binding. All post-readiness identity checks, the genuine
wrong-instance negative case, and 20 repeated release `g14_04` tests passed.

This is consistent with the Linux/glibc spawn path: Rust uses `posix_spawn`,
glibc waits for vfork completion, and Linux signals that completion before
switching the task's memory mapping during exec. Sources:
[Rust 1.99 spawn](https://github.com/rust-lang/rust/blob/1.99.0/library/std/src/sys/process/unix/unix.rs),
[glibc 2.39](https://github.com/bminor/glibc/blob/glibc-2.39/sysdeps/unix/sysv/linux/spawni.c),
[Linux exec](https://github.com/torvalds/linux/blob/v6.17/fs/exec.c),
[Linux vfork completion](https://github.com/torvalds/linux/blob/v6.17/kernel/fork.c).
The handshake closes that measurement boundary without trusting a child-supplied
identity or changing the evidence comparison.

[Complete CI at 5489260](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40672365945)
passed all six jobs: fmt/clippy/debug/release workspace tests, PostgreSQL,
Python SDK, RED suite, audit/deny and coverage. `g14_04` passed in both profiles.
Later commits rerun the same complete suite; PR checks identify their status.
The main job logged 6,434 passing tests across both profiles and 12 ignored
test instances; these totals include crate integration and documentation tests.

[Hosted build/capability run at 75d349f](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40675095033)
passed all three jobs: release regression, Agent Zero image/runtime smoke,
and actual kernel/collector/audit capability testing.

- Agent Zero source: `ff2a5b9c9c4e490ba38dd7c313e779510bb2071a`.
- Tested image: `sha256:be627589ed4929bb88dc515ce1d94b5b4e3da6207af99bcfd2c88a2132676c7c`.
- 314 installed packages checked. Actual upstream context initialization and
  local terminal file creation passed with networking disabled, UID 10001,
  no capabilities and a read-only root filesystem. **Model calls: 0.**
- [Image artifact](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40675095033/artifacts/12809694755):
  1,593,329,137 bytes, GitHub artifact SHA-256
  `45fb373ad6ed583f74c65227d19c6c6ba9d31666608c45abd0588aef2256093b`,
  retained for 14 days. Includes the tested image, image metadata, dependency
  inventory and smoke output. No model secret was present during build.

Earlier image builds succeeded but runtime checks exposed a read-only-filesystem
assertion, missing upstream state directories, attempted root-password setup,
and an uncached tokenizer. These were repaired while retaining the sandbox.
The first workflow falsely reported success because a pipeline masked the smoke
failure; explicit bash pipefail now makes it fatal. That first green workflow
is **not** counted as a successful runtime check.

## Real hosted kernel evidence, distinct from an agent workload

The capability run used Linux `6.17.0-1022-azure`, synchronized clocks, the real
probe/Noise transport/wrapped-key collector, and real Linux audit. It preserved
49 signed batches, 968 kernel events, and three signed health records; two
health records carried Active coverage and the initial record did not.
Worst reported clock error was 3,021 microseconds. The component interval was
`1793184659333..1793184661349` ms. Audit recorded no loss, backlog or restart.

The exported archive passed the existing Rust verifier on the runner and again
in a separate local process after download, with **zero findings**. The
observer public anchor was
`056b2697da3bc105efd8593cb7cc0d6690885e5cdfcd1e7f3ac5f72120bfe3d4`;
final chain head was
`fdf15ce9ec7482ed7ba6cca4eace73d2d972f315294c61dbf243995c73f7244e`.
Seven offline mutations were detected with the separately retained checkpoint;
five were also rejected by the signature/chain verifier. Valid prefix/suffix
windows still require the independent checkpoint for completeness.

[Public evidence artifact](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40675095033/artifacts/12810321073)
SHA-256: `a6e5384d715f0f4987e70fb5820df8779bf2886cc34e71b44bcac42d38182991`.
This is an ephemeral CI key under GitHub-host custody, not an institutionally
provisioned anchor. There was **no autonomous model-driven workload**.

A local corroboration of the first component run found one PID/time agreement,
one additional AIP exec and zero external-only records: the UID-changing
`setpriv` wrapper produced two same-PID execs but audit filtered out its root
exec. This is recorded as a comparison limitation, not complete agreement.
The follow-up test directly starts the child as UID 10001 and requires explicit
corroboration without an unmatched workload exec. At `c980449` this stricter gate
correctly failed: audit stamped the actual sleep exec at `1793185273022` ms,
AIP at `1793185273025` ms, but the declared interval began at `1793185273023` ms.
The external event was excluded by the unchanged interval filter. The next
revision establishes the interval before a one-second pre-launch guard and
ends it after a one-second post-exit guard; signed coverage must include both.
It neither changes captured timestamps nor relaxes matching tolerance.

The audit parser also now accepts the rule's x86-64 `execveat` (322), in addition
to `execve` (59), and exposes unsupported architectures as unparsed. Failed
attempts remain failed. Source: [Linux syscall table](https://github.com/torvalds/linux/blob/v6.17/arch/x86/entry/syscalls/syscall_64.tbl).
The fresh hosted run, rather than retrospective changes to old archives, is the
acceptance check for these corrections.

## Historical per-framework record — before the 2026-10-29 attempt

| Framework commit | Model/task | Agents/processes/effects | Result |
| --- | --- | --- | --- |
| Agent Zero `ff2a5b9c9c4e490ba38dd7c313e779510bb2071a` | Approved model credentials unavailable; genuine Click issue 3652 task prepared | Not executed; all counts unknown | Image and offline runtime/tool smoke passed; autonomous integration blocked |
| DeerFlow `f79debed59ca6b1a31628e6b5ce55c8507793a4c` | Model unavailable; same task with subagents enabled | Not executed; all counts unknown | Source/API inspected; launcher written; multi-container deployment unimplemented |
| OpenHands SDK `46b1fa5cb91ada17e6ec938c7e8624a4fa19fa98` | Model unavailable; public Click issue 3652 prepared | Not executed; all counts unknown | Source/API inspected; launcher written; issue resolution unexecuted |

At that historical checkpoint no new signed execution archive existed for
these frameworks. The later Agent Zero archive and failed acceptance are now
retained above; no accepted patch, authenticated logical delegation or framework
swarm validation is established by that attempt.

## Original limitations and subsequent acceptance status

1. **Model and network provisioning:** GitHub reported zero repository secrets
   and zero environments on 2026-10-28. Approved restricted model credentials,
   exact model/endpoint configuration, hard budget enforcement and tested
   restricted egress are not supplied. These block credentialed remote-model tasks. A later zero-credential public
   CPU model attempt executed but failed acceptance; it did not establish this
   remote-model configuration. SSH details are unnecessary for initial hosted
   integration. See [HOSTED_VALIDATION.md](HOSTED_VALIDATION.md) for exact needs.
2. **Runtime installation:** Agent Zero built and its offline runtime check
   passed. DeerFlow and OpenHands images have not built or run. Agent Zero's
   transitive requirements are not fully locked upstream; the tested image
   and package inventory are retained as an artifact.
3. **Custody and provisioning:** hosted component checks use a fresh wrapped
   key outside the workload's reach. Institution-owned keys, independent
   retention, gateway budget controls and workspace quotas remain to provision.
   Explicit local-isolated mode trusts host root/kernel; the default off-host
   mode continues to reject a same-machine collector.
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
7. **Degradation:** the actual five-act RBI rehearsal passed, including
   interference/uncertainty and recovery. No degradation experiment has yet
   run during a genuine third-party autonomous workload.
8. **Performance:** bounded resource sampling exists, but observer CPU/RSS,
   ingestion rate, collector latency, reconciliation latency, storage growth
   and matched observed/unobserved agent-task overhead are not measured.
9. **Coverage:** Linux audit avoids attaching a foreign program to the
   monitored tracepoint. Both still trust the kernel. Complete ground truth
   and real-agent comparison remain open; no complete-coverage percentage is
   reported. Nested/unshared workload namespaces can remain unknown.
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
flow preservation. The actual hosted RBI rehearsal also passed at `5489260`,
`3e15d31` and `0773e09`; these remain controlled demonstration results.

The next gate is the genuine Agent Zero Click task using approved restricted
model credentials, tested egress/budget enforcement, and independent task
review. Then execute DeerFlow and OpenHands, delegation/research/browser,
concurrency, workload degradation and performance gates. Keep PR #6 in draft.

The current engineering status, including the complete local-isolation core
LangGraph path and the later failed Agent Zero attempt, is recorded in
[END_TO_END_VALIDATION.md](../../docs/enterprise/END_TO_END_VALIDATION.md).
The original branch-discovery and component test history above is preserved.
