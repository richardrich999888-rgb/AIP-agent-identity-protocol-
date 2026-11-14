# P0-050 S2 sandbox refusal and CI integration

12 November 2026. **Bounded repair accepted: local, teaching and full workspace CI pass.
Separate Security workflow fails; release NOT READY.**
Source: `6764c7eb38fa3c5cb0d9884303b14c1cd422d6ad` on the approved
`feature/airon-teach-demo`, draft PR #21. No main merge or force push.

## Selected item and acceptance

Read the previous replay checkpoint and fetched current AIP branches. The
next item was S2's teaching-branch sandbox/CI discrepancy. Reviewed the actual
PR #16 at `c39fc1f0431ddfaffa2d62199874e18e92087969`, its diff and historical
runs before installing scoped build tooling. Current OVERLAY branch metadata
was refreshed; no OVERLAY implementation or missing historical commit was
reconstructed or tested. This is one bounded integration, not completion of S2.

Acceptance: real authorized stdout; only loopback inside the network namespace;
a genuinely changed exit rejected; unavailable namespaces refused before
one-shot consumption; environment/timeout tests require actual execution;
no ignored sandbox cases or relaxed authorization/signature assertions; fresh
public-material evidence verification. The existing 12/26 teaching gate must
remain intact. Full CI is a separate acceptance condition, not inferred from a
focused test pass.

## Defect and minimal change

Parent `62db903` full CI `43175595162`, quality job `131038984856`, failed the
three documented sandbox tests. Full decoded logs are retained losslessly in
`baseline/quality-job.log.gz`. That was a fresh provider inspection of a prior
run, not a new baseline CI run.

A fresh local red test used `/bin/false` as a refusing launcher. Before the
repair it returned a signed `Code(1)` record despite no tool execution. The
regression exited 101 as expected (`local/baseline-refusal.*`). This controlled
launcher reproduction does not pretend to reproduce AppArmor locally: this
local host has no userns AppArmor sysctl.

The PR #16 readiness probe uses the same namespace flags, empty environment and
workdir as the tool launch. A failed probe now returns `SandboxUnavailable`
before replay consumption or signing. The runner rechecks authority expiry and
program bytes after the probe. Two regressions expire authority or replace the
program during that interval and require refusal without consumption. The
deadline test requires a real startup marker plus SIGKILL; the empty-environment
test requires exit zero. No cryptographic thresholds changed.

The old exit tamper test changed an already-failed `Code(1)` into `Code(1)`.
Identical signed bytes were correctly accepted. This was false runner attribution
and an ineffective mutation under failed setup, not a signature bypass.

PR #16's global AppArmor sysctl disable was **not** integrated. On disposable
GitHub-hosted CI only, `with_cgroup.sh` adds a temporary `/usr/bin/unshare`
AppArmor `userns` profile, runs the delegated cgroup/userns checks as uid 1001,
removes its profile on ordinary exit/signals, and asserts the host restriction
stayed unchanged. It never replaces an existing profile. Local/self-hosted
policy remains operator-configured. SIGKILL cannot run shell cleanup; this
policy mechanism is for disposable CI only, not a production deployment.

Primary rationale: Ubuntu's [restricted user namespace explanation](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces)
and [AppArmor design specification](https://discourse.ubuntu.com/t/spec-unprivileged-user-namespace-restrictions-via-apparmor-in-ubuntu-23-10/37626).
These sources justify evaluating an application profile; the retained job log,
not the documentation, proves that this job actually used and removed it.

## Fresh results

| Check | Observed result | Original evidence |
|---|---|---|
| Baseline refusing-launcher regression | Expected failure, exit 101; signed false tool-exit record returned | `local/baseline-refusal.*` |
| Initial integrated sandbox suite | 23 pass, zero failed/ignored | `local/sandbox-regression.*` |
| Final scoped Rust suites | 289 pass: 187 runtime + 76 sovereign unit + 24 sandbox + 2 SQLite; zero failed/ignored | `local/scoped-regression.*` |
| Formatting and scoped Clippy | Pass, warnings denied | `local/format.*`, `local/final-format.*`, `local/clippy.*` |
| Live local CLI | Authorized echo output digest matches; ungranted tool denied; original bundle verifies; one-byte exit and wrong anchor rejected | `local/cli-original/`, `local/cli-evidence.*` |
| Published-source teaching CI | 289 Rust and 197 focused Python pass; all 24 sandbox tests run as uid 1001 | `ci/teaching-job.log`, run `43212899727` |
| Hosted AppArmor boundary | Temporary profile loaded and removed; global userns restriction stayed 1 | Same full job log |
| Frozen teaching acceptance | Holdout 12/12, attacks 26/26, frozen nonactivation 6/6 subset; rejected copied-plural controls retained | `ci/original/exclusion-evidence/` |
| Downloaded runner packet, separate local build | Original verifies with public material only; one-byte tamper and wrong key reject | `reverified-final/`, `local/downloaded-evidence-final.*` |
| Downloaded signed teaching packet | OpenSSL signatures plus native replay: all 38 outcomes pass | `reverified-final/teaching-replay/` |
| Security | Four unchanged HIGH findings remain; no suppression/deletion | `ci/trivy-original.zip`, `ci/trivy-original/`, `ci/trivy-job.log` |

Counts overlap: do not add local and CI totals or count the six-case subset twice.
The five extra sandbox tests relative to the parent are three reviewed PR #16
probe controls and two new post-probe authority/program controls. Rust source
comments were clarified after the local suite; hosted CI used the complete
published tree. The original local binary and fresh published-source verification
builds have separate retained hashes. No original record was regenerated. The final documentation checkpoint also
clarifies that the shared wrapper's cgroup prerequisite belongs to separate
workspace containment tests; the namespace runner does not enforce cgroup limits.

The first downloaded-evidence helper attempt verified the three runner cases
then failed on the wrong public-key JSON field and a missing `/sys/class/net`
in this mount namespace. The failed helper snapshot, log and partial outputs
are retained (`verify_download-attempt1.py.txt`, `reverified/`,
`local/downloaded-evidence.*`). The correction uses the inspected synthetic
expert key pin and `/proc/net/dev`; it does not alter acceptance data.

## Source, archive and host provenance

Published source and CI merge `b5731ecbad0857a8014d13b15f1f07702b66acba` have
identical tree `56ec58a2773556bfd6a26c6643913aa9bb43ca09`.
`source-publication.json` and `ci/merge-commit.json` retain provider metadata.
The complete teaching artifact is `ci/teaching-original.zip`, artifact
13941019172, SHA-256
`9616c688579d411080e9303f1b427b806f7bfb607200217f3608ef7765094dec`.
It was hash checked before safe extraction, and its original members are
retained under `ci/original/`. Hashing gives integrity, not independent custody.

Local host: uid 1000, Linux 6.18.57 x86_64, AMD EPYC 9V74, 9 available logical
CPUs, reported MemTotal 10,206,472 KiB; no swap. These are reported host resources,
not reserved hardware. CI: uid 1001, Linux 7.0.0-1017-azure x86_64, 4 CPUs.
Exact tool versions, commands, measured command durations, host details and
binary/source hashes are in `local/host.json`, command receipts and CI logs.
No throughput/scalability benchmark is claimed from these timings.

Rust/Cargo 1.99.1 was installed in a task-local directory only after source and
manifest review. Official component hashes and licence-file hashes are in
`toolchain/toolchain-provenance.json`; the manifest pin and bootstrap commands are
retained alongside it. Product Cargo dependencies and lockfile are unchanged. The recorder
uses Python stdlib and existing native Ed25519 verification; no new runtime
signature algorithm, package requirement or licence change. CI still resolves
existing floating action/toolchain references; a fully pinned air-gap supply
chain remains an open kit requirement.

Initial dependency acquisition and CI were connected. Subsequent local Rust
checks used `--locked --offline`. Post-download verification ran in a fresh
network namespace: only loopback and no external route in
`reverified-final/commands.json`. This is a bounded no-network verification run,
not a fresh-machine offline installation, independently administered host
firewall proof or a qualified initial-network-namespace sensor deployment.

## Reproduce and interpret

Use a trusted build of source `6764c7e` with prerequisites already staged:

```sh
cargo build --locked --offline -p vanian-sovereign -p syntriass-runtime --bins
cargo test --locked --offline -p vanian-sovereign -p syntriass-runtime
python3 validation/ci/record_sandbox.py --binary target/debug/vanian --out /tmp/NEW-sandbox-run
```

For the retained CI original, independently authenticate `public.json` before
relying on its identities. This trial pins its SHA-256 as
`f203443e3abe7d0b12ff57b0a8bc51722f0fc56112167b72a1b8292f6c4b32d1`.
Then run `vanian verify --public .../public.json --bundle .../authorized.json`.
Expected: `AUTHORIZED_AND_RUNNER_ATTESTED`, independent observation
`CannotProve`. `tampered-exit.json` and `wrong-public.json` are separate attack
copies and must exit 1. Exact replay commands are retained; `verify_download.py`
can rerun the downloaded checks into a new directory with a separately built
`vanian` and `syntriass`. It pins this synthetic packet, not general expert trust.

## Unclosed boundaries and next item

A successful readiness probe does not attest the subsequent launch. Namespace
setup or exec can still fail afterward and be mistaken for the tool's exit.
Per-launch acknowledgement is **OPEN**; add a deterministic probe-success /
launch-failure regression before selecting its smallest defensible repair.
Also open: executable hash-to-exec race, filesystem confinement, CPU/memory
limits, wall-clock/launcher failure handling, independent observer and key
custody. A process binding is not proof of an in-process logical agent.

No native Sniffer Dog sensor was rebuilt or run in this item. These signed
bundles are runner evidence, not complete kernel-observation archives. No model,
expert-authenticated approval, knowledge pack, commercial show, clean-machine
kit install, pilot readiness or enterprise qualification is established.
Full-mode rehearsal counts remain zero. Keep PR #21 draft.

Next bounded item: reproduce and close the per-launch acknowledgement gap;
then classify the four retained-render Trivy findings without erasing historical
evidence or disabling the sensor. The broader S2 workstream remains PARTIALLY
VERIFIED. All other product gates remain in `P0-050-OPEN-GAPS.md`.

## Existing excluded and blocked coverage

No sandbox test is ignored. Broader job success does not mean every security
scenario executed. `ci/red-job.log` explicitly retains ten BLOCKED ledger rows:
OI-01 through OI-06 need CAP_BPF/CAP_PERFMON and tracefs; OI-08 is deferred;
OI-13 through OI-15 need root/CAP_BPF/tracefs. They are not fresh detections.
The RED job verifies its runnable ledger subset only.

`ci/postgres-job.log` records 14 storage controls ignored in the ordinary pass
and then **14/14 executed successfully** with the explicit restricted-role live
DB command. The 10k database benchmark and three real HTTP/SDK/MCP integration
checks remain ignored in that job for their documented environment/explicit-run
requirements; no performance or real-framework acceptance is inferred.
Full workspace debug: **3,593 passed, 0 failed, 10 ignored**; release:
**3,595 passed, 0 failed, 8 ignored**. Coverage: **3,591 passed, 0 failed,
8 ignored**, excluding doc tests. `ci/test-summary.json` preserves the exact
ignored rows. These are overlapping configurations, not 10,000 distinct cases.

The eight ordinary ignored cases are two output-generation helpers, one observer
throughput measurement, two crypto throughput gates and three real HTTP/SDK/MCP
checks. Both crypto throughput gates execute and pass in release, leaving six
ordinary ignored cases there. Two additional ignored doc snippets use incomplete
usage context (`aip-execution/src/profile.rs:202`) or a nonproduction
`test-fixtures` example (`aip-reconcile/src/result.rs:767`). They are examples,
not security acceptance tests. No new ignore was added by this integration.
Remaining explicit-run integrations/measurements and blocked kernel rows are
not credited as passes.

## Final source CI snapshot

All runs below are completed for source `6764c7e`; provider metadata is retained
in `ci/source-runs-final.json` and job snapshots.

| Workflow | Run | Result | Material scope / limit |
|---|---:|---|---|
| Full CI | [43212899569](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43212899569) | PASS | Formatting, workspace/all-feature Clippy, debug and release tests, coverage, dependency audit/deny, SDK, PostgreSQL and runnable RED ledger; exclusions above remain explicit |
| Teaching scoreboard | [43212899727](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43212899727) | PASS | 289 Rust, 197 Python; frozen 12/26, signed CLI packets |
| Harness contracts | [43212898869](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43212898869) | PASS | Component contracts; no live framework-task success claim |
| Security | [43212899116](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43212899116) | FAIL | Trivy KSV-0009/0010/0118/0121 in retained `HELM_20261028T103133Z/template-enabled.yaml`; cargo audit and secret scan pass |

`ci/quality-job.log.gz` retains the complete decoded debug/release job log. Both
passes run the 24 sandbox cases and each removes the temporary profile, retaining
userns restriction 1. `ci/coverage-job.log.gz` shows the same cleanup and 24-case
coverage run. `ci/coverage-original.zip` is the untouched 443,365-byte artifact,
SHA-256 `da71af06031be874cf18b46f9e8563a65bbbdb9d87dc19444efe8c8f3469cf42`;
its member hash is in `ci/coverage-members.json`. The retained Trivy ZIP is
SHA-256 `fc00cadafcce5d6410b6dadc1c6805cb2dae84e5a596200d2b1189a022a30029`.

The evidence change adds no runtime, test, workflow or recorder changes to its
actual parent. A concurrent `5bc0c5f68690e5d2656716a97c2cfbb2ce105e08` teaching
scoreboard commit arrived after `6764c7e` while publication was prepared. The
initial ref update returned a provider error; a fresh head inspection detected
that concurrent commit. The checkpoint was reapplied on top without conflicts,
force-push or overwriting it. Its teaching harness/workflow changes are preserved.
The four S2 runner/test/recorder/wrapper files still match the tested `6764c7e`
bytes, but the complete final tree differs. Source CI results above are not
relabelled as final-tree validation. The concurrent teaching run `43215328974`
was observed completed/success, while its full CI was pending. Final-head CI
is inspected separately; pending checks are not passes.
