# vanian-sovereign

The sovereign slice: a decision point that authorizes a tool call, a runner
that executes it inside Linux namespaces, and an offline verifier for the
signed evidence bundle that results.

## Test preconditions

The tool-sandbox tests in `tests/agent_execution.rs` run the **real** namespace
sandbox and fail when that facility is unavailable. The shared workspace CI
wrapper also checks cgroup delegation for the separate containment tests.
Missing prerequisites fail rather than turning an unexecuted check into a pass.

| Requirement | Why | Supplied in CI by |
|---|---|---|
| util-linux `unshare`, with unprivileged **user, net, pid and mount** namespaces available to the test user | the sandbox is built from them | `validation/ci/with_cgroup.sh` |
| a delegated **cgroup v2** subtree with a usable freezer | separate workspace containment tests exercise the freezer; the namespace runner itself does not use cgroups | the same script |

`validation/ci/with_cgroup.sh` preflights both as the unprivileged test user
and exits non-zero with the kernel's own reason if either is unavailable. Run
the suite through it locally too:

```sh
bash validation/ci/with_cgroup.sh cargo test -p vanian-sovereign
```

### Ubuntu 24.04 and unprivileged user namespaces

On Ubuntu hosts with `kernel.apparmor_restrict_unprivileged_userns=1`, an approved
AppArmor profile is required. The wrapper keeps that host-wide restriction
unchanged. Only on disposable GitHub-hosted CI it adds a temporary profile
granting `userns` to `/usr/bin/unshare`, removes that profile on exit and checks
that the sysctl did not change. It refuses to replace an existing profile or
configure a local/self-hosted machine automatically. Missing prerequisites fail.

It does **not** run the tests as root instead. Root can create the namespaces,
but it also changes what these tests measure — file modes, capability checks,
what a sandboxed process is permitted to touch — so a pass as root would not be
evidence about the unprivileged path the product actually uses.

### Why a refusal is not skipped

A runtime skip in the built-in Rust test harness is a pass: `#[ignore]` is
resolved at compile time, and a test that prints a reason and returns early is
counted as `ok`. There is therefore no way to report a skipped sandbox test as
`SKIPPED` in the summary, and printing "skipped" while the harness counts a
pass would be worse than failing. So these tests fail, loudly, and the
precondition is fixed in the environment instead.

## A defect this suite did not catch for a while

`unshare` is a child process. A kernel that refuses the namespaces does not
make `spawn` fail — `unshare` execs, fails its own setup, writes to stderr and
exits non-zero. The runner used to treat that as the tool's own exit status and
sign a run record for it. Three consequences:

1. a signed evidence record claimed a tool had run and exited 1 when nothing
   ran at all;
2. `tampered_exit_code_rejected` changed that `Code(1)` to the same value,
   leaving the signed bytes unchanged; accepting it did not show a signature
   verification defect;
3. `sandbox_environment_is_empty` and `deadline_kills_the_tool` *passed*, since
   a tool that never runs produces no output and a non-zero exit, which is
   exactly what each asserted.

`SandboxRunner::probe_namespaces` checks readiness before the one-shot decision
is consumed. A refusal is
`RunError::SandboxUnavailable`: nothing is consumed, nothing is signed. The two
tests above additionally assert the tool actually ran, so neither can pass on
an absence again.

Authority expiry and the program pin are checked again after the probe. The
probe cannot extend signed authority. The deadline test also requires a real
startup marker and SIGKILL, rather than accepting any nonzero exit as a timeout.

The probe is not a per-execution witness: a later setup failure is still possible
between it and launch. The runner remains a proof-of-concept adapter, with
`CannotProve` independent observation. Full launch acknowledgement, executable
hash-to-exec race closure, filesystem confinement and resource limits remain open.
This change does not make the sandbox or Sniffer Dog enterprise-qualified.

## Retained CLI evidence

`python3 validation/ci/record_sandbox.py --binary target/debug/vanian --out NEW_DIR`
retains the original authorized bundle and public identities, an unauthorized
action refusal, a separate one-byte exit mutation and wrong-anchor refusal.
Verification runs in new CLI processes after removal of the temporary private
state. This tests public-material verification on the same host; authenticate
the public anchors independently before relying on a third-party bundle.
The keys share one administrator and the verdict remains `CannotProve` for
independent observation. No model inference or Sniffer Dog kernel capture runs.
