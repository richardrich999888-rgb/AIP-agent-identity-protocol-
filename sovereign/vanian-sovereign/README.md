# vanian-sovereign

The sovereign slice: a decision point that authorizes a tool call, a runner
that executes it inside Linux namespaces, and an offline verifier for the
signed evidence bundle that results.

## Test preconditions

The tool-sandbox tests in `tests/agent_execution.rs` run the **real** sandbox.
They have two host requirements, and they **fail rather than skip** when either
is missing, because a sandbox test that passes without a sandbox has not run.

| Requirement | Why | Supplied in CI by |
|---|---|---|
| util-linux `unshare`, with unprivileged **user, net, pid and mount** namespaces available to the test user | the sandbox is built from them | `validation/ci/with_cgroup.sh` |
| a delegated **cgroup v2** subtree with a usable freezer | the containment tests exercise the freezer | the same script |

`validation/ci/with_cgroup.sh` preflights both as the unprivileged test user
and exits non-zero with the kernel's own reason if either is unavailable. Run
the suite through it locally too:

```sh
bash validation/ci/with_cgroup.sh cargo test -p vanian-sovereign
```

### Ubuntu 24.04 and unprivileged user namespaces

Ubuntu 24.04 — the current `ubuntu-latest` GitHub runner image — ships
`kernel.apparmor_restrict_unprivileged_userns=1`, which denies unprivileged
user namespaces. The wrapper sets it to `0` before running the tests.

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
2. because a genuine `Code(1)` was indistinguishable from it,
   `tampered_exit_code_rejected` — which tampers a record **to** `Code(1)` —
   could not detect the tampering;
3. `sandbox_environment_is_empty` and `deadline_kills_the_tool` *passed*, since
   a tool that never runs produces no output and a non-zero exit, which is
   exactly what each asserted.

`SandboxRunner::probe_namespaces` now proves the namespaces can be created
before the one-shot decision is consumed. A refusal is
`RunError::SandboxUnavailable`: nothing is consumed, nothing is signed. The two
tests above additionally assert the tool actually ran, so neither can pass on
an absence again.
