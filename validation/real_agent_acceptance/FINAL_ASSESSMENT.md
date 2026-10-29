# Real-agent acceptance — final assessment

**Branch** `claude/real-agent-acceptance-n5ysvd`
**Date** 2026-10-29
**Scope** PR #8 / PR #12 reconciliation, the P0 acceptance test, and
verification of five upstream agent frameworks

---

## 0. The headline, without decoration

**No genuine agent execution was performed for any of the five assigned
frameworks.** Four are `NOT_EXECUTED` and one is `BLOCKED`. The reason is a
single hard blocker: this container has no reachable model endpoint, and the
assignment is explicit that a framework import or smoke test is not a pass.
Running them anyway would have produced five green rows that meant nothing.

What *was* executed is the P0 acceptance test, on a GitHub-hosted runner,
twice. It failed both times, and the failures are real, retained and now
legible. That is the substance of this package.

| Gate | Classification | One-line reason |
|---|---|---|
| PR #8 / #12 reconciliation | **PASS** | four commits merged; direction justified; CI confirms the gateway fix took effect |
| P0 same-run acceptance test | **FAIL** | fails at the enterprise client readback, after the agent and the kernel observation |
| P1 smolagents | **NOT_EXECUTED** | no reachable model endpoint; API verified, adapter written |
| P1 aider | **NOT_EXECUTED** | same; CLI contract verified, fixture unit-tested |
| P1 goose | **BLOCKED** | Rust binary, no PyPI package, no verified headless contract |
| P1 browser-use | **NOT_EXECUTED** | same model blocker; API verified, needs a Chromium binary |
| P1 Open Interpreter | **NOT_EXECUTED** | same model blocker; import defect found and fixed |
| P2 ground truth | **NOT_EXECUTED** | depends on P1 |
| P3 security negatives | **NOT_EXECUTED** | depends on P1 |
| P4 repeatability | **NOT_EXECUTED** | depends on P1 |

No metric in this package is reported as zero. Unmeasured is
`NOT_MEASURED`, everywhere.

---

## 1. The reconciliation, and why it ran in that direction

PR #12 (`fix/vanian-end-to-end-green`) is the tip of the stack and already
contained PRs #6, #7, #9 and #11. It did **not** contain four commits that
sit only on PR #8's head. Every one of them raises assurance, so the merge
went #8 → #12, not the reverse.

The most consequential is a two-character class of bug worth naming
explicitly, because it will recur:

```python
with sqlite3.connect(db) as connection:   # manages a TRANSACTION
with closing(sqlite3.connect(db)) as connection:   # manages the CONNECTION
```

The first form leaves the connection open. The database sits inside the
bind-mounted workload directory, so the open descriptor is a reference under
the mount, `umount` returns `EBUSY` at teardown, `cleanup_errors` is
non-empty, and the controller correctly downgrades an otherwise passing run
to `FAIL`. A test-infrastructure bug was therefore presenting as a cleanup
failure of the system under test.

The other three: `gateway_password()` (upstream rejects three adjacent
letters or digits, which random base64 produces often — 130 of 2000 old
samples rejected, 0 of 2000 new), failure-path evidence retention, and the
`safe_error` classifier that keeps Pydantic's password-echoing response body
out of the record.

**CI confirmed the merge was right.** The previously recorded failure was
`FAILED_GATEWAY_ACCOUNT_PROVISIONING_BEFORE_AGENT` with
`autonomous_workload_executed=false`. Run 40825279520 got past gateway
provisioning entirely and failed much later.

---

## 2. P0 — what the acceptance test actually does, and where it breaks

Run 40825279520 (ubuntu-24.04, commit `35f215d`) completed thirteen stages
including chrony clock sync, auditd start with its ruleset captured, the
pinned `IBM/mcp-context-forge @ ff6a566a` fetch, the pinned `llama3.2:1b`
model provisioned by reviewed manifest digest, and a full Rust build of the
probe, collector, verifier, corroborator, gateway and service. Then:

```
same_run_validation.py line 653 -> evidence.command(clients, ...)
evidence.Refused: python exited 1
```

That is the **enterprise client readback** — the Python SDK, OpenAPI
contract, official MCP client, TypeScript SDK and browser console all reading
back the same run bundle. It sits *after* the agent, the signed authority,
the MCP request, the kernel observation and the reconciliation.

### The defect I fixed first was not the failure — it was the blindness

`evidence.command` discards the child's stderr, and its comment says why:
the child may echo credentials. That judgement is correct and I did not
change it. This readback receives three API key files and compares whole run
bundles; its stderr genuinely can carry key material.

The defect is on the other side. `run_client_smoke.py` runs 25 bare
predicates and, on failure, writes nothing anywhere the controller retains.
Suppressing a channel that may contain secrets is right. Leaving no channel
at all is not.

The repair records which of 12 stages is executing and, on any exception,
writes `client-smoke-failure.json` into `public/` — which the workflow
already uploads — carrying the stage, the exception type and a
classification from a fixed table. **Never the exception message**, by the
same discipline `safe_error` already uses.

It is insert-only: 25 predicates before, 25 after, asserted against git
history rather than a threshold. Thirteen regression tests pin it, including
one that puts a credential-shaped string in an exception and asserts it
appears nowhere in the record.

**The underlying readback failure is still `UNKNOWN_PENDING_NEXT_RUN`.** I
am not going to guess at it. The next run will name the stage, and that is
the point of the repair.

---

## 3. P1 — the five frameworks, and two findings that change the target list

Every API fact below came from `inspect.signature` against an installed
wheel, or from `--help` on an installed binary. None came from
documentation.

### The targets are not all what their names suggest

**goose.** `block/goose` now serves `aaif-goose/goose` (Agentic AI
Foundation, Linux Foundation). It is **Rust**, Apache-2.0, `v1.57.0`
(2026-10-28), installed by shell script, rpm or tarball. **There is no PyPI
package.** The upstream README advertises a CLI and an embedding API but
confirms no non-interactive flag, so there is no headless contract to write
an adapter against.

> **Supply-chain hazard.** PyPI `goose-ai` 0.1.0 (uploaded 2026-05-13,
> summary `anupamas0x1`, no homepage) is **not this project**. Anyone
> reaching for `pip install goose-ai` installs an unrelated package into the
> trust path of an accountability system. The lock file records
> `do_not_install` for it explicitly.

**Open Interpreter.** `openinterpreter/openinterpreter` is now a **Rust
rewrite based on Codex** (`rust-v0.0.56`, 2026-10-07) with no Python API; it
speaks the Codex exec protocol via `interpreter exec --chat-completions`. The
original Python project "lives on as a community-maintained fork at
`endolith/open-interpreter`". The PyPI artifact `open-interpreter 0.4.3` was
last released 2024-10-26.

And that artifact **does not import at all** on a current environment:

```
interpreter/core/utils/system_debug_info.py line 4:  import pkg_resources
ModuleNotFoundError: No module named 'pkg_resources'
```

`setuptools >= 81` removed `pkg_resources`; the runner had 84.2.1. Root-caused
and remediated by pinning `setuptools < 81` (verified with 80.10.2), after
which the real API is available: `interpreter.auto_run` (default `False`),
`interpreter.offline`, `interpreter.llm.api_base`, and
`interpreter.chat(message, display, stream, blocking)`.

### The three that verified cleanly

| | version | licence | verified entry point |
|---|---|---|---|
| smolagents | 1.26.0 | Apache-2.0 upstream — **the wheel declares none** | `CodeAgent(tools, model, executor_type).run(task)` |
| aider | 0.86.2 | Apache-2.0 (classifier) | `aider --model --openai-api-base --message --yes-always --auto-test --test-cmd` |
| browser-use | 0.13.14 | MIT (classifier) | `Agent(task, llm, browser).run(max_steps)` (async) |

Two licence notes worth carrying into any distribution review: **smolagents
and open-interpreter wheels declare no licence metadata at all** — no
`License`, no `License-Expression`, no classifier. The licence is real but it
is not provable from the artifact you install. And **browser-use 0.13.14 does
not depend on playwright**; it drives Chromium directly over CDP through
`cdp-use 1.4.5`, so the browser binary is a separate provisioning step.

All five point at **one OpenAI-compatible endpoint** — the locally
provisioned, digest-pinned CPU model the repository already uses. No cloud
account, no credential read from the host. `ChatOpenAI` accepts `base_url`,
`OpenAIServerModel` accepts `api_base`, aider accepts `--openai-api-base`,
and `interpreter.llm.api_base` is settable. All four confirmed by signature.

### What the adapters do, and the one thing that matters about their shape

Each adapter publishes an `EffectSpec` **before** the run: the independently
checkable consequence the run must produce — an exact file content, a git
commit plus a passing test, an HTTP access-log line the agent cannot write,
a signed gateway receipt. A contract published afterwards could have been
chosen to fit whatever happened.

Everything an adapter reports is `SELF_REPORTED` and can never satisfy its
own gate. A unit test asserts no two frameworks share an effect detail, since
a shared effect would let one framework's run satisfy another's criterion.

The goose adapter **refuses**, with a stated reason, rather than inventing an
argv. That is the correct output for an unverified contract.

---

## 4. Why P1–P4 could not run here

| Blocker | Evidence | Remedy |
|---|---|---|
| No reachable model endpoint | proxy reports `403 to CONNECT` for `huggingface.co:443` and `registry.ollama.ai:443`; `api.anthropic.com/v1/models` → 401, no model credential in the environment | allow-list `registry.ollama.ai`, or supply a model API key as an environment secret |
| cgroup v1, not v2 | `/proc/self/mountinfo` shows per-controller cgroup v1 mounts; `cgroup.controllers` exposes only `hugetlb` | run where cgroup v2 delegates `cpu`, `memory`, `pids` |
| No synchronised clock | `timedatectl`: "System has not been booted with systemd as init system" | the CI workflow's chrony path already solves this |
| No self-hosted runner | `real-agent-live.yml` needs `[self-hosted, linux, snifferdog-disposable]` + a protected environment | provision it, or add a GitHub-hosted workflow for the five |

**The first blocker is already proven solvable.** Step 12 of run
40825279520, "Provision public pinned CPU model", **succeeded** on a
GitHub-hosted runner. The model path works there. So does auditd, chrony and
cgroup v2. The five-framework runs are buildable on GitHub-hosted runners;
they are not buildable in this container.

I did not weaken the one gate that stopped the acceptance test running
locally. `same_run_validation.py` refuses unless
`RUNNER_ENVIRONMENT == "github-hosted"`. That is an assurance criterion —
"explicitly disposable" — not a defect. I dispatched to Actions instead.

---

## 5. A correction to the forensic record

This container runs **6.18.44-fc-v185**, not the 6.18.44-fc-v24 of the
maturity addendum, and the capability picture differs:

```
CONFIG_BPF_LSM=y                      (was: not set)
CONFIG_SECURITY_LANDLOCK=y            (was: not set)
/sys/kernel/security/lsm = lockdown,capability,landlock,selinux,bpf
```

**This is not a capability claim.** ADR-008 already records the exact trap:
a `CONFIG_LSM` string and an LSM list are not evidence that BPF-LSM attach
works. No runtime attach test was performed, so the honest status is
CONFIG-OBSERVED and LSM-LIST-OBSERVED. `CONFIG_KPROBES`, `CONFIG_TCG_TPM`
and `CONFIG_IMA` remain absent, so the kprobe and TPM blockers stand
unchanged.

What it does mean: the earlier conclusion that BPF-LSM and Landlock are
unavailable **to this programme** was a fact about one kernel build, not
about the deployment target. The `OSS_DEPENDENCY_AND_TOOLING_SURVEY.md`
recommendation to record Landlock as a *deployment requirement* rather than a
dead end is now supported by a second data point.

---

## 6. What is honestly established, and what is not

**Established:**

- the PR #8 → #12 reconciliation is correct, and CI demonstrates the gateway
  fix took effect by moving the failure point past the agent;
- the same-run acceptance test runs end-to-end through thirteen stages
  including a real pinned local model and a real auditd capture, and fails at
  the client readback;
- that failure now produces a retained, redaction-safe diagnostic instead of
  `python exited 1`, insert-only, with 13 regression tests;
- five upstream frameworks verified by signature against pinned artifacts,
  with four defects or hazards found: the goose rename, the `goose-ai`
  name-collision, the Open Interpreter Rust/Python split, and the
  `pkg_resources` import failure (root-caused and fixed);
- one launcher interface over all five, with pre-declared effect contracts,
  27 passing unit tests, and an explicit refusal where a contract is unknown.

**Not established — and not claimed anywhere in this package:**

- that any of the five frameworks ran;
- that Sniffer Dog observed any of them;
- any coverage, attribution, latency, overhead or repeatability figure;
- that the same-run acceptance test can pass;
- that BPF-LSM or Landlock work on any kernel, as opposed to being configured;
- any bank acceptance or production approval. Nothing in an internal test
  suite can establish that, and this package does not try.

---

## 7. Next actions, in dependency order

1. **Read the next run's `client-smoke-failure.json`** and fix the named
   stage. This is the only P0 work that can proceed without new
   infrastructure.
2. **Unblock the model endpoint** — one network-policy entry or one secret.
   Everything in P1–P4 is downstream of this single decision.
3. **Add a GitHub-hosted five-framework workflow**: install ollama and the
   pinned model, install each framework at its locked pin, run the probe and
   collector, start auditd, execute the adapter, then check the pre-declared
   `EffectSpec` against independent ground truth.
4. **Resolve goose properly** — fetch `goose-docs.ai` installation and CLI
   documentation and establish whether a headless invocation exists. If it
   does not, goose stays `BLOCKED` and that is the honest result.
5. Only after a framework reaches a real `PASS` do P2, P3 and P4 have
   anything to measure.
