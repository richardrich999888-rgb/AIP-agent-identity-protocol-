# AIRI real-world validation

**Status: EXPERIMENT_PASSED.** Not `REAL_WORLD_VALIDATION_PROVEN`. §10 says why.

AIRI and Sniffer Dog 2.0 were put in front of an independent external observer
for the first time. Ten adversarial scenarios ran; all ten behaved as required.
The exercise also produced one finding that Vanian's own test suite could not
have produced, because Vanian's own test suite is written by the same people
who wrote Vanian.

That finding is in §6, and it is the most valuable thing here.

---

## 1. Validation architecture

```
              ┌──────────────────────────────────────────────┐
              │  SUBJECT — airi-subject-agent (the ACTOR)    │
              │  emits real signed AIRI events, and lies     │
              │  about the correspondence to reality         │
              └───────┬──────────────────────────────┬───────┘
                      │ claims                       │ acts
                      ▼                              ▼
        ┌─────────────────────────┐    ┌──────────────────────────────┐
        │ A. AIRI event chain     │    │  execve · connect · exit     │
        │ B. agent self-report    │    └──────────────┬───────────────┘
        │  (SAME trust boundary   │      ══ KERNEL ═══╪═══════════════
        │   as the subject)       │                   ▼
        └─────────────────────────┘    ┌──────────────────────────────┐
                      │                │ C. A3S Observer              │
                      │                │    eBPF · sys_enter_execve   │
                      │                │ D. Sniffer Dog 2.0           │
                      │                │    perf · sched_process_exec │
                      │                │ E. ftrace                    │
                      │                │    ftrace · sched_process_exec│
                      │                │ F. OBI / Langfuse — absent   │
                      │                └──────────────┬───────────────┘
                      └───────────┬──────────────────-┘
                                  ▼
                         correlate.py — a READER
                    joins on process identity + window
                                  │
                                  ▼
             PROVEN · CORROBORATIVE · SELF_REPORTED · UNKNOWN · CANNOT_PROVE
                    (external-validation labels — NOT Vanian verdicts)
```

The organising rule, and the reason for every design decision below:

> **The actor should not control the evidence used to judge the actor.**

## 2. External tools

Assessed before installation, not after.

| Tool | Licence | Open source? | Status |
|---|---|---|---|
| **A3S Observer** 0.11.0 (`06105bb`) | MIT | yes, single licence | **INSTALLED, WORKING** — 23/24 probes |
| **Tetragon** | Apache-2.0 / GPL-2.0 (BPF) | yes | **BLOCKED** — kernel has no kprobes |
| **OBI** (`7ec9f37`) | Apache-2.0 | yes | **BUILT, emits 0 spans** — needs kprobes |
| **OTel Collector** 0.111.0 | Apache-2.0 | yes | **INSTALLED, unused** — no producer to collect from |
| **Langfuse** (`4c63fad`) | **MIT *except* `ee/`** | **open-core, not fully open source** | **UNAVAILABLE** — all six registries blocked |
| ftrace reader | n/a (kernel) | n/a | READY |

Per-tool detail, with the exact commands that were executed and their observed
output, in `validation/external/*/STATUS.md`.

Two verification results worth surfacing rather than rounding off:

- **Langfuse is open-core.** Its `LICENSE` places `ee/`, `web/src/ee/` and
  `worker/src/ee/` under a separate licence. The core is MIT; the enterprise
  portion is not. The `ee/` directory exists in the clone.
- **OBI was tested, not assumed.** It builds and starts. Run against a live
  HTTP workload for 14 seconds it emitted **zero spans**, because its process
  discovery and network paths are kprobe-based. A running process producing
  nothing is worse than an absent one, because it invites the assumption of
  coverage.

## 3. Installation commands

Every command below was executed and its result observed.

```sh
# A3S Observer — its registries (quay.io, Docker Hub) are blocked, so: source.
git clone --depth 1 https://github.com/A3S-Lab/Observer /tmp/airi_Observer
rustup toolchain install nightly --component rust-src --profile minimal
# bpf-linker must match host LLVM. LLVM is 18 here; bpf-linker 0.11.1 needs
# newer and fails to compile. 0.9.13 is the LLVM-18 version.
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18 PATH=/usr/lib/llvm-18/bin:$PATH
cargo install bpf-linker --version 0.9.13 --locked
cd /tmp/airi_Observer && cargo +nightly build --release -p a3s-observer-collector

# OBI
git clone --depth 1 https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation /tmp/airi_obi
cd /tmp/airi_obi && export GOTOOLCHAIN=auto && make generate && make compile

# OTel Collector
mkdir -p /opt/otelcol && curl -sSL \
  https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.111.0/otelcol_0.111.0_linux_amd64.tar.gz \
  | tar xz -C /opt/otelcol

# Tetragon (built previously; runtime blocked)
# see validation/external/tetragon/BUILD.md
```

Nothing was substituted for anything unavailable, and no installation command
is recorded here that was not run.

## 4. Permission model

| Component | Privilege | Why | Enforcement capability |
|---|---|---|---|
| A3S Observer | root (eBPF load, ring buffers) | kernel observation | **can** enforce; **not built, not configured, not reachable** from the collector binary — its loader contains no cgroup or fanotify attach path, and its heartbeat reports `mode: "observe"` |
| Sniffer Dog 2.0 | root / `CAP_PERFMON` | `perf_event_open` | none |
| ftrace reader | root | tracefs | none |
| OTel Collector | none | — | none |
| Subject agent | unprivileged | it is the thing being watched | none |

Everything runs observe-only. Nothing in this tree kills, denies, throttles or
modifies any process.

## 5. Trust-boundary analysis

| Source | Controlled by subject? | Independent of Sniffer Dog? | Mechanism | Standing |
|---|---|---|---|---|
| AIRI event chain | **yes — it is the actor's own account** | n/a | in-process | **claim** |
| Agent log | **yes** | n/a | in-process | **claim** |
| Langfuse trace *(if present)* | **yes — SDK-fed** | no | in-process → store | **claim, durably stored** |
| OTel/OBI telemetry *(if present)* | partly | varies | varies | **transport record** |
| **A3S Observer** | no | **yes — different probe site** | eBPF · `syscalls:sys_enter_execve` | independent |
| **Sniffer Dog 2.0** | no | it *is* the system under test | perf · `sched:sched_process_exec` | under test |
| **ftrace** | no | interface only | ftrace · `sched:sched_process_exec` | weakly independent |

The rule none of these may violate: **an external tool never becomes a trust
anchor by having reported something.** Langfuse, OpenTelemetry, OBI, Tetragon
and A3S are reference instruments. `aip_airi::corroborate` and `aip_reconcile`
remain the only things in this repository that decide what evidence means.

**Why A3S is genuinely independent and ftrace is only weakly so.** Sniffer Dog
samples `sched:sched_process_exec`. The ftrace reader reads *the same
tracepoint* — different buffer, different decoder, same probe site, so
agreement corroborates Sniffer Dog's *reading* rather than the *event*. A3S
observes at `syscalls:sys_enter_execve`, a **different probe site** reached by a
different mechanism and decoded by a different project. That is what makes
`PROVEN` mean something here.

## 6. The finding

**Running A3S Observer alongside Sniffer Dog 2.0 silently blinded Sniffer
Dog — zero exec events, and zero reported loss.**

Isolated, same host, same workload:

| Arm | Sniffer Dog exec events |
|---|---|
| Sniffer Dog alone | **4** |
| Sniffer Dog with A3S running | **0** |

In one experiment window: A3S saw `/usr/bin/wc`, ftrace saw `/usr/bin/wc`,
Sniffer Dog saw nothing and reported `{"kind":"summary","events":2,"lost":0}`.

**Cause.** A3S attaches a BPF program to `sched:sched_process_exec` that
returns 0. The kernel gates that tracepoint's *perf* submission on the attached
program's return value in `perf_trace_run_bpf_submit()`, keyed per
`trace_event_call` — **per tracepoint, host-wide** — so every `perf_event_open`
consumer of that tracepoint stops receiving samples. The ftrace submission path
is separate and unaffected, which is exactly the asymmetry observed, and is
what makes the diagnosis certain rather than plausible.

**Consequence.** Any process that can load a BPF program can silently blind
Sniffer Dog's tracepoint sensors. It needs `CAP_BPF`, it never touches Sniffer
Dog, and Sniffer Dog goes on reporting healthy coverage.

**What Vanian gets right anyway.** `CANNOT_PROVE` and "absence is never
evidence of non-execution" mean this yields no *false verdict*. A blinded
sensor produces silence, and silence degrades to "cannot say".

**What is actually wrong.** The **coverage claim**. A sensor in this state is
`ACTIVE`, reports zero loss, and covers nothing. A verifier asking "was this
window covered?" gets `yes` and is wrong. Sniffer Dog's loss accounting detects
*ring overrun*; this is not overrun, so there is nothing for it to count.

Nothing was changed in response. This is validation work and production
semantics are out of scope here. Analysis, isolation test, reproduction steps
and four candidate directions (none endorsed) are in
`validation/external/a3s_observer/TRACEPOINT_INTERFERENCE.md`.

## 7. Experiment methodology

`AIRI-INDEPENDENT-OBSERVATION-001`, in
`validation/scenarios/airi_independent_observation_001/`.

The subject (`agent/`) emits a real, correctly signed AIRI chain through the
real `aip-airi` API — `AgentExecutionStarted → ModelInvocationRequested →
ModelInvocationObserved → ToolInvocationRequested → ToolExecutionReported →
SubprocessExecution → ExecutionCompleted/Failed`. **The cryptography is never
the lie.** Every event verifies. The dishonesty is in the correspondence
between claim and reality — the class of lie a signature cannot catch.

Observers attach first. The coverage window opens only once each reports
attached, and closes after the subject finishes. Anything outside it is
outside coverage, never a miss — treating it otherwise would manufacture a gap
and blame an observer for it.

Evidence discipline: written once, made read-only, digested before correlation
and re-verified after. **No external source can modify AIRI's evidence** — the
AIRI log is written by the subject alone and the digest check would fail
otherwise. `correlate.py` is a pure reader.

## 8. Event correlation model

Per claim, compared: claimed event kind · claimed program · observed program ·
process identity (pid, ppid, boot_id) · parent/child relation · timestamps ·
network peer and port · cardinality · which sources saw it · which mechanisms
those sources represent.

Classification, gated on coverage first so an uncovered window can never
produce anything but `CANNOT_PROVE`:

| Label | Requires |
|---|---|
| `PROVEN` | ≥2 **mechanism-independent** live sources agreeing, both covering the window |
| `CORROBORATIVE` | independent agreement from one source, or from sources sharing a mechanism |
| `SELF_REPORTED` | only the subject; **and** every claim class with no host-visible mark |
| `UNKNOWN` | covered, but the join could not be completed |
| `CANNOT_PROVE` | no live observer covered the window |

**These are not Vanian verdicts.** They are external-validation labels about
evidence sufficiency *in this experiment*. Nothing writes them into an
`EvidenceStrength`, an `EvidenceCeiling`, a provenance level, a
`ReconciliationResult` or a `Corroboration`.

A **suppressed** source is excluded from the independent set and said so — it
is not a source that "saw nothing". Reading suppression as absence is the exact
error this exercise exists to prevent, and §6 is why the harness now knows the
difference.

## 9. Adversarial scenarios

Full table with per-scenario reasoning in
`validation/scenarios/airi_independent_observation_001/SCENARIOS.md`.
Machine-readable matrix in `validation/reports/AIRI_VALIDATION_MATRIX.{csv,json}`.

**10 executed, 10 passed. 5 not executed, reasons recorded. 1 occurred
unprompted (§6).**

The two that carry the most weight:

- **Scenario 1 — claimed a tool ran; nothing ran.** A correctly signed,
  structurally valid, chain-consistent claim. `verify_airi_event` returns `Ok`,
  as it should — authorship and integrity *are* intact. Two
  mechanism-independent observers covered the window and saw nothing. Result:
  `SELF_REPORTED`, never `PROVEN`, with cardinality divergence flagged (1
  claimed, 0 observed). **A perfect signature over a false statement bought the
  actor nothing.**
- **Scenario 6 — claimed an act that leaves no host-visible mark.** The correct
  answer is "cannot be established"; the tempting wrong answer is "unsupported,
  therefore false". It stayed `SELF_REPORTED` and was never called false.

## 10. Acceptance criteria

| Gate | Met? |
|---|---|
| `TOOLING_READY` | yes — A3S + ftrace + Sniffer Dog live; OTel installed |
| `ENVIRONMENT_READY` | yes — preflight PARTIAL, blockers named |
| `EXPERIMENT_READY` | yes |
| `EXPERIMENT_EXECUTED` | yes — 10 scenarios |
| `EXPERIMENT_PASSED` | **yes — 10/10** |
| `REAL_WORLD_VALIDATION_PROVEN` | **NO** |

`REAL_WORLD_VALIDATION_PROVEN` is withheld deliberately. It requires
demonstrated independent agreement between AIRI's claimed execution and
external observation, and while that was demonstrated *for subprocess
execution on one host*, the following are not established and the claim would
paper over them:

- The subject is synthetic, and its lies are the ones it was written to tell.
  This is not a real agent framework under real load.
- **No model invocation was independently observed at all.** Every
  `ModelInvocation*` claim is `SELF_REPORTED`, structurally — no local observer
  can attribute a hosted inference call. That half of the AIRI chain is
  currently unvalidatable by this method.
- Exit status, tool outcome and network *ordering* are not independently
  checkable here (no kprobes, no timing on egress records).
- §6 shows a live path by which the observation layer can be silently defeated.
- Two of five named tools are functionally unavailable; one is unavailable
  entirely.

## 11. Known gaps

1. **`# CONFIG_KPROBES is not set`.** Blocks Tetragon completely and OBI
   functionally; removes A3S's exit evidence. The single biggest environmental
   constraint.
2. **Model invocations are unobservable.** Half the AIRI chain cannot be
   corroborated by any host observer, by construction. AIRI already says this;
   the experiment confirms it empirically.
3. **AIRI has no network event kind.** Observed egress is undeclared *by
   construction*, so scenarios 5 and 13 cannot score the agent — a gap in what
   AIRI can express, not agent dishonesty.
4. **Egress ordering.** A3S egress records carried no timing in these runs, so
   "after completion" in scenario 13 is asserted by construction, not shown.
5. **BPF tracepoint gating (§6).** A coverage-assertion gap, unfixed.
6. **Langfuse is open-core**, and unavailable regardless.
7. **Telemetry-pipeline scenarios (7–9) are untested** — there is no pipeline.
8. **Root is assumed benign.** Nothing here survives a root-privileged
   adversary, and §6 shows `CAP_BPF` alone is enough.

## 12. Reproducibility

```sh
sudo ./validation/preflight.sh                    # READY / PARTIAL / BLOCKED
cd validation/scenarios/airi_independent_observation_001
sudo ./run.sh honest                              # or any scenario in SCENARIOS.md
sudo ./build_matrix.py                            # consolidate the matrix
```

`A3S_ENABLED=0 ./run.sh <scenario>` runs without A3S — how Sniffer Dog's
unsuppressed behaviour in §6 was measured.

Evidence lands in `validation/traces/airi001-<run>/` (sealed, read-only, with
`SHA256SUMS`), reports in `validation/reports/`. Host: Linux 6.18.44-fc-v24,
x86_64, root.

---

## Trust-boundary changes

**NONE.**

No file under `aip-*` was modified. `EvidenceOrigin`, `EvidenceCeiling`,
provenance levels, `ObservationRecord`, independent-observation semantics,
`Reconciliation`, `EffectAssessment`, `UNKNOWN`, `CANNOT_PROVE`, NEXORA
authority and identity/authority/delegation semantics are all untouched.

No second Reconciliation engine and no competing proof authority was created —
`correlate.py` deliberately issues no Vanian verdict, which is why §6 could be
reported as a finding rather than silently absorbed into a classification.

The subject agent and the correlator carry their own `[workspace]` tables, so
the production workspace manifest is unchanged: `cargo metadata` still reports
29 members.

---

> The purpose of this work was to make AIRI and Sniffer Dog 2.0 face an
> independent external observer and show they are an accountability system
> rather than another telemetry system.
>
> On the evidence: for subprocess execution, they are. A signed false claim was
> refused corroboration by two independent mechanisms, and an unobservable
> claim was correctly left unresolved rather than called false.
>
> And the same independent observer showed that the observation layer can be
> silently switched off from inside the kernel while it reports itself healthy.
> Both of those are the exercise working.
