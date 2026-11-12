# Founder guide — P0-051 current bounded demonstrations

**Release: NOT READY.** The runnable addition is the corrected teaching applicability gate.
It is expert-guided capability validation, not autonomous self-improvement or
model fine-tuning. The complete three-minute investor show is not yet executable.

The applicability replay follow-up adds a runnable **VERIFY component**: check
externally selected keys/byte pins and recompute the frozen 12-case holdout and
26-case attack suite with no model or network downloads. Follow
[Independent verification](INDEPENDENT-VERIFICATION.md#replay-without-trusting-diagnostic-pass-fields).
An edited PASS summary cannot make this check pass. This is not the final signed
knowledge-pack scene or a full investor rehearsal.

## P0-051: show why a taught rule failed

With the staged Linux binary, Python 3.10+, Git and this checkout:

```bash
python3 research/capability-learning/harness/record_session_scoreboard.py \
  --binary target/debug/syntriass --with-examples --out /tmp/p051-session-new
```

Show `rejected-control/scoreboard.json`: the original 11/12 control remains
rejected and its failed row links to the exact exclusion question, cited sentence
and answer edits. Then show `corrected-validation/scoreboard.json` (12/12) and
`corrected-attacks/scoreboard.json` (26/26, including six nonactivation probes).
Show each `result.json`: the explicitly reviewed examples pass 3/3 separately.
The 11/12 control remains rejected even with passing examples. Passing this
diagnostic does not approve or activate anything.

Presenter: “This is an EXPERT-GUIDED TAUGHT CAPABILITY. Here is the document,
the question and the answer that supplied this part of the rule. The test found
a failure. These are questions to review, not an automatic diagnosis. After
explicitly selecting the cited exclusion forms, the signed suite passes. The
capability still needs authorized approval before it can be used.”

This is a live scripted component exercise with synthetic engineer answers.
Only its suites are signed; reports and question links are unsigned. Session
example labels are explicitly declared and bound to the exact inputs; the
reviewer identity is not authenticated. Pre-review NOT_MEASURED outputs remain
retained. Missing, ambiguous or out-of-domain answers never count as negative
example successes. No model, human approval screen, pack, kernel observation or complete
investor show runs. See [the general command](../demo/TEACH_SESSION_SCOREBOARD.md).

Recovery: preserve the failed output directory. Exit 2 means refusal; inspect
`result.json` and command stderr for stale input, bad trust or missing prerequisites.
Exit 3 means the signed suite or the separately reviewed examples rejected the candidate. Correct the reviewed input
and rerun into a new directory; do not change frozen expected labels.

The mapping component took 2.5933206640002027 seconds locally (concurrent test
load) and 1.8950681390000028 seconds on CI, with separate hardware records. These
are single observations, not a performance range or investor-show duration. Required Linux models/inference, final installer,
independent sensor boundary, UI/approval and packs are still unavailable as a
complete kit. The three-minute sequence below remains NOT READY.

## Current teaching-session check (P0-050 iteration 1)

With the staged binary and Python/Git prerequisites below:

```bash
python3 research/capability-learning/harness/record_exclusion_policy.py \
  --binary target/debug/syntriass --out /tmp/p0-050-applicability-new
```

This creates a real teaching session and applies scripted engineer answers.
The expert is offered explicit singular/plural exclusions, each linked to its
quoted source, which must remain. It proves that these answers can be compiled
and tested without a model. It does not demonstrate a live human UI, signed
approval, activation, general language learning or the full teaching workflow.

At implementation `ef3d9d434e5ed55e5994331abc91c03833f997ff`, **expect exit 0 /
PASS_BOUNDED_B3**. The corrected candidate passes 12/12 holdout and 26/26 attacks,
including all six frozen nonactivation probes. Inspect
`explicit-forms-attacks/scoreboard.json`: battery-cell case fa-3 now returns
NOT_APPLICABLE. The copied-plural control still fails 11/12 and 18/26, exit 3;
those expected failures remain visible. None of these candidates is activated.

Presenter: “I keep the source's wording and explicitly add the reviewed exclusion
forms. AIRON tests the rule. It refuses excluded equipment, asks for missing
measurements within scope, and leaves unrelated questions outside this capability.
Passing tests still requires a separate authorized approval before use.”

The program retains original/corrected answers, source citations, signed suites,
full diagnostics and measured metadata in a new output directory. Its operation
uses only the Python standard library and the staged runtime; no installation or
download occurs during execution. The session, edits and diagnostics are unsigned;
only the synthetic test suites are signed. This is a live scripted component
exercise, not a live human-teaching UI or external expert approval. See
[`P0-050-FINAL-REPORT.md`](../assurance/P0-050-FINAL-REPORT.md).

To repeat the isolated component run after staging all prerequisites:

```bash
env -u CM_IN_NETNS bash research/compute-memory/bench/offline.sh \
  python3 research/capability-learning/harness/record_exclusion_policy.py \
  --binary target/debug/syntriass --out /tmp/p0-050-applicability-isolated
```

Use a new directory. If exit 3 occurs, inspect the failed rows and preserve the
entire directory; do not relabel expected outcomes. If a prerequisite is missing,
report NOT READY and stage the verified component before repeating. An unavailable
network namespace is a refusal, not permission to claim isolation on a connected
host. No native sensor runs inside this wrapper. Existing signed capabilities
need new validation/approval and explicit supersession after recompilation.

## Commercial scripts — required sequence, currently NOT READY

| Script | Presenter sequence | Current readiness / recovery |
|---|---|---|
| Investor, target three minutes | **Pull the Plug → Teach One Rule → Catch the Lying Agent.** Show local answer/citation and network boundary; teach a bounded rule, questions/tests/approval/use/pack verification; then show undeclared execution and independently verify the original archive | Full live sequence NOT READY: model, lifecycle/UI/pack and qualified sensor/kit gates remain. Do not substitute the old plug → liar → quantum launcher or unlabelled video |
| Regulated enterprise | Authorize a synthetic agent; perform an undeclared action; inspect independent kernel evidence; verify offline; export audit material | NOT READY as a final accepted mode. Missing coverage must yield CANNOT_PROVE; interruption/restart must retain the original archive and failure |
| Defence / sovereign AI | Disconnect external network; run local intelligence; show tenant/clearance refusals; verify evidence; explain air-gap installation, updates and hardware limits | NOT READY until the complete supported kit and independent boundary are tested. A software namespace alone does not qualify the sensor host |
| Technical, target five minutes | Explain scope; run the current component command; inspect citations, rejected control, 12/12 and 26/26 reports; run independent signature/hash verification; show open approval/pack gates | Only this bounded component segment is runnable today. Five minutes is a presentation budget, not a measured end-to-end result |

Narration for the future investor flow: “This answer runs locally. Now an expert
teaches one bounded rule from a cited document. AIRON asks what is missing, tests
the rule and waits for authorized approval. Finally, this agent hides an action;
the independent evidence exposes the discrepancy.” Use that narration only when
each corresponding scene is actually available. Every recording must visibly
state its source SHA, hardware and recorded status.

No complete script duration has been measured in P0-050. The local applicability
recorder took **0.4039170820005893 seconds** on the labelled nine-CPU development
host; that is not the investor show's duration. Measure the complete live show,
report any overrun and optimize without hiding live execution.

Profile A targets the founder laptop: local AI/teaching/pack verification and
clearly labelled recorded Linux evidence. Profile B targets qualified Linux:
live sensors, local AI, live PQ/CBOM and verification. Both complete profiles are
still open. No fresh Mac hardware observation, macOS binary compatibility or
minimum laptop sizing was established by this Linux component test.

## Run the bounded live demonstration

On a development Linux x86-64 host, with Rust/Cargo, Git and Python 3.10+ already
installed, run the commands below from this repository.

Iteration 2 was tested with Rust 1.99.1. The updated rusqlite dependency requires
at least Rust 1.89; the whole workspace's minimum-toolchain support was not tested.
Use the recorded toolchain for reproduction. SQLite is bundled into the binary.

```bash
cargo build --locked -p syntriass-runtime --bin syntriass
python3 research/capability-learning/harness/record_scoreboard.py \
  --binary target/debug/syntriass --out /tmp/p0-049-homework
```

Choose a new output directory for each run. The recorder refuses to overwrite
prior evidence. It makes no downloads and requires no model weights. Cargo may
need network access to populate its build cache: **this is a developer build,
not the final offline installer**. A prebuilt, hash-verified binary is required
for a truly disconnected installation; that kit is still incomplete.

The retained local run used the existing namespace wrapper (Linux with permitted
unprivileged user/network namespaces). To reproduce that bounded run:

```bash
env -u CM_IN_NETNS bash research/compute-memory/bench/offline.sh \
  python3 research/capability-learning/harness/record_scoreboard.py \
  --binary target/debug/syntriass --out /tmp/p0-049-homework-isolated
```

This recorded zero loopback counter increments and no non-loopback interface.
It contains no sensor or model; it does not establish the independent isolation
boundary required for the initial-netns Sniffer Dog demonstration.

The recorder generates pinned synthetic datasets, creates a temporary test expert
key, ingests tenant-labelled documents, proposes capabilities and runs the real
`cap-scoreboard` command. Public keys, signed suites, capability bytes and full
diagnostics are retained. Private keys and working state are removed. Results:

| Case | Expected validation | What to show |
|---|---|---|
| Motor capability | 14/14 expert cases; exit 0 | Passing homework still leaves the stored capability PROPOSED |
| Original transformer candidate | 11/12; exit 3 | `val-09`: cable input, expected OUT_OF_SCOPE, got ACCEPT; review exclusion terms |
| Corrected transformer capability | 12/12; exit 0 | Same validator accepts the already documented corrected rule |

Presenter: “This checks a bounded rule against a signed set of expert test cases.
Here the rule wrongly accepts a cable. AIRON shows the exact input, expected and
actual result, the branch that ran and questions to revisit. Passing these checks
does not approve or activate the rule.”

Do not present the scripted engineer as an external domain expert. The corrected
capabilities are existing recorded fixtures; this command does **not** teach a new
rule live. The two tasks are both maintenance examples, not two customer sectors.

For an existing operator-controlled local state:

```bash
target/debug/syntriass cap-scoreboard \
  --config /absolute/path/config.json \
  --hash CAPABILITY_SHA256 \
  --suite /absolute/path/suite.json
```

Exit 0: validation passes. Exit 3: validation fails and JSON explains why. Exit 2:
unusable input/trust/configuration, including a missing trusted expert or changed
stored capability bytes. `stored_state` and `stored_executable` report the current
record separately. The command never changes capability lifecycle state.

## What the other demonstrations can currently show

These commands belong to W, `feature/wow-demos` at `6ad92ae`, not this teaching
checkout. Check out W separately; no branch integration was performed here.

```bash
python3 demos/launch.py check
python3 demos/launch.py run pull-the-plug --out /tmp/p0-049-plug
python3 demos/launch.py run security --out /tmp/p0-049-security
python3 demos/launch.py run quantum --out /tmp/p0-049-quantum
python3 demos/launch.py run pq --out /tmp/p0-049-pq
```

| Demonstration | Prerequisites / what it could prove | What is not established now |
|---|---|---|
| Pull the plug | Verified Qwen weights, pinned llama-server, local Python environment; live answers and namespace counters | Independent physical isolation, full packet capture or new-machine acceptance |
| Catch the lying agent | Linux kernel facilities, initial netns, auditd, probe/collector/verifier; compare declared and observed activity | Complete observation or safety against a hostile root; current host lacks the required sensor setup |
| Quantum X-ray | Accessible demo implementation, CBOM build, synthetic planted files, independent ground truth | The original local-only W4 implementation is unavailable; command is not runnable from O |
| PQ switch — **PROOF OF CONCEPT** | Accessible demo implementation, Linux/container runtime, identity material, tcpdump; compare same app binary with/without overlay | Original W5 source/captures unavailable; no certification or production readiness |

Do not run a host-network sensor demonstration as an “offline proof” without an
independently established network boundary. Do not disable the sensor to make an
offline namespace test pass.

## Requested investor sequence — NOT READY

| Target slot (not measured) | Live action | Presenter narration |
|---|---|---|
| 0:00–0:45 | PULL THE PLUG | “The model and these synthetic documents are on this machine. Watch the network evidence as it answers.” |
| 0:45–2:10 | TEACH ONE RULE | “The expert provides a bounded rule. AIRON asks about uncertainty, tests it, and requires authorized approval before reuse.” |
| 2:10–3:00 | CATCH THE LYING AGENT | “The agent's own log omits an action. Compare it with the independently collected observation and verify the signed bytes.” |

These are timing targets only. W's current `investor-3min` instead runs plug → liar
→ quantum. **Do not use it as acceptance of this requested sequence.** Replace its
sequence and add a real teaching readiness gate after W3 is complete. No measured
duration for the requested show exists, so no three-minute claim is made.

## Failure recovery and verification

1. A failed suite is a useful failure. Keep the result; revisit the cited rule or
   suggested question. Re-propose the corrected artifact and validate again.
   Never edit expectations, weaken the eight-expert-case/counterexample gates or
   treat generated tests as expert approval.
2. An unknown expert requires a legitimate operator-provisioned trust anchor.
   Do not automatically trust a key supplied alongside an untrusted suite.
3. A hash mismatch requires restoring authenticated bytes or explicitly creating
   a new proposal. Do not relabel the old artifact as verified.
4. Missing weights/runtime/dependencies mean NOT READY. Do not fall back to a
   cloud model, downloads during installation, or an unlabelled recording.
5. Sensor failure means unavailable/partial evidence. Retain the failed attempt,
   restore the sensor, verify its coverage and reset the rehearsal pass count.

```bash
cd /tmp/p0-049-homework
sha256sum -c SHA256SUMS
```

Checksums detect changed bytes relative to this manifest; an independently trusted
manifest/signature is still required for authenticity. See
`INDEPENDENT-VERIFICATION.md` for scoped verification and limitations.

Hardware records include Linux/kernel, CPU affinity, memory, cgroup availability,
child CPU time, peak RSS and exact elapsed time. Local and CI measurements are
retained separately; neither is the published 2-vCPU/8-GB benchmark host. Full
model/sensor/PQ prerequisites and measured sizing on a second machine remain open.

## Bounded runner evidence check

Source `6764c7e` adds `validation/ci/record_sandbox.py`. On a supported Linux
host, run it with a trusted `vanian` binary and a new output directory to show
an authorized echo, denied ungranted action, public-material verification and
tampered-evidence rejection. See the S2 assurance checkpoint for prerequisites
and exact commands. Label this **runner attestation, independent observation
CANNOT_PROVE**. It earns no live Sniffer Dog, model, teaching approval or complete
investor/bank/defence sequence credit.
