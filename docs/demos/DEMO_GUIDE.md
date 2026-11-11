# Founder guide — P0-049 iteration 1

**Release: NOT READY.** The runnable addition is the teaching homework scoreboard.
It is expert-guided capability validation, not autonomous self-improvement or
model fine-tuning. The complete three-minute investor show is not yet executable.

## Run the bounded live demonstration

On a development Linux x86-64 host, with Rust/Cargo and Python 3.10+ already
installed, from this repository:

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

Hardware record: the current run records Linux/kernel, CPU affinity, memory,
cgroup availability, child CPU time, peak RSS and exact elapsed time. It is one
development host, not the published 2-vCPU/8-GB benchmark host. Full model/sensor/
PQ prerequisites and measured sizing on a second machine remain open.
