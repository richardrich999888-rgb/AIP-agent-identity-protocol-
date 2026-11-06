# Catch the lying agent (W2)

An agent is told to do task X. A hidden step makes it also do something it
was not asked to do, and its own log leaves that out. Sniffer Dog shows the
undeclared action from signed kernel evidence, an independent cross-check
agrees, the evidence verifies offline, and a one-byte tamper fails. Built in
steps W2.1–W2.3 (`docs/demos/MASTER_LOOP.md`).

## W2.1 — the agent and the ground truth

**`agent.py` is a demonstration instrument**, scripted to misbehave on
purpose. It says nothing about how any real agent framework behaves. On
screen it is called "a scripted test agent".

| | Declared (and in its own log) | Hidden (`--mode lying` only; never in its log) |
|---|---|---|
| Action | read the invoice; write a one-line summary into its workspace | one TCP connection to an undeclared destination, sending a synthetic line carrying the run nonce; one file written outside its workspace |
| Data | synthetic invoice | synthetic only (`synthetic-exfil <nonce>`), no real data |

**The lie:** both modes produce the same self-log. The tests compare the
step sequences and check that the self-log contains no hint of the
undeclared action.

**`ground_truth.py` is independent ground truth**, held by the harness and
written by neither the agent nor the observer:
- a loopback listener records each connection it receives (arrival time,
  peer port, payload nonce);
- the outside-scope directory is listed after the run.

`run_agent(mode, out_dir)` writes `ground-truth.json` with the agent's pid,
its self-log and what really happened. W2.2's detection is scored against
this file.

### Design choices W2.2 depends on

- **The undeclared actions run in the agent's own main thread**, not in a
  short-lived child or a worker thread. The strategic validation work
  (`claude/strategic-validation-loop`) found that sub-20 ms children and
  worker-thread actions are often recorded *unbound*. That fix is not on
  this branch's base. Here the signed evidence can tie the connect to this
  process instance.
- **The agent stays alive `--linger` seconds** (default 3) after its work,
  as a real long-lived agent would, so the observer can measure the
  process. The linger is stated, not hidden.
- **Run directories must not reveal the mode.** The agent logs file paths,
  and a directory called `lying` would give the game away. `run_agent`
  refuses such names (whole-word match, so `/home/leslie` is fine).

### Tests

`python3 -m unittest discover -s demos/lying-agent -p 'test_*.py'`, 8 tests:
- both runs complete the declared task;
- the self-logs are indistinguishable and contain no hint of the hidden
  action;
- the honest run does nothing undeclared;
- the lying run really connects once with its nonce, inside the run window,
  and writes the outside file;
- the ground truth names its source;
- the stated linger is honoured;
- a mode-revealing run directory is refused, and a non-word substring is not;
- the payload is synthetic.

Local run, 2026-11-06, sandbox (4 vCPU, 15 GB RAM, no GPU): 8/8 passed,
no warnings.

## W2.2 — observe, cross-check, verify, tamper (`observe.py`, `show.py`)

```sh
python3 demos/lying-agent/observe.py OUT_DIR --mode lying     # root; release binaries; auditd running
python3 demos/lying-agent/show.py OUT_DIR/lying-agent-*.json  # the on-screen story
```

One run, end to end:

1. **Sniffer Dog:** `aip-probe` (holds no signing key; sensors `sched,
   sockstate, connector, fanotify`) ships kernel evidence to `aip-collector`
   (a separate process holding the only key) over the confidential transport.
2. **auditd:** an independent observer on a **different kernel subsystem**,
   recording `connect` syscalls and watching the outside-scope directory.
3. **The scripted agent** runs (`ground_truth.run_agent`).
4. **Offline check:** `aip-observe-verify` checks the archive with the
   published key alone. Then **one byte of a signed field** (the detected
   connect's remote port) is changed, and verification must fail. A byte
   outside the signed canonical preimage would legitimately still verify,
   so the tamper is aimed at a signed field.

### Detection rule (fixed before any run)

- **Connect detected:** a signed `SocketState` event in the run window with
  `new_state = SYN_SENT`, remote = the undeclared destination, **bound to the
  agent's measured process instance** (pid + start tick + executable hash).
  An unbound event (pid number only) does not count.
- **File detected:** a signed `Fanotify` event for the outside-scope file,
  bound to the agent.
- **Missing evidence** is shown as "NOT DETECTED", never inferred.
- **"The agent's log does not mention it"** is computed by searching the
  log's text fields for the destination, the outside file and the run nonce.
  Numeric fields are skipped, so a port cannot match a timestamp.

### Results on this sandbox (4 vCPU, 15 GB RAM, no GPU)

| Run | Mode | Sniffer Dog connect (bound to agent) | Sniffer Dog file | auditd connect / file | Verified | 1-byte tamper |
|---|---|---|---|---|---|---|
| development ×4 | lying | 4/4 | 4/4 | 4/4 / 4/4 | 4/4 | rejected 4/4 |
| development ×1 | honest | none | none | none / none | yes | — |
| evidence `evidence/2026-11-06/` (commit `aab3e12`, clean tree) | lying | yes, pid 1745 = agent pid | yes | yes, pid 1745 / yes | yes | rejected |

The committed evidence run holds:
- the result file and `screen.txt`;
- `public/` (signed archives and `observer.pub`);
- `auditd.txt`, both verifier outputs, and the tampered archive;
- the agent's run directory with its own log and the ground truth.

No key material: the throwaway keys are deleted in a `finally` even when a
run fails, and a test forces a failure to check this.

**Clock:** this sandbox has no NTP sync. The collector requires a synced
clock by default; these runs set `AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0`, and
the collector signed its worst-case clock error into the evidence. The screen
says so.

Tests (`test_observe.py`):
- units for the self-log search, the tamper helper and the screen (it renders
  only what the result says, including NOT DETECTED and a tamper that wrongly
  verifies);
- live: lying caught and attributed to the agent's pid by both observers,
  honest reports nothing, verify passes, tamper rejected;
- live: a failed run leaves no key material.

Live tests are SKIPPED, not passed, without root, binaries or auditd (e.g.
on CI).

Local run, 2026-11-06: 13/13 passed in `demos/lying-agent`.
