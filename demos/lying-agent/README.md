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
