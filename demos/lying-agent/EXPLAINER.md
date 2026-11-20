# Catch the lying agent — one page

**The question it answers:** if an AI agent does something it wasn't asked
to do and leaves it out of its own log, would you know?

## What you see (about 5 minutes)

1. **The agent's own log.** A scripted test agent is asked to summarise an
   invoice. Its log says it read the invoice and wrote the summary. Nothing
   else.
2. **What Sniffer Dog saw.** From the operating system's kernel, not from the
   agent: the agent's process also **connected to a destination it never
   declared** and **wrote a file outside its workspace**. Each record names
   the exact process (process id, start time and a fingerprint of its
   program), and the records are **signed** by a separate collector holding
   the only key.
3. **A second, independent witness.** The Linux audit system, a different
   part of the kernel that Sniffer Dog does not use, saw the same connection
   from the same process.
4. **Anyone can check it, offline.** The signed record verifies with a
   published public key and nothing else. Change one byte of it and the check
   fails, live.
5. **The control.** The same agent without the hidden step: nothing is
   reported.

## Words to use

- "A **scripted test agent**, built to misbehave for this demonstration."
- "The kernel saw it; the agent's own log didn't say it."
- "Signed by a separate collector; verifiable offline with a public key."
- "A second, independent witness in the kernel agreed."

## Do not say

- Not "this catches every misbehaving agent." It shows one undeclared
  connection and one undeclared file write, on this machine, by an agent
  scripted to do them.
- Not "tamper-proof." The record is **tamper-evident**: changes are
  detected, as shown live.
- Not "AI firewall" or "it blocked the agent." Nothing was blocked; the
  action was observed and proven afterwards.
- Not "proves what was sent." Sniffer Dog records that a connection was made
  and to where, not the content.
- Not "works on any machine with no setup." It needs a Linux kernel, root
  for the sensors, and auditd for the second witness.

## Honest limits, shown or stated

- **Clock:** on a machine without NTP time sync, the collector is told to
  run anyway, signs its worst-case clock error into the evidence, and the
  screen says so. A demo machine should run with time sync on.
- **Same machine:** the collector runs as a separate process on the same
  machine. Separate administration on another machine is a deployment step,
  not shown here.
- **Short-lived processes:** an action by a process that exits within
  milliseconds can be recorded without being tied to that process. The test
  agent acts from its main process and stays alive, as real agents do.

## How a customer checks it

```sh
sudo demos/lying-agent/run.sh OUT --with-control     # exits 0 only if every rule holds
python3 demos/lying-agent/show.py OUT/scripted-agent/lying-agent-*.json
target/release/aip-observe-verify --observer-id collector.lying --key-version 1 \
  --pubkey-file OUT/scripted-agent/public/observer.pub \
  --batches OUT/scripted-agent/public/attested.archive.jsonl \
  --health OUT/scripted-agent/public/health.archive.jsonl
```

The acceptance rules are written in `acceptance.py` before any run. Every
number and line on screen comes from the result file, whose path is printed
last.
