# aip-sentinel-feed

Render AIP's attested kernel evidence as an effect log an out-of-band
reconciler can tail.

```
AttestedBatch*  ──▶  verify under the observer's anchor  ──▶  effects.jsonl
   (collector-signed)        (fail closed: exit 1, no output)
```

## Why

Everything else in this system is *inline*: it proves what went through the
funnel. It has no answer for an agent that declines to use the funnel, and a
stricter funnel does not help — a stricter funnel is still one an agent can
route around. Catching that needs reconciliation against a sensor outside the
governed channel.

`orbitaltrust-accountability/rust/ot-sentinel` is that reconciler. Its effect
sensor tails a JSONL log of process spawns and network egress, and its own
source records that the detector behind it "had nothing feeding it". The logs
it was designed for are written by the components being watched — a tool
server's access log is the tool server's account of itself.

This feed replaces that root. AIP observes spawns and connections from the
kernel, binds them to instances through pidfd, and has an off-host collector
sign the result.

**The coupling is a file.** This crate does not depend on `ot-sentinel` or on
its evidence chain. See `docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md` (closed,
option A) for why that matters and what is forbidden.

## Run it

```bash
cargo run -p aip-sentinel-feed -- \
  --observer-id collector.phase1 --key-version 1 \
  --pubkey-file integrations/agents/results/sealed/observer.pub \
  --batches    integrations/agents/results/sealed/attested.archive.jsonl \
  --out        integrations/agents/results/sealed/effect_feed.jsonl
```

Exit `0` with a feed, `1` if the archive did not verify (nothing is written),
`2` on bad arguments.

## The sealed result, and what it says about coverage

Against Phase 1's real LangGraph archive:

```
2 batches verified; emitted 22 records (21 spawn, 1 egress, 1 with measured
bytes); not rendered 188 (fork without bound execution 74, exec start
unverified 0, connect attempt not established 0, no clock anchor 0, timestamp
before epoch 0, unbound: spawn 22 exec 84 connect 8)
```

Sealed at `integrations/agents/results/sealed/effect_feed.jsonl`. The 21
spawns agree with the 21 delegation edges Phase 3 derives from the same
archive.

Every observed event is accounted for, and the accounting balances exactly
(117 forks = 21 + 74 + 22; 105 execs = 21 + 84; 9 connect initiations =
1 + 8). `sf15` asserts that equation as a test.

**Read the second number.** 84 of 105 `execve`s could not be bound to a
measured instance: the workload was `bash` spawning short-lived children that
exited before the probe could complete a pidfd-anchored measurement. That is
the documented `bound: null` case — "saw the exec, could not measure it" — and
this is the first artefact that shows its *magnitude* on a busy host. It is a
coverage limit, it is reported rather than inferred, and it is the honest
answer to "what fraction of execution does the observer actually bind?" on a
workload of this shape.

## What this is not

Not independent corroboration. `ot-sentinel` was written by the same people as
AIP. Corroboration means an observer someone else built — see
`aip-corroborate` (bpftrace, auditd) and `aip-spiffe` (SPIRE). This completes
an architecture; it does not validate one.

## Tests

```bash
cargo test -p aip-sentinel-feed        # 34: rendering, drop rules, real archive, CLI gate
cargo test -p aip-feed-conformance     #  4: ot-sentinel parses the feed and acts on it
```

The second is the load-bearing one: it writes the real Phase-1 feed to disk,
reads it back through `ot-sentinel`'s own tailer (zero malformed lines), and
drives its detectors — with a soundness control proving the detector is not
simply always red.
