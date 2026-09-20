# Blinding resilience — the five signals, and what each one actually catches

> **Status: normative, September 2026.** The single question this document
> answers: when the observer's delivery path is disrupted, does Sniffer Dog
> emit a signed integrity failure and return `CANNOT_PROVE`, or does it sign
> coverage it does not have? Every claim below names the code and the test.

## The problem, stated precisely from the kernel source

The perf loss counter (`PERF_RECORD_LOST`, `event->lost_samples`) is
incremented in exactly one place in the kernel: the `fail:` label of
`__perf_output_begin()` (`kernel/events/ring_buffer.c`), reached only when the
ring buffer is **genuinely full**. A kernel-resident attacker who hooks
*higher* — at `perf_event_output`, `perf_trace_run_bpf_submit`, or
`bpf_ringbuf_submit` — and returns early produces **no sample and no loss
record**. The drop is invisible to the sensor's own accounting. The netlink
connector's `ENOBUFS` is the same story from the other side: it fires on a
full receive queue, not on a hook that drops the message before the socket
sees it.

**The consequence for design: a single sensor's own loss counter cannot be
trusted to notice that the sensor has been blinded.** Any honest
blinding-detection has to rest on signals a submission-path hook does not
control.

## The five signals

| # | Signal | What it catches | What it does NOT catch | Where |
|---|--------|-----------------|------------------------|-------|
| 1 | **per-CPU `PERF_RECORD_LOST`** read into the batch's `dropped_events`, surfaced by the collector as counted loss → degraded epoch | Honest backpressure: a genuinely full ring under high syscall rate | A submission-path hook (the counter is never touched) | `aip-observe/src/perf.rs:556` (`PERF_RECORD_LOST => …`); collector `track_probe_stream` → `ProbeStreamFault::EventsLost` |
| 2 | **netlink `ENOBUFS`** on `recvmsg`, treated as first-class loss, never a silent retry; the probe forgets exec-time bindings across the gap | Connector receive-queue overflow | A hook that drops the connector message before the socket | `aip-observe/src/linux.rs` (`SourceError::EventsLost`); `aip-probe/src/sensors.rs` |
| 3 | **Cross-sensor divergence** — a gate-independent connector exec with no corroborating perf exec in-window, while perf is declared live → `Unverifiable` for the perf mechanism → `IntegrityUnknown` | **The submission-path hook.** This is the one signal that survives a hook on a single delivery path, because it rests on a *different* facility delivering what the hooked one did not | A hook that suppresses **both** paths at once, or the connector alone (the standing kernel-compromise limit) | `aip-observe/src/divergence.rs`; applied in `aip-collector/src/sink.rs` before attest |
| 4 | **Collector heartbeat + hash-chain sequence-gap** → `CANNOT_PROVE` for the interval | A frozen or starved probe (`SIGSTOP`, cgroup throttle): batches stop, or a sequence range does not continue | Nothing within a batch that was delivered intact | `aip-observe/src/continuity.rs`; `ProbeStreamFault::SequenceDiscontinuity`; health-freshness in `SignedSensorHealth::availability_for` |
| 5 | **Signed per-batch coverage** (`active_mechanisms` + `mechanism_integrity`; epoch intersection in `covered_by`), and the structural rule that a non-occurrence claim needs a gate-independent mechanism | A blinded sensor's silence is never read as *negative* evidence: absence of an event from a suppressed sensor cannot license "it did not happen" | It is a rule about what may be *claimed*, not a positive detector — signal 3 is the positive half | `SignedSensorHealth::covered_by_kernel_pushed_source`; `SourceMechanism::is_gate_independent_kernel_pushed` |

## Why signal 3 is the load-bearing one, and how it is expressed

Signals 1, 2 and 4 all read a sensor's own books or the chain's own
continuity. A hook that drops above the accounting defeats 1 and 2; a hook
that keeps batches flowing defeats 4. Signal 3 is the only one that does not
ask the possibly-hooked sensor whether it is well: it asks a *different*
kernel facility what happened and notices the disagreement.

The finding is recorded as `MechanismIntegrity::Unverifiable`, **not**
`ForeignTracepointGate`. That distinction is deliberate and honest:
`ForeignTracepointGate` asserts the probe *found* a foreign eBPF program on
the tracepoint's gate — a positive fact. Under a delivery-path hook the probe
finds nothing (its own detection query may itself be hooked). The collector
merely observes that one sensor delivered what another did not, and therefore
cannot establish that the silent sensor was capable. `Unverifiable` says
exactly that, and it already drives `ObserverState::IntegrityUnknown` through
the existing signer pathway.

The collector, as the attesting authority, records this finding into the
batch's own integrity reports before signing, overriding a probe's too-rosy
self-report for that cycle. A later batch with no divergence carries the
probe's `Verified` again, and recovery proceeds — the finding is per-cycle,
not sticky.

## The tests

- **Unit** (`aip-observe/src/divergence.rs`, 10 tests): agreement is not
  divergence; a missed connector exec is; silence is only divergence when the
  perf sensor was declared live; the window boundary; the `(pid, tgid)` join
  key; many gaps are one finding; only execs are comparable.
- **End-to-end exit gate** (`aip-collector/src/sink.rs`): a batch shaped
  exactly as a delivery-path hook produces it — connector delivered the exec,
  perf did not, **and the probe reported the perf sensor `Verified`** — still
  lands on `IntegrityUnknown` with attested coverage withdrawn. The negative
  control (both sensors deliver the exec) does not raise a finding.

## What this does not do — the limit, kept intact

Every technique that reaches these signals requires the attacker to already
hold kernel code execution (a loaded module, an LPE, or `CAP_BPF` +
`bpf_override_return`). This is the "root/kernel compromise of the observed
host" the technical brief lists as NOT defended. Signal 3 does not defeat a
kernel attacker: one who hooks **both** the perf path and the netlink
connector, or who hooks the connector alone, defeats it, and a full-root
attacker can additionally hide the program from any detection query.

The claim this document supports is exactly and only this: **when a common,
single-path delivery hook is present — which is what every public PoC
(TripleCross, ebpfkit, the 0xMatheuZ perf rootkit) actually deploys — Sniffer
Dog degrades to a signed `IntegrityUnknown` / `CANNOT_PROVE` rather than
signing a clean window it cannot justify.** That is a narrow, survivable
claim, and it is the honest one.
