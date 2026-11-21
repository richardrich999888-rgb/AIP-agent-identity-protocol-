# 3.4b live run: the collector killed mid-window (adversarial #15, #10)

Command, run three times on the cloud session container as root, on
loopback only:
`python3 command-center/lab/live_observer_kill.py OUT_DIR`

| Run | Checks | Batches verified and ingested | Last covered instant vs kill | DEGRADED first reported |
|---|---|---|---|---|
| 1 | 7/7 | 8 | −829 ms | about 9.5 s after the kill |
| 2 | 7/7 | 8 | −527 ms | 10,476 ms after the kill |
| 3 | 7/7 | 8 | −496 ms | 10,486 ms after the kill |

Run 1's values are in `run1/result.json`. Its DEGRADED time comes from the
first DEGRADED poll; polls are about 1 s apart.

What each run shows:

- **Real components.** The release `aip-collector` and `aip-probe` were used,
  with sensors sched, sockstate, socksend and connector. Every poll went
  through the real `aip-observe-verify`, and every poll verified.
- **After the SIGKILL.** No batch arrives. The probe logs `Connection
  refused`, and the store's coverage stops at the last signed window.
- **At task end.** The whole task window is **not** covered. The state is
  DEGRADED, and the open gap starts before the kill.

**Probe loss, observed once (21 Nov 12:41Z, `docs/enterprise-wow/evidence/3.4b-live-kill/run-loss-20261121/result.json`).**
During a `run.sh` pass, the probe reported **1 dropped event** (batch
sequence 4), and signed coverage stopped 5.1 s before the kill. The check
"pre-kill part of the task is covered" therefore **failed**, correctly: a
loss or a gap is never called clean. Two immediate reruns passed 7/7 with
no loss. Over the six kill runs so far, this is 1 failure. The cause of the
drop is not established. The container had restarted 11 min earlier.

Limitations, stated so they are not assumed:

- **State lag.** The summary state stays COVERED for up to
  `max_silence_ms` (10 s) after the observer dies, plus the last window's
  length. `window_covered()` is exact throughout: `covered_to_ms` stops
  advancing at the kill. A console must show "covered to <time>", never a
  bare green state.
- **No synced clock.** `AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0`, because this
  container has no NTP. The collector's clock is trusted.
- **Same host.** The collector and probe ran on one host, so this is not
  off-host custody.
- **Not run here:** the per-event Activity Explorer and the console banner
  (3.4c, blocked on 0.1).

Each `runN/` holds `result.json` (every poll), the collector and probe logs,
the collector's public key, and the signed archive. Private key material in
the work directory was **not** copied.
