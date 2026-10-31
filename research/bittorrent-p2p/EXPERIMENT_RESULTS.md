# Experiment results — central vs resumable central vs BitTorrent-style distribution

## Setup (identical for every method)

| Item | Value |
|---|---|
| Host | one 2-vCPU, 8 GB VM (HARDWARE_PROFILE in `research/compute-memory/`) |
| Network | 1 source + N peers, each in its own Linux network namespace, veth into one bridge; egress shaped with `tbf` (pyroute2 0.9.7); no route outside the testbed |
| Links | peers 100 Mbit/s each way; source 100 or 500 Mbit/s |
| Payload | seeded-PRNG incompressible file (64, 128, 256 MiB), SHA-256 published before transfer |
| Central baseline | `http_node.py`: threaded HTTP/1.1, zero-copy `sendfile`; `http_plain` ignores Range, `http_range` honours it |
| P2P | libtorrent 2.1.1: private BEP 52 v2-only torrent, 1 MiB pieces, DHT/LSD/UPnP/NAT-PMP off, static peer list, smart-ban |
| Measured by | kernel interface counters (bytes), `/proc/<pid>/stat` (CPU), `VmHWM` (memory), SHA-256 of every received copy |
| Code | `bench/bench.py`, `bench/run_matrix.sh`, `bench/summarize.py`; raw JSON in `results/` |

**Validity limit.** All nodes share two vCPUs and one kernel. Byte counts,
integrity, resume and authorisation behaviour are protocol facts and
transfer. Fleet times are **emulated-link** times and are pessimistic for
BitTorrent, whose six nodes compete for the same two CPUs (BitTorrent used
~66 CPU-seconds in a ~48 s run). No LAN performance claim is made.

## Iteration 1 — baseline matrix (27 runs, all copies verified)

5 peers, 256 MiB, median of 3 (range in brackets):

| Source link | Method | Fleet time (s) | Source sent (× payload) | All links sent (× payload) | CPU (s) | Peak RSS/node (MB) |
|---|---|---|---|---|---|---|
| 100 Mbit | http_plain | 113.1 [113.0–113.1] | 5.01 | 5.03 | 10.0 | 31 |
| 100 Mbit | http_range | 113.0 [113.0–113.3] | 5.01 | 5.03 | 9.8 | 32 |
| 100 Mbit | bittorrent | **47.7** [47.1–51.2] | **1.83** | 5.88 | 66.4 | 131 |
| 500 Mbit | http_plain | **23.1** [23.1–23.2] | 5.01 | 5.01 | 7.9 | 33 |
| 500 Mbit | http_range | 23.1 [23.1–23.3] | 5.01 | 5.02 | 8.2 | 31 |
| 500 Mbit | bittorrent | 28.5 [25.1–31.1] | 3.46 | 5.50 | 39.8 | 131 |

Variations (n = 1): 64 MiB at 100 Mbit — HTTP 28.9 s / BT 11.1 s; 3 peers at
256 MiB — HTTP 67.8 s / BT 47.8 s.

Reference floors at 100 Mbit: central = 5 × 256 MiB over 100 Mbit = 107 s
(measured 113 s, 95 %); swarm ≥ 21.5 s (one copy must cross a 100 Mbit
link). BitTorrent reached 2.2× its floor; CPU contention on this host is the
likely but **unverified** cause.

## Iteration 2 — interruption and resume

Peer p2 SIGKILLed at ≥ 50 %, restarted on its partial data (128 MiB):

| Method | Data re-received after restart |
|---|---|
| http_plain | 128 MiB (100 %: no Range → restarts from zero) |
| http_range | 64 MiB (50 %: exact remainder) |
| bittorrent, libtorrent defaults | 128 MiB (100 %) — **defect found** |
| bittorrent, `max_queued_disk_bytes` = 4 MiB | 64.4 MiB (50.3 %); re-check on restart kept 51.6 % of a 52.9 % download |

Root cause: libtorrent 2.1 queues up to 100 MiB (default
`max_queued_disk_bytes`) of verified pieces before writing; the model file did
not exist on disk at 94 % progress and appeared only at completion (observed with directory polling and
`/proc/<pid>/fd`). A crash loses everything queued. Bounding the queue fixed
resume, did not change speed (256 MiB: 51.0 s [48.2–51.3]) and cut peak memory
per node from 131 MB to 46 MB. `bt_node.py` now sets 4 MiB.

## Iteration 3 — integrity under a malicious seeder

p1 holds a copy with every 4th piece corrupted and announces all pieces
unchecked (libtorrent `seed_mode`). Result (128 MiB, both queue settings):
honest peers recorded 1–2 hash failures, smart-ban ended the exchange, and **all
four honest copies match the published SHA-256**. Corrupted bytes reached no
honest copy.

## Iteration 4 — who may join the swarm

3 peers, 64 MiB; p3 is an intruder that knows the source address.

| Configuration | Intruder bytes received | Honest peers |
|---|---|---|
| private torrent + static list, no TLS (control) | **69,702,907 (the whole file)** | complete, verified |
| SSL torrent; intruder cert from a rogue CA | **0** | complete, verified (9.5 s) |
| SSL torrent; intruder cert from the publisher CA but scoped to another release | **0** | complete, verified (8.5 s) |
| SSL torrent, no intruder | — | complete, verified (10.9 s) |

Finding on the way: libtorrent accepts a peer certificate for an SSL torrent
only when its CN/SAN equals the torrent name or `*`; leaves with arbitrary
CNs fail with `tlsv1 alert internal error`. This makes per-release scoping
possible (row 3) and makes `*` certificates dangerous (valid for every
release signed by that CA). Test keys are generated per run and deleted.

## Hypothesis outcomes

| ID | Verdict | Evidence |
|---|---|---|
| H1 swarming faster when source uplink is the bottleneck | **VALIDATED IN SCOPE** | 47.7 s vs 113 s (5 peers); 47.8 vs 67.8 s (3 peers) |
| H2 fewer source bytes | **VALIDATED IN SCOPE** | 1.8× vs 5.0× (100 Mbit); 3.5× vs 5.0× (500 Mbit) |
| H3 central at least as fast when source ≥ Σ client links | **VALIDATED IN SCOPE** | 23.1 s vs 28.5 s |
| H4 P2P costs more CPU and memory | **VALIDATED IN SCOPE** | ~6.6× CPU; 46 MB vs 31 MB per node (bounded queue) |
| H5 corruption cannot enter an honest copy | **VALIDATED IN SCOPE** (one corruption pattern, one malicious peer) | 0 corrupted copies |
| H6 resume without re-transfer | **VALIDATED after configuration fix**; FALSIFIED with defaults | 50.3 % re-received vs 100 % |
| H7 only publisher-certified, release-scoped nodes obtain pieces | **VALIDATED IN SCOPE**; private+static alone is **FALSIFIED** as access control | 0 vs 69.7 MB |

Reproduce: see `bench/README.md` (exact commands; ≈ 90 min on this host).
