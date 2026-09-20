# Observer path — measured

Companion to `STORAGE_PERFORMANCE.md`, which covers the evidence vault. This
covers the signing and verification path: what it costs to attest a batch, and
what it costs an auditor to verify one.

Raw output, with the host it came from, is sealed at
`validation/perf/observer_path.txt`. Reproduce:

```bash
cargo test --release -p aip-observe --test throughput -- --ignored --nocapture
```

## Why this document exists

The technical brief previously declined to quote any performance figure on the
grounds that none had been measured. That was a defensible refusal and a poor
one. An institution deciding whether to put this beside a workload needs an
order of magnitude, and "we have not measured it" invites the reader to assume
the worst — or, worse, to assume nothing and discover the number in production.

The refusal was also inaccurate: the evidence vault has had measurements since
`STORAGE_PERFORMANCE.md`. It was the observer path that had none.

## Method

Fixed iteration counts, inputs built to a fixed shape, and percentiles taken
from the sorted sample by nearest rank — so every figure below is a value that
actually occurred, not an estimate. 2,000 batches, 100 discarded as warm-up.
Nothing is randomised: a benchmark that samples differently on each run cannot
be compared between two commits. The only nondeterminism is the Ed25519
signature nonce, which comes from the OS and does not affect the cost of
signing.

The benchmark is `#[ignore]`d. A timing assertion inside the ordinary test run
would be a flaky test: the suite must not fail because the machine was busy.

## Results

Host: Linux 6.18.44-fc-v37, 4 CPU, Intel Xeon @ 2.80 GHz, release build.
Batch canonical size 139 bytes. Single-threaded, in-process.

| Operation | Rate | Mean | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| Canonical encoding | ~6,400,000/s | 0.2 µs | 0.2 | 0.2 | 0.2 | 0.6 |
| Sign + chain, no persist | ~23,000/s | 43.3 µs | 41.3 | 61.1 | 70.0 | 214.2 |
| **Attest (persisted)** | **~2,500/s** | **394.6 µs** | 384.5 | 478.6 | 548.9 | 1079.7 |
| **Verify (offline)** | **~21,700/s** | **46.2 µs** | 43.1 | 64.7 | 85.3 | 149.4 |

## The result that matters

**Attestation is bound by storage, not by cryptography.** Of the 395 µs it
takes to attest one batch, 43 µs is signing and chaining and **351 µs (89%) is
writing the new chain position to disk.** The two rows are measured separately
for exactly this reason: the first question a reviewer asks about an
attestation rate is which of the two bounds it, and that deserves a number
rather than an opinion.

The consequence is practical. If a deployment needs more attestation
throughput, the lever is the storage path — batching the snapshot write,
faster media, or a different durability point — and **not** the signature
algorithm. Replacing Ed25519 would move 11% of the cost.

Two derived figures an operator can plan with:

- **Verifying a retained archive of 1,000,000 attested batches takes about
  46 seconds single-threaded.** Verification is a pure function of each record
  and parallelises trivially.
- **One collector sustains ~2,500 batches per second.** At the pilot's
  one-batch-per-second probe interval that is an upper bound of ~2,500 observed
  hosts per collector before attestation itself binds. It is arithmetic on one
  axis, not a capacity figure: network, lock contention and the archive write
  are excluded and will bind first.

## What these numbers are not

They are not a service level, and they are not a claim about a production
deployment. They exclude the network, the probe's own sampling cost, and the
disk the evidence archive lands on. They were taken on a development virtual
machine; the benchmark prints its host line for that reason, and **no figure
here should be quoted without it**.

They also say nothing about the observed workload's overhead, which is the
number an institution most wants and which cannot be obtained honestly from a
synthetic benchmark. That is a pilot measurement on the institution's own
hosts, against the institution's own agent.
