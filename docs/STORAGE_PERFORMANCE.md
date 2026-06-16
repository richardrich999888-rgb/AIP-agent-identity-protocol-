# Storage Performance — PostgreSQL Evidence Vault

Real measurements from the `pg_benchmark_10k` integration benchmark, run
against PostgreSQL 16 over localhost (single-threaded client, sequential
operations). Reproduce:

```bash
AIP_TEST_DATABASE_URL=postgresql://aip:aip@127.0.0.1:5432/aip \
  cargo test --release --features postgres pg_benchmark_10k -- --ignored --nocapture
```

## Results (N = 10,000 packets)

| Operation | Result | Notes |
|---|---|---|
| **Insert** (store) | **~228 packets/sec** · **~4.4 ms/packet** | Each `store` is one transaction: tenant check + packet INSERT + ~7 authority-node INSERTs + ~6 authority-edge INSERTs (~15 round-trips) |
| **Get by id** | **~0.29 ms mean** (1,000 lookups) | Primary-key + tenant indexed lookup |
| **Fetch tenant (10k)** | **~456 ms** | `all_for_tenant` — full scan of one tenant's packets |
| **Authority query (10k)** | **~475 ms** | fetch tenant packets + build in-memory index + resolve action |

(Hardware/storage will shift absolute numbers; ratios are the point.)

## Interpretation

- **Get-by-id is fast and flat** (sub-millisecond) — the common auditor
  lookup ("show me this packet") scales fine.
- **Insert is transaction-bound**, not CPU-bound. ~4.4 ms/packet reflects ~15
  sequential statements per store for the materialised authority graph.
  Throughput rises substantially with client concurrency (the pool is sized
  16) and/or statement pipelining; the figure above is deliberately the
  pessimistic single-threaded sequential case.
- **Authority query cost grows with tenant size** because the current handler
  rebuilds the in-memory index from all of a tenant's packets per query
  (~475 ms at 10k). This is the known limitation carried over from the
  in-memory design.

## Known limitation & the materialised path

The `authority_nodes` / `authority_edges` tables are **already written** on
every store (tenant-isolated, indexed). The current `/v1/authority/{id}`
handler does not yet query them — it rebuilds from packets for backend
parity. The optimisation (no new schema needed) is to answer authority
queries with indexed SQL against those tables, turning the ~475 ms full
rebuild into an indexed lookup. Tracked as a follow-up; out of scope for this
storage-migration sprint (which was about durability, not query tuning).

## Scaling guidance for a pilot

- Get-by-id and single-packet verification: no concern at pilot scale.
- High insert throughput: increase client concurrency (multiple producers)
  and/or raise the pool size; consider batching authority-row writes.
- Large per-tenant authority queries: adopt the materialised-table query path
  before a tenant exceeds tens of thousands of packets.
