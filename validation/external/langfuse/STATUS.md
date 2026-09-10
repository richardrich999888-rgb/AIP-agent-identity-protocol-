# Langfuse — UNAVAILABLE, and it is open-core rather than open source

| | |
|---|---|
| Repository | `github.com/langfuse/langfuse`, HEAD `4c63fad` |
| Licence | **MIT Expat, except `ee/`, `web/src/ee/`, `worker/src/ee/`** which are under a separate licence in `ee/LICENSE` |
| Status | **UNAVAILABLE** |

## Licence, checked rather than assumed

The mandate asked for verification that each project is *genuinely* open
source. Langfuse is **open-core**. Its own `LICENSE` says so:

> All content that resides under the "ee/", "web/src/ee/", and/or
> "worker/src/ee/" directories … is licensed under the license defined in
> "ee/LICENSE".

The `ee/` directory exists in the clone. The core is MIT; the enterprise
portion is not. That is a material distinction for a project being adopted as
validation tooling, and it is recorded rather than rounded to "MIT".

## Why it is unavailable

Self-hosting requires six container images:

```
docker.langfuse.com/langfuse/langfuse-worker:4
docker.langfuse.com/langfuse/langfuse:4
docker.io/clickhouse/clickhouse-server:25.12
cgr.dev/chainguard/minio
docker.io/redis:7
docker.io/postgres:17
```

Every registry involved is blocked by this environment's egress policy —
measured, not assumed:

| Host | Result |
|---|---|
| `docker.langfuse.com` | unreachable |
| `cgr.dev` | unreachable |
| `docker.io` | unreachable |
| `registry-1.docker.io` | 401 (API only; layer host blocked) |

No substitute was installed.

## The trust rule that would have applied

Langfuse records what an agent's SDK tells it. That makes a Langfuse trace a
**self-report with a durable store** — the same trust class as the AIRI event
chain itself, and emphatically not independent evidence. Had it been available
it would have appeared in the matrix beside the agent's own log, never beside
A3S or Tetragon.
