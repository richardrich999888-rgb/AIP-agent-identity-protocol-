# OpenTelemetry eBPF Instrumentation (OBI) — BUILT, PRODUCES NOTHING HERE

| | |
|---|---|
| Repository | `github.com/open-telemetry/opentelemetry-ebpf-instrumentation`, HEAD `7ec9f37` |
| Licence | Apache-2.0 |
| Maintained | yes, actively (CNCF / OpenTelemetry) |
| Requirements | Linux 5.8+, BTF, root |
| Build | Go 1.25+ (fetched 1.27.1 via `GOTOOLCHAIN=auto`), clang for BPF |
| Status | **BUILT — FUNCTIONALLY BLOCKED** |

## Build (executed)

```sh
git clone --depth 1 https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation /tmp/airi_obi
cd /tmp/airi_obi && export GOTOOLCHAIN=auto
make generate     # 28 BPF objects, clang 18
make compile      # bin/obi, 128 MB
```

Both succeeded.

## Why it produces nothing

```
level=ERROR msg="Unable to load eBPF watcher for process events"
  component=discover.ProcessWatcher
  error="instrumenting function \"sys_bind\": setting kprobe: ...
         open /sys/kernel/tracing/kprobe_events: no such file or directory"
```

OBI's probe mix is 146 uprobes, 46 kprobes, 10 kretprobes, 4 tracepoints. The
uprobes would work here (`CONFIG_UPROBE_EVENTS=y`); its **process discovery**
and its kernel-side network instrumentation are kprobe-based, and
`# CONFIG_KPROBES is not set`.

Tested empirically rather than inferred: OBI was run against a live HTTP
workload (a local `http.server`, the subject agent's TCP request, and a `curl`)
for 14 seconds.

**Spans emitted: 0.**

So OBI is recorded as functionally blocked. It starts, it logs, and it observes
nothing — which is worse than being absent, because a running process with no
output invites the assumption that it is covering something.

## What is lost

OBI was the only candidate for MCP JSON-RPC visibility and GenAI telemetry.
Neither is obtainable in this environment, and no substitute was installed.

## Unblocking

A kernel with `CONFIG_KPROBES=y`. The build recipe above is unchanged and
already works.
