# OpenTelemetry Collector — INSTALLED; nothing to collect

| | |
|---|---|
| Version | `otelcol` 0.111.0, linux/amd64 |
| Licence | Apache-2.0 |
| Install | GitHub release tarball — reachable and verified |
| Privileges | none |
| Modifies AIRI? | no |

```sh
mkdir -p /opt/otelcol
curl -sSL https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.111.0/otelcol_0.111.0_linux_amd64.tar.gz \
  | tar xz -C /opt/otelcol
/opt/otelcol/otelcol --version     # otelcol version 0.111.0
```

**It is installed and it is not used in the experiment**, for a reason worth
stating plainly: its role was to receive telemetry from OBI, and OBI produces
none on this kernel. A collector with no producer collects nothing. Running it
to make the tooling list look complete would be theatre.

## The trust rule it exists under

A collector normalises timestamps and preserves source identity. It does not
confer independence, and passing an observation through it must never raise
that observation's standing. Telemetry that arrives at a collector is exactly
as trustworthy as the thing that emitted it.

If a future run does have producers, the collector's output is a **transport
record**, not evidence, and belongs on the left of a reconciliation with
everything else the subject said about itself.
