# Item 1.4 (P2): OTel Collector, OpenLIT, Falco

This was run on 21 Nov 2026, before the Sat 06:00 IST checkpoint, in the
cloud session container.

| Project | Pin | How obtained | Result | Verdict |
|---|---|---|---|---|
| OTel Collector (core) | `v0.165.0`, commit `e883d737e499` (same as `../survey.json`) | `cmd/otelcorecol` built from that commit with `go build -trimpath` (go1.26.11). It is not published as an installable module past v0.63.0. Binary SHA-256 `cd37abe8…791c`; it reports `0.165.0-dev`. | Receives OTLP/HTTP and forwards JSON through `otlphttp` (`encoding: json`). Works offline. | **USABLE** as an export pipe. Not needed for P0. |
| OpenLIT SDK | `openlit==1.45.0` (the `py-1.45.0` tag in the survey) | pip, in a venv; 62 packages in `requirements-openlit.lock.txt` | `chain.py`, offline: **3 passed / 0 failed checks**. Spans pass through the collector; `gen_ai.usage.input_tokens` = 3 and `output_tokens` = 5 equal the mock's TEST DATA. See findings. | **INSTRUMENTATION ONLY.** Do not use its cost. |
| Falco | `falcosecurity/falco:0.45.2`, digest `sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e` | `docker pull` | It starts and loads rules, then aborts: `libpman: unable to bump RLIMIT_MEMLOCK … Operation not permitted`. 0 events. | **BLOCKED_BY_INFRASTRUCTURE**, final for this host. |

## Findings

1. **OpenLIT makes a network call at `init`.** It fetches `pricing.json`
   from `raw.githubusercontent.com`. Offline, it logs "Unexpected error
   occurred while fetching pricing info" and continues. An offline
   deployment must pass a local pricing file. Whether a local file removes
   the call was not tested.
2. **OpenLIT reports `gen_ai.usage.cost = "0"` when it has no price.** This
   is the zero-for-unmeasured failure already seen in LiteLLM (1.3). Never
   take cost from it. Cost comes from `llm_capture` (4.1a) with a declared
   price, or is shown as "no telemetry".
3. OpenLIT also exports logs. A collector with no logs pipeline answers 404
   ("Failed to export logs batch"). This is a configuration matter: add a
   logs pipeline, or disable OpenLIT's logs.
4. **Falco cannot run here.** The container lacks CAP_SYS_RESOURCE (CapEff
   `000001fffeffffff`, bit 24 clear), and the memlock hard limit is 8,192
   KiB. Both `docker run --ulimit memlock=-1:-1` and `prlimit` are refused
   (`falco-memlock-check.txt`, `falco-modern-ebpf.log`). On a normal host
   with that capability it may run, but that was **not tested**. The
   project's own probe sensors use tracefs and opened here (0.4).

## Reproduce

```
unshare -n sh -c 'python3 command-center/server/netns_lo_up.py && \
  OPENLIT_VENV/bin/python research/oss/openlit-otel/chain.py OTELCORECOL OUT.json'
```

Output of the recorded run: `chain-run.json`.
