# Pull the plug (W1)

Side by side: an ordinary cloud-API assistant and AIRON Native. Pull the
cable; one fails, one keeps answering with citations, and a live meter shows
0 bytes out. Built in steps W1.1–W1.4 (`docs/demos/MASTER_LOOP.md`).

## W1.1 — the cloud-API side (`cloud_app.py`)

The contrast, not the product. It sends each question to a remote
OpenAI-compatible `chat/completions` endpoint.

- **Nothing embedded.** No default endpoint and no key exist in this file or
  the repository. The operator supplies `CLOUD_API_URL` (and optionally
  `CLOUD_API_KEY`, `CLOUD_MODEL`, `CLOUD_TIMEOUT_S`) at demo time. Without an
  endpoint the app makes no network call and reports *"not configured — this
  app requires internet and a cloud endpoint"*.
- **Never invents an answer.** It returns only text the endpoint sent; a
  malformed reply is `failed / malformed_response`.
- **Fails cleanly, with the real reason:** `no_route`, `dns_unavailable`,
  `timeout`, `connection_refused`, `http_<code>`, `malformed_response`. When
  a proxy is in the path the result carries `via_proxy`, so an offline
  "refused" by a local proxy is not mistaken for the cloud refusing.
- **The key is never output**: it is sent as a bearer header and appears in
  no result or log.

```sh
python3 demos/pull-the-plug/cloud_app.py ask "What is the refund policy?"   # JSON; exit 0 only if answered
```

Tests: `python3 -m unittest discover -s demos/pull-the-plug -p 'test_*.py'`,
11 tests, all against a local mock on `127.0.0.1`; none contacts a real API.
Two run the app in a real offline namespace via `demos/common/harness.py` and
are SKIPPED (not passed) where user namespaces are unavailable.

Local run, 2026-11-06, sandbox (4 vCPU, 15 GB RAM, no GPU): 11/11 passed,
0 skipped.

Note for the owner: the brief's "never use a model API" applies to the
demos' own models (W0.3). This app is the deliberate counter-example the
brief asks for in W1.1, and it calls only an endpoint the operator configures
at demo time.

## W1.2 — the live meter (`meter.py`)

Per answer, for both sides, every figure measured during that answer and
labelled with its source:

| Field | Source | Notes |
|---|---|---|
| strategy, outcome, sources, model calls, prompt/completion tokens, escalations, per-component CPU-s, runtime wall ms | **runtime-reported** (`syntriass serve --eval` → `{"id", "response": Response}`; a `{"error"}` reply is a failure carrying the runtime's message; `ask`'s bare `Response` is also read) | A field the runtime did not report is `null`, never filled in |
| wall ms, child CPU-seconds | **measured by the meter**, around the call (`getrusage(RUSAGE_CHILDREN)` delta) | Independent of the runtime's own report |
| bytes out | **measured by the meter**: change in this network namespace's **non-loopback** transmit counter | Offline demo namespace: only the demo runs there. On a connected host the counter is namespace-wide, and the result says so |
| ₹ per answer | computed only from operator-set rates: `METER_INR_PER_CPU_HOUR` (local), `METER_INR_PER_1K_TOKENS` (cloud) | No rate → **no rupee figure** ("rate not set"). The cloud side gets a figure only if the endpoint reported token usage. Formula and rate are always in the result |

```sh
echo '<request json>' | python3 demos/pull-the-plug/meter.py local <syntriass serve --eval ...>
python3 demos/pull-the-plug/meter.py cloud "What is the refund policy?"
```

Tests (`test_meter.py`, 10 of the 21 in this directory):
- a stand-in runtime prints a `Response` in the runtime's JSON shape and burns 0.3 s of real CPU, which the meter measures from outside (≥ 0.25 s);
- missing runtime fields stay `null`;
- unparseable output is a failure with no runtime figures;
- rupee figures appear only with a rate;
- offline, bytes out is **0 even when the runtime attempts an outbound connection** (namespace test, SKIPPED-not-passed without user namespaces);
- a drift guard fails if any runtime field the meter reads is renamed in `sovereign/syntriass-runtime/src/app.rs`.

**Not yet shown:** the meter against the real `syntriass` binary. That needs a
staged model, so it happens in W1.4, after W0.3.

Local run, 2026-11-06, sandbox (4 vCPU, 15 GB RAM, no GPU): 23/23 passed in
this directory, 0 skipped, no warnings.

Correction (same day): the first W1.2 commit read the `serve --eval` envelope
as if it were the `Response`, so against the real binary every runtime field
would have been null. Fixed, with the stand-in now emitting the real envelope
and a drift guard pinning it in `src/bin/syntriass.rs`.
