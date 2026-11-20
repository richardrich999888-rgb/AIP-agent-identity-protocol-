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

## W1.3 — the side-by-side page (`server.py`, `page.html`)

```sh
DEMO_LOCAL_CMD='["target/release/syntriass","serve","--eval","--config","<cfg>"]' \
DEMO_PRINCIPAL='{"tenant":"<tenant>","clearance":"<clearance>"}' \
python3 demos/pull-the-plug/server.py 8765          # → http://127.0.0.1:8765/
```

- **Local only.** Binds `127.0.0.1`. Requests whose `Host` header is not that
  origin get 403, which guards against DNS rebinding. Bodies are capped at 16 KiB.
- **Nothing external.** One self-contained page: inline CSS/JS, no CDN, font,
  remote script or style. A Content-Security-Policy restricts it to its own
  origin. The browser check confirms **zero requests** leave the origin.
- **Answers are data, not markup.** Everything is inserted with `textContent`;
  there is no HTML sink (`innerHTML`, `insertAdjacentHTML`, `document.write`).
- **Network indicator.** Every 2 s it shows the harness's route check:
  "OFFLINE — no network route" or "ONLINE — route via <interfaces>".
- **Traceable numbers.** One question goes to both sides concurrently through
  the meter. Each answer is written to a result file (`DEMO_RESULTS_DIR`,
  git-ignored by default), and the page shows its path. Meter rows carry
  their source label. No meter rows are shown for a side that made no call.

Tests (`test_server.py`, 32 in this directory in total):
- **Page and API:** no external references, no HTML sinks, CSP present;
  status reflects the route check; both sides answer and the shown result
  file matches; a foreign Host is refused; bad bodies are rejected;
  loopback bind only.
- **Real-browser check** (`browser_check.js`, Chromium via Playwright): no
  page errors, no external requests, both columns render.
- **End-to-end pulled plug:** the server runs inside the offline namespace
  with a cloud endpoint configured. The page shows OFFLINE; the local side
  answers with **0 bytes out**; the cloud side fails with `no_route`.

Two tests skip-with-reason (never pass): the browser check where Node or
Playwright is unavailable (CI runner), and the end-to-end test where user
namespaces are unavailable.

Fixed while building W1.3: `cloud_app.ask(env)` read proxies from the ambient
process environment instead of `env`. Proxy and `NO_PROXY` now come from the
same `env` as every other setting.

The local side in these tests is the stand-in runtime. W1.4 runs the real
`syntriass` binary.

Local run, 2026-11-06, sandbox (4 vCPU, 15 GB RAM, no GPU): 32/32 passed,
0 skipped, no warnings.
