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
