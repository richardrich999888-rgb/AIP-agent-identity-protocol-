# LiteLLM usage and cost capture without Postgres (enterprise WOW loop, item 1.3)

**Answer: yes, through the SDK callback.** It works with no Postgres, no
network beyond loopback, and no enterprise code, but only with a capture
layer that undoes three places where LiteLLM reports `0` for something it
did not measure. The proxy custom-logger path was **not tested**: see "Proxy
path" below for why.

## Setup

- `python3 -m venv core && core/bin/pip install 'litellm==1.110.2'`. This is
  the core install, without the `[proxy]` extra. The resolved set is 60
  packages, frozen in `requirements-core.lock.txt` (`pip freeze`; versions
  only, no hashes).
- Python 3.11.17.
- `LITELLM_LOCAL_MODEL_COST_MAP=True`, so LiteLLM uses its bundled cost map
  instead of fetching one.
- The model is `mock_openai.py`, a deterministic OpenAI-compatible server on
  127.0.0.1. Its text and usage are **TEST DATA**. Prices are declared **test
  prices**: input 1e-6 and output 2e-6 USD per token.

## Results

| Check | Command | Result |
|---|---|---|
| Unit tests | `python3 -m unittest test_capture test_mock_openai` | 23 passed / 0 failed / 0 skipped |
| Mutations of `capture.py` | `mutations.txt` | 3/3 caught |
| Acceptance, offline | `env -u DATABASE_URL LITELLM_LOCAL_MODEL_COST_MAP=True unshare -n core/bin/python acceptance.py records.jsonl --isolated` | **16/16 checks**, exit 0 (`acceptance-run.txt`, records copied to `acceptance-records.txt`, since the repo ignores `*.jsonl`) |
| LiteLLM's own raw values | `… unshare -n core/bin/python raw_zeros.py --isolated` | `raw-zeros.txt` |

The acceptance run covers five calls:

- a priced call: tokens 3/5/8 from the provider, and cost = 3×in + 5×out;
- an unpriced model;
- a provider response with no `usage`;
- a provider HTTP 500;
- a call missing `owner` metadata.

It also asserts four things:

- one record per call;
- every record is labelled TEST DATA;
- no `DATABASE_URL` is set;
- no module named `*enterprise*` was loaded.

`--isolated` runs in a fresh network namespace, with only loopback up, and
checks that `pypi.org` does not resolve.

## Findings

1. **LiteLLM reports 0 for unmeasured cost and tokens** (`raw-zeros.txt`):
   - for an unpriced model, `response_cost` is `0.0`;
   - when the provider sends no `usage`, tokens are `0/0/0` and cost is
     `0.0`, with status `success`;
   - when the call fails, tokens and cost are 0.

   Consuming `standard_logging_object` directly would show "no telemetry"
   as 0, which adversarial #12 forbids. `capture.py` maps all three cases to
   `None` with a stated `cost_basis`. It reads whether usage was reported
   from the raw provider response (`original_response`), and whether the
   price was unknown from `response_cost_failure_debug_info`.
2. **Callback exceptions are swallowed.** LiteLLM calls the hooks with
   keyword arguments. A hook with other parameter names raised `TypeError`,
   and LiteLLM logged that only at debug level, as "[Non-Blocking]". The
   capture silently recorded nothing. The adapter counts what it writes; the
   caller must compare that count with the number of calls it made (the
   acceptance run does).
3. **The `[proxy]` extra installs proprietary code, and `import litellm`
   loads it.** `pip install 'litellm[proxy]==1.110.2'` pulls in
   `litellm-enterprise==0.1.83.post1`. Its metadata says
   `License-Expression: LicenseRef-Proprietary`, and its `LICENSE.md` is the
   BerriAI Enterprise license (SHA-256 `a3160d11…e1b2f9`). With it installed,
   a plain `import litellm` loads `litellm_enterprise.*` modules. The core
   install has no such package and loads none.
4. Per-call metadata (`agent_id`, `workflow`, `owner`) arrives in
   `kwargs["litellm_params"]["metadata"]`. It is **not** in
   `standard_logging_object.metadata`, where `requester_metadata` was `None`.

## Proxy path

Not tested. The proxy needs the `[proxy]` extra, and that extra brings in
and loads the proprietary package (finding 3). Its license allows
development and testing without a subscription, but this loop's rule
(matrix, item 1.1) is to import nothing under it. Whether the proxy runs
without Postgres is therefore **not established**. It is also not needed:
the SDK path answers the question.

## What this does not show

- That an agent's metadata is true. Attribution here is whatever the caller
  passes in `metadata`. Binding it to a verified agent identity is the
  gateway's and event store's job (2.1 and 4.1), not LiteLLM's.
- Real tokenizer counts or real prices. Both are TEST DATA.
- Streaming, async calls or retries. Only synchronous `completion()` was
  exercised.
- Writing into the event store (2.1 depends on 0.1, which is blocked).
  Records go to a JSONL file.
