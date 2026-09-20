# B10 — receipt issuance at an HTTP API boundary

```
agent ──HTTP──▶ aip-http-gateway ──HTTP──▶ the institution's API
                      │
                      ├─ resolve against the institution's SIGNED route map
                      ├─ recompute the argument commitment ITSELF
                      └─ seal a SignedToolReceipt BEFORE the response returns
```

## What this closes

The kernel observer sees a socket from an agent to an API. It cannot see which
operation was invoked with what parameters inside that TLS session, and it must
not guess. So an unauthorised transfer surfaces today as *"a connection to a
registered destination"*, not as *"a transfer of ₹40 lakh to an unapproved
beneficiary"*. Only the party that terminates the request can close that gap.

`aip-mcp-gateway` does this for MCP. An institution's estate is HTTP.

## Run it

```bash
cargo build -p aip-http-gateway
validation/http_gateway/run.sh
```

No root, no kernel capability, no network. Needs `python3` and `curl`.

## Result (sealed in `sealed/`)

| Act | Request | Outcome | Receipt |
|-----|---------|---------|---------|
| 0 | gateway started on a route map whose `tool_id` was edited after signing | **refused to start** | none, and no sink created |
| 1 | `POST /v1/transfers` `{amount, beneficiary: acct-9}` | forwarded, HTTP 200 | `Forwarded`, commits `7ba190c6…` |
| 2 | the same call with `beneficiary: acct-EVIL` | forwarded, HTTP 200 | `Forwarded`, commits `3b46fc08…` |
| 3 | `POST /v1/transfers/bulk` — a path the institution never named | **refused, HTTP 404**, never forwarded | none possible: no tool to sign about |
| 4 | no `X-AIP-Agent-Id` / a malformed decision id | **refused, 401 / 400** | none possible: no agent, no decision |
| 5 | `POST /v1/transfers` with an unreadable body | **refused, HTTP 400** | `Refused`, commits `74234e98…` (the digest of `null`) |

**3 receipts, all verified offline from the published public key alone.**
Acts 3 and 4 contribute none, and that is asserted, not assumed.

Acts 1 and 2 are the point of the whole exercise: one field of the request
changed, and the commitment changed with it. That is what moves a finding from
"an unauthorised connection" to "an unauthorised transaction".

## Soundness controls

A demonstration that cannot fail proves nothing, so three things are checked to
be capable of failing:

* The same receipts are **refused** when verified under a different public key.
  Without this, "3 verified" could mean the verifier accepts anything.
* The route map with one `tool_id` edited after signing **stops the gateway
  starting**, and no receipt sink is created. Without this, the map's signature
  would be decoration.
* The readiness probe deliberately hits a path the route map does not name, so
  it is refused at admission and never enters the receipt stream. An earlier
  version of this script probed a real route; its probe was silently counted as
  a receipt and inflated every count below it. Fixed, and the count assertion
  now names exactly which calls should produce receipts.

## The upstream is a stand-in, and that is the honest scope

`upstream.py` echoes the request it received. That is deliberate: the run is not
about what an API computes, it is about whether the receipt commits to exactly
the request the API received — checkable only if the upstream reports it back.

**What this run does not show:** the gateway in front of a real institutional
API, under real load, with a real decision point issuing the expectations these
receipts would be compared against. That is B8 and pilot Phases 2–3. This is the
issuance half of B10, built and demonstrated; the deployment half is integration
work on an institution's own estate.

## Known scope limits, stated rather than discovered

* **A non-JSON response commits to nothing.** A tool answering in CSV or a
  binary format has its request receipted and its answer uncommitted. Closing
  this needs a commitment defined over opaque bytes, which is a format change.
* **The gateway cannot see a path it is not in front of.** A deployment that
  leaves a second route to the same API has a bypass, and no property of this
  crate detects it — the kernel probe and the out-of-band reconciler are what
  cover that, which is why the three deploy together.
* **Availability is traded for accountability.** The receipt is written and
  flushed *before* the response returns; if the sink fails, the request fails. A
  forwarded call whose receipt was lost is exactly the unaccounted effect this
  system exists to prevent. An operator needing the other trade needs a
  different tool.
* **`keygen` writes keys to files.** For a lab or a first bootstrap only. A file
  key is a copyable key; production keys belong in an HSM (`aip-hsm`).

## Where the artefacts live

`results/` is scratch — `run.sh` deletes and recreates it on every run, and it
is git-ignored because it contains freshly generated private keys. `sealed/`
is the committed snapshot of one run, with the matching **public** keys, so
the receipt stream can be re-verified from the repository alone:

```bash
target/debug/aip-receipt-verify \
  --receipts validation/http_gateway/sealed/receipts.jsonl \
  --gateway-id did:aip:gateway:EDGE-1 --key-version 1 \
  --pubkey    validation/http_gateway/sealed/gateway.pub
```
