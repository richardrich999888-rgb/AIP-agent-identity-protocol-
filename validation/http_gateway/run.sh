#!/usr/bin/env bash
# Live B10 run: receipts issued at an HTTP API boundary, verified offline.
#
# Five acts, each of which must produce the stated outcome or the run fails.
# Nothing here is asserted by the gateway about itself: every receipt is
# checked afterwards by `aip-receipt-verify`, using only the published public
# key, and the upstream echoes the request it received so the commitment can be
# checked against what actually arrived.
#
# Needs: a built workspace, python3, curl. No kernel capability, no root.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/validation/http_gateway"
WORK="${AIP_HTTP_GATEWAY_WORK:-$HERE/results}"
BIN="$ROOT/target/debug"

UPSTREAM_PORT=8099
GATEWAY_PORT=8098
ISSUER="did:aip:institution:BANK"
GATEWAY="did:aip:gateway:EDGE-1"
AGENT="did:aip:agent:PAYMENTS-1"
DECISION="0123456789abcdef0123456789abcdef"

fail=0
note() { printf '\n== %s\n' "$*"; }
ok()   { printf '   PASS  %s\n' "$*"; }
bad()  { printf '   FAIL  %s\n' "$*"; fail=1; }

cleanup() {
  [[ -n "${UPSTREAM_PID:-}" ]] && kill "$UPSTREAM_PID" 2>/dev/null
  [[ -n "${GATEWAY_PID:-}"  ]] && kill "$GATEWAY_PID"  2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

for tool in "$BIN/aip-http-gateway" "$BIN/aip-route-map" "$BIN/aip-receipt-verify"; do
  [[ -x "$tool" ]] || { echo "missing $tool — run: cargo build -p aip-http-gateway"; exit 2; }
done
command -v curl >/dev/null || { echo "curl is required"; exit 2; }

rm -rf "$WORK"; mkdir -p "$WORK"
RECEIPTS="$WORK/receipts.jsonl"

# ── Setup: keys and a signed route map ───────────────────────────────────────
note "Setup — the institution signs its route map; the gateway gets its own key"
"$BIN/aip-route-map" keygen --out-private "$WORK/issuer.key" --out-public "$WORK/issuer.pub" 2>/dev/null
"$BIN/aip-route-map" keygen --out-private "$WORK/gateway.key" --out-public "$WORK/gateway.pub" 2>/dev/null
[[ "$(stat -c %a "$WORK/issuer.key")" == "600" ]] \
  && ok "private keys are created 0600, not chmod'ed afterwards" \
  || bad "private key mode is $(stat -c %a "$WORK/issuer.key"), expected 600"

"$BIN/aip-route-map" sign \
  --routes "$HERE/routes.json" --map-id "bank-edge" --issuer-id "$ISSUER" \
  --revision 1 --valid-from-ms 1700000000000 \
  --key "$WORK/issuer.key" --out "$WORK/route-map.json" >/dev/null 2>&1 \
  && ok "route map signed" || bad "route map would not sign"

"$BIN/aip-route-map" verify --map "$WORK/route-map.json" \
  --issuer-id "$ISSUER" --pubkey "$WORK/issuer.pub" > "$WORK/map-verify.txt" 2>&1 \
  && ok "an auditor verifies the map from the public key alone" \
  || bad "the signed map does not verify"

# ── Act 0: the gateway refuses to start on a map it cannot verify ────────────
note "Act 0 — a tampered route map must stop the gateway starting, not warn"
python3 - "$WORK/route-map.json" "$WORK/route-map-tampered.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["routes"][0]["tool_id"] = "tool.something.harmless"
json.dump(m, open(sys.argv[2], "w"))
PY
if "$BIN/aip-http-gateway" --listen "127.0.0.1:$GATEWAY_PORT" \
     --upstream "http://127.0.0.1:$UPSTREAM_PORT" \
     --route-map "$WORK/route-map-tampered.json" \
     --issuer-id "$ISSUER" --issuer-pubkey "$WORK/issuer.pub" \
     --gateway-id "$GATEWAY" --key-version 1 --gateway-key "$WORK/gateway.key" \
     --receipts "$WORK/should-not-exist.jsonl" >"$WORK/act0.txt" 2>&1
then bad "the gateway started on a route map that does not verify"
else ok "refused to start: $(head -1 "$WORK/act0.txt" | cut -c1-90)"
fi
[[ -f "$WORK/should-not-exist.jsonl" ]] && bad "a receipt sink was created despite the refusal" \
  || ok "no receipt sink was created"

# ── Start the real pair ──────────────────────────────────────────────────────
python3 "$HERE/upstream.py" "$UPSTREAM_PORT" & UPSTREAM_PID=$!
"$BIN/aip-http-gateway" --listen "127.0.0.1:$GATEWAY_PORT" \
  --upstream "http://127.0.0.1:$UPSTREAM_PORT" \
  --route-map "$WORK/route-map.json" \
  --issuer-id "$ISSUER" --issuer-pubkey "$WORK/issuer.pub" \
  --gateway-id "$GATEWAY" --key-version 1 --gateway-key "$WORK/gateway.key" \
  --receipts "$RECEIPTS" >"$WORK/gateway.log" 2>&1 & GATEWAY_PID=$!

# Readiness is probed on a path the route map does not name, so the probe is
# refused at admission and never reaches the receipt stream. A probe that
# receipted itself would inflate every count below by one, and the count is
# what Act 3 and Act 4 are actually asserting.
for _ in $(seq 1 50); do
  [[ "$(curl -s -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:$GATEWAY_PORT/__readiness__" 2>/dev/null)" == "404" ]] && break
  sleep 0.1
done

call() { # method path body...
  local method="$1" path="$2"; shift 2
  curl -s -o "$WORK/last-body.json" -w '%{http_code}' -X "$method" \
    "http://127.0.0.1:$GATEWAY_PORT$path" \
    -H "Content-Type: application/json" "$@"
}

# ── Act 1: an authorised transfer is forwarded and receipted ─────────────────
note "Act 1 — an authorised transfer: forwarded, and the receipt commits to it"
code=$(call POST /v1/transfers \
  -H "X-AIP-Agent-Id: $AGENT" -H "X-AIP-Decision-Id: $DECISION" \
  -d '{"amount":4000000,"beneficiary":"acct-9"}')
[[ "$code" == "200" ]] && ok "forwarded (HTTP $code)" || bad "expected 200, got $code"
grep -q '"beneficiary": "acct-9"' "$WORK/last-body.json" \
  && ok "the upstream received exactly the arguments the receipt commits to" \
  || bad "the upstream echo does not show the arguments"

# ── Act 2: the same tool, a different beneficiary ────────────────────────────
note "Act 2 — one field changed: a different commitment, which is the point"
call POST /v1/transfers \
  -H "X-AIP-Agent-Id: $AGENT" -H "X-AIP-Decision-Id: $DECISION" \
  -d '{"amount":4000000,"beneficiary":"acct-EVIL"}' >/dev/null

# ── Act 3: a request the institution never named ─────────────────────────────
note "Act 3 — an unrouted path: refused, never forwarded, no receipt possible"
code=$(call POST /v1/transfers/bulk \
  -H "X-AIP-Agent-Id: $AGENT" -H "X-AIP-Decision-Id: $DECISION" -d '{"n":1}')
[[ "$code" == "404" ]] && ok "refused (HTTP $code) — nothing reached the upstream" \
  || bad "expected 404, got $code"

# ── Act 4: an unidentified caller ────────────────────────────────────────────
note "Act 4 — no agent identity and no decision cited: refused before anything"
code=$(call GET /v1/beneficiaries)
[[ "$code" == "401" ]] && ok "refused (HTTP $code)" || bad "expected 401, got $code"
code=$(call GET /v1/beneficiaries -H "X-AIP-Agent-Id: $AGENT" -H "X-AIP-Decision-Id: nothex")
[[ "$code" == "400" ]] && ok "a malformed decision id is refused (HTTP $code)" \
  || bad "expected 400, got $code"

# ── Act 5: a named call the gateway cannot read is still receipted ───────────
note "Act 5 — a named tool with an unreadable body: refused AND receipted"
code=$(call POST /v1/transfers \
  -H "X-AIP-Agent-Id: $AGENT" -H "X-AIP-Decision-Id: $DECISION" -d '{not json')
[[ "$code" == "400" ]] && ok "refused (HTTP $code)" || bad "expected 400, got $code"

# ── Verification: offline, from the published key alone ──────────────────────
note "Verification — an auditor, offline, with only the gateway's public key"
"$BIN/aip-receipt-verify" --receipts "$RECEIPTS" --gateway-id "$GATEWAY" \
  --key-version 1 --pubkey "$WORK/gateway.pub" > "$WORK/receipts.txt" 2>&1
verify_rc=$?
cat "$WORK/receipts.txt"
[[ $verify_rc -eq 0 ]] && ok "every receipt verified" || bad "a receipt did not verify"

# Exactly the calls that named a tool AND identified a caller: the two
# transfers and the unreadable one. Acts 3 and 4 must contribute nothing.
count=$(grep -c . "$RECEIPTS" 2>/dev/null || echo 0)
[[ "$count" == "3" ]] \
  && ok "3 receipts: 2 forwarded transfers + 1 receipted refusal" \
  || bad "expected 3 receipts, found $count (acts 3 and 4 must produce none)"

# The two transfers differ in one field, so their commitments must differ.
# Selected by tool and disposition rather than by row number: row order depends
# on what else happened to be in the stream, and an assertion that depends on
# that is one that passes for the wrong reason.
mapfile -t commitments < <(
  awk '$2=="tool.transfer.create" && $4=="Forwarded" {print $NF}' "$WORK/receipts.txt"
)
if [[ ${#commitments[@]} -ne 2 ]]; then
  bad "expected 2 forwarded transfer receipts, found ${#commitments[@]}"
elif [[ "${commitments[0]}" == "${commitments[1]}" ]]; then
  bad "the beneficiary change did not change the commitment"
else
  ok "the two transfers commit differently: ${commitments[0]:0:12}... vs ${commitments[1]:0:12}..."
fi

# A receipt signed by someone else must not verify.
"$BIN/aip-receipt-verify" --receipts "$RECEIPTS" --gateway-id "$GATEWAY" \
  --key-version 1 --pubkey "$WORK/issuer.pub" >/dev/null 2>&1 \
  && bad "receipts verified under the WRONG key — the check is vacuous" \
  || ok "soundness control: the same receipts are refused under another key"

printf '\n'
if [[ $fail -eq 0 ]]; then
  echo "RESULT: PASS — artefacts in $WORK"
else
  echo "RESULT: FAIL — artefacts in $WORK"
fi
exit $fail
