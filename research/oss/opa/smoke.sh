#!/usr/bin/env bash
# Live smoke run for item 1.2: OPA as a local decision server.
#
#   research/oss/opa/smoke.sh /path/to/opa
#
# Starts `opa run --server` on loopback with policy/ and data.json, asks for
# five decisions over HTTP and compares each with the expected one, then
# stops OPA and shows what a caller sees when OPA is down (connection
# refused). It exits non-zero on any mismatch.
set -euo pipefail
OPA=${1:?usage: smoke.sh /path/to/opa}
HERE=$(cd "$(dirname "$0")" && pwd)
ADDR=127.0.0.1:18181
URL=http://$ADDR/v1/data/vanian/mcp/decision
READY_TRIES=50   # x 0.1 s

"$OPA" version | head -1
"$OPA" run --server --addr "$ADDR" --log-level error "$HERE/policy/mcp_call.rego" "$HERE/policy/data.json" &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
for _ in $(seq $READY_TRIES); do curl -sf "http://$ADDR/health" >/dev/null && break; sleep 0.1; done
curl -sf "http://$ADDR/health" >/dev/null || { echo "FAIL: OPA did not become healthy"; exit 1; }
echo "opa pid $PID healthy on $ADDR"

fails=0
ask() { # name, input-json, expected-result-json
  local got
  got=$(curl -s -X POST "$URL" -H 'content-type: application/json' -d "{\"input\": $2}" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("result"), sort_keys=True))')
  local want; want=$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1]), sort_keys=True))' "$3")
  if [ "$got" = "$want" ]; then echo "ok   $1 -> $got"; else echo "FAIL $1 -> $got (want $want)"; fails=$((fails+1)); fi
}
ask allowed   '{"agent_id":"recon-reporter","server":"fs","tool":"read_file"}'  '{"allow":true,"reasons":[]}'
ask wrongtool '{"agent_id":"recon-reporter","server":"fs","tool":"write_file"}' '{"allow":false,"reasons":["call not in allowlist"]}'
ask revoked   '{"agent_id":"ex-worker","server":"fs","tool":"read_file"}'       '{"allow":false,"reasons":["agent revoked"]}'
ask unknown   '{"agent_id":"ghost","server":"fs","tool":"read_file"}'           '{"allow":false,"reasons":["call not in allowlist","unknown agent"]}'
ask malformed '{"agent_id":7}'                                                  '{"allow":false,"reasons":["malformed input"]}'

kill $PID; wait $PID 2>/dev/null || true
set +e
curl -s -o /dev/null -X POST "$URL" -d '{"input":{}}'
rc=$?
set -e
echo "after stop: curl exit $rc (7 = connection refused). The caller gets no decision and must treat that as deny."
[ "$rc" -eq 7 ] || { echo "FAIL: expected connection refused"; fails=$((fails+1)); }
echo "mismatches: $fails"
[ "$fails" -eq 0 ]
