#!/usr/bin/env bash
#
# run_m3.sh — the same real-child-process task under three agent frameworks,
# observed by the key-less probe, attested by the separate-process collector,
# verified offline, and lineage derived — judged PER RUN against the pids the
# framework itself reported.
#
# Pre-registered per-run checks (fixed before any result was read):
#   present  : the run's parent pid AND child pid each appear in a kernel
#              event of the offline-verified archive
#   bound    : the child's SchedTracepoint ProcessExec carries a process-
#              instance binding (pid + start tick + exe hash), not a bare pid
#   edge     : aip-lineage, after re-verifying the archive, derives an edge
#              whose parent pid and child pid are exactly the run's pair
# Totals are reported per framework with their denominators. An edge between
# any other pair (the harness shell, the host) never counts.
#
# Frameworks: LangGraph (StateGraph), LlamaIndex Workflows, pydantic-ai
# (agent/tool loop with the framework's FunctionModel). NO language model in
# any of them; what is exercised is each framework's own orchestration putting
# a real process on the kernel.
#
# Usage: run_m3.sh <outdir> [RUNS_PER_FRAMEWORK]
# Env:   AIP_PROBE_DRAIN_INTERVAL_MS (recorded; 1000 = old once-per-batch ingest)
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
OUT=$(mkdir -p "$1" && cd "$1" && pwd); N=${2:-5}
B="$REPO/target/release"; AG="$REPO/integrations/agents"
DRAIN=${AIP_PROBE_DRAIN_INTERVAL_MS:-20}
die() { echo "m3: FAIL $*" | tee -a "$OUT/transcript.txt" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "needs root"
[ -r /sys/kernel/tracing/available_events ] || mount -t tracefs nodev /sys/kernel/tracing
declare -A PY=( [langgraph]="$AG/.venv/bin/python" [llamaindex]="$AG/frameworks/llamaindex/.venv/bin/python" [pydanticai]="$AG/frameworks/pydanticai/.venv/bin/python" )
declare -A SUBJ=( [langgraph]="$AG/agent_subject.py" [llamaindex]="$AG/frameworks/llamaindex/subject.py" [pydanticai]="$AG/frameworks/pydanticai/subject.py" )
for fw in langgraph llamaindex pydanticai; do [ -x "${PY[$fw]}" ] || die "venv missing for $fw"; done
{ echo "commit=$(git -C "$REPO" rev-parse HEAD) dirty_src=$(git -C "$REPO" status --porcelain -- aip-standalone | wc -l)"
  echo "kernel=$(uname -r) runs_per_framework=$N drain_interval_ms=$DRAIN batch_interval_ms=1000"
  echo "langgraph=$(${PY[langgraph]} -c 'import importlib.metadata as m;print(m.version("langgraph"))')"
  echo "llama-index-workflows=$(${PY[llamaindex]} -c 'import importlib.metadata as m;print(m.version("llama-index-workflows"))')"
  echo "pydantic-ai-slim=$(${PY[pydanticai]} -c 'import importlib.metadata as m;print(m.version("pydantic-ai-slim"))')"
  echo "require_synced_clock=0 (host unsynchronized; bound signed)"; } > "$OUT/params.txt"

W="$OUT/work"; mkdir -p "$W/state"; chmod 700 "$W"
PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
echo -n m3-pass > "$W/pass"
env AIP_PROBE_ID=probe.m3 AIP_PROBE_COLLECTOR_ENDPOINT=127.0.0.1:1 AIP_PROBE_COLLECTOR_NOISE_PUBKEY="$(printf '0%.0s' $(seq 1 64))" \
    AIP_PROBE_KEY_PATH="$W/probe.key.json" AIP_PROBE_SENSORS=sched timeout 4 "$B/aip-probe" > /dev/null 2>&1
PUB=$(python3 -c "import json;print(json.load(open('$W/probe.key.json'))['public_hex'])")
printf '[{"probe_id":"probe.m3","transport_pubkey_hex":"%s"}]\n' "$PUB" > "$W/probes.json"
env AIP_COLLECTOR_OBSERVER_ID=collector.m3 AIP_COLLECTOR_KEY_VERSION=1 AIP_COLLECTOR_KEY_PATH="$W/collector.key.wrapped" \
    AIP_COLLECTOR_PASSPHRASE_FILE="$W/pass" AIP_COLLECTOR_STATE_DIR="$W/state" AIP_COLLECTOR_LISTEN="127.0.0.1:$PORT" \
    AIP_COLLECTOR_PROBES_PATH="$W/probes.json" AIP_COLLECTOR_NOISE_KEY_PATH="$W/noise.key.json" \
    AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0 "$B/aip-collector" > "$W/collector.log" 2>&1 &
COLL=$!
for _ in $(seq 1 40); do [ -s "$W/state/noise.pub" ] && break; sleep 0.25; done
env AIP_PROBE_ID=probe.m3 AIP_PROBE_COLLECTOR_ENDPOINT="127.0.0.1:$PORT" AIP_PROBE_COLLECTOR_NOISE_PUBKEY="$(cat "$W/state/noise.pub")" \
    AIP_PROBE_KEY_PATH="$W/probe.key.json" AIP_PROBE_SENSORS=sched,sockstate,socksend,connector \
    AIP_PROBE_BATCH_INTERVAL_MS=1000 AIP_PROBE_DRAIN_INTERVAL_MS="$DRAIN" "$B/aip-probe" > "$W/probe.log" 2>&1 &
PRB=$!; PRB_T0=$(date +%s)
trap 'kill $PRB $COLL 2>/dev/null' EXIT
for _ in $(seq 1 40); do grep -q connected "$W/probe.log" && break; sleep 0.25; done
grep -q connected "$W/probe.log" || die "probe did not connect: $(tail -2 "$W/probe.log")"
sleep 2

: > "$OUT/agent.log"
for i in $(seq 1 "$N"); do
  for fw in langgraph llamaindex pydanticai; do
    "${PY[$fw]}" "${SUBJ[$fw]}" "/tmp/aip_m3_${fw}_$i" 2>&1 | sed "s/^/[$fw] /" >> "$OUT/agent.log"
    rm -f "/tmp/aip_m3_${fw}_$i"
    sleep 0.3
  done
done
A0=$(grep -c "batch acked" "$W/probe.log")
for _ in $(seq 1 300); do [ "$(grep -c "batch acked" "$W/probe.log")" -ge $((A0 + 2)) ] && break; sleep 0.1; done
# Probe CPU over the whole run (utime+stime ticks) and wall time, for the
# drain-interval cost tradeoff.
read -r UT ST < <(awk '{print $14, $15}' /proc/$PRB/stat)
echo "probe_cpu_ticks=$((UT + ST)) clk_tck=$(getconf CLK_TCK) probe_wall_s=$(( $(date +%s) - PRB_T0 ))" > "$OUT/probe_cost.txt"
kill $PRB; wait $PRB 2>/dev/null; kill $COLL; wait $COLL 2>/dev/null; trap - EXIT

S="$W/state"
"$B/aip-observe-verify" --observer-id collector.m3 --key-version 1 --pubkey-file "$S/observer.pub" \
    --batches "$S/attested.archive.jsonl" --health "$S/health.archive.jsonl" > "$OUT/offline_verify.txt" 2>&1
echo "verify_exit=$?" >> "$OUT/offline_verify.txt"
"$B/aip-lineage" --observer-id collector.m3 --key-version 1 --pubkey-file "$S/observer.pub" \
    --batches "$S/attested.archive.jsonl" > "$OUT/delegation_chain.txt" 2>&1
echo "lineage_exit=$?" >> "$OUT/delegation_chain.txt"
cp "$S/attested.archive.jsonl" "$S/health.archive.jsonl" "$S/observer.pub" "$W/collector.log" "$W/probe.log" "$OUT/"
rm -rf "$W"   # throwaway keys
python3 "$HERE/analyze_m3.py" "$OUT"
