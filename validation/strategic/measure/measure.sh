#!/usr/bin/env bash
#
# measure.sh — recall / precision / attribution / latency / overhead of the
# Sniffer Dog observation pipeline against an independent ground truth.
#
# Matching rules and denominators are fixed HERE, before any result is read:
#
#   Ground truth (GT): execs the workload launched (unique path + Popen pid)
#     AND that the independent ftrace reference saw (kernel-confirmed). An exec
#     the workload launched but ftrace did not see is reported separately and is
#     not in the denominator (the reference itself may have missed it).
#   Sched recall      = GT execs matched by a SchedTracepoint ProcessExec with
#                       the same unique filename  / |GT|
#   Sched precision   = marker-path ProcessExec records matched to GT
#                       / all marker-path ProcessExec records (dups counted)
#   Connector recall  = GT execs matched by a ProcConnector Exec with the same
#                       pid within the trial window / |GT|
#   Attribution acc.  = matched Sched records whose pid == the workload-recorded
#                       pid for that path / matched Sched records
#   Latency           = (a) kernel exec time - launch time (capture lag) and
#                       (b) batch attested_at - kernel exec time (exec->signed)
#   Overhead          = workload wall time with pipeline ON vs OFF, alternating
#                       trials, identical K and CONC.
#
# Scope limits (not claims): one host; collector is process-separated, not
# host-separated; ftrace reads the same sched tracepoint as SchedTracepoint
# (interface-independent only) while ProcConnector is a different kernel
# facility; the clock is unsynchronized here unless the host provides NTP.
#
# Usage: measure.sh <outdir> [TRIALS] [K] [CONC]
# Env:   AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK (default 1; recorded in results)
#        AIP_MEASURE_SENSORS (default sched,connector)
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
TRIALS=${2:-5}; K=${3:-200}; CONC=${4:-4}
CLOCKREQ=${AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK:-1}
SENSORS=${AIP_MEASURE_SENSORS:-sched,connector}
FT="$REPO/validation/linux/ftrace_observer.sh"
B="$REPO/target/debug"
die() { echo "measure: FAIL $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "needs root"
for x in aip-probe aip-collector aip-observe-verify; do [ -x "$B/$x" ] || die "missing $B/$x (build first)"; done
"$FT" preflight >/dev/null || die "ftrace reference unavailable"
{ echo "commit=$(git -C "$REPO" rev-parse HEAD)"; echo "kernel=$(uname -r)"; echo "trials=$TRIALS k=$K conc=$CONC";
  echo "require_synced_clock=$CLOCKREQ"; echo "sensors=$SENSORS"; nproc | sed 's/^/nproc=/'; } > "$OUT/params.txt"

start_pipeline() {  # $1 = trial dir
  local W="$1/work"; mkdir -p "$W/state"
  PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
  echo -n "measure-pass" > "$W/pass"
  env AIP_PROBE_ID=probe.m AIP_PROBE_COLLECTOR_ENDPOINT=127.0.0.1:1 \
      AIP_PROBE_COLLECTOR_NOISE_PUBKEY="$(printf '0%.0s' $(seq 1 64))" \
      AIP_PROBE_KEY_PATH="$W/probe.key.json" AIP_PROBE_SENSORS=sched \
      timeout 4 "$B/aip-probe" > "$W/keygen.log" 2>&1
  [ -s "$W/probe.key.json" ] || return 1
  local PUB; PUB=$(python3 -c "import json;print(json.load(open('$W/probe.key.json'))['public_hex'])")
  printf '[{"probe_id":"probe.m","transport_pubkey_hex":"%s"}]\n' "$PUB" > "$W/probes.json"
  env AIP_COLLECTOR_OBSERVER_ID=collector.m AIP_COLLECTOR_KEY_VERSION=1 \
      AIP_COLLECTOR_KEY_PATH="$W/collector.key.wrapped" AIP_COLLECTOR_PASSPHRASE_FILE="$W/pass" \
      AIP_COLLECTOR_STATE_DIR="$W/state" AIP_COLLECTOR_LISTEN="127.0.0.1:$PORT" \
      AIP_COLLECTOR_PROBES_PATH="$W/probes.json" AIP_COLLECTOR_NOISE_KEY_PATH="$W/noise.key.json" \
      AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK="$CLOCKREQ" \
      "$B/aip-collector" > "$W/collector.log" 2>&1 &
  COLL=$!
  for _ in $(seq 1 40); do [ -s "$W/state/noise.pub" ] && break; sleep 0.25; done
  [ -s "$W/state/noise.pub" ] || return 1
  env AIP_PROBE_ID=probe.m AIP_PROBE_COLLECTOR_ENDPOINT="127.0.0.1:$PORT" \
      AIP_PROBE_COLLECTOR_NOISE_PUBKEY="$(cat "$W/state/noise.pub")" \
      AIP_PROBE_KEY_PATH="$W/probe.key.json" AIP_PROBE_SENSORS="$SENSORS" \
      AIP_PROBE_BATCH_INTERVAL_MS=1000 \
      "$B/aip-probe" > "$W/probe.log" 2>&1 &
  PRB=$!
  for _ in $(seq 1 40); do grep -q connected "$W/probe.log" 2>/dev/null && break; sleep 0.25; done
  grep -q connected "$W/probe.log" || return 1
  sleep 2   # sensors attached before the window opens (no manufactured gap)
}

stop_pipeline() { kill "$PRB" 2>/dev/null; wait "$PRB" 2>/dev/null; kill "$COLL" 2>/dev/null; wait "$COLL" 2>/dev/null; }

for t in $(seq 1 "$TRIALS"); do
  TD="$OUT/trial_$t"; mkdir -p "$TD"
  # OFF: identical workload, no pipeline running.
  python3 "$HERE/workload.py" "$TD/bins_off" "$K" "$CONC" "$TD/off.json" > /dev/null
  rm -rf "$TD/bins_off"
  # ON: pipeline + independent ftrace reference.
  start_pipeline "$TD" || { stop_pipeline; echo "trial $t: pipeline failed to start" >> "$OUT/errors.txt"; continue; }
  VANIAN_FTRACE_INSTANCE="vm_$t" "$FT" start > /dev/null
  python3 "$HERE/workload.py" "$TD/bins_on" "$K" "$CONC" "$TD/on.json" > /dev/null
  sleep 3   # >= 2 batch intervals so the window is fully batched
  VANIAN_FTRACE_INSTANCE="vm_$t" "$FT" stop "$TD/ftrace.trace" > /dev/null
  stop_pipeline
  rm -rf "$TD/bins_on"
  W="$TD/work/state"
  "$B/aip-observe-verify" --observer-id collector.m --key-version 1 --pubkey-file "$W/observer.pub" \
      --batches "$W/attested.archive.jsonl" --health "$W/health.archive.jsonl" > "$TD/verify.txt" 2>&1
  echo "verify_exit=$?" >> "$TD/verify.txt"
  cp "$W/attested.archive.jsonl" "$W/health.archive.jsonl" "$W/observer.pub" "$TD/" 2>/dev/null
  rm -rf "$TD/work"   # throwaway keys
  echo "trial $t done"
done
python3 "$HERE/analyze.py" "$OUT"
