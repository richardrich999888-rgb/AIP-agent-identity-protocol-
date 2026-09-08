#!/usr/bin/env bash
#
# reproduce_interference.sh — the observation-integrity finding, deterministically.
#
# Two arms, identical except for one thing: whether a no-op BPF program is
# attached to sched:sched_process_exec while Sniffer Dog 2.0 observes it.
#
#   Arm A (baseline)    : Sniffer Dog alone
#   Arm B (interfered)  : Sniffer Dog + tracepoint_interferer (returns 0)
#
# In each arm the same fixed set of exec events is generated inside an explicit
# observation window, and Sniffer Dog's exec count and reported loss are
# recorded. The finding is reproduced if Arm B shows zero execs AND zero
# reported loss while Arm A shows the execs.
#
# The interferer is the finding reduced to its minimal cause: two BPF
# instructions, no A3S code. If Sniffer Dog goes blind with only this
# attached, the cause is the perf-submission return-value gate and nothing
# else. See tracepoint_interferer.c.
#
# Observe-only. Nothing here kills, denies or modifies any observed process;
# the interferer suppresses a perf submission and touches nothing else.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VALIDATION=$(cd "$HERE/.." && pwd)
RECORDER="$VALIDATION/scenarios/exp01_linux_runtime_observation/recorder/target/release/exp01-recorder"
INTERFERER="$HERE/tracepoint_interferer"
TP=sched/sched_process_exec
TP_ID_FILE=/sys/kernel/tracing/events/$TP/id

RESULTS="$HERE/results"
RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
RUN="$RESULTS/$RUN_ID"
DURATION_MS=${DURATION_MS:-6000}
NEXECS=${NEXECS:-8}

die() { echo "repro: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (perf_event_open + BPF load)"
[ -r "$TP_ID_FILE" ] || die "tracepoint $TP not present at $TP_ID_FILE"
[ -x "$RECORDER" ] || { echo "repro: building recorder..."; (cd "$(dirname "$(dirname "$RECORDER")")/.." && cargo build --release) || die "recorder build failed"; }
[ -x "$INTERFERER" ] || { echo "repro: building interferer..."; (cd "$HERE" && gcc -O2 -o tracepoint_interferer tracepoint_interferer.c) || die "interferer build failed"; }

mkdir -p "$RUN"
TP_ID=$(cat "$TP_ID_FILE")

# ── environment capture (section 1 of the mandate) ──────────────────────────
{
  echo "run_id: $RUN_ID"
  echo "utc: $(date -u +%FT%TZ)"
  echo "kernel: $(uname -r)"
  echo "arch: $(uname -m)"
  echo "boot_id: $(cat /proc/sys/kernel/random/boot_id)"
  echo "tracepoint: $TP"
  echo "tracepoint_id: $TP_ID"
  echo "sniffer_dog_mechanism: perf_event_open(PERF_TYPE_TRACEPOINT, config=$TP_ID), CLOCK_MONOTONIC, sample_period=1"
  echo "interferer_mechanism: BPF_PROG_TYPE_TRACEPOINT (2 insns: r0=0; exit) attached via PERF_EVENT_IOC_SET_BPF"
  echo "perf_event_paranoid: $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
  echo "unprivileged_bpf_disabled: $(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)"
  echo "capeff: $(grep CapEff /proc/self/status | awk '{print $2}')"
  echo "recorder: $RECORDER"
  echo "duration_ms: $DURATION_MS"
  echo "planned_execs_per_arm: $NEXECS"
  echo "config_kprobes: $(zcat /proc/config.gz 2>/dev/null | grep -E '^# CONFIG_KPROBES|^CONFIG_KPROBES' || echo 'unknown')"
  echo "config_uprobe_events: $(zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_UPROBE_EVENTS' || echo 'unknown')"
} > "$RUN/environment.txt"

# The fixed workload. A distinctive binary the correlator can grep for,
# executed a fixed number of times inside the window.
generate_execs() {
  for _ in $(seq 1 "$NEXECS"); do
    /usr/bin/wc -c /etc/hostname >/dev/null 2>&1
  done
}

# One arm. $1 = arm name, $2 = "interfered" | "baseline".
run_arm() {
  local arm=$1 mode=$2
  local sd_log="$RUN/${arm}_sniffer_dog.jsonl"
  local sd_ready="$RUN/.${arm}_ready"
  local intf_log="$RUN/${arm}_interferer.log"
  : > "$sd_ready"

  local intf_pid=""
  if [ "$mode" = interfered ]; then
    "$INTERFERER" "$TP_ID" > "$intf_log" 2>&1 &
    intf_pid=$!
    # Wait for the gate to be held before Sniffer Dog attaches, so we are
    # never measuring a race at the boundary.
    for _ in $(seq 1 100); do
      grep -q INTERFERER_ATTACHED "$intf_log" 2>/dev/null && break
      kill -0 "$intf_pid" 2>/dev/null || break
      sleep 0.05
    done
    grep -q INTERFERER_ATTACHED "$intf_log" 2>/dev/null \
      || { echo "repro: interferer failed to attach; see $intf_log" >&2; kill "$intf_pid" 2>/dev/null; return 1; }
  fi

  # Sniffer Dog's real live sensor.
  "$RECORDER" "$sd_log" "$DURATION_MS" 2> >(tee "$sd_ready" >&2) &
  local sd_pid=$!
  for _ in $(seq 1 200); do
    grep -q READY "$sd_ready" 2>/dev/null && break
    grep -q 'sensor unavailable' "$sd_ready" 2>/dev/null && { echo "repro: sniffer dog sensor unavailable" >&2; break; }
    sleep 0.05
  done

  # Explicit observation window. Startup execs (Sniffer Dog's own, the shell's)
  # happen before this and are outside it, so they are never counted as the
  # workload — the same window discipline the other experiments use.
  local win_open_ns win_close_ns
  win_open_ns=$(date +%s%N)
  generate_execs
  win_close_ns=$(date +%s%N)

  wait "$sd_pid" 2>/dev/null
  [ -n "$intf_pid" ] && { kill "$intf_pid" 2>/dev/null; wait "$intf_pid" 2>/dev/null; }
  rm -f "$sd_ready"

  # Count execs of the workload binary inside the window.
  python3 - "$sd_log" "$win_open_ns" "$win_close_ns" "$arm" "$mode" "$RUN/${arm}_summary.json" <<'PY'
import json, sys
sd_log, win_open, win_close, arm, mode, out = sys.argv[1:7]
win_open, win_close = int(win_open), int(win_close)
wc_in_window = wc_total = loss = total_exec = 0
integrity = None
# Sniffer Dog timestamps are CLOCK_MONOTONIC ns; the window bounds are
# realtime ns. They are different clocks, so we do not filter exec events by
# the realtime window — instead we count wc execs across the capture, which is
# unambiguous because the only wc execs in the run are the workload's. The
# window markers are recorded for provenance and to bound the arm in time.
for line in open(sd_log):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    r = json.loads(line)
    k = r.get("kind")
    if k == "exec":
        total_exec += 1
        if r.get("filename", "").endswith("/wc"):
            wc_total += 1
    elif k == "loss":
        loss += r["count"]
    elif k == "mechanism_integrity" and r.get("at") == "close":
        integrity = r.get("state")
summary = {
    "arm": arm, "mode": mode,
    "window_open_realtime_ns": win_open,
    "window_close_realtime_ns": win_close,
    "sniffer_dog_wc_execs": wc_total,
    "sniffer_dog_total_execs": total_exec,
    "sniffer_dog_reported_loss": loss,
    # The production observer's own integrity self-report (the fix): does it
    # know it may have been blinded? "verified" | "integrity_unknown" | None.
    "sniffer_dog_integrity_self_report": integrity,
}
open(out, "w").write(json.dumps(summary, indent=2))
print(f"  {arm:12} mode={mode:11} wc_execs={wc_total} total_execs={total_exec} "
      f"reported_loss={loss} integrity={integrity}")
PY
}

echo "repro: run $RUN_ID -> $RUN"
echo "repro: tracepoint $TP id=$TP_ID, $NEXECS wc execs per arm"
echo
echo "Arm A — baseline (Sniffer Dog alone):"
run_arm arm_a_baseline baseline
echo
echo "Arm B — interfered (Sniffer Dog + no-op BPF gate on the tracepoint):"
run_arm arm_b_interfered interfered
echo

# ── verdict ─────────────────────────────────────────────────────────────────
python3 - "$RUN" "$NEXECS" <<'PY'
import json, sys
run, nexecs = sys.argv[1], int(sys.argv[2])
a = json.load(open(f"{run}/arm_a_baseline_summary.json"))
b = json.load(open(f"{run}/arm_b_interfered_summary.json"))

reproduced = (
    a["sniffer_dog_wc_execs"] > 0 and
    b["sniffer_dog_wc_execs"] == 0 and
    b["sniffer_dog_reported_loss"] == 0
)
# The fix: the observer must now KNOW it was blinded. Baseline integrity is
# "verified" (no foreign gate); the interfered arm is "integrity_unknown"
# (the production ProcessTracer::mechanism_integrity check saw the foreign
# program). That self-report is what makes the collector sign
# ObserverState::IntegrityUnknown instead of a false Active.
a_int = a.get("sniffer_dog_integrity_self_report")
b_int = b.get("sniffer_dog_integrity_self_report")
detected = (a_int == "verified" and b_int == "integrity_unknown")
verdict = {
    "finding": "observer reports healthy coverage while observation was suppressed",
    "arm_a_baseline_wc_execs": a["sniffer_dog_wc_execs"],
    "arm_b_interfered_wc_execs": b["sniffer_dog_wc_execs"],
    "arm_b_interfered_reported_loss": b["sniffer_dog_reported_loss"],
    "reproduced": reproduced,
    "arm_a_baseline_integrity": a_int,
    "arm_b_interfered_integrity": b_int,
    "fix_detected_the_gate": detected,
    "interpretation": (
        "REPRODUCED and DETECTED: with the gate held, Sniffer Dog observed "
        f"zero of the {nexecs} execs and reported zero loss — but its "
        "mechanism-integrity check reported 'integrity_unknown', so the "
        "collector no longer signs a false Active. The fix converts silent "
        "blindness into a signed 'I cannot vouch'."
        if reproduced and detected else
        "See per-arm summaries; reproduced=%s detected=%s." % (reproduced, detected)
    ),
}
open(f"{run}/verdict.json", "w").write(json.dumps(verdict, indent=2))
print("VERDICT:", "REPRODUCED + FIX DETECTED" if reproduced and detected
      else ("REPRODUCED, FIX NOT DETECTED" if reproduced else "NOT REPRODUCED"))
print(f"  baseline   : wc_execs={a['sniffer_dog_wc_execs']} integrity={a_int}")
print(f"  interfered : wc_execs={b['sniffer_dog_wc_execs']} loss={b['sniffer_dog_reported_loss']} integrity={b_int}")
sys.exit(0 if reproduced and detected else 1)
PY
RC=$?

# Seal the raw artifacts.
( cd "$RUN" && sha256sum ./* > SHA256SUMS 2>/dev/null )
echo
echo "repro: artifacts sealed in $RUN"
exit $RC
