#!/usr/bin/env bash
# OBSERVATION-INTEGRITY-001 / reproduction
#
# THE ORDERING PROBLEM, AND HOW THIS DESIGN REMOVES IT
# ----------------------------------------------------
# A two-arm test (observer alone, then observer with A3S) cannot by itself
# separate interference from lifecycle ordering: the second arm restarts the
# observer, and a restart is exactly when an observer legitimately misses
# events. The mandate asks for that ambiguity to be excluded, not argued away.
#
# So the interference happens INSIDE ONE OBSERVER LIFETIME. A single
# exp01-recorder process is started once and never restarted. Three batches of
# identical, uniquely-tagged executions run against it:
#
#   P1  BEFORE   — no BPF program attached to the tracepoint
#   P2  DURING   — A3S Observer attached, mid-lifetime
#   P3  AFTER    — A3S Observer detached again, still mid-lifetime
#
# If P1 and P3 are observed and P2 is not, by the same process, with no
# restart and no reopen, then startup and shutdown ordering are excluded by
# construction rather than by argument.
#
# The recovery in P3 matters as much as the loss in P2: a one-way failure
# would be consistent with the observer simply dying. Recovery shows the
# suppression is coextensive with the attachment.
#
# GROUND TRUTH
# ------------
# The Linux audit subsystem records the same executions throughout, from a
# different kernel subsystem that is not on the perf submission path. It
# establishes that the P2 executions REALLY HAPPENED, so "the observer saw
# nothing" cannot be confused with "nothing occurred" — which is the whole
# subject of the investigation.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
OUT="${OUT_DIR:-$REPO/validation/observation_integrity/evidence/OI-001-$RUN_ID}"
mkdir -p "$OUT"

RECORDER="$REPO/validation/scenarios/exp01_linux_runtime_observation/recorder/target/release/exp01-recorder"
AUDIT="$REPO/validation/airi/observers/audit_observer.py"
A3S="${A3S_BIN:-/tmp/a3s/target/release/a3s-observer-collector}"

fail() { echo "FATAL: $*" >&2; exit 1; }
[ -x "$RECORDER" ] || fail "recorder not built: $RECORDER"
[ -f "$AUDIT" ]    || fail "audit observer missing"
[ -x "$A3S" ]      || fail "A3S collector not built: $A3S (see validation/external/a3s/EVALUATION.md)"

# PHASE ATTRIBUTION WITHOUT A CLOCK
# ---------------------------------
# Sniffer Dog's exec record carries `filename` and pids — not argv. A tag in
# argv would therefore be invisible to the very observer under test, and
# attributing its events to a phase would fall back to comparing its
# CLOCK_MONOTONIC timestamps against the harness's wall clock. That is a
# cross-clock comparison, and cross-clock comparisons have already produced one
# false result in this programme.
#
# So each phase execs its OWN BINARY, a copy of /bin/true at a distinct path.
# The phase is then carried in the `filename` field of the observed record
# itself. Every observer here — Sniffer Dog by filename, audit and A3S by argv
# and path — attributes an exec to a phase from the record's own content, with
# no clock involved.
TAG="OI001-$RUN_ID"
SHORT="$(printf '%s' "$RUN_ID" | md5sum | cut -c1-4)"
EXECS_PER_PHASE="${EXECS_PER_PHASE:-5}"
BINDIR="$OUT/bin"
mkdir -p "$BINDIR"
for P in P1 P2 P3 ATTACHED DETACHED; do
  cp /bin/true "$BINDIR/oi${P}${SHORT}"
done
anchor() { "$BINDIR/oi$1$SHORT" "ANCHOR-$1"; }

phase_execs() {                       # $1 = phase name
  local i
  for i in $(seq 1 "$EXECS_PER_PHASE"); do
    "$BINDIR/oi$1$SHORT" "${TAG}-$1-$i"
  done
}

# ARM — which sched tracepoints the interferer attaches to.
#   both      (default) fork + exec, as A3S ships
#   exec_only OI001_SKIP_SCHED_FORK=1
#   fork_only OI001_SKIP_SCHED_EXEC=1
# fork_only is the decisive control: if the observer keeps seeing EXEC events
# while losing SPAWN events, the suppression follows the specific tracepoint
# the BPF program is attached to. "Any BPF program blinds the observer" would
# predict both going dark, and is refuted by that arm.
ARM="${ARM:-both}"
A3S_ENV=()
case "$ARM" in
  both)      ;;
  exec_only) A3S_ENV=(OI001_SKIP_SCHED_FORK=1) ;;
  fork_only) A3S_ENV=(OI001_SKIP_SCHED_EXEC=1) ;;
  none)      ;;
  *) fail "unknown ARM: $ARM" ;;
esac

# ── environment, captured before anything runs ─────────────────────────
{
  echo "{"
  echo "  \"experiment\": \"OBSERVATION-INTEGRITY-001\","
  echo "  \"run_id\": \"$RUN_ID\","
  echo "  \"tag\": \"$TAG\","
  echo "  \"short\": \"$SHORT\","
  echo "  \"arm\": \"$ARM\","
  echo "  \"execs_per_phase\": $EXECS_PER_PHASE,"
  echo "  \"git_commit\": \"$(cd "$REPO" && git rev-parse HEAD)\","
  echo "  \"git_branch\": \"$(cd "$REPO" && git rev-parse --abbrev-ref HEAD)\","
  echo "  \"kernel\": \"$(uname -r)\","
  echo "  \"uname\": \"$(uname -a)\","
  echo "  \"uid\": $(id -u),"
  echo "  \"capabilities\": \"$(grep CapEff /proc/self/status | awk '{print $2}')\","
  echo "  \"btf_available\": $( [ -r /sys/kernel/btf/vmlinux ] && echo true || echo false ),"
  echo "  \"config_kprobes\": \"$(zgrep -E '^#? ?CONFIG_KPROBES' /proc/config.gz 2>/dev/null | head -1)\","
  echo "  \"config_bpf_syscall\": \"$(zgrep -E '^CONFIG_BPF_SYSCALL' /proc/config.gz 2>/dev/null | head -1)\","
  echo "  \"perf_event_paranoid\": $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo null),"
  echo "  \"tracepoint_id\": $(cat /sys/kernel/tracing/events/sched/sched_process_exec/id 2>/dev/null || echo null),"
  echo "  \"tracepoint_enable_at_start\": \"$(cat /sys/kernel/tracing/events/sched/sched_process_exec/enable 2>/dev/null)\","
  echo "  \"observer_under_test\": \"aip_observe::ProcessTracer — perf_event_open(PERF_TYPE_TRACEPOINT) on sched:sched_process_{fork,exec}\","
  echo "  \"interferer\": \"A3S Observer collector — eBPF programs attached to syscall and sched tracepoints\","
  echo "  \"ground_truth\": \"linux audit subsystem — audit_syscall hook, NETLINK_AUDIT; not on the perf submission path\","
  echo "  \"started_unix_ns\": $(date +%s%N)"
  echo "}"
} > "$OUT/metadata.json"

log() { echo "[$(date +%s%N)] $*" | tee -a "$OUT/timeline.txt"; }

cleanup() {
  [ -n "${A3S_PID:-}" ] && kill -INT "$A3S_PID" 2>/dev/null
  [ -n "${AUDIT_PID:-}" ] && kill "$AUDIT_PID" 2>/dev/null
  [ -n "${REC_PID:-}" ] && kill "$REC_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

# ── ground-truth observer ──────────────────────────────────────────────
python3 "$AUDIT" \
  --out "$OUT/audit_ground_truth.jsonl" \
  --syscalls execve,execveat \
  --max-seconds 120 \
  --ready-file "$OUT/audit.ready" \
  > "$OUT/audit_observer.log" 2>&1 &
AUDIT_PID=$!
for _ in $(seq 1 200); do [ -s "$OUT/audit.ready" ] && break; sleep 0.05; done
[ -s "$OUT/audit.ready" ] || fail "ground-truth observer did not start"
log "audit ground-truth observer ready pid=$(cat "$OUT/audit.ready")"

# ── the observer under test: started ONCE, never restarted ─────────────
"$RECORDER" "$OUT/sniffer_dog.jsonl" 60000 > "$OUT/recorder.stdout" 2> "$OUT/recorder.stderr" &
REC_PID=$!
for _ in $(seq 1 200); do grep -q READY "$OUT/recorder.stderr" 2>/dev/null && break; sleep 0.05; done
grep -q READY "$OUT/recorder.stderr" 2>/dev/null || fail "Sniffer Dog sensor did not open"
log "sniffer dog READY pid=$REC_PID (single lifetime for all three phases)"
sleep 1

# ── P1: BEFORE ─────────────────────────────────────────────────────────
log "PHASE_1_BEGIN before-attach"
phase_execs P1
sleep 1
log "PHASE_1_END"

# ── attach the interferer, mid-lifetime ────────────────────────────────
log "A3S_ATTACH_BEGIN arm=$ARM env=${A3S_ENV[*]:-none}"
if [ "$ARM" = none ]; then
  log "A3S_ATTACHED skipped (arm=none, negative control)"
fi
if [ "$ARM" != none ]; then
  env A3S_OBSERVER_JSON=1 "${A3S_ENV[@]}" "$A3S" > "$OUT/a3s_events.ndjson" 2> "$OUT/a3s.log" &
  A3S_PID=$!
  for _ in $(seq 1 300); do grep -q "probes attached" "$OUT/a3s.log" 2>/dev/null && break; sleep 0.1; done
  grep -q "probes attached" "$OUT/a3s.log" 2>/dev/null || fail "A3S did not attach"
  log "A3S_ATTACHED pid=$A3S_PID attached=$(grep -o 'attached=[0-9]*' "$OUT/a3s.log" | head -1)"
  # In-stream anchor: an exec the observer under test should record IFF the
  # gate is not yet effective. It marks the confirmed-attached boundary
  # inside the observer's own event order, with no clock.
  anchor ATTACHED
fi
sleep 1

# ── P2: DURING ─────────────────────────────────────────────────────────
log "PHASE_2_BEGIN during-attach"
phase_execs P2
sleep 1
log "PHASE_2_END"

# ── detach ─────────────────────────────────────────────────────────────
if [ "$ARM" != none ]; then anchor DETACHED; fi
log "A3S_DETACH_BEGIN"
if [ -n "${A3S_PID:-}" ]; then
  kill -INT "$A3S_PID" 2>/dev/null
  for _ in $(seq 1 200); do kill -0 "$A3S_PID" 2>/dev/null || break; sleep 0.1; done
  kill -9 "$A3S_PID" 2>/dev/null
  A3S_PID=""
  sleep 2
fi
log "A3S_DETACHED"

# ── P3: AFTER ──────────────────────────────────────────────────────────
log "PHASE_3_BEGIN after-detach"
phase_execs P3
sleep 1
log "PHASE_3_END"

# ── stop, in a defined order ───────────────────────────────────────────
for _ in $(seq 1 700); do kill -0 "$REC_PID" 2>/dev/null || break; sleep 0.1; done
kill "$REC_PID" 2>/dev/null; wait "$REC_PID" 2>/dev/null
log "recorder stopped"
kill "$AUDIT_PID" 2>/dev/null; wait "$AUDIT_PID" 2>/dev/null
AUDIT_PID=""
log "audit observer stopped"

python3 "$HERE/analyze_interference.py" --dir "$OUT" --tag "$TAG" --short "$SHORT" \
  --arm "$ARM" --execs-per-phase "$EXECS_PER_PHASE" \
  > "$OUT/result.json" 2> "$OUT/analysis.log"
cat "$OUT/analysis.log" >&2
python3 "$HERE/window_analysis.py" --dir "$OUT" > "$OUT/window_analysis.json" 2>/dev/null || true
python3 "$HERE/summarize.py" "$OUT"
if [ -s "$OUT/window_analysis.json" ]; then
  python3 -c "
import json
try:
    w=json.load(open('$OUT/window_analysis.json'))
    if 'result' in w and w.get('confirmed_attached_window_execs') is not None:
        print(f"  CONFIRMED-WINDOW: {w['result']} (seen {w['seen_by_observer_under_test']}/{w['confirmed_attached_window_execs']})")
except Exception: pass
"
fi
echo "$OUT"
