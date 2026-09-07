#!/usr/bin/env bash
#
# AIRI-INDEPENDENT-OBSERVATION-001
#
# Runs one scenario of the AIRI subject under simultaneous independent
# observation, then correlates the accounts.
#
#   A. AIRI events        — the subject's own signed claims (the ACTOR)
#   B. agent self-report  — same process, same trust boundary
#   C. A3S Observer       — eBPF on syscalls:sys_enter_execve
#   D. Sniffer Dog 2.0    — perf_event_open on sched:sched_process_exec
#   E. ftrace             — ftrace on sched:sched_process_exec
#   F. OBI / Langfuse     — see ../../external/*/STATUS.md; unavailable here
#
# C, D and E are started BEFORE the subject and stopped after it, and the
# coverage window is delimited by markers written once every observer is
# confirmed attached. No external source may modify AIRI's evidence: the AIRI
# log is written by the subject alone, sealed with a digest, and the digest is
# re-verified after correlation.
#
# Safety: observe-only throughout. A3S runs in its default observe mode with
# no enforcement configured; the collector binary contains no enforcement
# attach path at all. Nothing here kills, denies, or modifies any process.
#
# Usage: run.sh [scenario] ; scenarios listed in SCENARIOS.md

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VALIDATION=$(cd "$HERE/../.." && pwd)
FTRACE="$VALIDATION/linux/ftrace_observer.sh"
SD_RECORDER="$VALIDATION/scenarios/exp01_linux_runtime_observation/recorder/target/release/exp01-recorder"
AGENT="$HERE/agent/target/release/airi-subject-agent"
A3S=${A3S_BIN:-/tmp/airi_Observer/target/release/a3s-observer-collector}
# A3S_ENABLED=0 runs without A3S. This matters: A3S attaches a BPF program to
# sched:sched_process_exec that returns 0, which suppresses that tracepoint's
# perf samples for EVERY perf consumer on the host — Sniffer Dog included.
# See ../../external/a3s_observer/TRACEPOINT_INTERFERENCE.md. The two cannot
# co-observe that tracepoint, so the harness records which one was live rather
# than pretending both were.
A3S_ENABLED=${A3S_ENABLED:-1}

SCENARIO=${1:-honest}
RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$SCENARIO}
RUN_DIR="$VALIDATION/traces/airi001-$RUN_ID"
REPORT_DIR="$VALIDATION/reports"
PORT=${PORT:-18099}

die() { echo "airi001: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (eBPF + perf + tracefs)"
[ -x "$FTRACE" ] || die "missing $FTRACE"
[ -x "$AGENT" ] || { echo "airi001: building subject agent..."; (cd "$HERE/agent" && cargo build --release) || die "agent build failed"; }
[ -x "$SD_RECORDER" ] || { echo "airi001: building sniffer dog recorder..."; (cd "$VALIDATION/scenarios/exp01_linux_runtime_observation/recorder" && cargo build --release) || die "recorder build failed"; }

mkdir -p "$RUN_DIR" "$REPORT_DIR"
echo "airi001: scenario=$SCENARIO run=$RUN_ID"

AIRI_LOG="$RUN_DIR/airi_events.jsonl"
META="$RUN_DIR/subject_meta.json"
A3S_LOG="$RUN_DIR/a3s_events.ndjson"
SD_LOG="$RUN_DIR/sniffer_dog.jsonl"
FT_LOG="$RUN_DIR/ftrace.trace"

cleanup() {
  kill "${A3S_PID:-}" "${SD_PID:-}" "${LISTENER_PID:-}" 2>/dev/null
  "$FTRACE" teardown 2>/dev/null
}
trap cleanup EXIT

# ── a local listener, so "network egress" is real without leaving the host ──
python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
LISTENER_PID=$!

# ── C. A3S Observer ─────────────────────────────────────────────────────────
A3S_AVAILABLE=no
if [ "$A3S_ENABLED" = 1 ] && [ -x "$A3S" ]; then
  A3S_OBSERVER_JSON=1 "$A3S" > "$A3S_LOG" 2> "$RUN_DIR/a3s.log" &
  A3S_PID=$!
  for _ in $(seq 1 120); do
    grep -q 'probes attached' "$RUN_DIR/a3s.log" 2>/dev/null && { A3S_AVAILABLE=yes; break; }
    kill -0 "$A3S_PID" 2>/dev/null || break
    sleep 0.25
  done
  [ "$A3S_AVAILABLE" = yes ] || echo "airi001: A3S did not report attach — recorded as unavailable, not substituted"
elif [ "$A3S_ENABLED" != 1 ]; then
  echo "airi001: A3S disabled for this run (A3S_ENABLED=0)"
else
  echo "airi001: A3S binary absent at $A3S — recorded as unavailable, not substituted"
fi

# ── E. ftrace ───────────────────────────────────────────────────────────────
FT_AVAILABLE=no
if "$FTRACE" preflight >/dev/null 2>&1; then
  VANIAN_FTRACE_INSTANCE=airi001 "$FTRACE" start >/dev/null && FT_AVAILABLE=yes
fi

# ── D. Sniffer Dog 2.0 ──────────────────────────────────────────────────────
SD_READY="$RUN_DIR/.sd_ready"; : > "$SD_READY"
"$SD_RECORDER" "$SD_LOG" "${SD_DURATION_MS:-9000}" 2> >(tee "$SD_READY" >&2) &
SD_PID=$!
SD_AVAILABLE=no
for _ in $(seq 1 120); do
  grep -q READY "$SD_READY" 2>/dev/null && { SD_AVAILABLE=yes; break; }
  grep -q 'sensor unavailable' "$SD_READY" 2>/dev/null && break
  sleep 0.05
done
[ "$SD_AVAILABLE" = yes ] || echo "airi001: Sniffer Dog sensor unavailable — recorded, not substituted"

# Sniffer Dog's perf tracepoint path is gated by any BPF program attached to
# the same tracepoint. With A3S live, its silence is SUPPRESSION, not an
# observation that nothing happened, and the correlator must not read it as
# the latter.
SD_STATUS="$SD_AVAILABLE"
if [ "$SD_AVAILABLE" = yes ] && [ "$A3S_AVAILABLE" = yes ]; then
  SD_STATUS="suppressed_by_bpf_tracepoint_gate"
fi

# Only now is every observer attached. Anything before this point is outside
# coverage, and treating it as a miss would manufacture a gap and blame an
# observer for it.
[ "$FT_AVAILABLE" = yes ] && VANIAN_FTRACE_INSTANCE=airi001 "$FTRACE" mark "airi001 window open $RUN_ID"
WINDOW_OPEN_NS=$(date +%s%N)

# ── the subject ─────────────────────────────────────────────────────────────
"$AGENT" "$AIRI_LOG" "$META" "$SCENARIO" "$PORT"
SUBJECT_RC=$?
sleep 2   # let ring buffers drain; loss is reported by each observer, not inferred

WINDOW_CLOSE_NS=$(date +%s%N)
[ "$FT_AVAILABLE" = yes ] && VANIAN_FTRACE_INSTANCE=airi001 "$FTRACE" mark "airi001 window close $RUN_ID"

# ── close observers ─────────────────────────────────────────────────────────
kill -INT "${A3S_PID:-0}" 2>/dev/null; wait "${A3S_PID:-0}" 2>/dev/null
# Wait for the recorder to finish its own duration rather than killing
# it. It flushes per event so a kill would not lose evidence, but letting
# it close cleanly keeps its own summary line accurate.
wait "${SD_PID:-0}" 2>/dev/null
[ "$FT_AVAILABLE" = yes ] && VANIAN_FTRACE_INSTANCE=airi001 "$FTRACE" stop "$FT_LOG" >/dev/null
kill "$LISTENER_PID" 2>/dev/null
trap - EXIT
rm -f "$SD_READY"

cat > "$RUN_DIR/run_meta.json" <<EOF
{
  "experiment": "AIRI-INDEPENDENT-OBSERVATION-001",
  "run_id": "$RUN_ID",
  "scenario": "$SCENARIO",
  "kernel": "$(uname -r)",
  "boot_id": "$(cat /proc/sys/kernel/random/boot_id)",
  "window_open_realtime_ns": $WINDOW_OPEN_NS,
  "window_close_realtime_ns": $WINDOW_CLOSE_NS,
  "subject_exit": $SUBJECT_RC,
  "observers": {
    "a3s_observer": "$A3S_AVAILABLE",
    "sniffer_dog": "$SD_STATUS",
    "ftrace": "$FT_AVAILABLE",
    "obi": "unavailable",
    "langfuse": "unavailable"
  },
  "note": "OBI and Langfuse are unavailable in this environment; see validation/external/*/STATUS.md. Absence of a source is recorded, never substituted."
}
EOF

# ── seal, correlate, verify the seal ────────────────────────────────────────
( cd "$RUN_DIR" && sha256sum ./*.jsonl ./*.json ./*.ndjson ./*.trace 2>/dev/null > SHA256SUMS )
chmod -w "$RUN_DIR"/*.jsonl "$RUN_DIR"/*.ndjson "$RUN_DIR"/*.trace 2>/dev/null

REPORT="$REPORT_DIR/airi001-$RUN_ID.md"
"$HERE/correlate.py" "$RUN_DIR" > "$REPORT"
CORR_RC=$?

# matrix.json is written by the correlator, so exclude it from the seal check.
( cd "$RUN_DIR" && grep -v 'matrix.json' SHA256SUMS | sha256sum -c --quiet ) \
  || die "EVIDENCE MUTATED BY ANALYSIS — run invalid"
echo "airi001: AIRI evidence digests verified unchanged after correlation"
echo "airi001: report -> $REPORT"
exit $CORR_RC
