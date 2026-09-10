#!/usr/bin/env bash
#
# Experiment 1 — Independent Linux Runtime Observation Comparison
#
# Three accounts of one execution window:
#
#   1. the SUBJECT's own log        — a self-report, and it lies on purpose
#   2. SNIFFER DOG 2.0              — the system under test
#   3. the ftrace tracepoint reader — the reference instrument
#
# The question is not "do 2 and 3 agree". It is "does Sniffer Dog correctly
# classify the cases where 1 disagrees with the kernel".
#
# Read ../INDEPENDENCE_MATRIX.md and ../../linux/INDEPENDENCE.md before
# reading any result this produces. The reference instrument reads the SAME
# kernel tracepoints Sniffer Dog samples, so agreement corroborates Sniffer
# Dog's READING and not the EVENT.
#
# Evidence discipline: everything is written once, into a run directory, and
# never modified afterwards. The comparison reads those files and writes a
# separate report. Digests are taken before and after the comparison so that
# "the analysis did not touch the evidence" is a checked fact rather than an
# intention.
#
# Read-only with respect to the host: enables tracepoints, opens a perf ring,
# runs a workload of /bin/true and friends. Starts nothing, kills nothing,
# changes no configuration.

set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VALIDATION=$(cd "$HERE/../.." && pwd)
FTRACE="$VALIDATION/linux/ftrace_observer.sh"
RECORDER="$HERE/recorder/target/release/exp01-recorder"

RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
RUN_DIR="$VALIDATION/traces/exp01-$RUN_ID"
REPORT_DIR="$VALIDATION/reports"
DURATION_MS=${DURATION_MS:-4000}

die() { echo "exp01: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (perf tracepoints + tracefs)"
[ -x "$FTRACE" ]     || die "missing $FTRACE"

if [ ! -x "$RECORDER" ]; then
  echo "exp01: building recorder..."
  (cd "$HERE/recorder" && cargo build --release) || die "recorder build failed"
fi

"$FTRACE" preflight >/dev/null || die "reference instrument not READY; see preflight"

mkdir -p "$RUN_DIR" "$REPORT_DIR"
echo "exp01: run $RUN_ID -> $RUN_DIR"

SUBJECT_LOG="$RUN_DIR/subject_self_report.jsonl"
SD_LOG="$RUN_DIR/sniffer_dog.jsonl"
REF_LOG="$RUN_DIR/reference_ftrace.trace"
META="$RUN_DIR/run_meta.json"

# ── 1. reference instrument first ───────────────────────────────────────────
"$FTRACE" start
trap '"$FTRACE" teardown 2>/dev/null || true' EXIT

# ── 2. Sniffer Dog, and wait until its sensor is genuinely attached ─────────
# Starting the subject before the sensor attaches would manufacture a coverage
# gap and then blame the observer for it.
SD_READY="$RUN_DIR/.sd_ready"
: > "$SD_READY"
"$RECORDER" "$SD_LOG" "$DURATION_MS" 2> >(tee "$SD_READY" >&2) &
SD_PID=$!

for _ in $(seq 1 100); do
  grep -q READY "$SD_READY" 2>/dev/null && break
  grep -q 'sensor unavailable' "$SD_READY" 2>/dev/null && die "sniffer dog sensor unavailable — recorded, not substituted"
  sleep 0.05
done
grep -q READY "$SD_READY" || die "sniffer dog sensor did not become ready"

WINDOW_OPEN_NS=$(date +%s%N)
"$FTRACE" mark "exp01 window open $RUN_ID"

# ── 3. the subject ──────────────────────────────────────────────────────────
"$HERE/subject_workload.sh" "$SUBJECT_LOG"
SUBJECT_RC=$?

"$FTRACE" mark "exp01 window close $RUN_ID"
WINDOW_CLOSE_NS=$(date +%s%N)

# ── 4. close both observers ─────────────────────────────────────────────────
wait "$SD_PID" || true
"$FTRACE" stop "$REF_LOG"
trap - EXIT
rm -f "$SD_READY"

cat > "$META" <<EOF
{
  "run_id": "$RUN_ID",
  "kernel": "$(uname -r)",
  "boot_id": "$(cat /proc/sys/kernel/random/boot_id)",
  "window_open_realtime_ns": $WINDOW_OPEN_NS,
  "window_close_realtime_ns": $WINDOW_CLOSE_NS,
  "duration_ms": $DURATION_MS,
  "subject_exit": $SUBJECT_RC,
  "subject_self_report": "subject_self_report.jsonl",
  "sniffer_dog": "sniffer_dog.jsonl",
  "reference_instrument": "reference_ftrace.trace",
  "reference_mechanism": "ftrace sched_process_* tracepoints (kernel-rendered)",
  "sniffer_dog_mechanism": "perf_event_open sched_process_* tracepoints",
  "mechanism_independent": false,
  "mechanism_independence_note": "Both accounts read the same kernel tracepoints. Agreement corroborates Sniffer Dog's reading, not the event. See validation/linux/INDEPENDENCE.md."
}
EOF

# ── 5. seal the evidence, then compare ──────────────────────────────────────
( cd "$RUN_DIR" && sha256sum ./*.jsonl ./*.trace ./run_meta.json > SHA256SUMS )
chmod -w "$RUN_DIR"/*.jsonl "$RUN_DIR"/*.trace "$RUN_DIR"/run_meta.json 2>/dev/null || true

REPORT="$REPORT_DIR/exp01-$RUN_ID.md"
# A failing comparison is a result to be recorded, not an error to abort on:
# the digest check below must still run, and the report must still be written.
set +e
"$HERE/compare.py" "$RUN_DIR" > "$REPORT"
COMPARE_RC=$?
set -e

# The comparison must be a pure reader of the evidence.
( cd "$RUN_DIR" && sha256sum -c SHA256SUMS --quiet ) \
  || die "EVIDENCE MUTATED BY ANALYSIS — this invalidates the run"
echo "exp01: evidence digests verified unchanged after analysis"

echo "exp01: report -> $REPORT"
exit $COMPARE_RC
