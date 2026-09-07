#!/usr/bin/env bash
#
# ftrace_observer.sh — kernel-owned reference observer for process lifecycle.
#
# This is a REFERENCE INSTRUMENT. It is not part of Vanian, it is not an
# observer in Vanian's sense, it produces no ObservationRecord, it signs
# nothing, and its output must never be fed into a Reconciliation, a NEXORA
# proof, an EvidenceCeiling or a warrant decision.
#
# What it does: opens a dedicated ftrace instance, enables the kernel's
# sched_process_{fork,exec,exit} tracepoints on it, and copies out the kernel's
# own rendering of those events.
#
# READ validation/linux/INDEPENDENCE.md BEFORE DRAWING ANY CONCLUSION FROM ITS
# OUTPUT. It reads the same tracepoints Sniffer Dog 2.0 samples through
# perf_event_open. It is interface-independent of Sniffer Dog. It is NOT
# mechanism-independent of it, and the difference decides what a comparison
# against it is allowed to establish.
#
# Read-only with respect to the system under test: it enables tracepoints and
# reads a buffer. It starts nothing, stops nothing, kills nothing, and has no
# control surface of any kind.
#
# Usage:
#   ftrace_observer.sh preflight        # can this run here? exit 0 = yes
#   ftrace_observer.sh start            # begin capture
#   ftrace_observer.sh mark <text>      # write a synchronisation marker
#   ftrace_observer.sh stop <outfile>   # stop, write capture, tear down
#   ftrace_observer.sh teardown         # remove the instance, no output

set -euo pipefail

TRACEFS=/sys/kernel/tracing
INSTANCE_NAME=${VANIAN_FTRACE_INSTANCE:-vanian_ref}
INST="$TRACEFS/instances/$INSTANCE_NAME"
EVENTS=(sched/sched_process_fork sched/sched_process_exec sched/sched_process_exit)

die() { echo "ftrace_observer: $*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "must run as root (needs $TRACEFS)"
}

cmd_preflight() {
  local ok=0
  echo "instrument: ftrace tracepoint reader"
  if [ "$(id -u)" -ne 0 ]; then echo "  FAIL  not root"; ok=1; fi
  if ! mountpoint -q "$TRACEFS" 2>/dev/null && [ ! -f "$TRACEFS/available_events" ]; then
    echo "  FAIL  tracefs not mounted at $TRACEFS"; ok=1
  else
    echo "  ok    tracefs mounted at $TRACEFS"
  fi
  if [ ! -d "$TRACEFS/instances" ]; then
    echo "  FAIL  no $TRACEFS/instances — cannot isolate capture"; ok=1
  else
    echo "  ok    ftrace instances supported"
  fi
  local missing=()
  for e in "${EVENTS[@]}"; do
    grep -qx "${e/\//:}" "$TRACEFS/available_events" || missing+=("$e")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "  FAIL  tracepoints absent: ${missing[*]}"; ok=1
  else
    echo "  ok    tracepoints present: ${EVENTS[*]}"
  fi
  if [ $ok -eq 0 ]; then echo "  STATUS READY"; else echo "  STATUS BLOCKED"; fi
  return $ok
}

cmd_start() {
  require_root
  [ -d "$TRACEFS/instances" ] || die "no ftrace instances directory"
  # An existing instance from an aborted run is reused after being cleared,
  # never silently appended to.
  mkdir -p "$INST" || die "cannot create instance $INST"

  # CLOCK_MONOTONIC. Sniffer Dog's perf ring requests the same clock
  # explicitly, so the two timebases are comparable without conversion.
  # If the kernel refuses, that is recorded rather than papered over.
  if ! echo mono > "$INST/trace_clock" 2>/dev/null; then
    die "kernel refused trace_clock=mono; timestamps would not be comparable"
  fi
  [ "$(sed -n 's/.*\[\(.*\)\].*/\1/p' "$INST/trace_clock")" = "mono" ] \
    || die "trace_clock is not mono after being set"

  echo 0 > "$INST/tracing_on"
  : > "$INST/trace"
  for e in "${EVENTS[@]}"; do
    echo 1 > "$INST/events/$e/enable" || die "cannot enable $e"
  done
  echo 1 > "$INST/tracing_on"
  echo "ftrace_observer: capturing on instance '$INSTANCE_NAME' (clock=mono)"
}

cmd_mark() {
  require_root
  [ -d "$INST" ] || die "instance $INSTANCE_NAME not started"
  echo "$*" > "$INST/trace_marker"
}

cmd_stop() {
  require_root
  local out=${1:-}
  [ -n "$out" ] || die "stop requires an output path"
  [ -d "$INST" ] || die "instance $INSTANCE_NAME not started"
  echo 0 > "$INST/tracing_on"

  {
    echo "# vanian reference observer capture"
    echo "# instrument: ftrace tracepoint reader (kernel-owned rendering)"
    echo "# NOT a Vanian observer. Produces no attested observation."
    echo "# clock: $(cat "$INST/trace_clock")"
    echo "# kernel: $(uname -r)"
    echo "# boot_id: $(cat /proc/sys/kernel/random/boot_id)"
    echo "# captured_realtime_ns: $(date +%s%N)"
    echo "# events: ${EVENTS[*]}"
    echo "#"
    cat "$INST/trace"
  } > "$out"

  # Loss is a first-class fact, never inferred from a short capture.
  local dropped
  dropped=$(awk '/entries-in-buffer.*overrun/ {print}' "$INST/trace" | head -1 || true)
  [ -n "$dropped" ] && echo "ftrace_observer: buffer stats: $dropped"

  cmd_teardown
  echo "ftrace_observer: capture written to $out"
}

cmd_teardown() {
  require_root
  [ -d "$INST" ] || return 0
  echo 0 > "$INST/tracing_on" 2>/dev/null || true
  for e in "${EVENTS[@]}"; do
    echo 0 > "$INST/events/$e/enable" 2>/dev/null || true
  done
  rmdir "$INST" 2>/dev/null || true
}

case "${1:-}" in
  preflight) cmd_preflight ;;
  start)     cmd_start ;;
  mark)      shift; cmd_mark "$@" ;;
  stop)      shift; cmd_stop "${1:-}" ;;
  teardown)  cmd_teardown ;;
  *) die "usage: $0 {preflight|start|mark <text>|stop <outfile>|teardown}" ;;
esac
