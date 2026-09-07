#!/usr/bin/env bash
# AIRI-INDEPENDENT-AGENT-OBSERVATION-001
#
# Runs one scenario of the AIRI validation experiment end to end and preserves
# every raw artefact it produced.
#
# THE ORDERING IS THE EXPERIMENT
# ------------------------------
# The earlier Linux experiment recorded misses that were not misses: startup
# events fell outside the observation window and were counted as failures to
# observe. PHASE 9 of the mandate forbids repeating that, so the window here is
# established INSIDE the observed stream, not by wall clock:
#
#   1  start the model stub, wait until it is listening
#   2  start the independent observer, wait for its ready file
#   3  exec a distinctive WINDOW_OPEN marker  -> appears in the observer stream
#   4  run the subject
#   5  exec a distinctive WINDOW_CLOSE marker -> appears in the observer stream
#   6  let the observer drain until it sees WINDOW_CLOSE, then stop it
#   7  analyse
#
# Anything the observer recorded before WINDOW_OPEN or after WINDOW_CLOSE is
# out of window by construction, and the analyser drops it rather than treating
# it as evidence of anything.
#
# WHAT THIS SCRIPT DOES NOT DO
# ----------------------------
# It does not decide anything about Vanian's evidence semantics. It starts
# processes, marks a window, and preserves bytes. The comparison is in
# analyze.py, and even that produces a validation-harness verdict about
# whether the accountability chain behaved correctly — never a Vanian verdict.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SCENARIO="${1:-AIRI-001}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
NONCE="${SCENARIO}-${RUN_ID}"
TRACE_ROOT="${TRACE_ROOT:-$REPO/validation/traces/airi-001}"
TRACE_DIR="$TRACE_ROOT/${SCENARIO}-${RUN_ID}"
WORK="$TRACE_DIR/work"
mkdir -p "$WORK"

AGENT="$HERE/agent/target/debug/airi-subject-agent"
OBSERVER="$HERE/observers/audit_observer.py"
STUB="$HERE/model_stub.py"

fail() { echo "FATAL: $*" >&2; exit 1; }
[ -x "$AGENT" ] || fail "subject agent not built. Run: (cd $HERE/agent && cargo build)"
[ -f "$OBSERVER" ] || fail "observer missing"

# ── metadata, written before anything runs ──────────────────────────────
cat > "$TRACE_DIR/metadata.json" <<EOF
{
  "experiment": "AIRI-INDEPENDENT-AGENT-OBSERVATION-001",
  "scenario": "$SCENARIO",
  "run_id": "$RUN_ID",
  "nonce": "$NONCE",
  "git_commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "git_branch": "$(cd "$REPO" && git rev-parse --abbrev-ref HEAD)",
  "git_dirty": $( [ -z "$(cd "$REPO" && git status --porcelain)" ] && echo false || echo true ),
  "kernel": "$(uname -r)",
  "uname": "$(uname -a)",
  "observers": [
    {
      "name": "linux-audit",
      "mechanism": "audit_syscall hooks -> NETLINK_AUDIT",
      "independent_of_sniffer_dog": "mechanism",
      "note": "different probe site, subsystem, delivery path and record format from the sched tracepoints aip-observe reads"
    }
  ],
  "subject": {
    "binary": "$AGENT",
    "note": "emits REAL aip-airi events; every field it writes is a CLAIM"
  },
  "started_unix_ns": $(date +%s%N)
}
EOF

cleanup() {
  [ -n "${OBS_PID:-}" ] && kill "$OBS_PID" 2>/dev/null
  [ -n "${STUB_PID:-}" ] && kill "$STUB_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

# ── 1. model stub ───────────────────────────────────────────────────────
python3 "$STUB" 0 "$WORK/stub.port" > "$TRACE_DIR/model_stub.log" 2>&1 &
STUB_PID=$!
for _ in $(seq 1 100); do [ -s "$WORK/stub.port" ] && break; sleep 0.05; done
[ -s "$WORK/stub.port" ] || fail "model stub did not start"
PORT="$(cat "$WORK/stub.port")"
MODEL_ADDR="127.0.0.1:$PORT"
echo "model stub listening on $MODEL_ADDR"

# ── 2. independent observer, and proof it is ready before the subject ──
python3 "$OBSERVER" \
  --out "$TRACE_DIR/audit_observer.jsonl" \
  --syscalls execve,execveat,connect \
  --until-marker "WINDOW_CLOSE_${NONCE}" \
  --max-seconds 90 \
  --ready-file "$WORK/observer.ready" \
  > "$TRACE_DIR/audit_observer.log" 2>&1 &
OBS_PID=$!
for _ in $(seq 1 200); do [ -s "$WORK/observer.ready" ] && break; sleep 0.05; done
if [ ! -s "$WORK/observer.ready" ]; then
  echo "OBSERVER_START_FAILED" > "$TRACE_DIR/STATUS"
  cat "$TRACE_DIR/audit_observer.log" >&2
  fail "independent observer did not become ready — refusing to run the subject without it"
fi
echo "observer ready (pid $(cat "$WORK/observer.ready"))"

# ── 3. window open, marked inside the observed stream ───────────────────
/bin/sh -c ": WINDOW_OPEN_${NONCE}"
echo "WINDOW_OPEN_${NONCE} $(date +%s%N)" >> "$TRACE_DIR/window.txt"

# ── 3b. observation loss, for the scenario that tests it ───────────────
# AIRI-015 removes the observer after the window opens. The point is that the
# window then never closes, so the analyser has an uninterpretable interval and
# must refuse to conclude — never report the executions it did not see as
# executions that did not happen.
if [ "$SCENARIO" = "AIRI-015" ]; then
  echo "OBSERVATION_LOSS_INJECTED $(date +%s%N)" >> "$TRACE_DIR/window.txt"
  kill -9 "$OBS_PID" 2>/dev/null
fi

# ── 4. the subject ──────────────────────────────────────────────────────
REPLAY_ARGS=()
if [ "$SCENARIO" = "AIRI-012" ]; then
  # The replayed stream must be a REAL previous run's signed events. Nothing is
  # synthesised: if no donor run exists the scenario refuses to run rather than
  # fabricating one.
  DONOR="${REPLAY_EVENTS:-$(ls -1t "$TRACE_ROOT"/AIRI-001-*/airi_events.jsonl 2>/dev/null | head -1)}"
  [ -s "${DONOR:-}" ] || fail "AIRI-012 needs a prior AIRI-001 run to replay; none found under $TRACE_ROOT"
  cp "$DONOR" "$TRACE_DIR/replay_source.jsonl"
  REPLAY_ARGS=(--replay-events "$TRACE_DIR/replay_source.jsonl")
  echo "replaying $DONOR"
fi

"$AGENT" \
  --scenario "$SCENARIO" \
  --events "$TRACE_DIR/airi_events.jsonl" \
  --model-addr "$MODEL_ADDR" \
  --nonce "$NONCE" \
  --work-dir "$WORK" \
  "${REPLAY_ARGS[@]}" \
  > "$TRACE_DIR/subject_stdout.txt" 2> "$TRACE_DIR/subject_stderr.txt"
SUBJECT_RC=$?
echo "subject exited rc=$SUBJECT_RC"

# ── 4b. the transplanted execution, for the scenario that tests it ─────
# AIRI-011 runs the subject's committed argv from THIS script — a process that
# is not the subject and not a descendant of it. The command line an observer
# sees is byte-identical to the declared tool's. Only observer-side parentage
# distinguishes them, which is the property under test: the right command line
# appearing somewhere on the host must not be credited to this execution.
if [ "$SCENARIO" = "AIRI-011" ]; then
  MANIFEST="$(ls -1 "$WORK"/airi-*-manifest.json 2>/dev/null | head -1)"
  [ -s "${MANIFEST:-}" ] || fail "AIRI-011 needs the subject's manifest to replay its committed argv"
  mapfile -t TRANSPLANT_ARGV < <(python3 -c "
import json,sys
for a in json.load(open(sys.argv[1]))['declared_tool_argv']:
    print(a)
" "$MANIFEST")
  echo "TRANSPLANT_EXEC $(date +%s%N)" >> "$TRACE_DIR/window.txt"
  "${TRANSPLANT_ARGV[@]}"
fi

# ── 5. window close, marked inside the observed stream ──────────────────
/bin/sh -c ": WINDOW_CLOSE_${NONCE}"
echo "WINDOW_CLOSE_${NONCE} $(date +%s%N)" >> "$TRACE_DIR/window.txt"

# ── 6. drain and stop ───────────────────────────────────────────────────
for _ in $(seq 1 100); do kill -0 "$OBS_PID" 2>/dev/null || break; sleep 0.1; done
kill "$OBS_PID" 2>/dev/null
wait "$OBS_PID" 2>/dev/null
kill "$STUB_PID" 2>/dev/null

python3 - "$TRACE_DIR" "$SUBJECT_RC" <<'PYEOF'
import json, sys, time, pathlib
d = pathlib.Path(sys.argv[1]); m = json.loads((d / "metadata.json").read_text())
m["subject_exit_code"] = int(sys.argv[2]); m["ended_unix_ns"] = time.time_ns()
(d / "metadata.json").write_text(json.dumps(m, indent=2))
PYEOF

# ── 7. analysis ─────────────────────────────────────────────────────────
python3 "$HERE/analyze.py" --trace-dir "$TRACE_DIR" \
  > "$TRACE_DIR/analysis.json" 2> "$TRACE_DIR/analysis.log"
RC=$?
cat "$TRACE_DIR/analysis.log" >&2
python3 -c "
import json,sys
a=json.load(open('$TRACE_DIR/analysis.json'))
print(f\"{a['scenario']:10s} {a['harness_verdict']:6s} claim={a['claim_summary']} observed={a['observed_summary']} classification={a['classification']}\")
"
echo "$TRACE_DIR"
exit $RC
