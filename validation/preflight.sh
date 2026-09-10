#!/usr/bin/env bash
#
# preflight.sh — report what this environment can actually validate.
#
# This is a REPORT. It installs nothing, downloads nothing, configures nothing
# and changes no system state. Run it as often as you like.
#
# Per-instrument status:
#   READY    — usable now
#   PARTIAL  — present but limited; the limitation is named
#   BLOCKED  — not usable here; the reason is named
#
# The overall status is the weakest thing that matters, never an average.
# "Most instruments are READY" is not a status.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TRACEFS=/sys/kernel/tracing

READY=0; PARTIAL=0; BLOCKED=0

say()   { printf '%s\n' "$*"; }
ready() { printf '  \033[32mREADY\033[0m    %s\n' "$*"; READY=$((READY+1)); }
part()  { printf '  \033[33mPARTIAL\033[0m  %s\n' "$*"; PARTIAL=$((PARTIAL+1)); }
block() { printf '  \033[31mBLOCKED\033[0m  %s\n' "$*"; BLOCKED=$((BLOCKED+1)); }
note()  { printf '           %s\n' "$*"; }

say "Vanian validation preflight"
say "host: $(uname -sr)  user: $(id -un)  $(date -u +%FT%TZ)"
say ""

# ── host prerequisites ──────────────────────────────────────────────────────
say "Host prerequisites"
if [ "$(id -u)" -eq 0 ]; then ready "root"; else block "not root — kernel observation needs it"; fi

if [ -f "$TRACEFS/available_events" ]; then
  ready "tracefs at $TRACEFS"
else
  block "tracefs absent — no tracepoint observation of any kind"
fi

if [ -d "$TRACEFS/instances" ]; then
  ready "ftrace instances (isolated capture)"
else
  part "no ftrace instances — capture would share the global buffer"
fi

paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "?")
if [ "$paranoid" != "?" ]; then
  # Root with CAP_PERFMON opens tracepoints regardless of this value.
  if [ "$(id -u)" -eq 0 ]; then
    ready "perf_event_paranoid=$paranoid (root: tracepoints openable)"
  else
    part "perf_event_paranoid=$paranoid and not root — perf tracepoints likely denied"
  fi
else
  part "perf_event_paranoid unreadable"
fi
say ""

# ── Sniffer Dog 2.0, the system under test ──────────────────────────────────
say "Sniffer Dog 2.0 (system under test)"
missing=()
for tp in sched_process_fork sched_process_exec; do
  grep -qx "sched:$tp" "$TRACEFS/available_events" 2>/dev/null || missing+=("$tp")
done
if [ ${#missing[@]} -eq 0 ]; then
  ready "sched tracepoints present: sched_process_fork, sched_process_exec"
else
  block "sched tracepoints absent: ${missing[*]}"
fi

REC="$HERE/scenarios/exp01_linux_runtime_observation/recorder/target/release/exp01-recorder"
if [ -x "$REC" ]; then
  ready "experiment recorder built"
else
  part "experiment recorder not built — run.sh builds it on demand (needs cargo)"
fi
say ""

# ── reference instruments ───────────────────────────────────────────────────
say "Reference instruments"
if "$HERE/linux/ftrace_observer.sh" preflight 2>/dev/null | grep -q "STATUS READY"; then
  ready "ftrace tracepoint reader"
  note "interface-independent of Sniffer Dog; NOT mechanism-independent."
  note "see linux/INDEPENDENCE.md before drawing conclusions from it."
else
  block "ftrace tracepoint reader — run linux/ftrace_observer.sh preflight for detail"
fi

if [ -e "$TRACEFS/kprobe_events" ]; then
  ready "kprobes — Tetragon can attach (build: external/tetragon/BUILD.md)"
else
  block "Tetragon — kernel has no kprobe_events"
  note "'# CONFIG_KPROBES is not set' in this kernel. Not a permission or build"
  note "problem and not fixable from inside the guest. This is the single"
  note "biggest gap here: no available instrument observes process execution"
  note "through a mechanism Sniffer Dog does not already use."
fi
say ""

# ── robotics ────────────────────────────────────────────────────────────────
say "Robotics / autonomous-system instruments"
if command -v ros2 >/dev/null 2>&1; then
  ready "ROS 2 CLI on PATH"
else
  block "ROS 2 — not installed"
  note "packages.ros.org, deb.debian.org and the Docker Hub layer host are all"
  note "egress-blocked. No reachable channel. See robotics/STATUS.md."
fi
for t in gz ign gazebo; do command -v $t >/dev/null 2>&1 && found=$t; done
if [ -n "${found:-}" ]; then ready "Gazebo ($found)"; else block "Gazebo — not installed (apt blocked)"; fi
if command -v ros2 >/dev/null 2>&1 && ros2 bag --help >/dev/null 2>&1; then
  ready "rosbag2"
else
  block "rosbag2 — component of ROS 2"
fi
block "PX4 SITL — build toolchain requires apt"
block "RoboFuzz — requires ROS 2 and Gazebo"
say ""
say "  Not installed by decision, not by blockage:"
note "MAVLink MCP  — vehicle control surface with no SITL target (rule B)"
note "ROBOT.md MCP — a self-report source, not an observation source"
note "Webots       — excluded from the first wave by instruction"
say ""

# ── phases ──────────────────────────────────────────────────────────────────
say "Test-plan phases (scenarios/TEST_PLAN.md)"
if [ -f "$TRACEFS/available_events" ] && [ "$(id -u)" -eq 0 ]; then
  say "  1  Independent Linux runtime observation      READY"
else
  say "  1  Independent Linux runtime observation      BLOCKED"
fi
say "  2  Mechanism-independent corroboration        BLOCKED (no kprobes)"
say "  3  Autonomous self-report vs simulator truth  BLOCKED (no ROS 2/Gazebo)"
say "  4  Recording and deterministic replay         BLOCKED (no rosbag2)"
say "  5  Adversarial autonomous behaviour           BLOCKED (no RoboFuzz deps)"
say "  6  Effect boundary under simulated flight     BLOCKED (no PX4 SITL)"
say "  7  Physical-effect observation                BLOCKED (no hardware/safety case)"
say ""

# ── verdict ─────────────────────────────────────────────────────────────────
say "Summary: $READY ready, $PARTIAL partial, $BLOCKED blocked"
say ""
if [ "$BLOCKED" -gt 0 ] && [ "$READY" -gt 0 ]; then
  say "STATUS: PARTIAL"
  say ""
  say "Phase 1 can run. Phases 2-7 cannot. This environment can establish that"
  say "Sniffer Dog reads one kernel tracepoint correctly and classifies subject"
  say "self-reports correctly against it. It cannot establish anything about"
  say "autonomous systems, and it cannot establish anything physical."
  exit 1
elif [ "$BLOCKED" -eq 0 ]; then
  say "STATUS: READY"
  exit 0
else
  say "STATUS: BLOCKED"
  exit 2
fi
