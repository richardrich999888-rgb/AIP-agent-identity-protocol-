#!/usr/bin/env bash
#
# preflight.sh — report what this environment can actually validate for the
# Skill 25 physical-AI roadmap.
#
# This is a REPORT. It installs nothing, downloads nothing, configures nothing
# and changes no system state. It never substitutes a stand-in for a missing
# tool: a fabricated environment produces fabricated telemetry, and telemetry
# from it would be worse than none, because it would invite a claim.
#
# Per-instrument status:
#   READY    — usable now
#   PARTIAL  — present but limited; the limitation is named
#   BLOCKED  — not usable here; the reason is named
#
# Overall status is the weakest thing that matters, never an average.
#
# Companion to ../preflight.sh, which covers the Linux runtime observers. This
# one covers robotics, UAS, industrial and physical observation.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
READY=0; PARTIAL=0; BLOCKED=0

say()   { printf '%s\n' "$*"; }
ready() { printf '  \033[32mREADY\033[0m    %s\n' "$*"; READY=$((READY+1)); }
part()  { printf '  \033[33mPARTIAL\033[0m  %s\n' "$*"; PARTIAL=$((PARTIAL+1)); }
block() { printf '  \033[31mBLOCKED\033[0m  %s\n' "$*"; BLOCKED=$((BLOCKED+1)); }
note()  { printf '           %s\n' "$*"; }

have()  { command -v "$1" >/dev/null 2>&1; }
pymod() { "${PY:-python3}" -c "import $1" >/dev/null 2>&1; }

PY=${PY:-python3}

say "Vanian physical-AI validation preflight"
say "host: $(uname -sr) $(uname -m)   user: $(id -un)   $(date -u +%FT%TZ)"
say ""

# ── host ────────────────────────────────────────────────────────────────────
say "Host"
. /etc/os-release 2>/dev/null || true
say "  distribution: ${PRETTY_NAME:-unknown}"
case "${VERSION_ID:-}" in
  24.04) ready "Ubuntu 24.04 — matches ROS 2 Jazzy, the current LTS distribution" ;;
  22.04) ready "Ubuntu 22.04 — matches ROS 2 Humble" ;;
  *)     part  "distribution is not a ROS 2 LTS target; a container would be needed" ;;
esac

AVAIL_KB=$(df -Pk / | awk 'NR==2{print $4}')
AVAIL_GB=$((AVAIL_KB / 1024 / 1024))
if [ "$AVAIL_GB" -ge 40 ]; then
  ready "disk: ${AVAIL_GB} GiB free — enough for ROS 2 + Gazebo + PX4"
elif [ "$AVAIL_GB" -ge 15 ]; then
  part "disk: ${AVAIL_GB} GiB free — enough for the observer stack, not for a full robotics image"
else
  block "disk: ${AVAIL_GB} GiB free — too little for any robotics environment"
fi

if [ -e /dev/dri/renderD128 ]; then
  ready "GPU render node present — Gazebo rendering possible"
else
  part "no /dev/dri render node — Gazebo would need software rendering or headless physics only"
fi

if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
  ready "display available"
else
  note "no display — headless only; not a blocker for physics or SITL"
fi
say ""

# ── containerisation ────────────────────────────────────────────────────────
say "Containerisation"
if have docker; then
  if timeout 20 docker info >/dev/null 2>&1; then
    ready "docker daemon reachable"
  else
    block "docker present but the daemon is unreachable — no containerised ROS/Gazebo/PX4"
  fi
else
  block "docker absent"
fi
say ""

# ── network channels the robotics stack needs ───────────────────────────────
say "Package channels"
probe() { # name url
  local code
  code=$(timeout 25 curl -sS -o /dev/null -w '%{http_code}' "$2" 2>/dev/null) || code="000"
  case "$code" in
    2*|3*) ready "$1 reachable (HTTP $code)" ;;
    403)   block "$1 denied by egress policy (HTTP 403) — $2" ;;
    000)   block "$1 unreachable (no response) — $2" ;;
    *)     part  "$1 returned HTTP $code — $2" ;;
  esac
}
probe "ROS 2 apt repository"  "http://packages.ros.org/ros2/ubuntu/dists/noble/Release"
probe "GitHub (clone source)" "https://github.com/PX4/PX4-Autopilot"
probe "PyPI"                  "https://pypi.org/simple/opencv-python-headless/"
say ""

# ── robotics middleware ─────────────────────────────────────────────────────
say "Robotics"
for t in ros2:"ROS 2 CLI" colcon:"colcon build tool" rosdep:"rosdep"; do
  cmd=${t%%:*}; label=${t#*:}
  if have "$cmd"; then ready "$label"; else block "$label absent"; fi
done
if have gz; then ready "Gazebo Sim (gz)"; elif have gazebo; then part "Gazebo Classic only — end-of-life for ros2_control; modern Gazebo required"; else block "Gazebo Sim absent"; fi
pymod rclpy && ready "rclpy" || block "rclpy absent"
for p in ros2_control:"ros2_control" nav2_bringup:"Nav2" moveit:"MoveIt 2" rosbag2_py:"rosbag2" tracetools:"ros2_tracing"; do
  mod=${p%%:*}; label=${p#*:}
  pymod "$mod" && ready "$label" || block "$label absent"
done
say ""

# ── physical observation ────────────────────────────────────────────────────
say "Physical observation (the external observer)"
if pymod cv2; then
  V=$("$PY" -c "import cv2;print(cv2.__version__)" 2>/dev/null)
  if "$PY" -c "import cv2;cv2.aruco.getPredefinedDictionary(cv2.aruco.DICT_APRILTAG_36h11)" >/dev/null 2>&1; then
    ready "OpenCV $V with the AprilTag 36h11 dictionary"
  else
    part "OpenCV $V present but the AprilTag dictionary is unavailable"
  fi
else
  block "OpenCV absent — pip install opencv-python-headless"
fi
pymod numpy && ready "NumPy" || block "NumPy absent"
pymod pupil_apriltags && ready "pupil-apriltags (standalone AprilTag 3 bindings)" \
  || part "pupil-apriltags absent — not required; OpenCV carries the 36h11 family"

CAMS=$(ls /dev/video* 2>/dev/null | wc -l)
if [ "$CAMS" -gt 0 ]; then
  ready "$CAMS camera device(s) present — a real external observation is possible"
else
  block "no /dev/video* device — NO REAL CAMERA. Only synthetic scenes can be rendered,"
  note  "and a synthetic scene is not an observation of any world. The collector"
  note  "labels such runs SimulatorGroundTruth and the adapter refuses them as"
  note  "physical claims. That refusal is the correct answer, not a defect."
fi
say ""

# ── UAS ─────────────────────────────────────────────────────────────────────
say "UAS"
have px4 && ready "PX4 binary" || block "PX4 SITL absent"
pymod pymavlink && ready "pymavlink (protocol instrumentation only)" || block "pymavlink absent"
have mavsdk_server && ready "mavsdk_server" || block "MAVSDK absent"
note "ARM=DISABLED  TAKEOFF=DISABLED  MISSION EXECUTION=DISABLED — no vehicle may be armed"
note "by any script in this tree. See uas/hitl/README.md."
say ""

# ── industrial ──────────────────────────────────────────────────────────────
say "Industrial"
pymod asyncua && ready "asyncua (OPC UA in Python — a stand-in, NOT open62541)" || block "asyncua absent"
have forte && ready "4diac FORTE" || block "4diac FORTE absent"
if [ -f /usr/include/open62541.h ] || [ -f /usr/local/include/open62541.h ]; then
  ready "open62541 headers"
else
  block "open62541 absent"
fi
say ""

# ── the adapter itself ──────────────────────────────────────────────────────
say "Vanian external adapter"
if have cargo; then
  if (cd "$HERE/adapters/vanian-external-adapter" && cargo build --quiet --all-targets >/dev/null 2>&1); then
    ready "adapters/vanian-external-adapter builds"
  else
    block "the adapter does not build — run cargo test there for the reason"
  fi
else
  block "cargo absent — the adapter cannot be built or tested"
fi
say ""

# ── verdict ─────────────────────────────────────────────────────────────────
say "Summary: $READY ready, $PARTIAL partial, $BLOCKED blocked"
say ""
say "What can be executed here"
if pymod cv2 && have cargo; then
  say "  - the external fiducial observer, over SYNTHETIC scenes only"
  say "  - the admission adapter, over recorded traces, offline and deterministically"
else
  say "  - nothing in this tree"
fi
say ""
say "What cannot, and what it would take"
say "  - ROS 2 / Gazebo / ros2_control / Nav2 / MoveIt 2 / rosbag2 / ros2_tracing:"
say "    an allowlist entry for packages.ros.org, or a Docker Hub layer host, or a"
say "    pre-provisioned ROS 2 + Gazebo image."
say "  - PX4 SITL / MAVSDK: a reachable GitHub clone path and the apt toolchain."
say "  - open62541 / 4diac FORTE: a reachable clone path and a C toolchain build."
say "  - ANY physical observation: a camera. There is no /dev/video* here, and no"
say "    amount of software substitutes for one."
say ""

if [ "$BLOCKED" -eq 0 ]; then
  say "STATUS READY"
  exit 0
elif [ "$READY" -gt 0 ]; then
  say "STATUS PARTIAL — the physical-observation milestone is NOT reachable in this"
  say "environment, because it requires a camera that is not present."
  exit 0
else
  say "STATUS BLOCKED"
  exit 1
fi
