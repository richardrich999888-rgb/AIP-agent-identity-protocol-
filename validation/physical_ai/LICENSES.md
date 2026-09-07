# Physical-AI validation tooling — licence registry

Every external tool the Skill 25 validation roadmap names, with its licence as
read from the project's own licence file.

## How the `Verified` column was filled

`upstream text` means the licence file was fetched from the project's own
repository during this session and its opening text read. The URL fetched is in
the `Licence URL` column. Nothing in that column is from memory.

`UNVERIFIED` means the fetch failed or was not attempted. Those rows are marked
and must be checked before any distribution decision rests on them. **No row is
guessed.**

## Version pinning

The `Version` column is `UNPINNED` for every blocked tool, and that is honest
rather than lazy: none of them is installed in this environment (see
`../robotics/STATUS.md` and `README.md`), so there is no build to pin. Pinning a
version this session cannot fetch would be a fabricated fact in a document whose
whole purpose is not to contain any.

The three installed tools carry the exact version reported by the installed
artefact.

---

## Registry

| # | Name | Repository | Version | Licence | Licence URL | Verified | Direct dep or external tool | Linkage | Production dep? | Validation only? | Commercial concern | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | ROS 2 (rclcpp, core) | `github.com/ros2/rclcpp` | UNPINNED — not installed | Apache-2.0 | `raw.githubusercontent.com/ros2/rclcpp/rolling/LICENSE` | upstream text | external tool | none | **NO** | **YES** | none | Middleware for the robotics environment. Never linked by any `aip-*` crate. |
| 2 | Gazebo Sim (`gz-sim`) | `github.com/gazebosim/gz-sim` | UNPINNED — not installed | Apache-2.0 | `raw.githubusercontent.com/gazebosim/gz-sim/gz-sim9/LICENSE` | upstream text | external tool | none | **NO** | **YES** | none | Modern Gazebo. Gazebo Classic deliberately not used — see `README.md`. |
| 3 | `ros2_control` | `github.com/ros-controls/ros2_control` | UNPINNED — not installed | Apache-2.0 | `raw.githubusercontent.com/ros-controls/ros2_control/master/LICENSE` | upstream text | external tool | none | **NO** | **YES** | none | Provides the real controller boundary the profile's rungs describe. |
| 4 | `gz_ros2_control` | `github.com/ros-controls/gz_ros2_control` | UNPINNED — not installed | Apache-2.0 | `raw.githubusercontent.com/ros-controls/gz_ros2_control/master/LICENSE` | upstream text | external tool | none | **NO** | **YES** | none | The current Gazebo integration; the Classic one is end-of-life. |
| 5 | Nav2 | `github.com/ros-navigation/navigation2` | UNPINNED — not installed | **Mixed: LGPL-2.1-or-later, Apache-2.0, BSD-3-Clause** | `raw.githubusercontent.com/ros-navigation/navigation2/main/LICENSE` | upstream text | external tool | none | **NO** | **YES** | **YES — LGPL portions** | Per-package licence; the repository's own LICENSE says to read each `package.xml`. Validation-only, run as a separate process, never linked. **Do not vendor.** |
| 6 | MoveIt 2 | `github.com/moveit/moveit2` | UNPINNED — not installed | BSD-3-Clause | `raw.githubusercontent.com/moveit/moveit2/main/LICENSE.txt` | upstream text | external tool | none | **NO** | **YES** | none | Manipulation workload. |
| 7 | `rosbag2` | `github.com/ros2/rosbag2` | UNPINNED — not installed | Apache-2.0 | `raw.githubusercontent.com/ros2/rosbag2/rolling/LICENSE` | upstream text | external tool | none | **NO** | **YES** | none | Recording and replay. Records self-reports; recording does not make them true. |
| 8 | `ros2_tracing` | `github.com/ros2/ros2_tracing` | UNPINNED — not installed | Apache-2.0 | `raw.githubusercontent.com/ros2/ros2_tracing/rolling/LICENSE` | upstream text | external tool | none | **NO** | **YES** | none | LTTng instrumentation **inside the subject's own processes**. Classified `SubjectMiddlewareInstrumentation`. |
| 9 | OpenCV | `github.com/opencv/opencv` | **5.0.0 (installed)** | Apache-2.0 | `raw.githubusercontent.com/opencv/opencv/4.x/LICENSE` | upstream text | external tool | none — separate Python process | **NO** | **YES** | none | Installed as `opencv-python-headless`. Used by the external fiducial observer. Verified against the 4.x branch licence file; the 5.x branch was not fetched. |
| 10 | AprilTag 3 | `github.com/AprilRobotics/apriltag` | UNPINNED — family used via OpenCV | BSD-2-Clause | `raw.githubusercontent.com/AprilRobotics/apriltag/master/LICENSE.md` | upstream text | external tool | none | **NO** | **YES** | none | The **36h11 family** is used through OpenCV's own dictionary rather than by linking this library, so the observer has one dependency instead of two and the renderer and detector agree by construction. |
| 11 | NumPy | `github.com/numpy/numpy` | **2.4.6 (installed)** | BSD-3-Clause | not fetched | **UNVERIFIED** | external tool | none | **NO** | **YES** | none | Transitive dependency of OpenCV. |
| 12 | PX4 Autopilot | `github.com/PX4/PX4-Autopilot` | UNPINNED — not installed | BSD-3-Clause | `raw.githubusercontent.com/PX4/PX4-Autopilot/main/LICENSE` | upstream text | external tool | none | **NO** | **YES** | none | SITL only. No vehicle is armed. |
| 13 | MAVLink | `github.com/mavlink/mavlink` | UNPINNED — not installed | **Generator (L)GPL-3.0; generated output MIT by explicit exception** | `raw.githubusercontent.com/mavlink/mavlink/master/COPYING` | upstream text | external tool | none | **NO** | **YES** | **YES — read the exception** | The repository's own COPYING states the generator is (L)GPLv3 and that output embedded in a binary product is licensed MIT under a stated exception. Only the *output* would ever be used, and not in production. |
| 14 | `pymavlink` | `github.com/ArduPilot/pymavlink` | **installed** | LGPL-3.0 | not fetched | **UNVERIFIED** | external tool | none — separate Python process | **NO** | **YES** | **YES — LGPL** | Installed for protocol instrumentation only. Never linked into any Rust crate. Verify before any distribution. |
| 15 | MAVSDK | `github.com/mavlink/MAVSDK` | UNPINNED — not installed | BSD-3-Clause | `raw.githubusercontent.com/mavlink/MAVSDK/main/LICENSE.md` | upstream text | external tool | none | **NO** | **YES** | none | Full 3-clause text read. Command surface (arm/takeoff/mission) is why it is not installed here — see `../uas/README.md`. |
| 16 | open62541 | `github.com/open62541/open62541` | UNPINNED — not installed | MPL-2.0 | `raw.githubusercontent.com/open62541/open62541/master/LICENSE` | upstream text | external tool | none | **NO** | **YES** | **file-level copyleft** | MPL-2.0 is per-file copyleft. Fine as a separate process; do not vendor modified files into a proprietary build without review. |
| 17 | `asyncua` | `github.com/FreeOpcUa/opcua-asyncio` | **installed** | LGPL-3.0 | not fetched | **UNVERIFIED** | external tool | none — separate Python process | **NO** | **YES** | **YES — LGPL** | Installed as an OPC UA client/server **stand-in for open62541 at the protocol level**. It is a different implementation, not open62541, and the distinction is recorded rather than blurred. |
| 18 | Eclipse 4diac FORTE | `github.com/eclipse-4diac/4diac-forte` | UNPINNED — not installed | EPL-2.0 | `raw.githubusercontent.com/eclipse-4diac/4diac-forte/develop/LICENSE.md` | upstream text | external tool | none | **NO** | **YES** | weak copyleft | IEC 61499 runtime, for distributed-control experiments. Separate process. |
| 19 | ROS-Industrial (`industrial_core`) | `github.com/ros-industrial/industrial_core` | UNPINNED — not installed | Apache-2.0 (expected) | fetch returned 404 | **UNVERIFIED** | external tool | none | **NO** | **YES** | unknown until verified | The branch guessed for the fetch does not exist. **Verify before use.** |
| 20 | QGroundControl | `github.com/mavlink/qgroundcontrol` | UNPINNED — not installed | not fetched | **UNVERIFIED** | external tool | none | **NO** | **YES** | unknown until verified | Not required by any experiment defined here. Listed because the brief names it. |

---

## What the registry establishes

**No entry is a production dependency.** Column `Production dep?` is `NO` for all
twenty. The only new compiled artefact in this work is
`adapters/vanian-external-adapter`, which carries its own `[workspace]` table,
is not a workspace member, and depends on `aip-observation`, `aip-observe`,
`aip-crypto`, `serde` and `serde_json` — no external framework, enforced by
`tests/no_second_hierarchy.rs::the_adapter_names_no_external_framework_type`.

**Three entries carry real commercial-coupling risk** and all three are
validation-only and run as separate processes: Nav2's LGPL portions,
`pymavlink`/`asyncua` (LGPL), and open62541's file-level MPL. None is vendored.
None is linked. The MAVLink generator's (L)GPLv3 is the subtlest of them and the
exception in its own COPYING is the thing to read before relying on generated
headers.

**Four rows are UNVERIFIED** and are marked as such rather than filled from
memory: NumPy, `pymavlink`, `asyncua`, ROS-Industrial, and QGroundControl's
licence. Anyone making a distribution decision must verify those first.
