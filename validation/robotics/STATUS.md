# Robotics instruments — status: none installed, and why

This directory is empty of tooling. That is the finding, not an omission.

## The blockage

Every robotics instrument on the list reaches this environment through one of
three channels. All three are denied by the organisation's egress policy:

| Channel | Host | Result |
|---|---|---|
| ROS 2 apt repository | `packages.ros.org` | blocked |
| Debian/Ubuntu apt | `deb.debian.org` | blocked |
| Docker Hub image layers | `production.cloudfront.docker.com` | 403 at CONNECT — policy denial |

The Docker daemon itself runs (started here, storage-driver overlayfs, API on
`/var/run/docker.sock`). `docker run hello-world` still fails, at layer fetch.
The proxy recorded:

```json
{"kind":"connect_rejected",
 "detail":"gateway answered 403 to CONNECT (policy denial or upstream failure)",
 "host":"production.cloudfront.docker.com:443"}
```

`git clone`, `pip`, `npm`, `cargo` and the Go module proxy all work. That is
enough to obtain *source*, and not enough to obtain *a robot runtime*.

## What follows from it

```
ROS 2 (rclpy, *_msgs)     UNAVAILABLE  ── no reachable channel
  ├── ros2_mcp            UNAVAILABLE  ── imports rclpy
  ├── rosbag2             UNAVAILABLE  ── component of ROS 2
  ├── Gazebo + gazebo-mcp UNAVAILABLE  ── Gazebo is apt; MCP imports rclpy
  └── RoboFuzz            UNAVAILABLE  ── needs ROS 2 *and* Gazebo
PX4 SITL                  UNAVAILABLE  ── build toolchain is apt; sim is Gazebo
MAVLink MCP               NOT INSTALLED ─ deps install, but see below
ROBOT.md MCP              NOT INSTALLED ─ deps install, but see below
Webots                    NOT PURSUED  ── by instruction
```

The five repositories were cloned and their licences verified — Apache-2.0 for
`LCAS/ros2_mcp` and `RobotRegistryFoundation/robot-md-mcp`, MIT for
`kvgork/gazebo-mcp`, `sslab-gatech/RoboFuzz` and `ion-g-ion/MAVLinkMCP`. Full
per-tool assessment in `../external/TOOL_INVENTORY.md`.

## The two that would have installed, and were not

**MAVLink MCP.** Its PyPI dependencies (`mavsdk`, `mcp`, `fast-agent-mcp`,
`shapely`, `pyproj`) are all reachable. It was not installed for two reasons,
either sufficient alone:

1. Its surface is vehicle *command* — arm, disarm, takeoff, land, goto, mission
   upload, parameter set. Rule B requires exactly those capabilities to be off
   by default, and a server with all of them off is an empty server.
2. `mavsdk` needs a `mavsdk_server` and a vehicle or SITL behind it. PX4 SITL
   is blocked. It would connect to nothing.

Installing it would have added an armed-vehicle control surface to this session
in exchange for no observational capability.

**ROBOT.md MCP.** npm-installable, read-only, harmless. Also the wrong kind of
thing: it serves a robot's *declared capabilities*. In Vanian's vocabulary that
is a **self-report**. This exercise exists to compare self-reports against
independent observation; adding it would add a second self-report and no
observer. It has a real use later — as the declared side of a reconciliation —
and no use as validation tooling now.

## What was deliberately not done

- No partial or hand-assembled ROS installation. A fabricated environment
  produces fabricated telemetry, and telemetry from it would be worse than
  none, because it would invite a claim.
- No substitution of an unrelated simulator or plugin for a blocked one.
- No invented installation commands. Where a channel is blocked, the block is
  recorded with the host and the proxy's own error.
- **No vehicle armed or moved.** There is no vehicle, and there would have
  been no arming if there were.

## What would unblock this

An environment with **either** an allowlist entry for `packages.ros.org` and
`deb.debian.org`, **or** an allowlist entry for the Docker Hub layer host, or a
pre-provisioned ROS 2 + Gazebo image. Any one of those turns items 2–7 from
UNAVAILABLE into installable in a single pass, and the assessments in
`../external/TOOL_INVENTORY.md` are written so that pass does not have to
repeat this work.

Until then, phases 3–7 of `../scenarios/TEST_PLAN.md` cannot begin, and no
statement about Vanian and autonomous systems may be made from this
environment.
