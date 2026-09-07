# Robotics validation layer — blocked, and why

No ROS 2, Gazebo, `ros2_control`, Nav2, MoveIt 2, `rosbag2` or `ros2_tracing` is
installed. This is the same finding `../../robotics/STATUS.md` recorded,
re-confirmed by `../preflight.sh` in this session:

| channel | host | result |
|---|---|---|
| ROS 2 apt repository | `packages.ros.org` | HTTP 403 — egress policy |
| Docker image layers | Docker daemon | unreachable |
| GitHub clone | `github.com` | HTTP 403 — egress policy |

`pip` and `raw.githubusercontent.com` work, which is enough to obtain *source
and licences* and not enough to obtain *a robot runtime*.

## What the layer is for when it is unblocked

| directory | purpose |
|---|---|
| `ros2/` | node execution, topic inspection, action/service observation, deterministic scenario launch |
| `gazebo/` | **Gazebo Sim, not Classic** — world, robot model, deterministic clock, physics, contact events, sensors |
| `ros2_control/` | the real controller boundary: autonomy → controller → actuator interface, via `gz_ros2_control` |
| `nav2/` | optional navigation workload — goal, controller execution, localisation, completion, recovery |
| `moveit/` | manipulation — planned trajectory, controller command, gripper command, completion claim |
| `tracing/` | `ros2_tracing` callback timelines. **Classified `SubjectMiddlewareInstrumentation`**: LTTng inside the subject's own processes is not an independent observer |
| `rosbag2/` | record and replay; delayed, duplicated, reordered, missing and stale messages |

## The classification, fixed in advance

Every one of these is a **self-report** in Vanian's vocabulary except Gazebo's
physics state, which is independent *within the simulation only* and is not a
fact about any world. See `../EVIDENCE_INDEPENDENCE_MATRIX.csv`.

A ROS 2 topic is the subject describing itself. A `rosbag2` file is that
description recorded faithfully — recording a claim verbatim makes it durable,
not true. A controller acknowledgement is the controller's account of the
controller.

None of them may become an independent proof by being binary, timestamped,
high-rate, or labelled "telemetry".
