# Tooling inventory — assessed, not assumed

Ten instruments were named. Each was assessed against the same ten questions
before any installation was attempted. Nothing was installed because it was on
the list; nothing was substituted for anything that turned out to be
unavailable.

Assessment host: Linux 6.18.44-fc-v24 (Firecracker microVM guest), x86_64,
root, `CapEff: 000001fffeffffff`. Egress passes through the organisation's
agent proxy.

## Egress reality — the constraint that decided most of this

Measured, not assumed. Reachability probed directly:

| Host | Result |
|---|---|
| `github.com`, `raw.githubusercontent.com` | reachable |
| `pypi.org`, `files.pythonhosted.org` | reachable |
| `registry.npmjs.org`, `index.crates.io`, `proxy.golang.org` | reachable |
| `ghcr.io`, `registry-1.docker.io` | reachable (API), **image layers not** |
| `production.cloudfront.docker.com` | **403 at CONNECT** — policy denial |
| `quay.io` | **blocked** |
| `deb.debian.org` | **blocked** |
| `packages.ros.org` | **blocked** |

Consequences, stated plainly:

- `git clone` of a public repository works.
- `pip`, `npm`, `cargo` and the Go module proxy work.
- **`apt` does not work.** No system package can be installed.
- **Docker image pulls do not work.** The daemon starts and runs; the registry
  path is denied at the proxy. `docker run hello-world` fails at layer fetch.
- **The ROS 2 apt repository is unreachable.**

That single row — `packages.ros.org` blocked, `deb.debian.org` blocked,
Docker Hub blocked — is what makes the entire robotics stack unavailable here.
It is an environment property, not a property of the tools, and it is recorded
as such rather than worked around. The proxy documentation
(`/root/.ccr/README.md`) is explicit that policy denials are to be reported,
not routed around.

---

## 1. Tetragon — **BUILT, RUNTIME BLOCKED**

| | |
|---|---|
| Repository | `github.com/cilium/tetragon` |
| Licence | Apache-2.0 (BPF programs GPL-2.0) |
| Maintenance | Active, CNCF (Cilium) |
| Open source | Yes |
| Install method attempted | **From source.** Its normal paths — `quay.io` container image, `apt` — are both blocked. |
| Claude Code compatibility | N/A — a daemon and a CLI, not an MCP server |
| Privileges required | root, `CAP_BPF`/`CAP_SYS_ADMIN`, bpffs |
| Offline capable | Yes, once built |
| Hardware interaction | None |
| Read-only vs control | Tetragon *can* enforce (`SIGKILL`, override). **Enforcement not configured. Observation only.** |

**Build: succeeded.** `bpf/objs/*.o` built with `make LOCAL_CLANG=1 tetragon-bpf`
(clang 18.1.3), then `tetragon` and `tetra` built with Go 1.27.0 fetched via
`GOTOOLCHAIN=auto`. Recipe preserved in `tetragon/BUILD.md`. Binaries are not
committed — they are 114 MB and they do not run here.

**Runtime: blocked, and the reason is exact.** Tetragon starts, discovers BTF
(`/sys/kernel/btf/vmlinux`, 4,671,335 bytes), detects features, creates its
maps and ring buffer — and then fails to load its mandatory `__base__` sensor:

```
sensor __base__ ... failed to load: failed prog .../bpf_exit_v511.o
  attaching 'event_exit_acct_process' failed: creating tracefs event
  (arch-specific fallback for "acct_process"): creating probe entry on
  tracefs: open /sys/kernel/tracing/kprobe_events: no such file or directory
```

Root cause, from the running kernel's own config:

```
# CONFIG_KPROBES is not set
CONFIG_HAVE_KPROBES=y          <- architecture *could*; kernel was built without
CONFIG_UPROBE_EVENTS=y
CONFIG_BPF_SYSCALL=y
CONFIG_DEBUG_INFO_BTF=y
```

`/sys/kernel/tracing` is mounted and populated; it contains `uprobe_events` and
`dynamic_events` and **does not contain `kprobe_events`**. The `kprobe` PMU is
absent from `/sys/bus/event_source/devices/`. Tetragon's detected features
report `kprobe_multi: false, fmodret: false, override_return: false`.

This is not a permission problem, not a build problem, and not fixable from
inside the guest. This kernel has BPF but no kprobes. Tetragon's process
lifecycle sensors are kprobe-based, so Tetragon cannot observe on this host.

**Status: UNAVAILABLE — kernel lacks `CONFIG_KPROBES`.** Retained because the
build is reproducible and the blocker is environmental: on a host with kprobes,
this same recipe yields a working instrument.

---

## 2. ROS 2 (`rclpy`, runtime) — **UNAVAILABLE**

Prerequisite of items 3, 4, 5 and 8. Distributed as system packages from
`packages.ros.org` (**blocked**) or as container images from Docker Hub
(**blocked**). `rclpy` and the `*_msgs` packages are not usefully installable
from PyPI — they are generated against a ROS distribution's own build.

No workaround was attempted, and none should be: a hand-assembled partial ROS
would be a fabricated environment, and telemetry from it would be worthless as
evidence.

**Status: UNAVAILABLE — no reachable distribution channel.**

## 3. ROS 2 MCP — `LCAS/ros2_mcp` — **CLONED, NOT INSTALLED**

| | |
|---|---|
| Licence | Apache-2.0 (`LICENSE` present) |
| HEAD | `ad061ef`, last commit 2025-12-12 |
| Install method | Docker (`compose.yaml`, `Dockerfile`) or a ROS 2 workspace |
| Dependency | `import rclpy`, `rosidl_runtime_py` — **item 2** |
| Read-only vs control | **Mixed.** It publishes to topics and calls services. Publishing to `/cmd_vel` moves a robot. |

Clone succeeded; licence verified; source read. It cannot run: both of its
install paths terminate at a blocked host, and its imports require item 2.

Had it been installable, its topic-publishing tools would have been disabled by
default under rule B.

**Status: UNAVAILABLE — requires ROS 2 (item 2) and Docker Hub.**

## 4. Gazebo Sim + `kvgork/gazebo-mcp` — **CLONED, NOT INSTALLED**

| | |
|---|---|
| Licence | MIT (`LICENSE` present) |
| HEAD | `73b9bcf`, last commit 2026-07-10 |
| Declared deps | `mcp`, `pydantic`, `pyyaml` — all PyPI-reachable |
| Undeclared deps | `requirements.txt` states plainly that `rclpy`, `gazebo_msgs`, `geometry_msgs`, `sensor_msgs`, `std_msgs`, `std_srvs`, `nav_msgs` come from **apt** |
| Read-only vs control | **Control.** Spawns, deletes and moves models; sets entity state. |

Gazebo Sim itself is an apt package. `apt` is blocked.

The PyPI portion would install. That would produce an MCP server shell with no
simulator behind it — a tool that appears present and can observe nothing. That
is worse than absence, because it invites a claim. Not installed.

**Status: UNAVAILABLE — Gazebo Sim requires apt; MCP server requires ROS 2.**

## 5. RoboFuzz — `sslab-gatech/RoboFuzz` — **CLONED, NOT INSTALLED**

| | |
|---|---|
| Licence | MIT (`LICENSE` present) |
| HEAD | `b1d9570`, last commit 2026-05-18 |
| Provenance | Georgia Tech SSLab; the ESEC/FSE'22 artefact |
| Dependency | A full ROS 2 + Gazebo installation, plus PX4 for its UAS targets |
| Read-only vs control | **Control by design** — it is a fuzzer; it drives the system under test into invalid states. |

The most valuable instrument on the list for adversarial work, and the most
firmly blocked: it needs everything in items 2 and 4 at once.

**Status: UNAVAILABLE — requires ROS 2 and Gazebo.**

## 6. rosbag2 — **UNAVAILABLE**

Part of a ROS 2 distribution. Same channel, same blockage. Its recording
format is open and its files could in principle be parsed offline, but there is
no ROS 2 here to record from, so there are no bags.

**Status: UNAVAILABLE — component of item 2.**

## 7. PX4 SITL / HITL — **UNAVAILABLE**

`PX4/PX4-Autopilot` clones. Building SITL requires a large apt toolchain
(`gcc-arm-none-eabi`, `libeigen3-dev`, `python3-*` system packages) and its
simulation targets are Gazebo or jMAVSim. `apt` blocked; Gazebo blocked.

HITL is out of scope regardless: it requires physical flight-controller
hardware, and no vehicle is to be armed or moved during setup.

**Status: UNAVAILABLE — build toolchain requires apt.**

## 8. MAVLink MCP — `ion-g-ion/MAVLinkMCP` — **CLONED, DELIBERATELY NOT INSTALLED**

| | |
|---|---|
| Licence | MIT (`LICENSE` present) |
| HEAD | `776b05e`, last commit 2026-08-31 |
| Declared deps | `mavsdk`, `mcp>=1.6,<2`, `fast-agent-mcp`, `shapely`, `pyproj` — **all PyPI-reachable** |
| Read-only vs control | **Control.** Arm/disarm, takeoff, land, goto, mission upload, parameter set. |

This is the one robotics item whose Python dependencies would actually install.
It is not installed, for two independent reasons, either of which suffices:

1. **Rule B.** Its primary surface is vehicle command — arming a UAS, changing
   flight parameters, uploading missions. Rule B requires that capability to be
   disabled by default. An MCP server whose control tools are all disabled is
   an empty server.
2. **No target.** `mavsdk` needs a `mavsdk_server` binary and a vehicle or SITL
   to talk to. PX4 SITL is item 7 — blocked. It would connect to nothing.

Installing it would put an armed-vehicle control surface into the session in
exchange for zero observational capability. Declined.

**Status: NOT INSTALLED — control surface without a simulation target.**

## 9. Webots — **NOT ASSESSED FURTHER, BY INSTRUCTION**

Excluded from the first wave. It is Apache-2.0 and open source; it is also an
apt/binary-tarball desktop simulator with the same channel problem, and the
instruction was explicit that it not be installed merely for completeness.
Recorded, not pursued.

**Status: NOT PURSUED.**

## 10. ROBOT.md — `RobotRegistryFoundation/robot-md-mcp` — **CLONED, NOT INSTALLED**

| | |
|---|---|
| Licence | Apache-2.0 (`LICENSE` present) |
| HEAD | `1f73093`, last commit 2026-06-10 |
| Install method | npm (`package.json`) — **reachable** |
| Read-only vs control | Read-only. It serves robot capability descriptions. |

Installable and harmless. Also not an observation instrument: it describes what
a robot *claims* to be. In Vanian's terms that is a **self-report**, and this
exercise exists to compare self-reports against independent observation. Adding
it would add a second self-report, not a second observer.

It has a place later — as a declared-capability source to reconcile *against* —
but not as validation tooling, and installing it now would overstate the
robotics readiness of this environment.

**Status: NOT INSTALLED — self-report source, not an observation source.**

---

## Additionally assessed: not on the list, and available

## 11. ftrace tracepoint reader — **AVAILABLE, INSTALLED**

Not a third-party tool. `/sys/kernel/tracing` is mounted, `CONFIG_FTRACE=y`,
`CONFIG_TRACEPOINTS=y`, and `sched:sched_process_exec`, `sched_process_fork`
and `sched_process_exit` are all in `available_events`. Verified by capture:

```
echo-24090  [002] 38049.860190: sched_process_exec: filename=/bin/echo pid=24090 old_pid=24090
true-24091  [003] 38049.862306: sched_process_exec: filename=/usr/bin/env  pid=24091 old_pid=24091
true-24091  [003] 38049.863778: sched_process_exec: filename=/usr/bin/true pid=24091 old_pid=24091
```

Zero installation, kernel-owned rendering, no vendor.

**It is not a replacement for Tetragon and must not be described as one.**
Tetragon would have observed via eBPF programs on *kernel functions* —
a different mechanism from anything Sniffer Dog uses. ftrace reads the *same
`sched_*` tracepoints* that Sniffer Dog already samples through
`perf_event_open`. What it provides is examined honestly in
`../linux/INDEPENDENCE.md` and quantified in
`../scenarios/INDEPENDENCE_MATRIX.md`. The short version: it is
**interface-independent** of Sniffer Dog and **not mechanism-independent**,
and that distinction decides what Experiment 1 is allowed to conclude.

**Status: READY.**

---

## Summary

| # | Instrument | Status |
|---|---|---|
| 1 | Tetragon | UNAVAILABLE — kernel lacks `CONFIG_KPROBES` |
| 2 | ROS 2 runtime | UNAVAILABLE — `packages.ros.org` and Docker Hub blocked |
| 3 | ROS 2 MCP | UNAVAILABLE — needs #2 |
| 4 | Gazebo Sim / Gazebo MCP | UNAVAILABLE — needs apt and #2 |
| 5 | RoboFuzz | UNAVAILABLE — needs #2 and #4 |
| 6 | rosbag2 | UNAVAILABLE — component of #2 |
| 7 | PX4 SITL/HITL | UNAVAILABLE — needs apt; HITL out of scope |
| 8 | MAVLink MCP | NOT INSTALLED — control surface, no target |
| 9 | Webots | NOT PURSUED — by instruction |
| 10 | ROBOT.md MCP | NOT INSTALLED — self-report, not observation |
| 11 | ftrace reader | **READY** |

One instrument of eleven is usable in this environment.

Nothing was substituted for anything unavailable. No installation command was
invented: every command recorded in `tetragon/BUILD.md` was executed and its
result observed.
