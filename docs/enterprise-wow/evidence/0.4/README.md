# Item 0.4 — lab feasibility, 20 Nov 2026 (cloud session container)

Host: 4 vCPU, 15 GB, kernel 6.18.44-fc-v726, running as root (uid 0).

| Check | Command | Result | File |
|---|---|---|---|
| Docker daemon | `dockerd &` (started by hand; nothing supervises it) | server 29.9.2, overlayfs, cgroupfs driver, **cgroup v1** | `dockerd.log`, `docker-info.txt` |
| Container run | `docker run --rm hello-world` | exit 0 | `hello-world.txt` |
| Compose, 2 services | `docker compose -f compose-probe.yaml up --abort-on-container-exit` | probe → web over the compose network: exit 0; host → 127.0.0.1:18080: `vanian-0.4-ok`, exit 0 | `compose-probe.yaml`, `compose-run.txt` |
| Sensors, as found | `cargo run --release --locked -p aip-probe --example sensor_matrix` | **3/7** open: connector, fanotify, afpacket. sched, cgroup, sockstate, socksend fail closed: tracefs not mounted | `sensor-matrix-before-tracefs.txt` |
| Sensors, after setup | `mount -t tracefs nodev /sys/kernel/tracing`, then the same command | **7/7** open | `sensor-matrix-after-tracefs.txt` |
| Live sensor tests | `cargo test --locked -p aip-probe --test live_sensors -- --nocapture --test-threads=1` | 6 passed, 0 failed, 0 ignored; no `SKIPPED` line printed, so every test body ran | `live-sensors.txt` |

Decision: Compose runs, so 0.4 is **not** `BLOCKED_BY_INFRASTRUCTURE`. The
native-process fallback is not needed in this container.

Limits, stated so they are not assumed:

- `sensor_matrix` shows only that each sensor's opener succeeded. It reads no
  events. Event capture is shown only for fanotify and AF_PACKET (by
  `live_sensors`); the four tracer sensors opened but were not exercised here.
- dockerd and the tracefs mount are manual steps and do not survive a
  container restart. A lab script (item 6.1) must do both and check them.
- cgroup v1 with the cgroupfs driver. Anything that assumes cgroup v2 must be
  checked separately.
- This is the cloud session container, not a customer-like host.

`SHA256SUMS` covers every other file in this directory.
