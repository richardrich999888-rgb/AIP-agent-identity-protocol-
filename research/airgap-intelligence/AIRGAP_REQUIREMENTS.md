# What "air-gap native" requires

## Must work with every external route absent

| Requirement | Status in this repository |
|---|---|
| Inference on customer hardware, no external API | **Built** (llama.cpp on loopback; endpoint parser refuses non-loopback and hostnames) |
| No DNS / telemetry / CDN at runtime | **Built** for the CLI path (std-only HTTP to an IP literal; no telemetry). No web UI yet. |
| Model integrity before load | **Built** in demo/eval scripts (SHA-256 vs approved hash); **not** a signed manifest |
| Software install without registries | **Partly**: `cargo build --locked`; vendored dependency bundle and signed release bundle not produced |
| Local authentication | **Minimal**: OS uid → principal map |
| Offline verification of evidence | **Built**: run records verify with public keys only |
| Tested disconnection | **Built**: demo, eval and research runs execute in a user+net namespace whose only interface is loopback; an egress probe refuses to run if a route exists |

## Failure modes to design for (not yet handled unless stated)

- **Clock:** no internal time source assumed; AIP's collector refuses an
  undisciplined clock, the sovereign slice does not check clock quality.
- **Revoked or expired trust anchors:** no revocation distribution in the
  sovereign slice.
- **Unavailable peers / registry:** single-node has no dependency; P2P not built.
- **Update transfer:** must cross the gap by the customer's approved procedure
  (e.g. removable media + independent hash approval). A checksum carried on the
  same medium does not authenticate the package.

## What P2P can and cannot do here

P2P can share artifacts **within** one approved network segment. It cannot and
must not join two security domains: a disconnected classified network and an
internet-connected one are not connected by running the same software on both.
Cross-domain transfer is a separately authorised, human-controlled step.
Peer authentication (a node's key) is not authorisation to receive any data.
