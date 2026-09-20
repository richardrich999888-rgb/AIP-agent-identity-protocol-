# Tier 2 rootkit runbooks — DOCUMENT ONLY (rule 1)

No rootkit is run by anything in this repository. These are the VM runbooks a
human executes, and `parse_health.py` is the harness that ingests the
observer's signed health from such a run and asserts it reached the required
integrity state. `run.sh` exercises that harness against fixtures so it is
known-correct before it meets a real capture.

## The one environment these run in

A dedicated VM, snapshotted before each run and restored after, with **no
network path to any production or development host**. Secure Boot off (to load
the module) for the unhardened pass; the hardened pass re-enables the write
foreclosures below. Nothing here is run on the machine that built this repo.

## Per-tool runbook

First provision the VM: inside it, `AIP_ROOTKIT_VM=1 sudo -E ./vm_setup.sh`
(installs the toolchain and prints the two hardening profiles; it fetches,
builds and loads no rootkit, and refuses to run outside the disposable VM).
Then, for each tool: (1) clone into `../vendored/<tool>` for source review;
(2) in the VM, build and load per the tool's own docs; (3) start `aip-probe` +
`aip-collector` (both `sched` and `connector` sensors live — the connector is
the gate-independent anchor Phase 0 needs); (4) run the attack against a
marked pid; (5) copy the collector's `health.archive.jsonl` out of the VM into
`fixtures/<tool>.attack.health.jsonl`; (6) add a manifest row; (7) `./run.sh`.

| Tool | Technique | Sensor exercised | Required observed state |
|------|-----------|------------------|-------------------------|
| ebpfkit | `bpf()` interception, self-hiding (`--disable-bpf-obfuscation` = baseline) | perf submission path vs the connector anchor | `IntegrityUnknown` |
| bad-bpf `pidhide` | `getdents64` filtering | pidfd anchoring vs `/proc` enumeration | `IntegrityUnknown` or `IdentityDivergence` |
| TripleCross | `bpf_probe_write_user`, magic-packet backdoor | detection query vs kernel-lockdown baseline | `IntegrityUnknown` (unhardened); attack foreclosed (integrity-lockdown) |
| Boopkit | eBPF raw-socket TCP | AF_PACKET header tap | `IntegrityUnknown` or divergence |
| pamspy | uprobe on `pam_get_authtok` | **out of scope** — documented boundary, not a claim | n/a |

## The hardening matrix (run every row twice)

Unhardened, then with `lockdown=integrity` + `unprivileged_bpf_disabled=1` +
`net.core.bpf_jit_harden=2`. The delta is the defensive-baseline statement for
RBI: at or above `lockdown=integrity` + Secure Boot, the write-primitive and
unsigned-module-load paths are foreclosed; the residual pure delivery-path
hook requires defeating Secure Boot, which is out of scope and documented as
such. Under `lockdown=confidentiality` the observer's own tracing primitives
are disabled and it cannot run — a hard deployment precondition, surfaced to
RBI, not hidden.

## Status

**Not executed.** No VM run has been performed in this environment. The
harness and fixtures are a rehearsal; the fixtures are synthetic and labelled
so in `run.sh` output.
