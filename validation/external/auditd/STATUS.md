# Linux audit subsystem — independent cross-check for the BFSI pilot

| | |
|---|---|
| Instrument | Linux kernel audit subsystem (`NETLINK_AUDIT`), optionally the `auditd`/`auditctl` userspace |
| Mechanism | `audit_syscall_exit` — the **syscall boundary**, not a tracepoint |
| Independent of Vanian? | **Yes** — a different kernel facility from the perf-tracepoint path the Sniffer Dog samples. See `../../airi/OBSERVER_INDEPENDENCE.md` |
| In the trust boundary? | **No.** This is an external instrument. It is **compared against** Vanian and is **never** an input to a Reconciliation, NEXORA proof, EvidenceCeiling, or warrant (`../../README.md`). |
| Licence | GPL-2.0 (kernel); `audit` userspace GPL-2.0 |
| Modifies the agent? | No — passive; the agent is not instrumented |
| Observe-only? | Yes |

## Why audit, for a regulated institution

For process `execve`, the Sniffer Dog reads `sched:sched_process_exec` through
`perf_event_open`. The audit subsystem observes the **same act** through a
**different site** (`audit_syscall_exit`), so a defect or a foreign eBPF gate on
the perf-tracepoint path does not affect it. That makes it the strongest
independent witness available without a second host — and, unlike Tetragon, it
needs no kprobes (see the Tetragon note below), so it works on kernels the
Sniffer Dog's own cross-checks otherwise cannot.

A disagreement is signal: if audit records an `execve` the Sniffer Dog's account
lacks (and did not report as loss), the Sniffer Dog is wrong about that window.
Agreement corroborates but does not prove — both sit under the same host root
(`../../scenarios/TEST_PLAN.md`).

## Mechanism status on the repo's test kernel

Verified usable here without installing the `auditd` daemon: a `NETLINK_AUDIT`
socket accepts an `execve` rule and delivers SYSCALL/EXECVE/PATH/CWD records.
The working observer is `../../airi/observers/audit_observer.py`; the
independence argument is `../../airi/OBSERVER_INDEPENDENCE.md`
(verdict: `AUDIT_MECHANISM_USABLE`).

```
$ zgrep -E 'CONFIG_AUDIT(SYSCALL)?=' /proc/config.gz
CONFIG_AUDIT=y
CONFIG_AUDITSYSCALL=y
```

## Deploying it as the pilot cross-check (on institution hardware)

The `auditd` userspace is packaged by every enterprise Linux distribution
(`audit` / `auditd`), so on an institution host it is normally an already-approved
package rather than a source build. Minimal cross-check rule for the pilot's
agent actions:

```sh
# exec of the pilot agent's binaries (adjust the arch/path filters to the host)
auditctl -a always,exit -F arch=b64 -S execve -F dir=/var/lib/pilot-agent -k aip_pilot_exec
# connect() as a coarse network cross-check
auditctl -a always,exit -F arch=b64 -S connect -k aip_pilot_connect

# harvest for the comparison window
ausearch -k aip_pilot_exec --format raw > audit_exec.log
```

Where `auditd` cannot be added, the in-repo `NETLINK_AUDIT` observer
(`audit_observer.py`) is the fallback and needs no daemon.

Do **not** wire audit output into any `aip-*` crate. It is a witness to compare,
not evidence to consume. The comparison procedure is
`../CROSS_CHECK_BFSI.md`.

## Tetragon note

Tetragon (eBPF on **kprobes**) is the other candidate independent witness. It is
**blocked wherever the kernel lacks `CONFIG_KPROBES`** — the repo's test kernel
does (`../tetragon/BUILD.md`), so it could not be validated here. On institution
hardware, check `CONFIG_KPROBES` first; if present, Tetragon adds a second
independent witness, and audit + Tetragon agreeing against a differing Sniffer
Dog isolates a Sniffer Dog defect.
