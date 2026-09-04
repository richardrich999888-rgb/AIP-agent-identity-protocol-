# Identity Binding

## The tuple

A running process is named by all of these together. Any subset is a weaker claim and must
be labelled as one.

| Field | Why it is in the tuple |
|---|---|
| `pid` | Necessary, wildly insufficient alone. |
| `process_start_time` | Defeats PID reuse. Without it the tuple is not an identity. |
| `ppid` + `parent_start_time` | Lineage. A parent identified by PID alone reintroduces the reuse problem one level up. |
| `namespace_id` | Two processes with the same PID in different namespaces are different processes. |
| `cgroup_id` | Workload attribution; survives PID churn within a container. |
| `executable_measurement` | What actually ran. See below. |
| `runtime_instance` | The agent runtime incarnation, so a restart is distinguishable from continuity. |
| `uid` / `session_id` | Credential context; a privilege transition mid-execution is itself a signal. |

Not every field is available for every event on every platform. The schema carries them all
and marks the absent ones; a missing field is recorded as missing and never defaulted. A
defaulted field silently weakens the binding and nothing downstream can tell.

## PID reuse is the whole reason for the tuple

`PID 1234 = Agent X` is false the moment PID 1234 exits and the number is reissued. On a
busy host that is minutes. The consequence is not a missed detection — it is a false
attribution, where an unrelated process's actions are cryptographically attributed to an
agent that did not perform them.

For an accountability system this is the worst available failure. A missed detection loses
information; a false attribution manufactures it, and the manufactured record is signed and
durable.

`(pid, process_start_time)` is the minimum that closes it, and `process_start_time` must
come from the kernel's own record, not from a timestamp the process reports. Add namespace
and cgroup for container environments where PID namespaces make collisions routine rather
than occasional.

## Executable measurement

`exe_hash` in the current codebase hashes the executable's *path string*. `/usr/bin/python3`
hashes identically whatever the file contains, so the field survives the binary being
replaced. It is a measurement in name only, and the audit called it out specifically.

Real measurement, in descending order of strength:

1. **Load-time measurement by something the process cannot influence** — IMA, a TEE
   measured launch, or a container image digest verified at admission. Strongest, because
   the measurement happens before the process can act.
2. **Content hash of the on-disk binary at observation time.** Weaker: subject to
   time-of-measure-to-time-of-use, and the file can be replaced after exec. Usable, but
   record when it was taken.
3. **Path plus inode plus mtime.** Weak; a change detector, not a measurement. Label it
   accordingly.

Interpreted runtimes need a second measurement. Hashing `/usr/bin/python3` says nothing
about the script it is running, and for an agent the script is the behaviour. Measure the
entrypoint script and, where the threat model needs it, the loaded module inventory. If
neither is measured, the field states what it covers so nobody reads more into it.

## Binding lifecycle

A binding is created, is valid over an interval, and ends. Model it explicitly:

```
PROPOSED   -> binding requested, not yet corroborated
ACTIVE     -> corroborated by the observer, within validity window
EXPIRED    -> validity window passed
BROKEN     -> a tuple field changed (exec, credential transition, namespace move)
```

`BROKEN` is a signal, not a cleanup path. A process that execs into a different binary
mid-binding has changed what it is; continuing to attribute the old identity to it is the
false-attribution failure again. Emit the transition and require a fresh binding.

Give the validity window a bounded maximum. An `ACTIVE` binding with no expiry is the same
class of defect as AIP-C-01: an authority whose lifetime nothing enforces.

## Lineage

The question the system must be able to answer is *which agent ultimately caused this
process*, across `agent -> runtime -> pid -> ppid -> child`.

Store the parent chain with start times at each hop. A chain of bare PIDs is
reconstructable into a plausible and wrong genealogy after any reuse, and a plausible wrong
genealogy is worse than an absent one because it will be believed.

Cap traversal depth and carry a visited set. The audit found two unbounded graph walks in
the existing codebase (`delegation.rs:312`, `aip-service/src/revocation.rs:374`) with no
visited set, where a cyclic parent reference produces an infinite loop with unbounded
memory and disk writes. Process trees are attacker-influenced input; treat them as hostile.

## What a binding claim is worth

Record the strength alongside the binding, using the vocabulary from
`aip-mcp-execution-audit`:

- **asserted** — the process reported the tuple. Worth nothing against a hostile agent.
- **attested** — a second party signed the tuple. Worth what that party's key custody is
  worth; see `attestation-keys.md`.
- **observed** — a party the agent cannot influence read the tuple from the kernel.

A binding whose strength is not recorded will be read as `observed` by whoever consumes it
next. Make the field mandatory rather than optional.
