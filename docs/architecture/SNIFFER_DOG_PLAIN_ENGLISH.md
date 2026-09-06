# How the Sniffer Dog works — in plain English, and only what is true today

This is the description that may be used outside the repository. Every
sentence below is backed by code and tests on this branch at the commit named
in `SNIFFER_DOG_PR3_HARVEST_REPORT.md`. A companion table at the end lists
the claims from earlier drafts that must **not** be made, and why.

## The problem

An AI agent can say anything about what it did. A gateway can only see what
the agent chose to send through it. The Sniffer Dog is the part of the system
that does not believe either of them: it watches the operating system itself,
records what it saw under a key the agent cannot reach, and lets a separate
verifier compare that record with what the agent was actually authorised to
do. When the evidence is not there, it says so — `CANNOT_PROVE` — instead of
guessing.

## 1. It watches the kernel, not the agent's logs

A small probe on the host reads two kinds of facts straight from Linux:

- **Process events.** When any process forks a child and when that child
  starts running a program, the kernel announces it. The probe listens to
  those announcements (the `sched_process_fork` and `sched_process_exec`
  tracepoints, read through the standard `perf_event_open` interface) and
  pins each process down by three things that survive process-id reuse: the
  id, the exact start tick, and the machine's boot id. It then hashes the
  **contents** of the program the child is running, not its path.
- **Network connections.** When any process starts a TCP connection and when
  that connection completes, the kernel announces it (the
  `inet_sock_set_state` tracepoint). The probe records the endpoints and
  binds the *start* of the connection to the process that made it.

- **Frames on the wire.** Every frame a network device sends or receives is
  copied to the probe by the kernel's ordinary packet tap (`AF_PACKET`).
  The probe keeps the **headers** — addresses, ports, TCP flags and
  sequence numbers, and how many payload bytes there were — with the
  kernel's own capture time, and counts every frame the kernel dropped. It
  never keeps, hashes or looks at the payload itself, and the wire cannot
  tell it which process a frame belongs to. The same code can run on a
  mirror port on another machine, outside the watched host's control.

- **File writes.** When any process closes a file it had open for
  writing on a watched mount, the kernel queues an event (`fanotify`) that
  names the file and hands the probe a handle the kernel itself tied to the
  writing process. The probe records the file's path and inode and reads
  nothing from the file.

It also polls the kernel's socket tables and process list as a second,
weaker source, and it counts every event the kernel ring buffer dropped.
There is no eBPF program and no view of payloads.

## 2. It signs nothing on the host

The probe holds no key. Everything it collects is sent to a **collector**
that runs elsewhere and holds the signing key. The collector signs each batch
into a numbered chain, so a batch cannot be replayed, reordered, rolled back
or forked without the chain showing it. If the probe restarts, drops events,
or a batch goes missing, the collector marks the observer *degraded* or
*recovering* and refuses to claim it was watching during that time. If the
collector itself restarts, it checks its own remembered position against the
archive of records it previously signed; a collector that forgot, was rolled
back, or was fed an edited state file is caught by that arithmetic.

## 3. Authority is a separate signature

Before an agent acts, an independent **decision point** checks the agent's
signed tokens — who issued them, whether they were delegated properly, when
they expire — and signs a record of exactly which process instance is
authorised to do exactly which action. The decision point is not the agent
and does not hold the agent's key.

## 4. A verifier compares the two

The **reconciler** takes the decision point's signed expectation and the
collector's signed observations and answers one question: did the authorised
process do the authorised thing? Today it can answer that for four kinds of
action — making a TCP connection to an authorised endpoint, running a
program whose contents hash to the authorised value, sending bytes on a
connection to an authorised endpoint (the kernel's count of the bytes,
never the bytes themselves), and completing a write to an authorised file
path (the path, never what was written) — and it says
`VERIFIED_EXECUTION` at *attested* strength: signed by an independent
collector, but read from a host that a root attacker could still lie to.

For everything else, and whenever the observer was not watching, the answer
is `CANNOT_PROVE`. Other answers exist for specific situations: an
authorisation that was never seen executed while the observer had full
coverage (`PHANTOM_CLAIM`), a different process instance acting under an
agent's authorisation (`IDENTITY_DIVERGENCE`), a broken or forked
observer chain (`SENSOR_INTEGRITY_FAILURE`, `CONTINUITY_FAILURE`), and — when
the kernel shows an agent's process was created by an agent that neither
authorised it nor created its identity, with every piece of that evidence
signed — a lineage contradiction (`LINEAGE_VIOLATION`).

When the answer for a connection is `VERIFIED_EXECUTION`, the verifier also
asks the wire: did the packet tap see this connection's handshake at the
same time? The answer is written on the record — corroborated, not seen,
tap not running, or two handshakes at once — and cited. It is information,
not a stronger verdict: on the same machine the wire and the socket layer
sit under the same root, and a tap that saw nothing may simply have been
watching a different network path.

## 5. It builds an agent's record from evidence, not from the agent

Around those verdicts sits a profile of each agent: who issued its tokens,
who delegated what to it and whom it delegated to, which process spawned it
and which it spawned, and which decisions were verified, refused or
unprovable. Every line of that profile names the signature it rests on.
Anything the agent says about itself is kept in a separate box marked
*self-declared, unverified*. There is no score, rating or trust level
anywhere.

## 6. A warrant is permission to act on proof, and it is advisory by default

A **warrant engine** turns a verdict into a response class — observe, alert,
constrain or contain — using two separate axes: how serious the finding would
be if true, and how strongly the evidence establishes it. Containment can be
*permitted* only for mechanically proven evidence, only when an operator has
switched autonomous containment on, never for a protected system component,
and never when the observer was not watching. Out of the box, nothing is ever
more than an alert.

## 7. Nothing here contains anything

There is no code in this repository that kills a process, freezes a control
group, drops a packet or changes a firewall. The warrant is a signed statement
of what a later, separate containment component *would* be allowed to do.
That component does not exist yet.

## Claims that earlier drafts made and this text does not

| Earlier claim | Status | Why it cannot be said |
|---|---|---|
| "hooks straight into the OS using eBPF" | not implemented | static tracepoints via `perf_event_open`; no eBPF program exists |
| "hooks `sys_enter_execve`" | not implemented | `sched_process_exec` is used; it is a different, later hook that carries the resolved filename |
| "intercepts every socket (`cgroup/connect4`) and wire packet" | partly | `inet_sock_set_state` transitions, TCP only, plus an `AF_PACKET` tap that copies TCP/IP **headers** from the device layer (payload by length only, no process attribution); no cgroup hook, no eBPF, nothing is intercepted or blocked |
| "ingests actual database and proxy records out-of-band" | not implemented | application-log sensors exist only on the unmerged PR #3 branch; a decision document is required before adopting them (`OT_SENTINEL_HARVEST_AUDIT.md`) |
| "32-byte SHA-256 of the raw payload, exact arguments" | partly | the executed program's **contents** and the authorised action's **parameters** are hashed; a send is evidenced by the kernel's byte **count**; payloads and arguments are not visible from the kernel and no payload hash exists (invariant I23) |
| "cross-checks against the Gateway's append-only Merkle ledger" | not implemented | there is no gateway and no Merkle commitment in this repository; the collector's chain is a signed sequence, not a Merkle tree |
| "Matched / Unattributed Effect / Phantom Claim" | partly | `VERIFIED_EXECUTION` and `PHANTOM_CLAIM` are reachable; `UNATTRIBUTED_EFFECT` needs a signed completeness statement from the decision point that nothing produces yet |
| "automatically triggers instant isolation … XDP_DROP … cgroups v2 freeze" | not implemented, and forbidden at this stage | no actuation code exists; containment is Skill 9 |
| "Zero False Outages" | not a claim anyone can make | no outage statistics exist; the design goal is that nothing below proven evidence can cause an outage |
| "writes its own detections onto a tamper-evident hash chain" | partly | the collector's batches and health are a signed, sequenced chain; reconciliation records and warrants are not yet chained or persisted |
| "refuses to run in an amnesic state" | partly | the collector detects amnesia, rollback, fork and a truncated archive on resume and reports them; refusing to start is an operator choice built on that result |
| "10 Gbps", "line rate", "sub-1% overhead", "TRL" figures | not measurable here | no benchmark in this repository measures the observer; the figures on the `codex` branches measure unrelated userspace code |
