"""Heuristic shadow-AI classification from Sniffer Dog kernel events (item 2.3a). Pure.

Rule (HEURISTIC, never CONFIRMED):
- A process that **initiates** a TCP connection to a declared model endpoint
  (an LLM proxy or a model port), and has no identity in the registry, is a
  `HEURISTIC_AI_WORKLOAD`.
- Every other observed process is `UNCLASSIFIED`.
- `CONFIRMED` (an unregistered agent runtime proved by the gateway) belongs
  to P0-059's lineage and is not produced here, so the two cannot be confused.

"Initiates" means a `SocketState` event with `old_state == TCP_CLOSE (7)` and
`new_state == TCP_SYN_SENT (2)`. Measured on this kernel (lab run, item
2.3a): that transition runs in the connecting process's syscall context, so
`current_pid` is the client, and `remote` is the destination. On loopback,
other transitions run in softirq context, where `current_pid` names
whichever process the CPU was in. They are ignored on purpose.

Identity is (pid, pid_start_time_ticks) when a spawn or exec event bound
one; otherwise the pid alone, flagged `pid_reuse_not_excluded`.
`attribution_missing_reason` is one of the plan's four values: "no registry
row" (bound but unregistered) or "no binding" (no start time observed).
"signature invalid" and "no gateway session" need the gateway (P0-059) and
are never produced here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

TCP_CLOSE, TCP_SYN_SENT = 7, 2
HEURISTIC = "HEURISTIC_AI_WORKLOAD"
UNCLASSIFIED = "UNCLASSIFIED"


@dataclass(frozen=True)
class Endpoint:
    addr: tuple[int, ...]  # 16 bytes as the probe reports them (IPv4 in the first 4)
    port: int
    is_v6: bool = False


@dataclass
class Process:
    pid: int
    start_ticks: int | None = None
    names: set[str] = field(default_factory=set)
    connects: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    pid: int
    start_ticks: int | None
    names: tuple[str, ...]
    classification: str
    model_connects: int
    attribution_missing_reason: str | None
    pid_reuse_not_excluded: bool
    evidence_probe_seqs: tuple[int, ...]


def ipv4(a: str) -> tuple[int, ...]:
    """The probe's 16-byte form of a dotted IPv4 address."""
    parts = [int(x) for x in a.split(".")]
    if len(parts) != 4 or not all(0 <= x <= 255 for x in parts):
        raise ValueError(f"not an IPv4 address: {a}")
    return tuple(parts) + (0,) * 12


def _proc(procs: dict[int, Process], pid: int) -> Process:
    return procs.setdefault(pid, Process(pid))


def _bind(procs: dict[int, Process], e: dict) -> None:
    b = (e.get("bound") or {}).get("process") or {}
    pid, ticks = b.get("pid"), b.get("pid_start_time_ticks")
    if isinstance(pid, int) and isinstance(ticks, int):
        p = _proc(procs, pid)
        p.start_ticks = p.start_ticks or ticks


def observe(kernel_events: list[dict]) -> dict[int, Process]:
    """Fold kernel events into per-pid processes with names, bindings and connects."""
    procs: dict[int, Process] = {}
    for e in kernel_events:
        kind = e.get("kind")
        if not isinstance(kind, dict) or len(kind) != 1:
            continue
        (name, body), = kind.items()
        _bind(procs, e)
        if name == "ProcessSpawn":
            _proc(procs, body["child_pid"]).names.add(body.get("child_comm", ""))
            _proc(procs, body["parent_pid"]).names.add(body.get("parent_comm", ""))
        elif name == "ProcessExec":
            _proc(procs, body["pid"]).names.add(body.get("filename", ""))
        elif name == "SocketState":
            if body.get("old_state") == TCP_CLOSE and body.get("new_state") == TCP_SYN_SENT and body.get("protocol") == "Tcp":
                r = body["remote"]
                _proc(procs, body["current_pid"]).connects.append(
                    {"addr": tuple(r["addr"]), "port": r["port"], "is_v6": r["is_v6"], "probe_seq": e.get("probe_seq")})
    for p in procs.values():
        p.names.discard("")
    return procs


def classify(procs: dict[int, Process], model_endpoints: set[Endpoint],
             registry: set[tuple[int, int]]) -> list[Finding]:
    """One Finding per observed process (pid 0, the idle/softirq context, excluded)."""
    out = []
    for pid in sorted(procs):
        if pid <= 0:
            continue
        p = procs[pid]
        hits = [c for c in p.connects if Endpoint(c["addr"], c["port"], c["is_v6"]) in model_endpoints]
        registered = p.start_ticks is not None and (pid, p.start_ticks) in registry
        heuristic = bool(hits) and not registered
        reason = None
        if heuristic:
            reason = "no registry row" if p.start_ticks is not None else "no binding"
        out.append(Finding(pid, p.start_ticks, tuple(sorted(p.names)), HEURISTIC if heuristic else UNCLASSIFIED,
                           len(hits), reason, p.start_ticks is None,
                           tuple(c["probe_seq"] for c in hits if isinstance(c["probe_seq"], int))))
    return out
