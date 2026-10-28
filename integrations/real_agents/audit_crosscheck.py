"""Independent Linux audit exec observer, scoped to the workload uid.

Never clears existing audit rules. A unique rule is installed and removed for
this run only. No eBPF program is attached to Sniffer Dog's tracepoint: such an
attachment would correctly withdraw its mechanism-integrity coverage.
"""
import time
import uuid
from pathlib import Path
from evidence import Refused, command


def parse_status(text):
    fields = dict(line.split(maxsplit=1) for line in text.splitlines() if len(line.split()) == 2)
    try:
        result = {key: int(fields[key]) for key in ("enabled", "pid", "lost", "backlog")}
    except (KeyError, ValueError) as exc:
        raise Refused("incomplete Linux audit status") from exc
    if result["enabled"] != 1 or result["pid"] <= 0:
        raise Refused("requires active auditd with mutable per-run rules")
    return result


class AuditCrosscheck:
    def __init__(self):
        self.key = "sd" + uuid.uuid4().hex[:20]
        self.rule = ["always,exit", "-F", "arch=b64", "-S", "execve,execveat",
                     "-F", "euid=10001", "-k", self.key]
        self.started = False
        self.initial = None

    def start(self):
        self.initial = parse_status(command(["auditctl", "-s"]))
        command(["auditctl", "-a", *self.rule])
        self.started = True
        if self.key not in command(["auditctl", "-l"]):
            raise Refused("audit exec rule did not become active")

    def export(self, destination):
        for _ in range(20):
            final = parse_status(command(["auditctl", "-s"]))
            if final["lost"] != self.initial["lost"]:
                raise Refused("Linux audit reported lost events")
            if final["backlog"] == 0:
                break
            time.sleep(0.25)
        else:
            raise Refused("Linux audit backlog did not drain")
        if final["pid"] != self.initial["pid"]:
            raise Refused("auditd restarted during the observed window")
        # Exit 1/no matching records is a failed, not vacuous, cross-check.
        data = command(["ausearch", "-k", self.key, "--raw"])
        if "type=SYSCALL" not in data:
            raise Refused("auditd produced no syscall records")
        Path(destination).write_text(data)
        return {"source": "Linux audit", "key": self.key, "initial": self.initial, "final": final,
                "scope": "host uid 10001 execve/execveat; independent implementation/mechanism, shared kernel"}

    def close(self):
        if self.started:
            command(["auditctl", "-d", *self.rule])
            self.started = False
