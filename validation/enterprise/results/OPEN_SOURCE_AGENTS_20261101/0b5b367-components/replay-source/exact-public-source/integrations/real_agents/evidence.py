"""Verification policy, not a new signature format. Python 3.12+, stdlib only.

The Rust verifier decides signatures and chain integrity. This module checks
experiment scope and provenance only AFTER that independent process succeeds.
Checkpoints are controller custody records, not observer signatures.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

ARCHIVES = ("attested.archive.jsonl", "health.archive.jsonl")


class Refused(RuntimeError):
    pass


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def records(path):
    data = Path(path).read_bytes()
    if not data or not data.endswith(b"\n"):
        raise Refused(f"empty or unfinished archive: {Path(path).name}")
    return [json.loads(line) for line in data.splitlines()]


def command(args, *, timeout=120, **kwargs):
    result = subprocess.run([str(x) for x in args], capture_output=True,
                            text=True, timeout=timeout, **kwargs)
    if result.returncode:
        # Do not echo arbitrary framework stderr (it may contain credentials).
        raise Refused(f"{Path(str(args[0])).name} exited {result.returncode}")
    return result.stdout


def anchors_args(anchor):
    return ["--observer-id", anchor["observer_id"], "--key-version",
            str(anchor["key_version"]), "--pubkey", anchor["public_key"]]


def verify(archive, tools, anchor, checkpoint):
    archive, tools = Path(archive), Path(tools)
    # A checkpoint supplied with the evidence by an untrusted sender is NOT an
    # independent anchor. CLI requires its separate path; custody is documented.
    for name in ARCHIVES:
        expected = checkpoint["sha256"].get(name)
        if not expected or sha256(archive / name) != expected:
            raise Refused(f"controller checkpoint mismatch: {name}")
    output = command([tools / "aip-observe-verify", *anchors_args(anchor),
                      "--batches", archive / ARCHIVES[0], "--health",
                      archive / ARCHIVES[1], "--json"])
    report = json.loads(output)
    if report["findings"] or not report["batches"]["records"] or not report["health"]["records"]:
        raise Refused("verifier did not accept both nonempty archives")
    return report


def instance_key(process):
    return (tuple(process["boot_id"]), process["pid"], process["pid_start_time_ticks"])


def event_time(batch, event):
    anchor = batch.get("clock_anchor")
    if not anchor or "monotonic_ns" not in anchor:
        return None
    delta = event["kernel_timestamp_ns"] - anchor["monotonic_ns"]
    # Match aip-corroborate's signed integer division (towards zero), not
    # Python's floor division. Most events precede their batch anchor.
    millis = (abs(delta) // 1_000_000) * (-1 if delta < 0 else 1)
    return max(-(2**63), min(2**63 - 1, anchor["realtime_ms"] + millis))


def covered(health, start, end, mechanisms, max_error_us=1_000_000):
    """The final retained signed health must cover one complete Active epoch.

    Never union recovery windows or reuse an older Active record. Emission
    chronology cannot move backwards; equal timestamps retain archive order,
    so the last record wins. Bad health inside the interval still vetoes it.
    """
    latest = previous_emission = None
    for item in health:
        h = item["health"]
        emitted = h["emitted_at_ms"]
        if previous_emission is not None and emitted < previous_emission:
            return False
        if start <= emitted <= end and h["state"] != "Active":
            return False
        latest, previous_emission = h, emitted
    if latest is None:
        return False
    w, clock = latest.get("attested_coverage"), latest.get("clock")
    return bool(latest["state"] == "Active" and latest["continuity"] == "Verified" and w
                and w["from_ms"] <= start and w["to_ms"] >= end
                and set(mechanisms) <= set(latest["covered_by"])
                and clock and clock["synchronized"]
                and 0 <= clock["max_error_us"] <= max_error_us)


def summarize(batches, health, launch, start, end):
    """Container membership is observed process context, NOT logical identity.

    Match boot + PID namespace + mount namespace measured by the controller.
    PID-only matching and agent-supplied PIDs are deliberately unsupported.
    Exact start ticks identify the launch instance. No guessed child edges.
    """
    counts, host_counts = Counter(), Counter()
    instances = set()
    unbound = outside = unclocked = dropped = root_events = 0
    recent = []
    executions = []
    for signed in batches:
        b = signed["batch"]
        if b["probe_id"] != launch["probe_id"]:
            continue
        if b["claimed_to_ms"] < start or b["claimed_from_ms"] > end:
            continue
        dropped += b["dropped_events"]
        for e in b["kernel_events"]:
            when = event_time(b, e)
            if when is None:
                unclocked += 1
                continue
            if not start <= when <= end:
                continue
            kind = next(iter(e["kind"]))
            host_counts[kind] += 1
            bound = e.get("bound")
            if not bound:
                unbound += 1
                continue
            p, container = bound["process"], bound.get("container")
            if (p["boot_id"] != launch["process"]["boot_id"] or not container
                    or any(container[k] != launch["container"][k]
                           for k in ("pid_ns_inode", "mnt_ns_inode"))):
                outside += 1
                continue
            instances.add(instance_key(p))
            root_events += instance_key(p) == instance_key(launch["process"])
            counts[kind] += 1
            if kind == "ProcessExec":
                # The Rust corroborator resets its anchor for each batch.
                # Exact evidence references use that same signed clock domain.
                executions.append({"pid": p["pid"], "wall_ms": when,
                                   "batch_sequence": signed["sequence"]})
            recent.append({"state": "OBSERVED", "time_ms": when,
                           "kind": kind, "process": p, "container": container,
                           "batch_sequence": signed["sequence"],
                           "probe_seq": e["probe_seq"], "logical_agent": "CANNOT_PROVE"})
    mechanisms = ["SchedTracepoint", "Fanotify", "SockSendTracepoint"]
    coverage = covered(health, start, end, mechanisms)
    return {
        "kernel_state": "OBSERVED" if counts else "CANNOT_PROVE",
        "archive_scope": "controller-measured workload namespaces, signed probe observations",
        "coverage": "COVERED" if coverage else "INTEGRITY_UNKNOWN",
        "workload_events_by_kind": dict(counts), "host_events_by_kind": dict(host_counts),
        "process_instances": len(instances), "launch_instance_events": root_events,
        "unbound_host_events": unbound, "outside_workload_bound_events": outside,
        "events_without_clock_anchor": unclocked, "probe_reported_drops": dropped,
        "logical_agent_attribution": "CANNOT_PROVE", "authority": "CANNOT_PROVE",
        "reconciliation": "CANNOT_PROVE", "tool_gateway_receipts": "NOT_SUPPLIED",
        "actual_event_ground_truth": None, "missed_events": None,
        "coverage_percent": None, "incorrect_logical_attribution": None,
        "events": recent[-100:],
        "workload_executions": executions,
    }


def acceptance(summary, corroboration, workload_exit):
    """Integration gate, NOT the overall assignment's acceptance criteria."""
    failures = []
    c = summary["workload_events_by_kind"]
    if workload_exit != 0:
        failures.append("framework process failed")
    if summary["coverage"] != "COVERED":
        failures.append("no signed Active epoch encloses the workload")
    if not summary["launch_instance_events"]:
        failures.append("launcher process instance was not observed")
    for kind in ("ProcessExec", "FileEvent", "SocketSend"):
        if not c.get(kind):
            failures.append(f"no workload-bound {kind}")
    if summary["probe_reported_drops"] or summary["events_without_clock_anchor"]:
        failures.append("observer reported loss or lacks a clock anchor")
    if not corroboration.get("agreed"):
        failures.append("independent comparison has no agreements")
    observed = Counter((e["batch_sequence"], e["pid"], e["wall_ms"])
                       for e in summary.get("workload_executions", []))
    paired = Counter((e["aip"]["batch_sequence"], e["aip"]["pid"], e["aip"]["wall_ms"])
                     for e in corroboration.get("agreed", []))
    if not observed or observed - paired:
        failures.append("not every bound workload exec was independently corroborated")
    if corroboration.get("external_only") or corroboration.get("external_unparsed"):
        failures.append("independent comparison has unresolved gaps")
    return failures


def mutations(data):
    lines = data.splitlines(keepends=True)
    if len(lines) < 3:
        raise Refused("tamper tests need at least three real captured batches")
    altered = json.loads(lines[1])
    altered["attested_at_ms"] += 1
    return {"modify": lines[0] + json.dumps(altered).encode() + b"\n" + b"".join(lines[2:]),
            "remove_middle": b"".join(lines[:1] + lines[2:]),
            "remove_suffix": b"".join(lines[:-1]),
            "remove_prefix": b"".join(lines[1:]),
            "reorder": b"".join([lines[1], lines[0], *lines[2:]]),
            "duplicate": b"".join([lines[0], *lines]),
            "corrupt": b"not-json\n" + b"".join(lines[1:])}
