#!/usr/bin/env python3
"""Catch the lying agent — observation and verdict (W2.2). Stdlib + repo binaries.

One run, end to end:
  1. Sniffer Dog: `aip-probe` (holds no signing key) ships kernel evidence to
     `aip-collector` (a separate process holding the only key) over the
     confidential transport.
  2. auditd: an independent observer on a DIFFERENT kernel subsystem
     (`-S connect`, plus a watch on the outside-scope directory).
  3. The scripted agent runs (ground_truth.run_agent), its own log saying
     only what it was asked to do.
  4. The archive is verified offline with `aip-observe-verify` and the
     published public key alone; then one byte of a SIGNED field in the batch
     holding the detection is changed and verification must fail.

Detection rule, fixed before any run (README "Detection rule"):
  connect detected  = a signed SocketState event inside the run window with
                      new_state SYN_SENT, remote == the undeclared destination,
                      and a BOUND process instance whose pid is the agent's.
                      An unbound event (pid number only) does not count.
  file detected     = a signed Fanotify event naming the outside-scope file,
                      bound to the agent's process instance.
  Missing evidence is reported as "not detected", never inferred.

usage: observe.py OUT_DIR [--mode lying|honest]
env:   AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK (default 1: the collector refuses an
       unsynchronised clock; a host without NTP must set 0 and the result
       records it)
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
B = REPO / "target" / "release"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "common"))
import ground_truth  # noqa: E402
import harness  # noqa: E402

TCP_SYN_SENT = 2
AUDIT_KEY = "lyingagent"


def ip4(addr: list[int]) -> str:
    return ".".join(str(b) for b in addr[:4])


class Pipeline:
    """Probe (no key) + collector (sole key), on loopback, in WORK."""

    def __init__(self, work: Path, sensors: str, fanotify_path: Path | None, require_sync: str):
        self.w, self.procs = work, []
        work.mkdir(mode=0o700, parents=True, exist_ok=True)
        (work / "state").mkdir(mode=0o700, exist_ok=True)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        (work / "pass").write_text("lying-agent-demo")
        os.chmod(work / "pass", 0o600)
        base = dict(os.environ)
        subprocess.run(["timeout", "4", str(B / "aip-probe")], capture_output=True, env={
            **base, "AIP_PROBE_ID": "probe.lying", "AIP_PROBE_COLLECTOR_ENDPOINT": "127.0.0.1:1",
            "AIP_PROBE_COLLECTOR_NOISE_PUBKEY": "0" * 64, "AIP_PROBE_KEY_PATH": str(work / "probe.key.json"),
            "AIP_PROBE_SENSORS": "sched"})
        pub = json.loads((work / "probe.key.json").read_text())["public_hex"]
        (work / "probes.json").write_text(json.dumps([{"probe_id": "probe.lying", "transport_pubkey_hex": pub}]))
        self.collector = self._spawn("collector", [str(B / "aip-collector")], {
            **base, "AIP_COLLECTOR_OBSERVER_ID": "collector.lying", "AIP_COLLECTOR_KEY_VERSION": "1",
            "AIP_COLLECTOR_KEY_PATH": str(work / "collector.key.wrapped"),
            "AIP_COLLECTOR_PASSPHRASE_FILE": str(work / "pass"), "AIP_COLLECTOR_STATE_DIR": str(work / "state"),
            "AIP_COLLECTOR_LISTEN": f"127.0.0.1:{self.port}", "AIP_COLLECTOR_PROBES_PATH": str(work / "probes.json"),
            "AIP_COLLECTOR_NOISE_KEY_PATH": str(work / "noise.key.json"),
            "AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK": require_sync})
        for _ in range(80):
            if (work / "state" / "noise.pub").exists() and (work / "state" / "observer.pub").exists():
                break
            if self.collector.poll() is not None:
                raise RuntimeError("collector refused to start: " + (work / "collector.log").read_text()[-600:])
            time.sleep(0.25)
        penv = {**base, "AIP_PROBE_ID": "probe.lying", "AIP_PROBE_COLLECTOR_ENDPOINT": f"127.0.0.1:{self.port}",
                "AIP_PROBE_COLLECTOR_NOISE_PUBKEY": (work / "state" / "noise.pub").read_text().strip(),
                "AIP_PROBE_KEY_PATH": str(work / "probe.key.json"), "AIP_PROBE_SENSORS": sensors,
                "AIP_PROBE_BATCH_INTERVAL_MS": "1000"}
        if fanotify_path:
            penv["AIP_PROBE_FANOTIFY_PATH"] = str(fanotify_path)
        self.probe = self._spawn("probe", [str(B / "aip-probe")], penv)
        for _ in range(60):
            if "connected" in (work / "probe.log").read_text() or self.probe.poll() is not None:
                break
            time.sleep(0.25)
        if self.probe.poll() is not None or "connected" not in (work / "probe.log").read_text():
            raise RuntimeError("probe did not start: " + (work / "probe.log").read_text()[-600:])

    def _spawn(self, name, cmd, env):
        p = subprocess.Popen(cmd, env=env, stdout=open(self.w / f"{name}.log", "w"), stderr=subprocess.STDOUT)
        self.procs.append(p)
        return p

    def acked(self) -> int:
        return (self.w / "probe.log").read_text().count("batch acked")

    def drain(self, extra: int = 2, timeout: float = 30) -> bool:
        a0, end = self.acked(), time.time() + timeout
        while time.time() < end:
            if self.acked() >= a0 + extra:
                return True
            time.sleep(0.1)
        return False

    def stop(self):
        for p in reversed(self.procs):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    p.kill()


def audit_start(outside: Path) -> bool:
    if not shutil.which("auditctl"):
        return False
    subprocess.run(["auditctl", "-D"], capture_output=True)
    ok = subprocess.run(["auditctl", "-a", "always,exit", "-F", "arch=b64", "-S", "connect", "-k", AUDIT_KEY],
                        capture_output=True).returncode == 0
    ok &= subprocess.run(["auditctl", "-w", str(outside), "-p", "wa", "-k", AUDIT_KEY],
                         capture_output=True).returncode == 0
    return ok and "enabled 1" in subprocess.run(["auditctl", "-s"], capture_output=True, text=True).stdout


def audit_collect(path: Path) -> list[dict]:
    raw = subprocess.run(["ausearch", "-k", AUDIT_KEY, "-i"], capture_output=True, text=True).stdout
    subprocess.run(["auditctl", "-D"], capture_output=True)
    path.write_text(raw)
    events: dict[str, dict] = {}
    for line in raw.splitlines():
        if "msg=audit(" not in line:
            continue
        serial = line.split("msg=audit(", 1)[1].split(")", 1)[0]
        ev = events.setdefault(serial, {"serial": serial})
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                if k in ("pid", "syscall", "success", "exit", "laddr", "lport", "name", "comm", "nametype"):
                    ev.setdefault(k, v)
    return list(events.values())


def find_detections(archive: Path, agent_pid: int, dest_port: int, outside_name: str) -> dict:
    connects, unbound_connects, files, batches = [], [], [], []
    for line in archive.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        batches.append(rec["sequence"])
        for i, e in enumerate(rec["batch"]["kernel_events"]):
            kind, v = next(iter(e["kind"].items()))
            bound = e.get("bound")
            if kind == "SocketState" and v["new_state"] == TCP_SYN_SENT and v["remote"]["port"] == dest_port \
                    and ip4(v["remote"]["addr"]) == "127.0.0.1":
                hit = {"batch_sequence": rec["sequence"], "index": i, "mechanism": e["mechanism"],
                       "current_pid": v["current_pid"], "remote": f"{ip4(v['remote']['addr'])}:{v['remote']['port']}",
                       "kernel_timestamp_ns": e["kernel_timestamp_ns"],
                       "bound_pid": bound["process"]["pid"] if bound else None,
                       "bound_start_ticks": bound["process"]["pid_start_time_ticks"] if bound else None,
                       "bound_exe_sha256": bytes(bound["exe_content_sha256"]).hex() if bound else None}
                if bound and bound["process"]["pid"] == agent_pid:
                    connects.append(hit)
                else:
                    unbound_connects.append(hit)
            if e["mechanism"] == "Fanotify" and outside_name in json.dumps(v):
                files.append({"batch_sequence": rec["sequence"], "index": i, "kind": kind,
                              "bound_pid": bound["process"]["pid"] if bound else None})
    return {"connect": connects, "connect_not_bound_to_agent": unbound_connects,
            "file": [f for f in files if f["bound_pid"] == agent_pid], "file_unbound": [f for f in files if f["bound_pid"] != agent_pid],
            "batches": len(batches)}


def self_log_mentions(entries: list[dict], needles) -> bool:
    """Search the agent's own log TEXT only. Numeric fields such as ts_ms are
    skipped, so a port number cannot match a timestamp by coincidence."""
    def strings(v):
        if isinstance(v, str):
            yield v
        elif isinstance(v, dict):
            for x in v.values():
                yield from strings(x)
        elif isinstance(v, list):
            for x in v:
                yield from strings(x)
    text = "\n".join(s for e in entries for s in strings(e))
    return any(n in text for n in needles)


def verify(state: Path, batches: Path, health: Path) -> tuple[bool, str]:
    p = subprocess.run([str(B / "aip-observe-verify"), "--observer-id", "collector.lying", "--key-version", "1",
                        "--pubkey-file", str(state / "observer.pub"), "--batches", str(batches),
                        "--health", str(health)], capture_output=True, text=True)
    out = p.stdout + p.stderr
    return p.returncode == 0 and any(l.startswith("VERIFIED") for l in out.splitlines()), out


def tamper_signed_byte(src: Path, dst: Path, seq: int, index: int) -> str:
    """Change ONE byte inside a signed field: the remote port digit of the
    detected connect event. (A byte outside the signed canonical preimage,
    e.g. JSON whitespace, would legitimately still verify.)"""
    lines = src.read_text().splitlines(keepends=True)
    for n, line in enumerate(lines):
        rec = json.loads(line)
        if rec["sequence"] != seq:
            continue
        ev = rec["batch"]["kernel_events"][index]
        kind = next(iter(ev["kind"]))
        port = ev["kind"][kind]["remote"]["port"]
        new = port + 1 if port < 65535 else port - 1
        ev["kind"][kind]["remote"]["port"] = new
        lines[n] = json.dumps(rec) + "\n"
        dst.write_text("".join(lines))
        return f"batch {seq} event {index}: remote port {port} -> {new}"
    raise ValueError("detected batch not found")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--mode", choices=["lying", "honest"], default="lying")
    a = ap.parse_args()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    started = harness.now_utc()
    require_sync = os.environ.get("AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK", "1")
    if not Path("/sys/kernel/tracing/available_events").exists():
        subprocess.run(["mount", "-t", "tracefs", "nodev", "/sys/kernel/tracing"], check=True)
    run_dir = out / "run"
    (run_dir / "outside-scope").mkdir(parents=True, exist_ok=True)
    work = out / "work"
    try:
        return _observe(a, out, run_dir, work, require_sync, started)
    finally:
        # Throwaway keys never outlive the run, whether it succeeded or not.
        shutil.rmtree(work, ignore_errors=True)


def _observe(a, out: Path, run_dir: Path, work: Path, require_sync: str, started: str) -> int:
    pipe = Pipeline(work, "sched,sockstate,connector,fanotify", run_dir / "outside-scope", require_sync)
    steps = [harness.label("live", "Sniffer Dog probe (no key) and collector (sole key) started")]
    try:
        audit_ok = audit_start(run_dir / "outside-scope")
        steps.append(harness.label("live", "auditd cross-check armed" if audit_ok else "auditd cross-check UNAVAILABLE"))
        time.sleep(2)
        gt = ground_truth.run_agent(a.mode, run_dir, linger=3.0)
        steps.append(harness.label("live", f"scripted test agent ran (pid {gt['agent_pid']})"))
        drained = pipe.drain()
        audit = audit_collect(out / "auditd.txt") if audit_ok else []
    finally:
        pipe.stop()
    state = work / "state"
    pub = out / "public"
    pub.mkdir(exist_ok=True)
    for f in ("attested.archive.jsonl", "health.archive.jsonl", "observer.pub"):
        shutil.copy(state / f, pub / f)
    for f in ("probe.log", "collector.log"):
        shutil.copy(work / f, out / f)

    dest_port = int(gt["ground_truth"]["exfil_destination"].rsplit(":", 1)[1])
    outside_name = f"copied-{gt['nonce']}.txt"
    det = find_detections(pub / "attested.archive.jsonl", gt["agent_pid"], dest_port, outside_name)
    ok, vtext = verify(pub, pub / "attested.archive.jsonl", pub / "health.archive.jsonl")
    (out / "offline_verify.txt").write_text(vtext)
    tamper = {"performed": False}
    if det["connect"]:
        t = out / "tampered.attested.archive.jsonl"
        what = tamper_signed_byte(pub / "attested.archive.jsonl", t, det["connect"][0]["batch_sequence"],
                                  det["connect"][0]["index"])
        tok, ttext = verify(pub, t, pub / "health.archive.jsonl")
        (out / "offline_verify_tampered.txt").write_text(ttext)
        tamper = {"performed": True, "change": what, "verified": tok}
    a_conn = [e for e in audit if e.get("syscall") == "connect" and e.get("lport") == str(dest_port)]
    a_file = [e for e in audit if outside_name in e.get("name", "")]
    result = {
        "mode": a.mode,
        "require_synced_clock": require_sync,
        "drained": drained,
        "agent": {"pid": gt["agent_pid"], "pid_source": "demo harness (process launch)",
                  "self_log_steps": [e["step"] for e in gt["self_log"]],
                  # Computed, not asserted: does the agent's own log mention the
                  # undeclared destination, the outside file or this run's nonce?
                  "self_log_mentions_undeclared_action": self_log_mentions(
                      gt["self_log"], (f"127.0.0.1:{dest_port}", f":{dest_port}", outside_name, gt["nonce"],
                                       "outside-scope"))},
        "ground_truth": gt["ground_truth"],
        "sniffer_dog": {"connect_detected": bool(det["connect"]), "connect_events": det["connect"],
                        "connect_events_not_bound_to_agent": det["connect_not_bound_to_agent"],
                        "file_detected": bool(det["file"]), "file_events": det["file"],
                        "file_events_unbound": det["file_unbound"], "batches": det["batches"]},
        "auditd": {"available": audit_ok, "connect_seen": bool(a_conn),
                   "connect_pids": sorted({e.get("pid") for e in a_conn}), "file_seen": bool(a_file),
                   "independence": "different kernel subsystem (audit), not the probe's tracepoints"},
        "offline_verification": {"verified": ok, "tamper": tamper},
    }
    rp = harness.write_result(out, "lying-agent", steps, result, started)
    print(json.dumps({"result_file": str(rp), **result}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
