"""Live adversarial #15 / #10: kill the collector mid-window; the gap must be reported.

    python3 command-center/lab/live_observer_kill.py OUT_DIR

Runs on this host, as root, on loopback only:

1. Mount tracefs if it is absent, and record that.
2. Start the real `aip-collector` and `aip-probe` (release builds) with the
   pilot's configuration, and the kernel sensors sched, sockstate,
   socksend and connector.
3. Run a workload of exec and TCP connects. During it, poll the archive
   into an EventStore once per second through ArchiveIngestor, which runs
   the real `aip-observe-verify`.
4. SIGKILL the collector partway through the task window. Keep the workload
   and the polling going.
5. Assert the following, and exit non-zero if any fails:
   - every poll verified, with no ingestion of unverified data;
   - the pre-kill part of the task is covered;
   - the whole task window is NOT covered;
   - the coverage state at task end is DEGRADED;
   - an open gap starts no later than the kill.

Writes `result.json` and the raw logs and archive to OUT_DIR. Timings are
wall-clock and are recorded, not asserted beyond the inequalities above.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "server"))
import eventstore  # noqa: E402
import observer_ingest as oi  # noqa: E402

BIN = REPO / "target" / "release"
OBSERVER_ID, KEY_VERSION, PROBE_ID = "collector.lab.kill", 1, "probe.lab.kill"
SENSORS = "sched,sockstate,socksend,connector"
BATCH_INTERVAL_MS = 1000
PRE_KILL_S, POST_KILL_S, POLL_S = 8.0, 12.0, 1.0
STARTUP_WAIT_S = 10.0


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def wait_for(pred, timeout_s: float, what: str) -> None:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if pred():
            return
        time.sleep(0.2)
    raise SystemExit(f"timeout waiting for {what}")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def workload_step() -> None:
    subprocess.run(["/bin/true"], check=False)
    subprocess.run(["/bin/date"], stdout=subprocess.DEVNULL, check=False)
    s = socket.socket()
    s.settimeout(0.2)
    try:
        s.connect(("127.0.0.1", 9))
    except OSError:
        pass
    finally:
        s.close()


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    work = out / "work"
    (work / "state").mkdir(parents=True, exist_ok=True)
    result: dict = {"label": "live lab run on the cloud session container", "sensors": SENSORS}
    tracefs = Path("/sys/kernel/tracing/trace_pipe").exists()
    if not tracefs:
        subprocess.run(["mount", "-t", "tracefs", "nodev", "/sys/kernel/tracing"], check=True)
    result["tracefs_mounted_by_script"] = not tracefs
    port = free_port()
    (work / "pass").write_text("lab-kill-passphrase")
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    # The probe writes its transport key, then retries a connection forever;
    # the pilot stops it with `timeout 4`. Same here: wait for the key, stop it.
    with open(work / "probe.keygen.log", "wb") as klog:
        keygen = subprocess.Popen(
            [str(BIN / "aip-probe")], stdout=klog, stderr=subprocess.STDOUT,
            env={**base, "AIP_PROBE_ID": PROBE_ID, "AIP_PROBE_COLLECTOR_ENDPOINT": "127.0.0.1:1",
                 "AIP_PROBE_COLLECTOR_NOISE_PUBKEY": "0" * 64, "AIP_PROBE_KEY_PATH": str(work / "probe.key.json"),
                 "AIP_PROBE_SENSORS": "sched"})
        try:
            wait_for(lambda: (work / "probe.key.json").exists() and (work / "probe.key.json").stat().st_size > 0,
                     STARTUP_WAIT_S, "probe transport key")
        finally:
            keygen.terminate()
            keygen.wait(timeout=5)
    probe_pub = json.loads((work / "probe.key.json").read_text())["public_hex"]
    (work / "probes.json").write_text(json.dumps([{"probe_id": PROBE_ID, "transport_pubkey_hex": probe_pub}]))
    clog = open(work / "collector.log", "wb")
    collector = subprocess.Popen(
        [str(BIN / "aip-collector")], stdout=clog, stderr=subprocess.STDOUT,
        env={**base, "AIP_COLLECTOR_OBSERVER_ID": OBSERVER_ID, "AIP_COLLECTOR_KEY_VERSION": str(KEY_VERSION),
             "AIP_COLLECTOR_KEY_PATH": str(work / "collector.key.wrapped"),
             "AIP_COLLECTOR_PASSPHRASE_FILE": str(work / "pass"), "AIP_COLLECTOR_STATE_DIR": str(work / "state"),
             "AIP_COLLECTOR_LISTEN": f"127.0.0.1:{port}", "AIP_COLLECTOR_PROBES_PATH": str(work / "probes.json"),
             "AIP_COLLECTOR_NOISE_KEY_PATH": str(work / "noise.key.json"),
             # No NTP in this container: the synced-clock control is off for this lab run (a stated limit).
             "AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK": "0"})
    probe = None
    try:
        wait_for(lambda: (work / "state" / "noise.pub").exists() and (work / "state" / "observer.pub").exists(),
                 STARTUP_WAIT_S, "collector keys")
        plog = open(work / "probe.log", "wb")
        probe = subprocess.Popen(
            [str(BIN / "aip-probe")], stdout=plog, stderr=subprocess.STDOUT,
            env={**base, "AIP_PROBE_ID": PROBE_ID, "AIP_PROBE_COLLECTOR_ENDPOINT": f"127.0.0.1:{port}",
                 "AIP_PROBE_COLLECTOR_NOISE_PUBKEY": (work / "state" / "noise.pub").read_text().strip(),
                 "AIP_PROBE_KEY_PATH": str(work / "probe.key.json"), "AIP_PROBE_SENSORS": SENSORS,
                 "AIP_PROBE_BATCH_INTERVAL_MS": str(BATCH_INTERVAL_MS)})
        archive = work / "state" / "attested.archive.jsonl"
        wait_for(lambda: archive.exists() and archive.stat().st_size > 0, STARTUP_WAIT_S, "first attested batch")

        store = eventstore.EventStore(out / "events.db")
        anchor = oi.Anchor(OBSERVER_ID, KEY_VERSION, work / "state" / "observer.pub")
        ing = oi.ArchiveIngestor(store, archive, str(BIN / "aip-observe-verify"), anchor, now_ms)
        polls: list[dict] = []

        def run_for(seconds: float) -> None:
            end, next_poll = time.monotonic() + seconds, 0.0
            while time.monotonic() < end:
                workload_step()
                if time.monotonic() >= next_poll:
                    r = ing.poll()
                    c = oi.coverage(ing.windows(), now_ms())
                    polls.append({"at_ms": now_ms(), "verified": r.verified, "reason": r.reason, "lines": r.lines,
                                  "inserted": r.inserted, "state": c.state, "covered_to_ms": c.covered_to_ms})
                    next_poll = time.monotonic() + POLL_S
                time.sleep(0.1)

        task_from = now_ms()
        run_for(PRE_KILL_S)
        kill_at = now_ms()
        collector.send_signal(signal.SIGKILL)
        collector.wait(timeout=5)
        run_for(POST_KILL_S)
        task_to = now_ms()

        final = oi.coverage(ing.windows(), task_to)
        checks = {
            "every poll verified (nothing unverified ingested)": all(p["verified"] for p in polls),
            "batches were ingested before the kill": any(p["inserted"] > 0 for p in polls if p["at_ms"] < kill_at),
            "pre-kill part of the task is covered": oi.window_covered(final, task_from + BATCH_INTERVAL_MS * 2,
                                                                      kill_at - BATCH_INTERVAL_MS * 3),
            "whole task window is NOT covered": not oi.window_covered(final, task_from, task_to),
            "state at task end is DEGRADED": final.state == "DEGRADED",
            "open gap starts no later than the kill": bool(final.gaps) and final.gaps[-1]["from_ms"] <= kill_at,
            "store chain intact": store.verify() == [],
        }
        result.update({"task_from_ms": task_from, "kill_at_ms": kill_at, "task_to_ms": task_to,
                       "final": {"state": final.state, "spans": final.spans, "gaps": final.gaps,
                                 "losses": final.losses, "covered_to_ms": final.covered_to_ms},
                       "batches_ingested": store.count(), "polls": polls, "checks": checks})
        store.close()
    finally:
        for p in (probe, collector):
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
    (out / "result.json").write_text(json.dumps(result, indent=1) + "\n")
    for name, ok in result.get("checks", {}).items():
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    failed = [k for k, v in result.get("checks", {}).items() if not v]
    print(f"checks: {len(result.get('checks', {})) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed or not result.get("checks") else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
