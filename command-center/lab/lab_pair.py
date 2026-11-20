"""Start and stop a real aip-collector + aip-probe pair on loopback (lab helper).

The configuration is the one validation/pilot_e2e/run.sh uses: the probe holds no
evidence key, and the collector holds the only (wrapped) key and writes the
signed archive. `AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0`, because the cloud lab
container has no NTP. That is a stated limitation of every run using this.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BIN = REPO / "target" / "release"
STARTUP_WAIT_S = 10.0


def wait_for(pred, timeout_s: float, what: str) -> None:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if pred():
            return
        time.sleep(0.2)
    raise RuntimeError(f"timeout waiting for {what}")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@dataclass
class Pair:
    work: Path
    observer_id: str
    probe_id: str
    sensors: str
    batch_interval_ms: int = 1000
    collector: subprocess.Popen | None = None
    probe: subprocess.Popen | None = None
    _logs: list = field(default_factory=list)

    @property
    def archive(self) -> Path:
        return self.work / "state" / "attested.archive.jsonl"

    @property
    def pubkey(self) -> Path:
        return self.work / "state" / "observer.pub"

    def start(self) -> Pair:
        (self.work / "state").mkdir(parents=True, exist_ok=True)
        if not Path("/sys/kernel/tracing/trace_pipe").exists():
            subprocess.run(["mount", "-t", "tracefs", "nodev", "/sys/kernel/tracing"], check=True)
        base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        (self.work / "pass").write_text("lab-passphrase")
        key = self.work / "probe.key.json"
        klog = open(self.work / "probe.keygen.log", "wb")
        kg = subprocess.Popen([str(BIN / "aip-probe")], stdout=klog, stderr=subprocess.STDOUT,
                              env={**base, "AIP_PROBE_ID": self.probe_id, "AIP_PROBE_COLLECTOR_ENDPOINT": "127.0.0.1:1",
                                   "AIP_PROBE_COLLECTOR_NOISE_PUBKEY": "0" * 64, "AIP_PROBE_KEY_PATH": str(key),
                                   "AIP_PROBE_SENSORS": "sched"})
        try:
            wait_for(lambda: key.exists() and key.stat().st_size > 0, STARTUP_WAIT_S, "probe transport key")
        finally:
            kg.terminate()
            kg.wait(timeout=5)
            klog.close()
        pub = json.loads(key.read_text())["public_hex"]
        (self.work / "probes.json").write_text(json.dumps([{"probe_id": self.probe_id, "transport_pubkey_hex": pub}]))
        port = free_port()
        clog = open(self.work / "collector.log", "wb")
        self._logs.append(clog)
        self.collector = subprocess.Popen(
            [str(BIN / "aip-collector")], stdout=clog, stderr=subprocess.STDOUT,
            env={**base, "AIP_COLLECTOR_OBSERVER_ID": self.observer_id, "AIP_COLLECTOR_KEY_VERSION": "1",
                 "AIP_COLLECTOR_KEY_PATH": str(self.work / "collector.key.wrapped"),
                 "AIP_COLLECTOR_PASSPHRASE_FILE": str(self.work / "pass"),
                 "AIP_COLLECTOR_STATE_DIR": str(self.work / "state"), "AIP_COLLECTOR_LISTEN": f"127.0.0.1:{port}",
                 "AIP_COLLECTOR_PROBES_PATH": str(self.work / "probes.json"),
                 "AIP_COLLECTOR_NOISE_KEY_PATH": str(self.work / "noise.key.json"),
                 "AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK": "0"})
        wait_for(lambda: (self.work / "state" / "noise.pub").exists() and self.pubkey.exists(), STARTUP_WAIT_S, "collector keys")
        plog = open(self.work / "probe.log", "wb")
        self._logs.append(plog)
        self.probe = subprocess.Popen(
            [str(BIN / "aip-probe")], stdout=plog, stderr=subprocess.STDOUT,
            env={**base, "AIP_PROBE_ID": self.probe_id, "AIP_PROBE_COLLECTOR_ENDPOINT": f"127.0.0.1:{port}",
                 "AIP_PROBE_COLLECTOR_NOISE_PUBKEY": (self.work / "state" / "noise.pub").read_text().strip(),
                 "AIP_PROBE_KEY_PATH": str(key), "AIP_PROBE_SENSORS": self.sensors,
                 "AIP_PROBE_BATCH_INTERVAL_MS": str(self.batch_interval_ms)})
        wait_for(lambda: self.archive.exists() and self.archive.stat().st_size > 0, STARTUP_WAIT_S, "first attested batch")
        return self

    def stop(self) -> None:
        for p in (self.probe, self.collector):
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        for f in self._logs:
            f.close()
