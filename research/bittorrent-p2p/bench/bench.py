"""Distribution benchmark on the emulated LAN.

usage: bench.py OUT_JSON --method {http_plain,http_range,bittorrent}
                [--size-mib 256] [--peers 5] [--peer-mbit 100] [--src-mbit 100]
                [--kill PEER@FRACTION] [--restart] [--seed 7]

One run = build topology → publish file at src → all peers fetch
concurrently → verify every copy against the published SHA-256 → tear down.

Recorded (kernel counters and /proc, not self-reports):
  fleet_seconds         until the last peer holds a verified copy
  per_peer_seconds
  src_tx_bytes          bytes leaving the source's interface
  total_tx_bytes        bytes leaving all interfaces (network load)
  cpu_seconds           user+sys of every node process (from /proc/<pid>/stat)
  peak_rss_mb           max VmHWM over node processes
  verified              every peer's file SHA-256 == published SHA-256
Fault injection:
  --corrupt p1         p1 starts with a full copy in which every 4th piece has
                        flipped bytes and announces all pieces unchecked
                        (malicious seeder; bittorrent only)
  --kill p2@0.5         SIGKILL peer p2 when it reaches 50 % (fleet time then
                        excludes p2 unless --restart, which restarts it on the
                        same partial data and measures bytes re-received)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import testbed  # noqa: E402

WORK = os.environ.get("BENCH_WORK", "/home/claude/vanian-build/btwork")
PY = sys.executable
CLK = os.sysconf("SC_CLK_TCK")


def make_payload(path: str, size_mib: int, seed: int) -> str:
    """Synthetic incompressible model-sized file (seeded PRNG; deterministic)."""
    if not os.path.exists(path) or os.path.getsize(path) != size_mib << 20:
        rnd = random.Random(seed)
        with open(path, "wb") as f:
            for _ in range(size_mib):
                f.write(rnd.randbytes(1 << 20))
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(1 << 22):
            h.update(b)
    return h.hexdigest()


PIECE_KIB = 1024
CORRUPT_EVERY = 4  # every 4th piece of the malicious copy is corrupted


def make_corrupt_copy(src: str, dst: str, piece: int) -> int:
    """Copy src to dst flipping one 4 KiB run in every CORRUPT_EVERY-th piece."""
    n = 0
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        i = 0
        while b := fi.read(piece):
            if i % CORRUPT_EVERY == 0:
                b = bytes(x ^ 0xFF for x in b[:4096]) + b[4096:]
                n += 1
            fo.write(b)
            i += 1
    return n


def make_torrent(payload: str, out: str, piece_kib: int = PIECE_KIB, root_cert: str | None = None) -> None:
    """Private BEP 52 (v2-only) torrent; with root_cert an SSL torrent whose
    peers must present a certificate signed by that CA."""
    import libtorrent as lt

    fs = lt.file_storage()
    lt.add_files(fs, payload)
    ct = lt.create_torrent(fs, piece_kib * 1024, flags=lt.create_torrent.v2_only)
    ct.set_priv(True)
    if root_cert:
        ct.set_root_cert(open(root_cert).read())
    lt.set_piece_hashes(ct, os.path.dirname(payload))
    open(out, "wb").write(lt.bencode(ct.generate()))


def proc_stats(pid: int) -> tuple:
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        cpu = (int(f[11]) + int(f[12])) / CLK
        hwm = next(int(l.split()[1]) / 1024 for l in open(f"/proc/{pid}/status") if l.startswith("VmHWM:"))
        return cpu, hwm
    except (OSError, StopIteration, IndexError):
        return None, None


def sha256(path: str) -> str | None:
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(1 << 22):
            h.update(b)
    return h.hexdigest()


def run(a) -> dict:
    name = "model.bin"
    pub = os.path.join(WORK, "publish")
    os.makedirs(pub, exist_ok=True)
    payload = os.path.join(pub, name)
    digest = make_payload(payload, a.size_mib, a.seed)
    nodes = testbed.build(a.peers, a.peer_mbit, a.src_mbit)
    src, peers = nodes[0], nodes[1:]
    dirs = {p.name: os.path.join(WORK, "recv", p.name) for p in peers}
    for d in dirs.values():
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    reports = {p.name: os.path.join(WORK, f"report-{p.name}.json") for p in peers}
    for r in list(reports.values()) + [os.path.join(WORK, "report-src.json")]:
        if os.path.exists(r):
            os.remove(r)
    procs, cpu_hwm = {}, {}
    tx0 = {n.name: testbed.tx_bytes(n) for n in nodes}
    t0 = time.monotonic()
    killed, restarted = None, None
    kill_name, kill_frac = (a.kill.split("@")[0], float(a.kill.split("@")[1])) if a.kill else (None, None)

    def ssl_args(name):
        if not a.ssl or name not in pki:
            return []
        return ["--ssl", pki[name][0], pki[name][1], ""]

    def start_peer(p):
        if a.method == "bittorrent":
            return testbed.spawn(p, [PY, "-I", os.path.join(HERE, "bt_node.py"), tor, dirs[p.name], p.ip,
                                     ",".join(n.ip for n in nodes), reports[p.name]]
                                 + (["--seed-mode"] if p.name == a.corrupt else []) + ssl_args(p.name))
        return testbed.spawn(p, [PY, "-I", os.path.join(HERE, "http_node.py"), "get",
                                 f"http://{src.ip}:8080/{name}", os.path.join(dirs[p.name], name), reports[p.name]])

    pki = {}
    intruders = [x for x in (a.intruder or "").split(",") if x]
    if a.ssl:
        import pki as pkimod
        pki = pkimod.build(os.path.join(WORK, "pki"), name, ["src"] + [p.name for p in peers if p.name not in intruders],
                           intruders, a.intruder_kind)
    if a.method == "bittorrent":
        tor = os.path.join(WORK, "model.torrent")
        make_torrent(payload, tor, root_cert=pki.get("ca"))
        if a.corrupt:
            make_corrupt_copy(payload, os.path.join(dirs[a.corrupt], name), PIECE_KIB << 10)
        procs["src"] = testbed.spawn(src, [PY, "-I", os.path.join(HERE, "bt_node.py"), tor, pub, src.ip,
                                           ",".join(n.ip for n in nodes), os.path.join(WORK, "report-src.json")] + ssl_args("src"))
        time.sleep(1.0)
    else:
        procs["src"] = testbed.spawn(src, [PY, "-I", os.path.join(HERE, "http_node.py"), "serve", pub, "8080"]
                                     + (["--no-range"] if a.method == "http_plain" else []))
        time.sleep(0.8)
    t0 = time.monotonic()
    for p in peers:
        procs[p.name] = start_peer(p)
    done = {}
    resumed_bytes = None
    deadline = t0 + a.timeout
    while time.monotonic() < deadline:
        for name_, pr in procs.items():
            c, h = proc_stats(pr.pid)
            if c is not None:
                pc, ph = cpu_hwm.get(name_, (0, 0))
                cpu_hwm[name_] = (max(pc, c), max(ph, h))
        for p in peers:
            if p.name in done or p.name == killed and not restarted or p.name == a.corrupt or p.name in intruders:
                continue
            path = os.path.join(dirs[p.name], name)
            if a.method == "bittorrent":
                try:
                    rep = json.load(open(reports[p.name]))
                except (OSError, ValueError):
                    continue
                prog = rep["progress"]
                if rep.get("seconds_to_complete") is not None:
                    done[p.name] = time.monotonic() - t0
            else:
                prog = (os.path.getsize(path) / (a.size_mib << 20)) if os.path.exists(path) else 0
                if procs[p.name].poll() is not None and procs[p.name].returncode == 0 and prog >= 1:
                    done[p.name] = time.monotonic() - t0
            if p.name == kill_name and killed is None and prog >= kill_frac:
                procs[p.name].send_signal(signal.SIGKILL)
                procs[p.name].wait()
                killed = p.name
                killed_at = prog
                if a.restart:
                    time.sleep(2.0)
                    procs[p.name] = start_peer(p)
                    restarted = True
        expected = len(peers) - (1 if killed and not restarted else 0) - (1 if a.corrupt else 0) - len(intruders)
        if len(done) >= expected:
            break
        time.sleep(0.2)
    fleet = time.monotonic() - t0
    if a.restart and killed:
        rep = json.load(open(reports[killed]))
        resumed_bytes = rep.get("payload_down", rep.get("bytes_received"))
    tx1 = {n.name: testbed.tx_bytes(n) for n in nodes}
    for pr in procs.values():
        if pr.poll() is None:
            pr.terminate()
    for pr in procs.values():
        try:
            pr.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pr.kill()
    verified = {p.name: sha256(os.path.join(dirs[p.name], name)) == digest for p in peers if (p.name != killed or restarted) and p.name != a.corrupt and p.name not in intruders}
    hash_failures = 0
    if a.method == "bittorrent":
        for p in peers:
            try:
                hash_failures += json.load(open(reports[p.name])).get("hash_failures", 0)
            except (OSError, ValueError):
                pass
    intruder_bytes = {}
    for n in intruders:
        try:
            intruder_bytes[n] = json.load(open(reports[n])).get("payload_down", 0)
        except (OSError, ValueError):
            intruder_bytes[n] = None
    shutil.rmtree(os.path.join(WORK, "pki"), ignore_errors=True)  # test keys never persist
    testbed.teardown()
    return {"ssl": a.ssl, "intruders": intruders, "intruder_kind": a.intruder_kind if intruders else None, "intruder_payload_bytes": intruder_bytes,
        "method": a.method, "size_mib": a.size_mib, "peers": a.peers, "peer_mbit": a.peer_mbit, "src_mbit": a.src_mbit,
        "kill": a.kill, "corrupt": a.corrupt, "restart": a.restart, "killed_at_progress": locals().get("killed_at"),
        "completed": sorted(done), "timed_out": len(done) < len(peers) - (1 if killed and not restarted else 0) - (1 if a.corrupt else 0) - len(intruders),
        "fleet_seconds": round(fleet, 2), "per_peer_seconds": {k: round(v, 2) for k, v in sorted(done.items())},
        "src_tx_bytes": tx1["src"] - tx0["src"], "total_tx_bytes": sum(tx1[n] - tx0[n] for n in tx1),
        "payload_bytes": a.size_mib << 20,
        "cpu_seconds": round(sum(c for c, _ in cpu_hwm.values()), 2),
        "peak_rss_mb": round(max(h for _, h in cpu_hwm.values()), 1) if cpu_hwm else None,
        "verified": verified, "all_verified": all(verified.values()) and bool(verified),
        "hash_failures": hash_failures, "restarted_peer_bytes_received": resumed_bytes,
        "sha256": digest,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--method", required=True, choices=("http_plain", "http_range", "bittorrent"))
    ap.add_argument("--size-mib", type=int, default=256)
    ap.add_argument("--peers", type=int, default=5)
    ap.add_argument("--peer-mbit", type=float, default=100)
    ap.add_argument("--src-mbit", type=float, default=100)
    ap.add_argument("--kill")
    ap.add_argument("--restart", action="store_true")
    ap.add_argument("--corrupt")
    ap.add_argument("--ssl", action="store_true", help="SSL torrent; peers need publisher-CA certificates")
    ap.add_argument("--intruder-kind", default="rogue", choices=("rogue", "wrongscope"))
    ap.add_argument("--intruder", help="comma list of nodes that are NOT authorised (rogue CA cert under --ssl)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--timeout", type=float, default=900)
    a = ap.parse_args()
    os.makedirs(WORK, exist_ok=True)
    r = run(a)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(r, open(a.out, "w"), indent=2)
    print(json.dumps({k: r[k] for k in ("method", "size_mib", "src_mbit", "fleet_seconds", "src_tx_bytes", "total_tx_bytes", "cpu_seconds", "all_verified", "timed_out")}))


if __name__ == "__main__":
    main()
