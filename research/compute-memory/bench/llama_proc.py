"""llama-server lifecycle and kernel-level resource accounting (IO adapter).

All memory/fault/CPU numbers come from /proc, not from llama.cpp's own logs:
  VmSize   virtual address space           RssAnon  private heap (KV, compute buffers)
  RssFile  file-backed resident (mmap'd weights)    Pss  proportional share (shared pages / n)
  minflt / majflt  page faults without / with disk IO
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

CLK = os.sysconf("SC_CLK_TCK")
HEALTH_POLL_S = 0.05
HEALTH_TIMEOUT_S = 600


def proc_snapshot(pid: int) -> dict:
    """Memory, faults and CPU of one process from /proc (MiB, counts, seconds)."""
    st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    out = {"minflt": int(st[7]), "majflt": int(st[9]), "cpu_s": (int(st[11]) + int(st[12])) / CLK}
    for line in open(f"/proc/{pid}/status"):
        k, _, v = line.partition(":")
        if k in ("VmSize", "VmRSS", "VmHWM", "RssAnon", "RssFile", "RssShmem"):
            out[k] = int(v.split()[0]) / 1024
    for line in open(f"/proc/{pid}/smaps_rollup"):
        k, _, v = line.partition(":")
        if k in ("Pss", "Pss_Anon", "Pss_File"):
            out[k] = int(v.split()[0]) / 1024
    return out


def evict_page_cache(path: str) -> None:
    """Drop the file's clean pages from the page cache (cold-load emulation)."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    finally:
        os.close(fd)


def cached_fraction(path: str) -> float:
    """Fraction of the file's pages resident in page cache, via mincore(2)."""
    import ctypes
    import mmap

    size = os.path.getsize(path)
    page = mmap.PAGESIZE
    n = (size + page - 1) // page
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]
    fd = os.open(path, os.O_RDONLY)
    try:
        addr = libc.mmap(None, size, mmap.PROT_READ, mmap.MAP_SHARED, fd, 0)
        if addr in (None, ctypes.c_void_p(-1).value):
            raise OSError(ctypes.get_errno(), "mmap failed")
        vec = ctypes.create_string_buffer(n)
        try:
            if libc.mincore(ctypes.c_void_p(addr), size, vec) != 0:
                raise OSError(ctypes.get_errno(), "mincore failed")
        finally:
            libc.munmap(ctypes.c_void_p(addr), size)
    finally:
        os.close(fd)
    return sum(b & 1 for b in vec.raw) / n


@dataclass
class Server:
    """One llama-server bound to loopback."""
    binary: str
    model: str
    port: int
    args: tuple = ()
    log: str = "/dev/null"

    def start(self) -> float:
        """Start and block until /health == 200. Returns load seconds."""
        t0 = time.monotonic()
        self.proc = subprocess.Popen([self.binary, "-m", self.model, "--host", "127.0.0.1", "--port", str(self.port),
                                      "--no-webui", "-t", str(os.cpu_count()), *self.args],
                                     stdout=open(self.log, "w"), stderr=subprocess.STDOUT)
        while time.monotonic() - t0 < HEALTH_TIMEOUT_S:
            if self.proc.poll() is not None:
                raise RuntimeError(f"llama-server exited {self.proc.returncode}; see {self.log}")
            try:
                if urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=1).status == 200:
                    return time.monotonic() - t0
            except (urllib.error.URLError, ConnectionError, OSError):
                pass
            time.sleep(HEALTH_POLL_S)
        raise TimeoutError("llama-server did not become healthy")

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def stats(self) -> dict:
        return proc_snapshot(self.proc.pid)

    def post(self, path: str, body: dict, timeout: float = 600) -> tuple[dict, float]:
        """POST JSON; returns (response, wall seconds)."""
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        t0 = time.monotonic()
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        return data, time.monotonic() - t0

    def complete(self, prompt: str, n_predict: int, cache_prompt: bool = True, slot: int | None = None) -> dict:
        body = {"prompt": prompt, "n_predict": n_predict, "temperature": 0, "top_k": 1, "seed": 0,
                "cache_prompt": cache_prompt}
        if slot is not None:
            body["id_slot"] = slot
        d, wall = self.post("/completion", body)
        t = d.get("timings", {})
        return {"wall_s": wall, "prompt_n": t.get("prompt_n"), "prompt_ms": t.get("prompt_ms"),
                "predicted_n": t.get("predicted_n"), "predicted_ms": t.get("predicted_ms"),
                "draft_n": t.get("draft_n"), "draft_n_accepted": t.get("draft_n_accepted"),
                "tokens_cached": d.get("tokens_cached"), "content": d.get("content")}

    def tokens(self, text: str) -> int:
        return len(self.post("/tokenize", {"content": text})[0]["tokens"])

    def slot_action(self, slot: int, action: str, filename: str | None = None) -> tuple[dict, float]:
        return self.post(f"/slots/{slot}?action={action}", {"filename": filename} if filename else {})
