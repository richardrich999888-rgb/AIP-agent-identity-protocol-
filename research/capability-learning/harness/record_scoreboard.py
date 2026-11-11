#!/usr/bin/env python3
"""C1 recorded live CLI check on two synthetic maintenance domains; no model.

Run with an already built binary. All datasets are regenerated in a temporary
directory and verified against the tracked manifests before use. Temporary
expert keys never enter the evidence folder. Suites and public keys are retained;
the diagnostic itself is explicitly unsigned, not an execution receipt.

  python3 research/capability-learning/harness/record_scoreboard.py \
      --binary target/debug/syntriass --out /tmp/c1-evidence

Exit 0 means these bounded assertions passed, NOT full teaching-demo acceptance.
No downloads or builds are performed. This does not establish network isolation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parents[3]
CL = REPO / "research/capability-learning"
EXPERT = "expert:p0-049-synthetic-evaluator"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args: list, expected: int = 0) -> subprocess.CompletedProcess:
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=120)
    if result.returncode != expected:
        raise RuntimeError(f"{args[1]}: expected exit {expected}, got {result.returncode}: {result.stderr}")
    return result


def write(path: Path, value: dict | list) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def host_probe(path: str) -> dict:
    try:
        return {"status": "READ", "value": Path(path).read_text().strip()}
    except OSError as error:
        return {"status": "UNAVAILABLE", "reason": str(error)}


def generate(family: str, dest: Path) -> Path:
    import sys
    run([sys.executable, "-I", CL / f"datasets/{family}_tasks_v1.py", dest])
    manifest_path = f"research/capability-learning/data/{family}-tasks-v1/MANIFEST.json"
    pinned = json.loads(run(["git", "-C", REPO, "show", f"HEAD:{manifest_path}"]).stdout)["sha256"]
    for name, expected in pinned.items():
        if digest(dest / name) != expected:
            raise RuntimeError(f"dataset mismatch: {family}/{name}")
    return dest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    binary, out = a.binary.resolve(), a.out.resolve()
    if out.exists():
        raise RuntimeError("choose a new output directory; prior evidence is never overwritten")
    out.mkdir(parents=True)
    started, cpu0 = time.perf_counter(), resource.getrusage(resource.RUSAGE_CHILDREN)
    network_before = host_probe("/proc/net/dev")
    commit = run(["git", "-C", REPO, "rev-parse", "HEAD"]).stdout.strip()
    dirty = run(["git", "-C", REPO, "status", "--porcelain"]).stdout
    runs = []
    with tempfile.TemporaryDirectory(prefix="p0-049-scoreboard-") as temp:
        root = Path(temp)
        key_path = root / "expert.json"
        run([binary, "keygen", "--id", EXPERT, "--out", key_path])
        public = json.loads(key_path.read_text())["public_hex"]
        write(out / "expert-public.json", {EXPERT: public})
        for name, family, cap_path, expected_exit in [
            ("motor-corrected", "ir", "results/corrected/capability.json", 0),
            ("transformer-candidate", "tx", "results/v02/postfix/holdout_tx/capability.json", 3),
            ("transformer-corrected", "tx", "results/v02/postfix/corrected_atomic_tx/capability.json", 0),
        ]:
            work, retained = root / name, out / name
            work.mkdir(); retained.mkdir()
            data = generate(family, work / "data")
            state, cfg = work / "state", work / "config.json"
            cap = json.loads((CL / cap_path).read_text())
            tenant = cap["required"]["tenant"]
            write(cfg, {
                "state": str(state), "policy_version": cap["dependencies"]["policy_version"],
                "security_domain": cap["required"]["security_domain"], "rag_k": 4,
                "experts": {EXPERT: public}, "approvers": {}, "profile": "none",
                "python": "/UNUSED", "sidecar_script": "/UNUSED", "llama_server": "/UNUSED",
                "q4": {"path": "/UNUSED", "sha256": "0" * 64},
                "q8": {"path": "/UNUSED", "sha256": "0" * 64}, "port": 18080,
            })
            for doc in sorted((data / "corpus").glob("*.txt")):
                run([binary, "ingest", "--config", cfg, doc])
            proposal = json.loads(run([binary, "cap-propose", "--config", cfg, "--file", CL / cap_path]).stdout)
            records = list((state / "capabilities").glob("*.json"))
            before = {p.name: digest(p) for p in records}
            stored = json.loads(records[0].read_text())
            write(retained / "capability.json", stored["capability"])
            rows = [json.loads(line) for line in (data / "validation.jsonl").read_text().splitlines()]
            cases = work / "cases.jsonl"
            cases.write_text("".join(json.dumps({
                "id": r["id"], "text": r["text"], "label": r["label"],
                "counterexample": r.get("counterexample", r["label"] in
                    ("OUT_OF_SCOPE", "INVALID_TEST", "INSUFFICIENT_INPUT")),
            }) + "\n" for r in rows))
            suite = retained / "suite.json"
            run([binary, "suite-sign", "--key", key_path, "--cases", cases,
                 "--suite-id", f"p0-049/{name}", "--tenant", tenant,
                 "--task", cap["intended_task"], "--out", suite])
            t0 = time.perf_counter()
            result = run([binary, "cap-scoreboard", "--config", cfg, "--hash", proposal["hash"], "--suite", suite], expected_exit)
            duration = time.perf_counter() - t0
            report = json.loads(result.stdout)
            write(retained / "scoreboard.json", report)
            (retained / "stderr.txt").write_text(result.stderr)
            if {p.name: digest(p) for p in records} != before:
                raise RuntimeError("read-only scoreboard changed capability state")
            if report["validation"]["passed"] != (expected_exit == 0):
                raise RuntimeError("exit status and validation disagree")
            if expected_exit == 3:
                failed = [c for c in report["cases"] if c["passed"] is False]
                if not any(c["id"] == "val-09" and c["expected"] == "OUT_OF_SCOPE" and c["got"] == "ACCEPT"
                           and any(q["field_path"] == "scope_exclusion_terms.*" for q in c["review_questions"])
                           for c in failed):
                    raise RuntimeError("known holdout failure was hidden or lost its scope review question")
            runs.append({"name": name, "domain": family, "exit_status": result.returncode,
                         "wall_seconds": duration, "capability_hash": proposal["hash"],
                         "expert_passed": report["validation"]["expert_passed"],
                         "expert_cases": report["validation"]["expert_cases"], "state_unchanged": True})
    cpu1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    write(out / "result.json", {
        "schema": "syntriass.p0-049.scoreboard-evidence/v1", "result": "PASS_BOUNDED_C1",
        "commit": commit, "tree_dirty": bool(dirty), "dirty_paths": dirty.splitlines(),
        "binary_sha256": digest(binary), "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hardware": {"platform": platform.platform(), "logical_cpus": os.cpu_count(),
                     "affinity_cpus": len(os.sched_getaffinity(0)),
                     "meminfo": Path("/proc/meminfo").read_text().splitlines()[0],
                     "cgroup_cpu_max": host_probe("/sys/fs/cgroup/cpu.max"),
                     "cgroup_memory_max": host_probe("/sys/fs/cgroup/memory.max")},
        "wall_seconds": time.perf_counter() - started,
        "network": {"namespace": os.readlink("/proc/self/ns/net"),
                    "interfaces_before": network_before, "interfaces_after": host_probe("/proc/net/dev"),
                    "ipv4_routes": host_probe("/proc/net/route"), "ipv6_routes": host_probe("/proc/net/ipv6_route")},
        "child_cpu_seconds": cpu1.ru_utime + cpu1.ru_stime - cpu0.ru_utime - cpu0.ru_stime,
        "child_peak_rss_kib": cpu1.ru_maxrss, "model_calls": 0, "model_hashes": [],
        "runs": runs, "signed_material": "expert suites only; public trust anchor retained",
        "limitations": ["Engineer-generated synthetic fixtures, not external domain-expert approval.",
                        "Unsigned diagnostics; no signed answer receipts or knowledge packs.",
                        "One development host; no clean-machine acceptance or rehearsal credit.",
                        "No packet capture or independent network isolation proof.",
                        "No live model, drafting, UI or full teaching workflow in this run."],
    })
    files = sorted(p for p in out.rglob("*") if p.is_file())
    (out / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.relative_to(out)}\n" for p in files))
    print(json.dumps({"result": "PASS_BOUNDED_C1", "output": str(out), "runs": runs}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
