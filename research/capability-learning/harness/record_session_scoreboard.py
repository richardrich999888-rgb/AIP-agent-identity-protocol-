#!/usr/bin/env python3
"""Retain real C1 session CLI results and original signed synthetic suites.

No downloads/builds, no model, no activation; temporary private keys are removed.
This is a component exercise, not a full teaching or clean-machine rehearsal.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import tempfile
import time

import draft_from_session as D
import question_generator as Q
import record_answers as RA
import record_exclusion_policy as E
import record_holdout as H
import record_scoreboard as S
import score_teaching_session as T


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args()
    binary, out = a.binary.resolve(strict=True), a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    t0, cpu0 = time.monotonic(), resource.getrusage(resource.RUSAGE_CHILDREN)
    runs = []
    metadata = {"status": "INCOMPLETE", "source_commit": S.run(["git", "-C", S.REPO, "rev-parse", "HEAD"]).stdout.strip(),
                "dirty_paths": S.run(["git", "-C", S.REPO, "status", "--porcelain"]).stdout.splitlines(),
                "binary_sha256": T.sha(binary.read_bytes()), "recorder_sha256": S.digest(Path(__file__)),
                "diagnostic_sha256": S.digest(Path(T.__file__)),
                "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "hardware": {"platform": platform.platform(), "logical_cpus": os.cpu_count(),
                             "affinity_cpus": len(os.sched_getaffinity(0)),
                             "meminfo": S.host_probe("/proc/meminfo"),
                             "cgroup_cpu_max": S.host_probe("/sys/fs/cgroup/cpu.max"),
                             "cgroup_memory_max": S.host_probe("/sys/fs/cgroup/memory.max")},
                "network_before": S.host_probe("/proc/net/dev"), "runs": runs,
                "full_mode_rehearsal_credit": 0, "model_calls": 0,
                "limitations": ["Synthetic engineer answers and evaluator keys, not authenticated expert approval.",
                                "Session example agreement NOT_MEASURED; no label mapping was invented.",
                                "No model, UI, activation, knowledge pack, sensor, packet capture or separate-machine installation."]}
    try:
        with tempfile.TemporaryDirectory(prefix="p051-session-score-") as temp:
            work = Path(temp)
            spec = json.loads(H.TASK.read_text())
            data = S.generate("tx", work / "data")
            session = H.teach(work, data, spec, binary=binary)
            draft = D.draft(session, spec)
            questions = Q.generate(draft, spec)
            original = RA.answers_file(draft, questions, H.AS_INSTRUCTED, 1)
            corrected = copy.deepcopy(original)
            owner, = [q for q in questions["questions"] if q["field_path"] == "scope_exclusion_terms.*"]
            answer, = [x for x in corrected["answers"] if x["qid"] == owner["qid"]]
            answer["answer"] += [c["term"] for c in owner["exclusion_word_forms"]]
            answer["why"] = "Explicitly select each offered source-linked word form."
            key = work / "key.json"
            S.run([binary, "keygen", "--id", E.EXPERT, "--out", key])
            public = json.loads(key.read_text())["public_hex"]
            cfg = json.loads((work / "config.json").read_text())
            cfg.update(policy_version=spec["policy_version"], security_domain=spec["domain"], experts={E.EXPERT: public})
            T.write(work / "config.json", cfg)
            for name, answers, cases, expected, passed in (
                ("rejected-control", original, E.rows(data / "validation.jsonl"), 3, 11),
                ("corrected-validation", corrected, E.rows(data / "validation.jsonl"), 0, 12),
                ("corrected-attacks", corrected, E.attacks(data), 0, 26),
            ):
                T.write(work / "answers.json", answers)
                (work / "cases.jsonl").write_text("".join(json.dumps(c) + "\n" for c in cases))
                S.run([binary, "suite-sign", "--key", key, "--cases", work / "cases.jsonl",
                       "--suite-id", "p0-051/" + name, "--tenant", spec["tenant"], "--task", spec["intended_task"],
                       "--out", work / "suite.json"])
                command = [sys.executable, str(Path(T.__file__)), "--binary", str(binary), "--config", str(work / "config.json"),
                           "--tenant", spec["tenant"], "--session", session["session_id"], "--session-task", session["task"],
                           "--task", str(H.TASK), "--answers", str(work / "answers.json"),
                           "--document", str(data / spec["doc_file"]), "--suite", str(work / "suite.json"), "--out", str(out / name)]
                start = time.monotonic()
                result = subprocess.run(command, capture_output=True, timeout=120)
                (out / (name + ".stdout")).write_bytes(result.stdout)
                (out / (name + ".stderr")).write_bytes(result.stderr)
                runs.append({"command": command, "expected_exit": expected, "actual_exit": result.returncode,
                             "wall_seconds": time.monotonic() - start})
                T.require(result.returncode == expected, name + " returned an unexpected exit")
                observed = T.parse((out / name / "result.json").read_bytes())
                T.require(observed["validation"]["expert_passed"] == passed, "unexpected validation count")
                if expected == 3:
                    board = T.parse((out / name / "scoreboard.json").read_bytes())
                    row, = [r for r in board["cases"] if r["id"] == "val-09"]
                    T.require(any(q["qid"] == owner["qid"] and q["citation"] == owner["citation"]
                                  for q in row["session_questions"]), "missing exact exclusion-question link")
        metadata["status"] = "PASS_BOUNDED_SESSION_SCOREBOARD"
    finally:
        cpu1 = resource.getrusage(resource.RUSAGE_CHILDREN)
        metadata.update(wall_seconds=time.monotonic() - t0,
                        child_cpu_seconds=cpu1.ru_utime + cpu1.ru_stime - cpu0.ru_utime - cpu0.ru_stime,
                        child_peak_rss_kib=cpu1.ru_maxrss, network_after=S.host_probe("/proc/net/dev"))
        T.write(out / "result.json", metadata)
        files = sorted(p for p in out.rglob("*") if p.is_file())
        (out / "SHA256SUMS").write_text("".join(f"{S.digest(p)}  {p.relative_to(out)}\n" for p in files))
    print(json.dumps({"status": metadata["status"], "out": str(out), "runs": runs}, indent=2))


if __name__ == "__main__":
    main()
