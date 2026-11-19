#!/usr/bin/env python3
"""Record B3's bounded exclusion policy through the real offline CLI.

Uses an already built binary; downloads/builds nothing. Regenerates and checks
the pinned HU-TX-2 dataset, starts a real teaching session, applies explicit
engineer answers, compiles them, and runs signed suites through cap-scoreboard.
The copied-plural failure is retained as a control. No approval or activation.

Suites are signed with a temporary synthetic evaluator key. Retained public
trust material verifies integrity, not external expert identity. Session,
answer edits and diagnostics are unsigned. This is not a full W3 rehearsal.
Exit 0 requires all acceptance checks, including the broader attack suite.
Exit 3 retains a rejected attack suite and reports partial progress. The
expected copied-plural control failure does not certify the corrected IR.
"""
from __future__ import annotations

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

import apply_answers as B
import draft_from_session as D
import exclusion_terms as E
import question_generator as Q
import record_answers as RA
import record_holdout as H
import record_scoreboard as S

EXPERT = "expert:p0-049-synthetic-evaluator"


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def attacks(data: Path) -> list[dict]:
    """Frozen nonactivation cases plus explicit forms and whole-word controls."""
    cases = [{**r, "counterexample": True} for r in rows(data / "false_activation.jsonl")]
    for n, term in enumerate(term for pair in E.PAIRS for term in pair):
        for upper in (False, True):
            shown = term.upper() if upper else term
            cases.append({"id": f"form-{n}-{'upper' if upper else 'lower'}",
                          "text": f"{shown} C-4 11 kV, 700 megohms at 20 C, DAR 1.5",
                          "label": "OUT_OF_SCOPE", "counterexample": True})
    for n, tag in enumerate(("motorcycle", "xcables", "cabling", "generatorship")):
        cases.append({"id": f"whole-word-{n}",
                      "text": f"TX-30 11 kV, 260 megohms at 20 C, DAR 1.4. Tag: {tag}",
                      "label": "ACCEPT", "counterexample": False})
    return cases


def score(binary, cfg, key, cap, cases, work, retained, expected_exit=None):
    retained.mkdir()
    cap_file = retained / "capability.json"
    S.write(cap_file, cap)
    proposal = json.loads(S.run([binary, "cap-propose", "--config", cfg, "--file", cap_file]).stdout)
    cases_file = retained / "cases.jsonl"
    cases_file.write_text("".join(json.dumps(r) + "\n" for r in cases))
    suite = retained / "suite.json"
    S.run([binary, "suite-sign", "--key", key, "--cases", cases_file, "--suite-id",
           f"p0-049/b3/{retained.name}", "--tenant", cap["required"]["tenant"],
           "--task", cap["intended_task"], "--out", suite])
    stored = list((work / "state/capabilities").glob("*.json"))
    before = {p.name: S.digest(p) for p in stored}
    start = time.perf_counter()
    result = subprocess.run([str(x) for x in [binary, "cap-scoreboard", "--config", cfg,
                            "--hash", proposal["hash"], "--suite", suite]],
                            capture_output=True, text=True, timeout=120)
    duration = time.perf_counter() - start
    (retained / "stdout.txt").write_text(result.stdout)
    (retained / "stderr.txt").write_text(result.stderr)
    S.write(retained / "exit.json", {"actual": result.returncode, "expected": expected_exit})
    report = json.loads(result.stdout)
    S.write(retained / "scoreboard.json", report)
    if result.returncode not in (0, 3) or (expected_exit is not None and result.returncode != expected_exit):
        raise RuntimeError(f"{retained.name}: expected exit {expected_exit}, got {result.returncode}; "
                           f"full stdout/stderr retained in {retained}")
    if {p.name: S.digest(p) for p in stored} != before:
        raise RuntimeError("scoreboard changed lifecycle state")
    if report["validation"]["passed"] != (result.returncode == 0):
        raise RuntimeError("validation and exit status disagree")
    if expected_exit == 3 and not any(
        c["id"] == "val-09" and c["expected"] == "OUT_OF_SCOPE" and c["got"] == "ACCEPT"
        and c["passed"] is False for c in report["cases"]
    ):
        raise RuntimeError("the original Cable failure was not reproduced")
    return {"name": retained.name, "capability_hash": proposal["hash"],
            "exit_status": result.returncode, "wall_seconds": duration,
            "expert_passed": report["validation"]["expert_passed"],
            "expert_cases": report["validation"]["expert_cases"], "state_unchanged": True,
            "passed": report["validation"]["passed"], "failures": report["validation"]["failures"]}


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
    before_network = S.host_probe("/proc/net/dev")
    commit = S.run(["git", "-C", S.REPO, "rev-parse", "HEAD"]).stdout.strip()
    dirty = S.run(["git", "-C", S.REPO, "status", "--porcelain"]).stdout
    spec = json.loads(H.TASK.read_text())
    S.write(out / "word-form-policy.json", {"policy": E.POLICY, "pairs": E.PAIRS,
                                           "source_sha256": S.digest(Path(E.__file__))})
    with tempfile.TemporaryDirectory(prefix="p0-049-b3-") as temp:
        work = Path(temp)
        data = S.generate("tx", work / "data")
        session = H.teach(work, data, spec, binary=binary)
        draft = D.draft(session, spec)
        questions = Q.generate(draft, spec)
        owner, = [q for q in questions["questions"] if q["field_path"] == "scope_exclusion_terms.*"]
        original = RA.answers_file(draft, questions, H.AS_INSTRUCTED, 1)
        explicit = copy.deepcopy(original)
        entry, = [x for x in explicit["answers"] if x["qid"] == owner["qid"]]
        entry["answer"] += [c["term"] for c in owner["exclusion_word_forms"]]
        entry["why"] = "Explicitly select the offered exclusion forms and retain every quoted form."
        answered = B.apply(draft, spec, explicit)
        control = B.apply(draft, spec, original)
        if answered["status"] != "COMPILES" or control["status"] != "COMPILES":
            raise RuntimeError("teaching answers did not compile")
        changed = H.leaf_diff(control["ir"], answered["ir"])
        if len(changed) != 4 or any(not e["leaf"].startswith(".out_of_scope_terms[") for e in changed):
            raise RuntimeError("change is not exactly four explicit exclusion additions")
        for name, value in {"session": session, "draft": draft, "questions": questions,
                            "answers-control": original, "answers-explicit": explicit,
                            "answered-control": control, "answered-explicit": answered,
                            "ir-diff": changed}.items():
            S.write(out / f"{name}.json", value)
        key = work / "expert.json"
        S.run([binary, "keygen", "--id", EXPERT, "--out", key])
        public = json.loads(key.read_text())["public_hex"]
        S.write(out / "expert-public.json", {EXPERT: public})
        cfg = work / "validation-config.json"
        # Same source/corpus gates as the existing scoreboard recorder.
        config = json.loads((work / "config.json").read_text())
        config.update({"policy_version": spec["policy_version"], "security_domain": spec["domain"],
                       "experts": {EXPERT: public}})
        S.write(cfg, config)
        for document in sorted((data / "corpus").glob("*.txt")):
            S.run([binary, "ingest", "--config", cfg, document])
        validation = rows(data / "validation.jsonl")
        cap_control = H.compile_to(control["ir"], spec, work / "control.json")
        cap_explicit = H.compile_to(answered["ir"], spec, work / "explicit.json")
        runs = []
        for name, cap_file, cases, expected_exit in (
            ("copied-plural-control", cap_control, validation, 3),
            ("explicit-forms-validation", cap_explicit, validation, 0),
            ("copied-plural-attacks", cap_control, attacks(data), None),
            ("explicit-forms-attacks", cap_explicit, attacks(data), None),
        ):
            runs.append(score(binary, cfg, key, json.loads(cap_file.read_text()), cases,
                              work, out / name, expected_exit))
    attack_passed = runs[-1]["passed"]
    result = "PASS_BOUNDED_B3" if attack_passed else "PARTIAL_B3_ADVERSARIAL_FAILURE"
    before_failures = {f["id"]: f for f in runs[-2]["failures"]}
    new_failures = [f for f in runs[-1]["failures"] if before_failures.get(f["id"]) != f]
    cpu1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    S.write(out / "result.json", {
        "schema": "syntriass.p0-049.exclusion-policy-evidence/v1", "result": result,
        "commit": commit, "tree_dirty": bool(dirty), "dirty_paths": dirty.splitlines(),
        "binary_sha256": S.digest(binary), "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version, "policy": E.POLICY, "session_id": session["session_id"],
        "question_id": owner["qid"], "questions_sha256": B.questions_digest(questions),
        "dataset_manifest_sha256": S.digest(S.CL / "data/tx-tasks-v1/MANIFEST.json"),
        "hardware": {"platform": platform.platform(), "logical_cpus": os.cpu_count(),
                     "affinity_cpus": len(os.sched_getaffinity(0)),
                     "meminfo": Path("/proc/meminfo").read_text().splitlines()[0],
                     "cgroup_cpu_max": S.host_probe("/sys/fs/cgroup/cpu.max"),
                     "cgroup_memory_max": S.host_probe("/sys/fs/cgroup/memory.max")},
        "wall_seconds": time.perf_counter() - started,
        "child_cpu_seconds": cpu1.ru_utime + cpu1.ru_stime - cpu0.ru_utime - cpu0.ru_stime,
        "child_peak_rss_kib": cpu1.ru_maxrss,
        "network": {"namespace": os.readlink("/proc/self/ns/net"), "interfaces_before": before_network,
                    "interfaces_after": S.host_probe("/proc/net/dev"),
                    "ipv4_routes": S.host_probe("/proc/net/route"), "ipv6_routes": S.host_probe("/proc/net/ipv6_route")},
        "runs": runs, "model_calls": 0, "model_hashes": [], "activation_performed": False,
        "attack_gate_passed": attack_passed, "new_attack_failures": new_failures,
        "signed_material": "synthetic expert suites only; public key retained; private key discarded",
        "limitations": ["Four reviewed maintenance word pairs; not general language understanding.",
                        "Engineer-scripted answers, not external expert approval.",
                        "Session, answer edits and scoreboard are unsigned; no answer receipts.",
                        "One development host; no independent installation, packet capture or kernel sensor proof.",
                        "No live model, UI, activation, pack transfer or full W3 rehearsal."],
    })
    files = sorted(p for p in out.rglob("*") if p.is_file())
    (out / "SHA256SUMS").write_text("".join(f"{S.digest(p)}  {p.relative_to(out)}\n" for p in files))
    print(json.dumps({"result": result, "output": str(out), "runs": runs}, indent=2))
    if not attack_passed:
        print("record_exclusion_policy: NOT READY; corrected capability rejected by the attack suite. "
              "See explicit-forms-attacks/scoreboard.json. No approval or activation performed.", file=sys.stderr)
    return 0 if attack_passed else 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, H.R.Failure, subprocess.TimeoutExpired) as error:
        print(f"record_exclusion_policy: NOT READY: {error}", file=sys.stderr)
        raise SystemExit(2)
