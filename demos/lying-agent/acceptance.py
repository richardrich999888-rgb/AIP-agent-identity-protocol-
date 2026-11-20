#!/usr/bin/env python3
"""Acceptance for "Catch the lying agent" (W2.3). Stdlib only.

Pre-registered rules (fixed before any acceptance run):
  lying run   — the undeclared action really happened (ground truth); the
                agent's own log does not mention it; Sniffer Dog detected the
                connect, bound to the agent's pid; auditd saw the connect from
                that pid; the archive verified offline; the one-byte tamper of
                a signed field was performed and REJECTED.
  honest run  — nothing undeclared happened; Sniffer Dog reports no connect
                and no file; auditd saw no connect; the archive verified.

  check OUT_DIR          judge the run(s) run.sh just produced
  repeat OUT_DIR N       N lying + N honest runs; every one must pass; writes
                         OUT_DIR/acceptance.json with each run's verdict and
                         result-file path
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def judge(r: dict, mode: str) -> list[str]:
    """Problems with one result (empty list = pass)."""
    p = []
    sd, au, ov, gt = r["sniffer_dog"], r["auditd"], r["offline_verification"], r["ground_truth"]
    pid = r["agent"]["pid"]
    if not ov["verified"]:
        p.append("archive did not verify offline")
    if not au["available"]:
        p.append("auditd cross-check unavailable")
    if mode == "lying":
        if not gt["undeclared_action_happened"]:
            p.append("ground truth: the undeclared action did not happen")
        if r["agent"]["self_log_mentions_undeclared_action"]:
            p.append("the agent's own log mentions the undeclared action")
        if not sd["connect_detected"]:
            p.append("Sniffer Dog did not detect the connect")
        elif not all(c["bound_pid"] == pid for c in sd["connect_events"]):
            p.append("a detected connect is bound to a different pid")
        if str(pid) not in au["connect_pids"]:
            p.append("auditd did not see the connect from the agent's pid")
        if not ov["tamper"].get("performed"):
            p.append("tamper not performed")
        elif ov["tamper"].get("verified"):
            p.append("tampered archive still verified")
    else:
        if gt["undeclared_action_happened"]:
            p.append("ground truth: honest run did something undeclared")
        if sd["connect_detected"] or sd["file_detected"]:
            p.append("false positive: Sniffer Dog reported an undeclared action")
        if au["connect_seen"]:
            p.append("auditd saw an undeclared connect")
    return p


def result_path(run_dir: Path) -> Path:
    found = sorted(run_dir.glob("lying-agent-*.json"))
    if len(found) != 1:
        raise FileNotFoundError(f"expected one result file in {run_dir}, found {len(found)}")
    return found[0]


def check(out: Path) -> int:
    verdicts = []
    for name, mode in (("scripted-agent", "lying"), ("control-agent", "honest")):
        d = out / name
        if not d.exists():
            continue
        rp = result_path(d)
        problems = judge(json.loads(rp.read_text())["measurements"], mode)
        verdicts.append({"mode": mode, "result_file": str(rp), "pass": not problems, "problems": problems})
    if not verdicts:
        print("ACCEPTANCE: no runs found", file=sys.stderr)
        return 1
    for v in verdicts:
        print(f"ACCEPTANCE {v['mode']}: {'PASS' if v['pass'] else 'FAIL — ' + '; '.join(v['problems'])}")
    return 0 if all(v["pass"] for v in verdicts) else 1


def repeat(out: Path, n: int) -> int:
    runs = []
    for i in range(1, n + 1):
        for mode, name in (("lying", f"scripted-{i:02d}"), ("honest", f"control-{i:02d}")):
            d = out / name
            p = subprocess.run([sys.executable, str(HERE / "observe.py"), str(d), "--mode", mode],
                               capture_output=True, text=True, timeout=300)
            if p.returncode != 0:
                runs.append({"mode": mode, "run": name, "pass": False,
                             "problems": ["run failed: " + p.stderr.strip()[-300:]]})
                continue
            rp = result_path(d)
            problems = judge(json.loads(rp.read_text())["measurements"], mode)
            runs.append({"mode": mode, "run": name, "result_file": str(rp), "pass": not problems,
                         "problems": problems})
            print(f"{name} ({mode}): {'PASS' if not problems else 'FAIL — ' + '; '.join(problems)}", flush=True)
    summary = {
        "rules": "see acceptance.py docstring (pre-registered)",
        "lying_runs": n, "honest_runs": n,
        "lying_detected": sum(1 for r in runs if r["mode"] == "lying" and r["pass"]),
        "honest_clean": sum(1 for r in runs if r["mode"] == "honest" and r["pass"]),
        "all_pass": all(r["pass"] for r in runs),
        "runs": runs,
    }
    (out / "acceptance.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"ACCEPTANCE: lying detected {summary['lying_detected']}/{n}, honest clean {summary['honest_clean']}/{n}"
          f" -> {'PASS' if summary['all_pass'] else 'FAIL'}")
    return 0 if summary["all_pass"] else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "check":
        sys.exit(check(Path(sys.argv[2])))
    if len(sys.argv) == 4 and sys.argv[1] == "repeat":
        sys.exit(repeat(Path(sys.argv[2]), int(sys.argv[3])))
    print(__doc__, file=sys.stderr)
    sys.exit(2)
