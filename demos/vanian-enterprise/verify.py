"""Report each of the 12 capabilities. Exit 0 only if all 12 are VERIFIED.

Status per capability:

- VERIFIED: an automated test and a live run on this host both pass;
- PARTIAL: the parts that exist pass, but the capability is incomplete
  (the reason is printed);
- NOT_AVAILABLE: the code lives in P0-059, whose commits are not on this
  branch;
- NOT_IMPLEMENTED: nothing on this branch provides it;
- FAIL: a check that should pass did not.

    python3 demos/vanian-enterprise/verify.py LAB_RUNS_DIR
"""

import json
import sys
from pathlib import Path


def passed(runs: Path, name: str) -> bool | None:
    log = runs / f"test-{name}.log"
    if not log.exists():
        return None
    t = log.read_text(errors="replace")
    if name == "policy":
        return "PASS:" in t and "FAIL:" not in t
    if name == "server-suite":
        return t.rstrip().endswith("OK")
    if name == "litellm-acceptance":
        return "checks: 16 passed, 0 failed" in t
    return "test result: ok" in t and "FAILED" not in t


def live_result(runs: Path, name: str) -> bool | None:
    r = runs / f"{name}-latest" / "result.json"
    if not r.exists():
        return None
    checks = json.loads(r.read_text()).get("checks", {})
    return bool(checks) and all(checks.values())


def main(runs: Path) -> int:
    t = {n: passed(runs, n) for n in ("policy", "server-suite", "litellm-acceptance", "revocation-gap", "delegation-findings", "live-sensors")}
    kill = live_result(runs, "live-kill")
    shadow = live_result(runs, "live-shadow")

    def gate(ok, partial_reason):
        if ok is None:
            return "FAIL", "its check did not run: run test.sh and run.sh first"
        return ("PARTIAL", partial_reason) if ok else ("FAIL", "its check failed")

    p0059 = ("NOT_AVAILABLE", "P0-059 commits are not on this branch (item 0.1)")
    rows = [
        ("1 Agent inventory", p0059),
        ("2 Shadow AI", gate(shadow and t["server-suite"],
                             "HEURISTIC class passes live with 0 false positives; CONFIRMED class and registry are P0-059 (2.3b)")),
        ("3 Ghost AI", p0059),
        ("4 Orphan AI", p0059),
        ("5 Parent-child", p0059),
        ("6 Governance enforcement", gate(t["policy"] and t["server-suite"],
                                          "the OPA decision is tested but not wired into the gate: ADVISORY (3.1b)")),
        ("7 Human approval", ("NOT_IMPLEMENTED", "3.2 needs the gateway")),
        ("8 Activity and observer coverage", gate(t["server-suite"] and kill and t["live-sensors"],
                                                  "coverage, gaps and the kill run pass live; per-event rows and console are 3.4c")),
        ("9 Human vs agent attribution", ("NOT_IMPLEMENTED", "4.3 needs the gateway")),
        ("10 FinOps", gate(t["server-suite"] and t["litellm-acceptance"],
                           "capture and persistence pass against the TEST DATA mock; console 4.2 and agents 4.1b missing")),
        ("11 AIP identity", gate(t["revocation-gap"] and t["delegation-findings"],
                                 "crates tested; console is P0-059; findings pinned: DecisionPoint ignores revocation (ADR-001), "
                                 "Delegate scope not enforced and no proof of possession (ADR-002)")),
        ("12 Evidence verification", gate(t["server-suite"],
                                          "observer archives verified offline; bundle v2 and vcc-verify are P0-059")),
    ]
    for name, (status, why) in rows:
        print(f"{status:<16} {name}: {why}")
    verified = sum(s == "VERIFIED" for _, (s, _) in rows)
    failed = sum(s == "FAIL" for _, (s, _) in rows)
    print(f"verified {verified}/12, failed {failed}")
    (runs / "verify-summary.json").write_text(json.dumps(
        {"capabilities": [{"capability": n, "status": s, "reason": w} for n, (s, w) in rows],
         "checks": {**t, "live-kill": kill, "live-shadow": shadow}, "verified": verified, "failed": failed}, indent=1) + "\n")
    return 0 if verified == 12 else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
