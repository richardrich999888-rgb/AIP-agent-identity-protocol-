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
    if name in ("server-suite", "gate-suite", "inventory-suite", "orphan-suite"):
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
    t = {n: passed(runs, n) for n in ("policy", "server-suite", "gate-suite", "inventory-suite", "orphan-suite", "litellm-acceptance", "revocation-gap", "delegation-findings", "revocation-persistence", "live-sensors")}
    kill = live_result(runs, "live-kill")
    shadow = live_result(runs, "live-shadow")
    gate_live = live_result(runs, "live-gate")
    inv_live = live_result(runs, "live-inventory")
    orphan_live = live_result(runs, "live-orphan")

    def verified(ok, scope):
        if ok is None:
            return "FAIL", "its check did not run: run test.sh and run.sh first"
        return ("VERIFIED", scope) if ok else ("FAIL", "its check failed")

    def gate(ok, partial_reason):
        if ok is None:
            return "FAIL", "its check did not run: run test.sh and run.sh first"
        return ("PARTIAL", partial_reason) if ok else ("FAIL", "its check failed")

    p0059 = ("NOT_AVAILABLE", "P0-059 is BLOCKED_BY_EXTERNAL_APPROVAL (0.1, final); the native replacement is not built yet")
    rows = [
        ("1 Agent inventory", verified(t["inventory-suite"] and gate_live and inv_live,
                                      "registered agents and ids that reach the native gate: registry fields, key fingerprint, "
                                      "last seen and declared risk rule from gate records; kernel-only processes are not joined "
                                      "(no agent id in kernel events); no console UI yet (native, not P0-059)")),
        ("2 Shadow AI", gate(shadow and t["server-suite"],
                             "HEURISTIC class passes live with 0 false positives; CONFIRMED class and registry are P0-059 (2.3b)")),
        ("3 Ghost AI", p0059),
        ("4 Orphan AI", verified(t["orphan-suite"] and t["gate-suite"] and orphan_live,
                                "a revoked ancestor orphans its descendants: the orphaned grandchild process keeps running, "
                                "is observed by Sniffer Dog and refused at the native gate, which derives authority from the "
                                "registry lineage; UNKNOWN_OWNER is ADVISORY; grants are lab-issued, not AIP tokens; "
                                "revocation applies at gate restart (native, not P0-059)")),
        ("5 Parent-child", p0059),
        ("6 Governance enforcement", verified(t["policy"] and t["server-suite"] and t["gate-suite"] and gate_live,
                                              "PREVENTION for calls through the native gate (signed requests, authority derived from "
                                              "the registry lineage, OPA, OPA-down DENY); a path that bypasses the gate is not covered (native, not P0-059)")),
        ("7 Human approval", verified(t["gate-suite"] and gate_live,
                                      "held calls forward only with an operator-signed, request-bound, single-use approval; "
                                      "no console UI yet (native, not P0-059)")),
        ("8 Activity and observer coverage", gate(t["server-suite"] and kill and t["live-sensors"],
                                                  "coverage, gaps and the kill run pass live; per-event rows and console are 3.4c")),
        ("9 Human vs agent attribution", ("NOT_IMPLEMENTED", "4.3 not built yet (the native gate it needs now exists)")),
        ("10 FinOps", gate(t["server-suite"] and t["litellm-acceptance"],
                           "capture and persistence pass against the TEST DATA mock; console 4.2 and agents 4.1b missing")),
        ("11 AIP identity", gate(t["revocation-gap"] and t["delegation-findings"] and t["revocation-persistence"],
                                 "crates tested; console is P0-059; findings pinned: DecisionPoint ignores revocation and an unpersisted "
                                 "revocation is lost on restart (ADR-001), "
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
         "checks": {**t, "live-kill": kill, "live-shadow": shadow, "live-gate": gate_live, "live-inventory": inv_live, "live-orphan": orphan_live}, "verified": verified, "failed": failed}, indent=1) + "\n")
    return 0 if verified == 12 else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
