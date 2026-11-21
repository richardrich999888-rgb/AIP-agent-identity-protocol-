"""Live 2.2: build the agent inventory from a real live_gate run (native, not P0-059).

    python3 command-center/lab/live_inventory.py LIVE_GATE_DIR OUT_DIR

Reads the registry and the event store that live_gate.py wrote. Opens the
store, verifies the hash chain, builds the inventory, and checks it against
the steps live_gate.py is known to run. Writes inventory.json and
result.json. Exit 0 only if every check passes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "server"))
import eventstore  # noqa: E402
import inventory  # noqa: E402

PAGE = 1000


def main(gate_dir: Path, out: Path) -> int:
    """Build and check the inventory for one live_gate run. 0 = all checks pass, 1 = a check failed, 2 = no run."""
    out.mkdir(parents=True, exist_ok=True)
    if not (gate_dir / "events.db").is_file() or not (gate_dir / "registry.json").is_file():
        print(f"{gate_dir}: no live_gate run (events.db, registry.json): live inventory run SKIPPED")
        return 2
    reg = json.loads((gate_dir / "registry.json").read_text())
    store = eventstore.EventStore(gate_dir / "events.db")
    chain = store.verify()
    events = [e.event for e in store.events(kind=inventory.GATE_KIND, limit=PAGE)]
    store.close()
    rows = inventory.build(reg["agents"], events)
    by = {r["agent_id"]: r for r in rows}
    keys = [a["public_key_hex"] for a in reg["agents"].values()] + [o["public_key_hex"] for o in reg["operators"].values()]
    text = json.dumps(rows, indent=1)
    rr, pa, orch = by.get("recon-reporter", {}), by.get("payments-agent", {}), by.get("orchestrator", {})
    checks = {
        "store chain intact": chain == [],
        "all gate decisions read (fewer than one page)": len(events) < PAGE,
        "one row per registered agent, none unregistered": sorted(by) == sorted(reg["agents"])
        and all(r["status"] == "REGISTERED" for r in rows),
        "registry fields carried (parent, owner, framework)": pa.get("parent") == "orchestrator"
        and pa.get("owner") == "alice" and pa.get("framework") == "scripted-test-agent",
        "no public key in the inventory, fingerprint only": not any(k in text for k in keys)
        and all(len(r["key_fingerprint"]) == 64 for r in rows),
        "forged identity counted against the claimed id, not as activity": rr.get("signature_failures") == 1,
        "revoked authority use makes the agent HIGH": rr.get("revoked_authority_uses") == 1 and rr.get("risk") == "HIGH",
        "OPA outage counted, not a policy denial": rr.get("engine_unavailable") == 1 and rr.get("policy_denials") == 2,
        "invalid approval makes payments-agent MEDIUM": pa.get("invalid_approvals") == 1 and pa.get("risk") == "MEDIUM",
        "approval use counted": pa.get("approvals_used") == 1 and pa.get("held_for_approval") == 2,
        "never-seen agent is UNKNOWN with no last-seen time": orch.get("risk") == "UNKNOWN" and orch.get("last_seen_ms") is None,
        "seen agents have a last-seen time": all(isinstance(by[a].get("last_seen_ms"), int) for a in ("recon-reporter", "payments-agent")),
    }
    (out / "inventory.json").write_text(text + "\n")
    result = {"source": str(gate_dir), "gate_decisions": len(events), "rows": len(rows), "checks": checks,
              "label": "TEST DATA: scripted agents in the native gate lab run"}
    (out / "result.json").write_text(json.dumps(result, indent=1) + "\n")
    for name, ok in checks.items():
        print(("PASS " if ok else "FAIL ") + name)
    passed = sum(checks.values())
    print(f"checks: {passed} passed, {len(checks) - passed} failed")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
