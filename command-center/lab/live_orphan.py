"""Live 2.4: an orphaned grandchild keeps running, is observed, and is refused (native, not P0-059).

    VANIAN_OPA_BIN=…/opa GATE_VENV/bin/python command-center/lab/live_orphan.py OUT_DIR

1. Start the real collector and probe (Sniffer Dog), the TEST DATA tool server
   and the native gate with an empty, operator-signed revocation list.
2. Start a real process tree: orchestrator → child (recon-reporter) →
   grandchild (recon-worker). Only the grandchild signs, with a fresh TEST key.
3. The grandchild calls the gate: ALLOW, forwarded.
4. The operator revokes the child's grant (a new signed list; the gate is
   restarted with it, because the gate has no hot reload) and the child
   process is SIGKILLed. The grandchild keeps running, reparented.
5. The grandchild calls again: DENY "authority revoked", not forwarded. Then
   it drops the revoked grant from the chain it presents: must be DENY too.
6. orphan.classify: child REVOKED, grandchild ORPHANED. Owner removal: with
   bob removed from the principal directory, payments-agent is UNKNOWN_OWNER,
   which is ADVISORY: the gate still allows its call, and the run checks that,
   so the label cannot overstate.
7. The archive is accepted only if `aip-observe-verify` accepts it; the
   kernel events must show the fork edges and the grandchild's connections
   to both gate ports.
Writes result.json (no private keys; the TEST key files are deleted). Exit 0
only if every check passes.
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "server"))
import agent_registry as ar  # noqa: E402
import eventstore  # noqa: E402
import gate as gate_mod  # noqa: E402
import gate_http  # noqa: E402
import lab_pair  # noqa: E402
import observer_ingest as oi  # noqa: E402
import opa_gate  # noqa: E402
import orphan  # noqa: E402
import shadow_ai as sa  # noqa: E402
import signing  # noqa: E402
import tool_server  # noqa: E402

POLICY = HERE.parent / "policy"
SETTLE_S = 3.0
WAIT_S = 15.0
GRANTS = {"orchestrator": "g-root", "recon-reporter": "g-recon", "recon-worker": "g-worker", "payments-agent": "g-pay"}


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def _ppid(pid: int) -> int | None:
    try:
        return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return None


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    opa_bin = os.environ.get("VANIAN_OPA_BIN")
    if not opa_bin or not Path(opa_bin).is_file():
        print("VANIAN_OPA_BIN not set: live orphan run SKIPPED")
        return 2
    work = out / "tree"
    work.mkdir()
    k = {n: signing.generate() for n in ("orchestrator", "recon-reporter", "recon-worker", "payments-agent", "ops-1")}
    ag = lambda n, parent, owner="alice": {"public_key_hex": k[n][1].hex(), "owner": owner, "framework": "scripted-test-agent",
                                         "host": "lab", "runtime": "python3.11", "parent": parent, "responsible_human": owner}
    reg_doc = {"agents": {"orchestrator": ag("orchestrator", None), "recon-reporter": ag("recon-reporter", "orchestrator"),
                          "recon-worker": ag("recon-worker", "recon-reporter"),
                          "payments-agent": ag("payments-agent", "orchestrator", owner="bob")},
               "operators": {"ops-1": {"public_key_hex": k["ops-1"][1].hex()}}}
    (out / "registry.json").write_text(json.dumps(reg_doc, indent=1))
    (out / "grants.json").write_text(json.dumps(GRANTS, indent=1))

    def revocations(jtis, name):
        lst = {"revoked_jtis": jtis, "issued_at_ms": now_ms(), "operator_id": "ops-1"}
        (out / name).write_text(json.dumps({"list": lst, "signature_hex": signing.sign(signing.DOMAIN_REVOCATIONS, lst, k["ops-1"][0])}))
        return ar.load(out / "registry.json", out / name)

    reg, revoked0 = revocations([], "revocations-0.json")
    agents = reg_doc["agents"]
    tport = lab_pair.free_port()
    tsrv, hits = tool_server.serve(tport)
    threading.Thread(target=tsrv.serve_forever, daemon=True).start()
    store = eventstore.EventStore(out / "events.db")
    fwd = gate_http.http_forwarder(f"http://127.0.0.1:{tport}")

    def start(revoked):
        gt = gate_mod.Gate(reg, revoked, opa_gate.OpaGate(opa_bin, POLICY), store, fwd, now_ms,
                           grants=ar.load_grants(out / "grants.json", reg))
        port = lab_pair.free_port()
        srv = gate_http.serve(gt, port)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, port

    def call_as(agent, url, server, tool, args):
        r = {"agent_id": agent, "server": server, "tool": tool, "args": args,
             "authority_jtis": orphan.authority_chain(agents, GRANTS, agent), "delegation_depth": 1,
             "nonce": secrets.token_hex(16), "issued_at_ms": now_ms()}
        e = {"request": r, "signature_hex": signing.sign(signing.DOMAIN_REQUEST, r, k[agent][0])}
        req = urllib.request.Request(url, data=json.dumps(e).encode(), headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return {"http": resp.status, **json.load(resp)}
        except urllib.error.HTTPError as err:
            return {"http": err.code, **json.load(err)}

    def ask(n):
        (work / f"call-{n}").write_text("")
        res = work / f"result-{n}.json"
        lab_pair.wait_for(res.exists, WAIT_S, f"grandchild result {n}")
        return json.loads(res.read_text())

    (work / "grandchild.key").write_text(k["recon-worker"][0].hex())
    (work / "agent_id").write_text("recon-worker")
    (work / "chain.json").write_text(json.dumps(orphan.authority_chain(agents, GRANTS, "recon-worker")))
    pair = lab_pair.Pair(out / "sensor", "collector.lab.orphan", "probe.lab.orphan", "sched,sockstate,socksend,connector").start()
    procs, t = {}, {}
    try:
        srv, port0 = start(revoked0)
        (work / "gate_url").write_text(f"http://127.0.0.1:{port0}/call")
        orch = subprocess.Popen([sys.executable, str(HERE / "orphan_tree.py"), "orchestrator", str(work)])
        lab_pair.wait_for(lambda: (work / "grandchild.pid").exists(), WAIT_S, "process tree")
        procs = {"orchestrator": orch.pid, "child": int((work / "child.pid").read_text()),
                 "grandchild": int((work / "grandchild.pid").read_text())}
        before = ask(1)
        hits_after_allow = len(hits)
        # Revoke the child's grant; restart the gate with the new signed list; kill the child.
        t["revoked_at_ms"] = now_ms()
        _, revoked1 = revocations(["g-recon"], "revocations-1.json")
        srv.shutdown()
        srv, port1 = start(revoked1)
        (work / "gate_url").write_text(f"http://127.0.0.1:{port1}/call")
        os.kill(procs["child"], signal.SIGKILL)
        lab_pair.wait_for(lambda: _ppid(procs["grandchild"]) not in (None, procs["child"]), WAIT_S, "grandchild reparented")
        grandchild_ppid_after = _ppid(procs["grandchild"])
        after = ask(2)
        hits_after_deny = len(hits)
        # Attack: the orphan drops the revoked ancestor's grant from the chain it presents.
        (work / "chain.json").write_text(json.dumps(["g-root", "g-worker"]))
        stripped = ask(3)
        hits_after_strip = len(hits)
        pay = call_as("payments-agent", f"http://127.0.0.1:{port1}/call", "payments", "settle_batch", {"amount": 500})
        (work / "stop").write_text("")
        orch.wait(timeout=WAIT_S)
        lab_pair.wait_for(lambda: _ppid(procs["grandchild"]) is None, WAIT_S, "grandchild exit")
        time.sleep(SETTLE_S)
        srv.shutdown()
    finally:
        (work / "stop").write_text("")
        pair.stop()
        tsrv.shutdown()
        for f in ("grandchild.key",):
            (work / f).unlink(missing_ok=True)

    st_before = orphan.classify(agents, GRANTS, revoked0, {"alice", "bob"})
    st_after = orphan.classify(agents, GRANTS, revoked1, {"alice", "bob"})
    st_owner = orphan.classify(agents, GRANTS, revoked1, {"alice"})
    decisions = [e.event for e in store.events(kind=gate_mod.DECISION_KIND, limit=100)]
    chain_ok = store.verify() == []
    store.close()

    verifier = str(lab_pair.BIN / "aip-observe-verify")
    vstore = eventstore.EventStore(out / "observer.db")
    poll = oi.ArchiveIngestor(vstore, pair.archive, verifier, oi.Anchor(pair.observer_id, 1, pair.pubkey), lambda: 0).poll()
    vstore.close()
    kernel = [e for line in oi.complete_lines(pair.archive.read_bytes()) for e in json.loads(line)["batch"]["kernel_events"]] \
        if poll.verified else []
    spawns = {(b["parent_pid"], b["child_pid"]) for e in kernel for n, b in e.get("kind", {}).items() if n == "ProcessSpawn"}
    observed = sa.observe(kernel)
    gconn = [c["port"] for c in observed.get(procs.get("grandchild", -1), sa.Process(-1)).connects
             if c["addr"] == sa.ipv4("127.0.0.1")]
    worker = [d for d in decisions if d.get("agent_id") == "recon-worker"]
    checks = {
        "grandchild call before revocation is ALLOWED and forwarded": before.get("outcome") == "ALLOW" and before.get("forwarded") is True
            and hits_after_allow == 1,
        "child process killed, grandchild still running and reparented": grandchild_ppid_after not in (None, procs["child"]),
        "grandchild call after revocation is DENIED: authority revoked": after.get("outcome") == "DENY"
            and "authority revoked" in after.get("reasons", []),
        "the refused call never reached the tool server": hits_after_deny == hits_after_allow,
        "orphan that strips the revoked grant from its chain is DENIED, not forwarded":
            stripped.get("outcome") == "DENY" and hits_after_strip == hits_after_deny
            and stripped.get("reasons") == ["authority chain does not match registered lineage"],
        "the only tool-server hits are the allowed calls": hits == [("fs", "read_file"), ("payments", "settle_batch")],
        "the gate records every grandchild decision": [d["outcome"] for d in worker] == ["ALLOW", "DENY", "DENY"],
        "same grandchild process made every call": before.get("pid") == after.get("pid") == stripped.get("pid") == procs["grandchild"],
        "lineage before revocation: all ACTIVE": all(s.status == orphan.ACTIVE for s in st_before.values()),
        "after revocation: child REVOKED, grandchild ORPHANED, others ACTIVE":
            (st_after["recon-reporter"].status, st_after["recon-worker"].status, st_after["orchestrator"].status,
             st_after["payments-agent"].status) == (orphan.REVOKED, orphan.ORPHANED, orphan.ACTIVE, orphan.ACTIVE),
        "owner removed: payments-agent UNKNOWN_OWNER, ADVISORY":
            (st_owner["payments-agent"].status, st_owner["payments-agent"].enforcement) == (orphan.UNKNOWN_OWNER, "ADVISORY"),
        "ADVISORY is honest: the gate still allowed payments-agent": pay.get("outcome") == "ALLOW",
        "archive verified by aip-observe-verify": poll.verified,
        "Sniffer Dog saw the fork edges orchestrator→child→grandchild":
            {(procs.get("orchestrator"), procs.get("child")), (procs.get("child"), procs.get("grandchild"))} <= spawns,
        "Sniffer Dog saw the grandchild connect to the gate before and after revocation":
            port0 in gconn and port1 in gconn,
        "gate store chain intact": chain_ok,
    }
    result = {"label": "live lab run; TEST keys, TEST DATA tool server; grants are lab-issued, not AIP tokens",
              "pids": procs, "grandchild_ppid_after_kill": grandchild_ppid_after, "gate_ports": [port0, port1],
              "revoked_at_ms": t.get("revoked_at_ms"), "calls": {"before": before, "after": after, "stripped_chain": stripped, "payments_agent": pay},
              "lineage": {"before": {a: s.__dict__ for a, s in st_before.items()},
                          "after_revocation": {a: s.__dict__ for a, s in st_after.items()},
                          "after_owner_removal": {a: s.__dict__ for a, s in st_owner.items()}},
              "observer": {"poll": poll.__dict__, "grandchild_loopback_connect_ports": gconn,
                           "spawn_edges_seen": len(spawns)}, "checks": checks}
    (out / "result.json").write_text(json.dumps(result, indent=1, default=list) + "\n")
    for name, ok in checks.items():
        print(("PASS " if ok else "FAIL ") + name)
    passed = sum(checks.values())
    print(f"checks: {passed} passed, {len(checks) - passed} failed")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
