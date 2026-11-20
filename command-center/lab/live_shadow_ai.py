"""Live adversarial #1 (unregistered workload) and #2 (false-positive control).

    python3 command-center/lab/live_shadow_ai.py OUT_DIR

Starts the real collector and probe (lab_pair), plus the deterministic mock
model (TEST DATA) on a loopback port declared as the model endpoint. In the
same observed window it runs:

- A, `python3`, calls the mock's chat endpoint. It has no identity in the
  (empty) registry. Expected: HEURISTIC_AI_WORKLOAD with "no registry row".
- B, `python3 -m http.server` and a `python3` client fetching from it.
  Expected: UNCLASSIFIED (ordinary web traffic).
- C, `sort` on a file. Expected: UNCLASSIFIED.

The archive is accepted only if `aip-observe-verify` accepts it (through
ArchiveIngestor). It is then classified with shadow_ai. Exit 0 only if
every check passes. Writes result.json.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "server"))
sys.path.insert(0, str(HERE.parents[1] / "research" / "oss" / "litellm"))
import eventstore  # noqa: E402
import lab_pair  # noqa: E402
import mock_openai  # noqa: E402
import observer_ingest as oi  # noqa: E402
import shadow_ai as sa  # noqa: E402

SETTLE_S = 3.0  # > batch interval + attest latency, so the last events are archived


def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    pair = lab_pair.Pair(out / "work", "collector.lab.shadow", "probe.lab.shadow", "sched,sockstate,socksend,connector").start()
    mock = mock_openai.serve(0)
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    model_port = mock.server_address[1]
    web_port = lab_pair.free_port()
    py = sys.executable
    try:
        a = subprocess.Popen([py, "-c", (
            "import json,urllib.request\n"
            f"r=urllib.request.Request('http://127.0.0.1:{model_port}/v1/chat/completions',"
            "data=json.dumps({'model':'mock-1','messages':[{'role':'user','content':'hi'}]}).encode(),"
            "headers={'content-type':'application/json'})\n"
            "print(urllib.request.urlopen(r,timeout=5).read())")], stdout=subprocess.PIPE)
        web = subprocess.Popen([py, "-m", "http.server", str(web_port), "--bind", "127.0.0.1"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=tempfile.gettempdir())
        lab_pair.wait_for(lambda: web.poll() is None and _open(web_port), 10, "http.server")
        b = subprocess.Popen([py, "-c", f"import urllib.request;urllib.request.urlopen('http://127.0.0.1:{web_port}/',timeout=5).read()"])
        data = out / "sort-input.txt"
        data.write_text("c\nb\na\n")
        c = subprocess.Popen(["sort", str(data)], stdout=subprocess.DEVNULL)
        a_out = a.communicate(timeout=10)[0]
        for p in (b, c):
            p.wait(timeout=10)
        web.terminate()
        web.wait(timeout=5)
        time.sleep(SETTLE_S)
    finally:
        pair.stop()
        mock.shutdown()

    store = eventstore.EventStore(out / "events.db")
    verifier = str(lab_pair.BIN / "aip-observe-verify")
    poll = oi.ArchiveIngestor(store, pair.archive, verifier, oi.Anchor(pair.observer_id, 1, pair.pubkey), lambda: 0).poll()
    store.close()
    kernel = [e for line in oi.complete_lines(pair.archive.read_bytes()) for e in json.loads(line)["batch"]["kernel_events"]] \
        if poll.verified else []
    endpoints = {sa.Endpoint(sa.ipv4("127.0.0.1"), model_port)}
    findings = {f.pid: f for f in sa.classify(sa.observe(kernel), endpoints, registry=set())}
    heur = [f for f in findings.values() if f.classification == sa.HEURISTIC]
    expect_unclassified = {"web": web.pid, "b": b.pid, "c": c.pid}
    checks = {
        "archive verified by aip-observe-verify before classification": poll.verified,
        "A got a TEST DATA reply from the mock": b"TEST DATA" in (a_out or b""),
        "A (unregistered client of the model port) is HEURISTIC_AI_WORKLOAD":
            findings.get(a.pid) is not None and findings[a.pid].classification == sa.HEURISTIC,
        "A's attribution_missing_reason is set": findings.get(a.pid) is not None
            and findings[a.pid].attribution_missing_reason in ("no registry row", "no binding"),
        "B (http.server and its client) and C (sort) are not HEURISTIC":
            all(findings.get(pid) is None or findings[pid].classification == sa.UNCLASSIFIED for pid in expect_unclassified.values()),
        "B and C were observed (so the negative is not vacuous)":
            all(pid in findings for pid in expect_unclassified.values()),
        "no false positive: A is the only HEURISTIC process": [f.pid for f in heur] == [a.pid],
    }
    result = {"label": "live lab run; model is the TEST DATA mock", "model_port": model_port, "web_port": web_port,
              "pids": {"a": a.pid, **expect_unclassified}, "poll": poll.__dict__,
              "findings": [f.__dict__ for f in findings.values() if f.pid in {a.pid, *expect_unclassified.values()}],
              "heuristic_pids": [f.pid for f in heur], "observed_processes": len(findings), "checks": checks}
    (out / "result.json").write_text(json.dumps(result, indent=1, default=list) + "\n")
    for k, v in checks.items():
        print(f"{'ok  ' if v else 'FAIL'} {k}")
    failed = [k for k, v in checks.items() if not v]
    print(f"checks: {len(checks) - len(failed)} passed, {len(failed)} failed")
    return 0 if not failed else 1


def _open(port: int) -> bool:
    import socket
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
        return True
    except OSError:
        return False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(Path(sys.argv[1])))
