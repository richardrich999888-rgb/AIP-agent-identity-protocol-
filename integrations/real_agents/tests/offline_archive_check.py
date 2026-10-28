#!/usr/bin/env python3
"""Exercise real verifier binaries against an existing historical signed fixture.

This is an OFFLINE REGRESSION, not a new workload or independently held live
checkpoint. Public key and checkpoint are deliberately taken from a repository
fixture to exercise the mechanics; live runs require institutional custody.
"""
import argparse
import json
import sys
import subprocess
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evidence import ARCHIVES, anchors_args, command, mutations, sha256, verify

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--repo", type=Path, required=True)
parser.add_argument("--tools", type=Path, required=True)
args = parser.parse_args()
archive = args.repo / "integrations/agents/results/sealed"
anchor = {"observer_id": "collector.phase1", "key_version": 1,
          "public_key": (archive / "observer.pub").read_text().strip()}
checkpoint = {"sha256": {name: sha256(archive / name) for name in ARCHIVES}}
start = time.monotonic()
report = verify(archive, args.tools, anchor, checkpoint)
verification_seconds = time.monotonic() - start
other = args.repo / "validation/external/corroborate/results/sealed"
other_anchor = {"observer_id": "collector.corr", "key_version": 1,
                "public_key": (other / "observer.pub").read_text().strip()}
# The two-batch LangGraph fixture has health but no middle record to delete.
# The nine-batch corroboration fixture has no health archive. Test its batch
# signatures separately; never attach unrelated health or manufacture records.
command([args.tools / "aip-observe-verify", *anchors_args(other_anchor),
         "--batches", other / ARCHIVES[0], "--json"])
expected = sha256(other / ARCHIVES[0])
results = {}
with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp) / ARCHIVES[0]
    for name, data in mutations((other / ARCHIVES[0]).read_bytes()).items():
        path.write_bytes(data)
        result = subprocess.run([str(args.tools / "aip-observe-verify"), *anchors_args(other_anchor),
                                 "--batches", str(path), "--json"], capture_output=True)
        assert result.returncode in (0, 1), result.stderr
        assert sha256(path) != expected
        if name not in ("remove_suffix", "remove_prefix"):
            assert result.returncode == 1, name
        results[name] = {"signature_chain_rejected": result.returncode == 1,
                         "separately_retained_checksum_rejected": sha256(path) != expected}
print(json.dumps({"classification": "HISTORICAL_ARCHIVE_OFFLINE_REGRESSION",
                  "live_agent_run": False, "verification_seconds": verification_seconds,
                  "verifier": report, "mutations": results}, indent=2))
