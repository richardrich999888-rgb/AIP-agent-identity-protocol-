"""Write a runtime config and ingest the evaluation corpora into a fresh state dir.

usage: mkconfig.py STATE_DIR PROFILE [--approvers approvers.json] [--experts experts.json] [--port N]
                   [--domain D] [--policy P] [--corpus DIR ...]
Corpora: Sovereign eval corpus (plant-alpha/beta), ir-tasks-v1 (koravi-process,
tarvel-grid). Model paths/hashes are the pinned ones from
research/compute-memory/bench/run_all.sh.
"""
from __future__ import annotations

import glob
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
# Model directory and digests come from deploy/syntriass/models.manifest.json
# through resolve_model.py, so they are not duplicated here. MODELS and
# SYNTRIASS_BUNDLE still override, with the same precedence as every caller.
_RESOLVER = Path(__file__).resolve().parents[3] / "deploy/syntriass/resolve_model.py"
sys.path.insert(0, str(_RESOLVER.parent))
import resolve_model  # noqa: E402

MODELS = str(resolve_model.models_dir())


def _model_entry(logical_name):
    """Path plus pinned digest for one manifest entry."""
    record = resolve_model.entry(logical_name)
    return {"path": f"{MODELS}/{record['file']}", "sha256": record["sha256"]}
BIN = os.environ.get("SYNTRIASS_BIN", os.path.join(ROOT, "target/release/syntriass"))
# Bundled llama-server; LLAMA_SERVER still overrides. Resolved lazily so
# importing this module on a machine with no bundle does not fail.
try:
    LLAMA = str(resolve_model.llama_server())
except resolve_model.Refused:
    LLAMA = str(resolve_model.bundle_root()
                / resolve_model.manifest()["bundle_layout"]["llama_server"])


def main() -> None:
    state, profile = sys.argv[1], sys.argv[2]
    approvers = {}
    if "--approvers" in sys.argv:
        approvers = json.load(open(sys.argv[sys.argv.index("--approvers") + 1]))
    experts = {}
    if "--experts" in sys.argv:
        experts = json.load(open(sys.argv[sys.argv.index("--experts") + 1]))
    port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 8301
    def opt(name, default):
        return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default
    domain, policy = opt("--domain", "koravi-ot"), opt("--policy", "ep-114-revC")
    extra = [sys.argv[i + 1] for i, x in enumerate(sys.argv) if x == "--corpus"]
    shutil.rmtree(state, ignore_errors=True)
    os.makedirs(state)
    cfg = {
        "state": os.path.abspath(state), "policy_version": policy, "security_domain": domain, "rag_k": 3,
        "approvers": approvers, "experts": experts, "python": "/usr/local/bin/python3",
        "sidecar_script": os.path.join(ROOT, "research/system-one/harness/sidecar.py"),
        "llama_server": LLAMA, "profile": profile, "port": port,
        "q4": _model_entry("qwen2.5-1.5b-q4"),
        "q8": _model_entry("qwen2.5-1.5b-q8"),
    }
    path = os.path.join(state, "config.json")
    json.dump(cfg, open(path, "w"), indent=1)
    docs = sorted(glob.glob(os.path.join(ROOT, "sovereign/eval/corpus/*.txt"))) + sorted(glob.glob(os.path.join(ROOT, "research/capability-learning/data/ir-tasks-v1/corpus/*.txt"))) + \
        [f for d in extra for f in sorted(glob.glob(os.path.join(d, "*.txt")))]
    out = subprocess.run([BIN, "ingest", "--config", path, *docs], capture_output=True, text=True, check=True)
    print(json.dumps({"config": path, "ingested": len(out.stdout.splitlines())}))


if __name__ == "__main__":
    main()
