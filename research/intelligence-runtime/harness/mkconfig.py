"""Write a runtime config and ingest the evaluation corpora into a fresh state dir.

usage: mkconfig.py STATE_DIR PROFILE [--approvers approvers.json] [--experts experts.json] [--port N]
Corpora: Sovereign eval corpus (plant-alpha/beta), ir-tasks-v1 (koravi-process,
tarvel-grid). Model paths/hashes are the pinned ones from
research/compute-memory/bench/run_all.sh.
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
MODELS = os.environ.get("MODELS", "/home/claude/vanian-build/models")
BIN = os.environ.get("SYNTRIASS_BIN", os.path.join(ROOT, "target/release/syntriass"))
LLAMA = os.environ.get("LLAMA_SERVER", "/home/claude/vanian-build/build-llama-native/bin/llama-server")


def main() -> None:
    state, profile = sys.argv[1], sys.argv[2]
    approvers = {}
    if "--approvers" in sys.argv:
        approvers = json.load(open(sys.argv[sys.argv.index("--approvers") + 1]))
    experts = {}
    if "--experts" in sys.argv:
        experts = json.load(open(sys.argv[sys.argv.index("--experts") + 1]))
    port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 8301
    shutil.rmtree(state, ignore_errors=True)
    os.makedirs(state)
    cfg = {
        "state": os.path.abspath(state), "policy_version": "ep-114-revC", "security_domain": "koravi-ot", "rag_k": 3,
        "approvers": approvers, "experts": experts, "python": "/usr/local/bin/python3",
        "sidecar_script": os.path.join(ROOT, "research/system-one/harness/sidecar.py"),
        "llama_server": LLAMA, "profile": profile, "port": port,
        "q4": {"path": f"{MODELS}/qwen2.5-1.5b-instruct-q4_k_m.gguf", "sha256": "6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e"},
        "q8": {"path": f"{MODELS}/qwen2.5-1.5b-instruct-q8_0.gguf", "sha256": "d7efb072e7724d25048a4fda0a3e10b04bdef5d06b1403a1c93bd9f1240a63c8"},
    }
    path = os.path.join(state, "config.json")
    json.dump(cfg, open(path, "w"), indent=1)
    docs = sorted(glob.glob(os.path.join(ROOT, "sovereign/eval/corpus/*.txt"))) + sorted(glob.glob(os.path.join(ROOT, "research/capability-learning/data/ir-tasks-v1/corpus/*.txt")))
    out = subprocess.run([BIN, "ingest", "--config", path, *docs], capture_output=True, text=True, check=True)
    print(json.dumps({"config": path, "ingested": len(out.stdout.splitlines())}))


if __name__ == "__main__":
    main()
