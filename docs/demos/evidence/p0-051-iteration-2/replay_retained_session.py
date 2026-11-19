#!/usr/bin/env python3
"""Replay retained C1 inputs; never consume a stored PASS verdict.

Run from trusted P0-051 source with an independently selected binary hash and
expert public-key mapping. Authenticate the archive separately. This is an
operator-driven component replay, not pack import or expert authentication.
Exit codes are the diagnostic's: 0 pass, 3 rejected, 2 refused.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "binary", "folder", "trusted-keys", "out"):
        ap.add_argument("--" + name, type=Path, required=True)
    ap.add_argument("--binary-sha256", required=True)
    a = ap.parse_args()
    binary = a.binary.resolve(strict=True)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != a.binary_sha256:
        ap.exit(2, "REFUSED: selected binary hash mismatch\n")
    sys.path.insert(0, str(a.repo.resolve(strict=True) / "research/capability-learning/harness"))
    import score_teaching_session as T
    folder = a.folder.resolve(strict=True)
    session = T.parse((folder / "session.stdout").read_bytes())
    spec = T.parse((folder / "task.json").read_bytes())
    trusted = T.parse(a.trusted_keys.read_bytes())
    for value in (session["tenant"], session["session_id"]):
        T.require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_:-][A-Za-z0-9._:-]*", value),
                  "unsafe retained session path")
    T.require(Path(session["document"]).name == session["document"], "unsafe retained document path")
    with tempfile.TemporaryDirectory(prefix="p051-retained-replay-") as temp:
        work = Path(temp)
        tenant_dir = work / "state/teach" / session["tenant"]
        tenant_dir.mkdir(mode=0o700, parents=True)
        stored = tenant_dir / (session["session_id"] + ".json")
        stored.write_bytes((folder / "session.stdout").read_bytes())
        stored.chmod(0o600)
        config = {"state": str(work / "state"), "policy_version": spec["policy_version"],
                  "security_domain": spec["domain"], "rag_k": 4, "approvers": {}, "experts": trusted,
                  "python": sys.executable, "sidecar_script": "UNUSED_BY_TEACH",
                  "llama_server": "UNUSED_BY_TEACH", "profile": "none", "port": 18080,
                  "q4": {"path": "UNUSED_BY_TEACH", "sha256": "0" * 64},
                  "q8": {"path": "UNUSED_BY_TEACH", "sha256": "0" * 64}}
        T.write(work / "config.json", config)
        result = T.score(binary=binary, config=work / "config.json", tenant=session["tenant"],
                         session_id=session["session_id"], session_task=session["task"],
                         task=folder / "task.json", answers=folder / "answers.json",
                         document=folder / "source" / session["document"], suite=folder / "suite.json",
                         example_map=folder / "example-map.json", out=a.out)
    print(json.dumps({k: result[k] for k in ("status", "exit_status", "examples")}, indent=2))
    return result["exit_status"]


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("REFUSED: " + str(error), file=sys.stderr)
        raise SystemExit(2)
