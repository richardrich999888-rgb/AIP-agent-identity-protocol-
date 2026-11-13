"""Unsigned, content-addressed review prepared by fresh native session replay.

Integrity verification requires an externally supplied digest. It neither
authenticates an expert nor authorizes activation. Never sign a saved PASS label.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SCHEMA = "syntriass.teaching-review/v1"
FILES = ("session.stdout", "task.json", "answers.json", "suite.json", "example-map.json",
         "expert-public.json", "draft.json", "questions.json", "answered.json",
         "proposed-record.json", "scoreboard.json", "bound-capability.json",
         "example-cases.jsonl", "native-examples.stdout", "native-scoreboard.stdout")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(root, name):
    # Fixed inventory only; reject aliases, links and escapes before reading.
    path = root / name
    require(not path.is_symlink() and not path.parent.is_symlink(), "linked review input refused")
    require(path.resolve().is_relative_to(root.resolve()), "review input escapes bundle")
    raw = path.read_bytes()
    require(len(raw) <= 4 * 1024 * 1024, "review input exceeds 4 MiB")
    return raw


def prepare(root, report):
    """Called only after fresh score() replay; no approval key or state writes."""
    from score_teaching_session import parse
    require(report["status"] == "PASS_SESSION_AND_SUITE" and report["exit_status"] == 0,
            "review requires passing signed suite and reviewed examples")
    validation, examples = report["validation"], report["examples"]
    require(all(validation[k] is True for k in ("passed", "suite_signature_ok", "suite_independent")),
            "review requires independent signed validation")
    require(examples["status"] == "PASSED" and examples["passed"] == examples["total"] > 0
            and examples["withheld"] == 0 and all(c["passed"] is True for c in examples["cases"]),
            "review contains failed or withheld examples")
    session = parse(read(root, "session.stdout"))
    document = session["document"]
    require(isinstance(document, str) and document == Path(document).name and document not in (".", ".."),
            "invalid source filename")
    source_name = "source/" + document
    files = {name: digest(read(root, name)) for name in (*FILES, source_name)}
    require(files[source_name] == report["source_sha256"] == session["document_sha256"], "source digest mismatch")
    require(all(files[name] == expected for name, expected in report["input_sha256"].items()), "input digest mismatch")
    require(files["example-map.json"] == report["example_map_sha256"], "example map digest mismatch")
    rec = parse(read(root, "proposed-record.json"))
    cap = rec["capability"]
    require(rec["capability_hash"] == report["capability_hash"] == validation["capability_hash"], "capability binding mismatch")
    require(cap["required"]["tenant"] == report["tenant"] == session["tenant"], "review tenant mismatch")
    require(rec["state"] == "PROPOSED" and rec["approval"] is None, "review must not activate or approve")
    payload = {"schema": SCHEMA, "session_id": report["session_id"], "session_task": report["session_task"],
               "tenant": report["tenant"], "capability_id": cap["id"], "capability_version": cap["version"],
               "capability_hash": report["capability_hash"], "required": cap["required"],
               "source_file": source_name, "source_sha256": report["source_sha256"],
               "validation": validation, "examples": examples, "binary_sha256": report["binary_sha256"],
               "files": files, "authority": "UNSIGNED_REVIEW_REQUIRES_EXPERT_APPROVAL"}
    raw = canonical(payload)
    (root / "teaching-review.json").write_bytes(raw)
    return digest(b"syntriass.teaching-review/v1\n" + raw)


def verify(root, expected_digest):
    from score_teaching_session import parse
    require(isinstance(expected_digest, str) and len(expected_digest) == 64
            and all(c in "0123456789abcdef" for c in expected_digest), "invalid external review digest")
    raw = read(root, "teaching-review.json")
    require(digest(b"syntriass.teaching-review/v1\n" + raw) == expected_digest, "review commitment mismatch")
    payload = parse(raw)
    require(payload["schema"] == SCHEMA and canonical(payload) == raw, "unsupported or noncanonical review")
    source = payload["source_file"]
    require(isinstance(source, str) and source.startswith("source/") and len(Path(source).parts) == 2
            and Path(source).name not in (".", ".."), "invalid source inventory")
    require(set(payload["files"]) == {*FILES, source}, "incomplete review inventory")
    for name, expected in payload["files"].items():
        require(digest(read(root, name)) == expected, "review input changed: " + name)
    require(payload["authority"] == "UNSIGNED_REVIEW_REQUIRES_EXPERT_APPROVAL", "not an approval format")
    return {"status": "UNSIGNED_REVIEW_INTEGRITY_VERIFIED", "review_sha256": expected_digest,
            "expert_identity_verified": False, "activation_authorized": False,
            "limitation": "Pinned-byte integrity only; fresh native replay and expert signature remain separate gates."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--expected-digest", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.folder, args.expected_digest)))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "REFUSED", "error": str(error)}))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
