#!/usr/bin/env python3
"""Verify a v3 review approval using externally selected public key and policy.

Requires OpenSSL and repository Python harness sources, no agent runtime/model.
Policy/key provenance and the host clock remain evaluator responsibilities.
Unsigned lifecycle history is not authenticated by an approval signature.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "research/capability-learning/harness"))
import teaching_review as review
import score_teaching_session as session


def packed(x):
    return json.dumps(x, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def sha(x):
    return hashlib.sha256(x).hexdigest()


def require(ok, why):
    if not ok:
        raise ValueError(why)


def verify(folder, public_key, policy, now):
    record = session.parse((folder / "approved-record.json").read_bytes())
    a = record["approval"]
    cap, validation = record["capability"], record["validation"]
    require(sha(packed(cap)) == record["capability_hash"] == a["capability_hash"], "capability hash mismatch")
    require(validation["passed"] is True and validation["suite_signature_ok"] is True
            and validation["suite_independent"] is True, "failed validation")
    require(validation["capability_hash"] == a["capability_hash"]
            and sha(packed(validation)) == a["validation_report_hash"], "validation binding mismatch")
    require(a["approver_id"] != cap["proposed_by"], "self approval")
    grant = policy["authorities"][a["approver_id"]]
    fields = ("expert_id", "public_key_sha256", "tenant", "security_domain", "capability_ids", "min_version", "max_version", "max_clearance", "valid_from_ms", "expires_at_ms", "revoked")
    grant_bytes = packed({k: grant[k] for k in fields})
    require(sha(b"syntriass-approval-authority/v1\n" + grant_bytes) == a["authority_hash"], "authority policy changed")
    require(grant["expert_id"] == a["approver_id"] and sha(bytes.fromhex(public_key)) == grant["public_key_sha256"], "authority key mismatch")
    require(not grant["revoked"] and grant["valid_from_ms"] <= a["decided_at_ms"] <= now < grant["expires_at_ms"], "authority expired/revoked/not valid")
    require(grant["tenant"] == cap["required"]["tenant"] and grant["security_domain"] == cap["required"]["security_domain"], "authority scope mismatch")
    require(cap["id"] in grant["capability_ids"] and 0 < grant["min_version"] <= cap["version"] <= grant["max_version"], "authority version mismatch")
    ranks = {"public": 0, "internal": 1, "restricted": 2}
    require(ranks[cap["required"]["min_clearance"]] <= ranks[grant["max_clearance"]], "authority clearance mismatch")
    digest = a["teaching_review_hash"]
    review.verify(folder / "review", digest)
    body = session.parse((folder / "review/teaching-review.json").read_bytes())
    require(body["capability_hash"] == a["capability_hash"] and body["tenant"] == cap["required"]["tenant"], "review binding mismatch")
    signed = b"syntriass-capability-approval/v3\n" + packed([a[k] for k in
        ("capability_hash", "validation_report_hash", "approver_id", "consequential", "decided_at_ms", "authority_hash", "teaching_review_hash")])
    with tempfile.TemporaryDirectory() as temp:
        d = Path(temp)
        (d / "public.der").write_bytes(bytes.fromhex("302a300506032b6570032100" + public_key))
        (d / "signature.bin").write_bytes(bytes.fromhex(a["signature_hex"]))
        (d / "payload.bin").write_bytes(signed)
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(d / "public.der"),
            "-keyform", "DER", "-rawin", "-in", str(d / "payload.bin"), "-sigfile", str(d / "signature.bin")], capture_output=True)
        require(result.returncode == 0, "approval signature invalid")
    return {"status": "SIGNED_REVIEW_VERIFIED", "review_digest": digest,
            "lifecycle_history_authenticated": False, "native_replay_reproduced": False}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("folder", type=Path)
    ap.add_argument("--public-key", required=True)
    ap.add_argument("--policy", type=Path, required=True)
    args = ap.parse_args()
    try:
        print(json.dumps(verify(args.folder, args.public_key, session.parse(args.policy.read_bytes()), int(time.time() * 1000))))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(json.dumps({"status": "REFUSED", "error": str(error)}))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
