#!/usr/bin/env python3
"""Verify original synthetic lifecycle signatures using Python cryptography.

Authenticate archive and trust pins separately. This checks v1 and v2 approval
and suite bytes/bindings and pinned v2 authority grants, not unsigned history, current revocation,
expert credentials, observation or full C2 acceptance. Stage cryptography first.
"""
import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(value):
    # Original Rust pretty-JSON retains struct field order and sorted BTreeMaps.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verify(root, trust):
    results = []
    worlds = sorted(p.parent for p in root.glob("*/public.json"))
    require(bool(worlds) and {p.name for p in worlds} == set(trust), "missing or additional world/trust pins")
    for world in worlds:
        public = {k:v for k,v in trust[world.name].items() if k != "authority_grants"}
        require(json.loads((world / "public.json").read_text()) == public, "public material differs from selected pins")
        suites = {}
        for suite in json.loads((world / "suites.json").read_text()):
            body = {k: suite[k] for k in ("suite_id", "tenant", "task", "expert_id", "cases")}
            signed = b"syntriass-expert-suite/v1\n" + canonical(body)
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public["experts"][suite["expert_id"]]))
            key.verify(bytes.fromhex(suite["signature_hex"]), signed)
            suites[digest(signed)] = suite
        signed_records = set()
        files = sorted(world.glob("snapshot-*/*.json"))
        require(bool(files), "no retained original records")
        for path in files:
            rec = json.loads(path.read_text())
            cap_hash = digest(canonical(rec["capability"]))
            require(cap_hash == rec["capability_hash"], "capability hash mismatch")
            approval = rec["approval"]
            if approval is None:
                require(rec["state"] in ("PROPOSED", "VALIDATED"),
                        "fixture has an executable or validated record without approval")
                continue
            report = rec["validation"]
            require(report["passed"] and report["suite_signature_ok"] and report["suite_independent"], "failed validation")
            require(report["capability_hash"] == approval["capability_hash"] == cap_hash, "wrong approved capability")
            require(approval["validation_report_hash"] == digest(canonical(report)), "changed validation report")
            suite = suites[report["suite_hash"]]
            require(suite["tenant"] == rec["capability"]["required"]["tenant"], "wrong suite tenant")
            require(suite["expert_id"] == report["suite_expert"], "wrong suite expert")
            require(approval["approver_id"] != rec["capability"]["proposed_by"], "self-approval")
            signed = ("syntriass-capability-approval/v1\n" + cap_hash + "\n" + approval["validation_report_hash"]
                      + "\n" + approval["approver_id"] + "\n" + json.dumps(approval["consequential"])
                      + "\n" + str(approval["decided_at_ms"])).encode()
            if approval.get("authority_hash") is not None:
                grant = trust[world.name]["authority_grants"][approval["authority_hash"]]
                fields = ("expert_id", "public_key_sha256", "tenant", "security_domain", "capability_ids", "min_version", "max_version", "max_clearance", "valid_from_ms", "expires_at_ms", "revoked")
                ordered = {k: grant[k] for k in fields}
                require(digest(b"syntriass-approval-authority/v1\n" + canonical(ordered)) == approval["authority_hash"], "changed authority grant")
                require(grant["expert_id"] == approval["approver_id"], "wrong authority identity")
                require(grant["public_key_sha256"] == digest(bytes.fromhex(public["approvers"][approval["approver_id"]])), "wrong authority key")
                cap = rec["capability"]
                require(grant["tenant"] == cap["required"]["tenant"] and grant["security_domain"] == cap["required"]["security_domain"], "wrong authority tenant/domain")
                require(cap["id"] in grant["capability_ids"] and grant["min_version"] <= cap["version"] <= grant["max_version"], "outside authority scope/version")
                require(not grant["revoked"] and grant["valid_from_ms"] <= approval["decided_at_ms"] < grant["expires_at_ms"], "invalid decision-time authority")
                ranks = {"public": 0, "internal": 1, "restricted": 2, "secret": 3}
                require(ranks[cap["required"]["min_clearance"]] <= ranks[grant["max_clearance"]], "outside authority clearance")
                signed = b"syntriass-capability-approval/v2\n" + canonical([cap_hash, approval["validation_report_hash"], approval["approver_id"], approval["consequential"], approval["decided_at_ms"], approval["authority_hash"]])
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public["approvers"][approval["approver_id"]]))
            key.verify(bytes.fromhex(approval["signature_hex"]), signed)
            signed_records.add(cap_hash)
        results.append({"test": public["test"], "test_panicked": public["test_panicked"],
                        "world": world.name, "unique_approved_capabilities": len(signed_records),
                        "unique_signed_suites": len(suites), "snapshot_files": len(files)})
    return {"result": "ORIGINAL_SYNTHETIC_SIGNATURES_VERIFIED", "worlds": results,
            "lifecycle_history_authenticated": False, "teaching_authority_qualified": False}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("folder", type=Path)
    ap.add_argument("--trusted-pins", type=Path, required=True)
    a = ap.parse_args()
    try:
        print(json.dumps(verify(a.folder, json.loads(a.trusted_pins.read_text())), indent=2))
    except Exception as error:
        print("REFUSED: " + type(error).__name__ + ": " + str(error))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
