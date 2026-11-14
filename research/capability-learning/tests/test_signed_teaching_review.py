"""Actual native approval, replay, signature and activation; synthetic experts."""
import hashlib
import json
import subprocess
import os
import shutil
from pathlib import Path

import pytest
import test_teaching_review as F
import score_teaching_session as T
import teaching_review as V

case, template = F.case, F.template


def run(args, command, *extra):
    return subprocess.run([str(args["binary"]), command, "--config", str(args["config"]), *map(str, extra)], capture_output=True)


def ok(result):
    assert result.returncode == 0, result.stderr.decode()
    return json.loads(result.stdout) if result.stdout.strip() else None


def setup(case):
    args, result = F.passing(case)
    root, _ = case
    cap = T.parse((args["out"] / "bound-capability.json").read_bytes())
    ok(run(args, "ingest", args["document"]))
    proposed = ok(run(args, "cap-propose", "--file", args["out"] / "bound-capability.json"))
    assert proposed["hash"] == result["capability_hash"]
    ok(run(args, "cap-validate", "--hash", proposed["hash"], "--suite", args["suite"]))
    keyfile = root / "approval-key.json"
    p = subprocess.run([str(args["binary"]), "keygen", "--id", "expert:approver", "--out", str(keyfile)], capture_output=True)
    assert p.returncode == 0, p.stderr
    key = T.parse(keyfile.read_bytes())
    cfg = T.parse(args["config"].read_bytes())
    cfg["approvers"] = {key["id"]: key["public_hex"]}
    cfg["require_teaching_review"] = True
    cfg["approval_policy"] = {"authorities": {key["id"]: {
        "expert_id": key["id"], "public_key_sha256": hashlib.sha256(bytes.fromhex(key["public_hex"])).hexdigest(),
        "tenant": cap["required"]["tenant"], "security_domain": cap["required"]["security_domain"],
        "capability_ids": [cap["id"]], "min_version": 1, "max_version": cap["version"],
        "max_clearance": cap["required"]["min_clearance"], "valid_from_ms": 1, "expires_at_ms": 2**64-1, "revoked": False}}}
    T.write(args["config"], cfg)
    files = list((root / "state/capabilities").glob("*.json"))
    assert len(files) == 1
    return args, result, keyfile, files[0], cfg


def approve(args, result, key, pin=None):
    return run(args, "cap-approve", "--hash", result["capability_hash"], "--key", key,
               "--review", args["out"], "--review-digest", pin or result["teaching_review_sha256"])


def activate(args, result):
    return run(args, "cap-activate", "--hash", result["capability_hash"], "--actor", "operator", "--reason", "synthetic test")


def test_native_review_approval_signs_exact_digest_and_openssl_verifies(case):
    args, result, key, record, _ = setup(case)
    ok(approve(args, result, key))
    r = T.parse(record.read_bytes()); a = r["approval"]
    assert r["state"] == "APPROVED"
    assert a["teaching_review_hash"] == result["teaching_review_sha256"]
    public = T.parse(key.read_bytes())["public_hex"]
    der = key.parent / "public.der"; sig = key.parent / "signature.bin"; payload = key.parent / "payload.bin"
    der.write_bytes(bytes.fromhex("302a300506032b6570032100" + public))
    sig.write_bytes(bytes.fromhex(a["signature_hex"]))
    fields = [a[k] for k in ("capability_hash", "validation_report_hash", "approver_id", "consequential", "decided_at_ms", "authority_hash", "teaching_review_hash")]
    payload.write_bytes(b"syntriass-capability-approval/v3\n" + json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode())
    verify = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(der), "-keyform", "DER", "-rawin", "-in", str(payload), "-sigfile", str(sig)], capture_output=True)
    assert verify.returncode == 0, verify.stderr
    approved = record.read_bytes()
    bad = key.parent / "tampered-payload.bin"
    bad.write_bytes(payload.read_bytes() + b" ")
    tamper = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(der), "-keyform", "DER", "-rawin", "-in", str(bad), "-sigfile", str(sig)], capture_output=True)
    assert tamper.returncode != 0
    ok(activate(args, result))
    assert T.parse(record.read_bytes())["state"] == "ACTIVE"
    if os.environ.get("SYNTRIASS_TEACH_APPROVAL_EVIDENCE"):
        out = Path(os.environ["SYNTRIASS_TEACH_APPROVAL_EVIDENCE"])
        out.mkdir(parents=True, exist_ok=False)
        shutil.copytree(args["out"], out / "review")
        (out / "approved-record.json").write_bytes(approved)
        (out / "active-record.json").write_bytes(record.read_bytes())
        for file in (der, sig, payload, bad): shutil.copyfile(file, out / file.name)
        T.write(out / "public-trust.json", {"approver_id": "expert:approver", "public_hex": public,
            "approval_policy": T.parse(args["config"].read_bytes())["approval_policy"],
            "review_digest": result["teaching_review_sha256"], "synthetic_identity": True})
        T.write(out / "openssl-results.json", {"original_exit": verify.returncode,
            "original_stdout": verify.stdout.decode(), "tampered_exit": tamper.returncode,
            "tampered_stdout": tamper.stdout.decode(), "activation": "ACTIVE"})


@pytest.mark.parametrize("attack", ["changed-map", "changed-source", "wrong-pin", "missing-session", "wrong-authority", "missing-review", "missing-policy", "stored-report", "forged-pass", "forged-examples", "forged-suite", "wrong-tenant", "forged-count"])
def test_native_approval_rejects_without_record_mutation(case, attack):
    args, result, key, record, cfg = setup(case)
    pin = result["teaching_review_sha256"]
    if attack in ("changed-map", "changed-source"):
        path = args["out"] / ("example-map.json" if attack == "changed-map" else "source/" + args["document"].name)
        path.write_bytes(path.read_bytes() + b" ")
    elif attack == "wrong-pin": pin = "0" * 64
    elif attack == "missing-session":
        for p in (case[0] / "state/teach").rglob("*.json"): p.unlink()
    elif attack == "wrong-authority":
        cfg["approval_policy"]["authorities"]["expert:approver"]["tenant"] = "foreign"
        T.write(args["config"], cfg)
    elif attack == "missing-policy":
        cfg.pop("approval_policy"); T.write(args["config"], cfg)
    elif attack == "stored-report":
        r = T.parse(record.read_bytes()); r["validation"]["expert_cases"] += 1; T.write(record, r)
    elif attack in ("forged-pass", "forged-examples", "forged-suite", "wrong-tenant", "forged-count"):
        # Attacker recomputes a consistent public hash, so integrity alone passes.
        review = T.parse((args["out"] / "teaching-review.json").read_bytes())
        if attack == "forged-pass": review["validation"]["expert_cases"] += 1
        elif attack == "forged-count": review["examples"]["passed"] += 1
        elif attack == "wrong-tenant": review["tenant"] = "foreign"
        elif attack == "forged-suite":
            suite = T.parse((args["out"] / "suite.json").read_bytes())
            suite["signature_hex"] = "0" * 128
            T.write(args["out"] / "suite.json", suite)
            review["files"]["suite.json"] = V.digest((args["out"] / "suite.json").read_bytes())
        else:
            mapping = T.parse((args["out"] / "example-map.json").read_bytes())
            mapping["outcomes"]["ACCEPT"] = "not_allowed"
            T.write(args["out"] / "example-map.json", mapping)
            review["files"]["example-map.json"] = V.digest((args["out"] / "example-map.json").read_bytes())
        raw = V.canonical(review); (args["out"] / "teaching-review.json").write_bytes(raw)
        pin = V.digest(b"syntriass.teaching-review/v1\n" + raw)
        assert V.verify(args["out"], pin)["status"] == "UNSIGNED_REVIEW_INTEGRITY_VERIFIED"
    before = record.read_bytes()
    p = run(args, "cap-approve", "--hash", result["capability_hash"], "--key", key) if attack == "missing-review" else approve(args, result, key, pin)
    assert p.returncode != 0, attack
    assert record.read_bytes() == before, attack


@pytest.mark.parametrize("field", ["teaching_review_hash", "authority_hash", "validation_report_hash"])
def test_signature_cannot_be_stripped_or_rebound(case, field):
    args, result, key, record, _ = setup(case)
    ok(approve(args, result, key))
    r = T.parse(record.read_bytes()); r["approval"].pop(field); T.write(record, r)
    before = record.read_bytes()
    assert activate(args, result).returncode != 0
    assert record.read_bytes() == before


def test_required_review_rejects_legacy_activation(case):
    args, result, key, record, cfg = setup(case)
    cfg["require_teaching_review"] = False; T.write(args["config"], cfg)
    ok(run(args, "cap-approve", "--hash", result["capability_hash"], "--key", key))
    cfg["require_teaching_review"] = True; T.write(args["config"], cfg)
    before = record.read_bytes()
    p = activate(args, result)
    assert p.returncode != 0 and b"signed teaching review required" in p.stderr
    assert record.read_bytes() == before
