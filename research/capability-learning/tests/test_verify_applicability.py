"""Real Rust signatures + OpenSSL verification + native outcome replay."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

HARNESS = Path(__file__).resolve().parents[1] / "harness"
sys.path.insert(0, str(HARNESS))
import verify_applicability as V  # noqa: E402


@pytest.fixture(scope="module")
def recorded(tmp_path_factory):
    binary = Path(os.environ.get("SYNTRIASS_BIN", HARNESS.parents[2] / "target/debug/syntriass")).resolve()
    assert binary.is_file(), "build syntriass before replay acceptance; missing is not skipped"
    root = tmp_path_factory.mktemp("replay-original")
    evidence = root / "evidence"
    run = subprocess.run([sys.executable, str(HARNESS / "record_exclusion_policy.py"),
                          "--binary", str(binary), "--out", str(evidence)],
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stdout + run.stderr
    suite = V.read_json(evidence / "explicit-forms-validation/suite.json")
    trust = {k: suite[k] for k in ("tenant", "task", "expert_id")}
    trust.update(public_key_hex=V.read_json(evidence / "expert-public.json")[suite["expert_id"]],
                 capability_sha256=V.digest((evidence / "explicit-forms-validation/capability.json").read_bytes()),
                 binary_sha256=V.digest(binary.read_bytes()))
    return evidence, trust, binary


@pytest.fixture
def packet(recorded, tmp_path):
    evidence, trust, binary = recorded
    dest = tmp_path / "copy"
    shutil.copytree(evidence, dest)
    return dest, copy.deepcopy(trust), binary, tmp_path / "replay"


def test_original_signed_cases_recompute_without_scoreboards(packet):
    evidence, trust, binary, out = packet
    for path in list(evidence.rglob("scoreboard.json")) + [evidence / "result.json"]:
        path.unlink()
    report = V.verify(evidence, trust, binary, out)
    assert [s["passed"] for s in report["suites"]] == [12, 26]
    assert report["frozen_nonactivation_passed"] == 6
    assert report["activation_performed"] is False
    assert report["expert_identity_verified"] is False


@pytest.mark.parametrize("field", ["tenant", "task", "expert_id", "public_key_hex", "binary_sha256", "capability_sha256"])
def test_wrong_external_trust_is_rejected(packet, field):
    evidence, trust, binary, out = packet
    trust[field] = "00" * 32 if field.endswith(("sha256", "hex")) else "untrusted-other"
    with pytest.raises(V.Rejected):
        V.verify(evidence, trust, binary, out)


@pytest.mark.parametrize("mutation", ["signature", "label", "delete", "duplicate", "reorder", "tenant", "missing"])
def test_changed_signed_or_frozen_suite_is_rejected(packet, mutation):
    evidence, trust, binary, out = packet
    path = evidence / "explicit-forms-validation/suite.json"
    s = V.read_json(path)
    if mutation == "signature":
        value = bytearray.fromhex(s["signature_hex"])
        value[0] ^= 1
        s["signature_hex"] = value.hex()
    elif mutation == "label":
        s["cases"][0]["expected"] = "INSUFFICIENT_INPUT"
    elif mutation == "delete":
        s["cases"].pop()
    elif mutation == "duplicate":
        s["cases"][-1] = copy.deepcopy(s["cases"][0])
    elif mutation == "reorder":
        s["cases"].reverse()
    elif mutation == "tenant":
        s["tenant"] = "cross-tenant"
    path.write_text(json.dumps(s))
    if mutation == "missing":
        path.unlink()
    with pytest.raises((V.Rejected, FileNotFoundError)):
        V.verify(evidence, trust, binary, out)


def test_modified_capability_is_rejected_before_replay(packet):
    evidence, trust, binary, out = packet
    path = evidence / "explicit-forms-validation/capability.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(V.Rejected, match="capability hash mismatch"):
        V.verify(evidence, trust, binary, out)


def test_forged_pass_summary_cannot_hide_bad_applicability(packet):
    evidence, trust, binary, out = packet
    for label in V.CASES:
        path = evidence / label / "capability.json"
        cap = V.read_json(path)
        cap["applicability"]["any_terms"].append("V")
        path.write_text(json.dumps(cap))
        (evidence / label / "scoreboard.json").write_text('{"passed":true,"failures":[]}')
    # Deliberately trust the mutant bytes to exercise the behavioral gate,
    # beyond the separate changed-byte rejection test above.
    trust["capability_sha256"] = V.digest(path.read_bytes())
    (evidence / "result.json").write_text('{"result":"PASS_BOUNDED_B3"}')
    with pytest.raises(V.Rejected, match="outcome mismatch: fa-3"):
        V.verify(evidence, trust, binary, out)


def test_duplicate_json_fields_are_rejected(packet):
    evidence, trust, binary, out = packet
    path = evidence / "explicit-forms-validation/suite.json"
    path.write_text('{"cases":[],"cases":[]}')
    with pytest.raises(V.Rejected, match="duplicate JSON field"):
        V.verify(evidence, trust, binary, out)


def test_existing_output_is_preserved(packet):
    evidence, trust, binary, out = packet
    out.mkdir()
    (out / "original").write_text("retain")
    with pytest.raises(FileExistsError):
        V.verify(evidence, trust, binary, out)
    assert (out / "original").read_text() == "retain"


def test_missing_signature_engine_is_not_a_pass(packet):
    evidence, trust, binary, out = packet
    with pytest.raises(V.Rejected, match="OpenSSL is required"):
        V.verify(evidence, trust, binary, out, openssl=str(out.parent / "absent-openssl"))


@pytest.mark.parametrize("fault", ["zero", "duplicate", "wrong_id"])
def test_success_exit_without_exact_native_results_is_rejected(packet, fault):
    evidence, trust, _, out = packet
    binary = out.parent / "fake-cli"
    binary.write_text(f"#!{sys.executable}\n" +
                      "import json,sys\nfrom pathlib import Path\n" +
                      "cases=[json.loads(x) for x in Path(sys.argv[-1]).read_text().splitlines()]\n" +
                      "rows=[{'id':x['id'],'expected':x['label'],'got':x['label']} for x in cases]\n" +
                      {"zero": "rows=[]\n", "duplicate": "rows.append(rows[-1])\n",
                       "wrong_id": "rows[0]['id']='different'\n"}[fault] +
                      "for row in rows: print(json.dumps(row))\n")
    binary.chmod(0o700)
    trust["binary_sha256"] = V.digest(binary.read_bytes())
    with pytest.raises(V.Rejected, match="native replay"):
        V.verify(evidence, trust, binary, out)
