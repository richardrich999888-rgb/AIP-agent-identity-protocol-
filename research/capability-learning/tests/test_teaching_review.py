"""Fresh replay commitments are unsigned prerequisites, never activation grants."""
import json
import subprocess

import pytest

import test_example_mapping as fixtures
import score_teaching_session as T
import teaching_review as V

case, template = fixtures.case, fixtures.template


def passing(case):
    _, args = case
    fixtures.review(args)
    result = T.score(**args)
    assert result["status"] == "PASS_SESSION_AND_SUITE", result
    return args, result


def test_fresh_review_binds_inputs_and_verifies_in_separate_process(case):
    root, _ = case
    before = {str(p): p.read_bytes() for p in (root / "state").rglob("*") if p.is_file()}
    args, result = passing(case)
    digest = result["teaching_review_sha256"]
    review = T.parse((args["out"] / "teaching-review.json").read_bytes())
    assert review["source_sha256"] == result["source_sha256"]
    assert review["files"]["example-map.json"] == result["example_map_sha256"]
    assert review["validation"]["expert_passed"] == 12
    assert review["examples"]["passed"] == 3
    import sys
    p = subprocess.run([sys.executable, V.__file__, str(args["out"]), "--expected-digest", digest], capture_output=True)
    assert p.returncode == 0, p.stderr
    verified = json.loads(p.stdout)
    assert not verified["activation_authorized"] and not verified["expert_identity_verified"]
    assert {str(p): p.read_bytes() for p in (root / "state").rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("file", [*V.FILES, "source", "teaching-review.json"])
def test_every_bound_file_modification_rejects(case, file):
    args, result = passing(case)
    if file == "source":
        file = T.parse((args["out"] / "teaching-review.json").read_bytes())["source_file"]
    p = args["out"] / file
    p.write_bytes(p.read_bytes() + b" ")
    with pytest.raises(ValueError, match="changed|commitment"):
        V.verify(args["out"], result["teaching_review_sha256"])


@pytest.mark.parametrize("attack", ["wrong-pin", "missing-file", "symlink", "forged-pass"])
def test_untrusted_artifacts_do_not_authorize(case, attack):
    args, result = passing(case)
    pin = result["teaching_review_sha256"]
    if attack == "wrong-pin": pin = "0" * 64
    elif attack == "missing-file": (args["out"] / "suite.json").unlink()
    elif attack == "symlink":
        p = args["out"] / "suite.json"
        outside = args["out"].parent / "outside.json"
        outside.write_bytes(p.read_bytes()); p.unlink(); p.symlink_to(outside)
    else:
        p = args["out"] / "teaching-review.json"
        payload = T.parse(p.read_bytes()); payload["authority"] = "APPROVED"
        p.write_bytes(V.canonical(payload))
        pin = V.digest(b"syntriass.teaching-review/v1\n" + p.read_bytes())
    with pytest.raises((ValueError, OSError)):
        V.verify(args["out"], pin)


@pytest.mark.parametrize("failure", ["missing-map", "failed-suite", "failed-examples", "changed-source"])
def test_unsuccessful_replay_never_emits_review(case, failure):
    root, args = case
    if failure == "failed-suite": args["answers"] = root / "control.json"
    if failure != "missing-map": fixtures.review(args)
    if failure == "failed-examples":
        fixtures.edit(args["example_map"], lambda x: x["outcomes"].update(ACCEPT="not_allowed"))
    if failure == "changed-source": args["document"].write_bytes(args["document"].read_bytes() + b"Changed")
    result = T.score(**args)
    assert result["status"] != "PASS_SESSION_AND_SUITE"
    assert "teaching_review_sha256" not in result
    assert not (args["out"] / "teaching-review.json").exists()


def test_new_replay_does_not_trust_previously_saved_pass(case):
    args, result = passing(case)
    # A mutable saved result cannot change the bytes that the caller pinned.
    saved = args["out"] / "result.json"
    fake = T.parse(saved.read_bytes()); fake["approval_performed"] = True
    T.write(saved, fake)
    checked = V.verify(args["out"], result["teaching_review_sha256"])
    assert not checked["activation_authorized"]
    args["out"] = args["out"].with_name("fresh")
    fixtures.edit(args["answers"], lambda x: x.update(schema="forged"))
    # Schema may be checked by the answer processor; a changed binding must fail regardless.
    result = T.score(**args)
    assert result["status"] == "REFUSED"
    assert not (args["out"] / "teaching-review.json").exists()
