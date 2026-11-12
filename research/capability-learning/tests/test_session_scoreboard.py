"""Live native CLI integration; synthetic identities are not expert authentication."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

HARNESS = Path(__file__).resolve().parents[1] / "harness"
sys.path.insert(0, str(HARNESS))
import draft_from_session as D  # noqa: E402
import question_generator as Q  # noqa: E402
import record_answers as RA  # noqa: E402
import record_exclusion_policy as E  # noqa: E402
import record_holdout as H  # noqa: E402
import record_scoreboard as S  # noqa: E402
import record_teach_session as R  # noqa: E402
import score_teaching_session as T  # noqa: E402


@pytest.fixture(scope="module")
def template(tmp_path_factory):
    root = tmp_path_factory.mktemp("session-scoreboard-inputs")
    binary = Path(os.environ.get("SYNTRIASS_BIN", HARNESS.parents[2] / "target/debug/syntriass")).resolve()
    assert binary.is_file(), "build the native CLI; this acceptance test must not skip"
    spec = json.loads(H.TASK.read_text())
    data = S.generate("tx", root / "data")
    session = H.teach(root, data, spec, binary=binary)
    draft = D.draft(session, spec)
    questions = Q.generate(draft, spec)
    answers = RA.answers_file(draft, questions, H.AS_INSTRUCTED, 1)
    T.write(root / "control.json", answers)
    owner, = [q for q in questions["questions"] if q["field_path"] == "scope_exclusion_terms.*"]
    answer, = [a for a in answers["answers"] if a["qid"] == owner["qid"]]
    answer["answer"] += [c["term"] for c in owner["exclusion_word_forms"]]
    answer["why"] = "Select the explicit source-linked alternatives."
    T.write(root / "answers.json", answers)
    T.write(root / "task.json", spec)
    T.write(root / "session.json", session)
    S.run([binary, "keygen", "--id", E.EXPERT, "--out", root / "key.json"])
    public = json.loads((root / "key.json").read_text())["public_hex"]
    cfg = json.loads((root / "config.json").read_text())
    cfg.update(policy_version=spec["policy_version"], security_domain=spec["domain"], experts={E.EXPERT: public})
    T.write(root / "config.json", cfg)
    for name, cases in (("suite", E.rows(data / "validation.jsonl")), ("attacks", E.attacks(data))):
        (root / (name + ".jsonl")).write_text("".join(json.dumps(c) + "\n" for c in cases))
        S.run([binary, "suite-sign", "--key", root / "key.json", "--cases", root / (name + ".jsonl"),
               "--suite-id", "p0-051/" + name, "--tenant", spec["tenant"],
               "--task", spec["intended_task"], "--out", root / (name + ".json")])
    return root, binary


@pytest.fixture
def case(template, tmp_path):
    source, binary = template
    root = tmp_path / "inputs"
    shutil.copytree(source, root)
    cfg = json.loads((root / "config.json").read_text())
    cfg["state"] = str(root / "state")
    T.write(root / "config.json", cfg)
    session = json.loads((root / "session.json").read_text())
    args = dict(binary=binary, config=root / "config.json", tenant=session["tenant"],
                session_id=session["session_id"], session_task=session["task"], task=root / "task.json",
                answers=root / "answers.json", document=root / "data/corpus/halvorn-hu-tx-2.txt",
                suite=root / "suite.json", out=tmp_path / "score")
    return root, args


def load(path):
    return json.loads(path.read_text())


def edit(path, mutate):
    value = load(path)
    mutate(value)
    T.write(path, value)


def test_corrected_session_passes_without_touching_lifecycle(case):
    root, args = case
    before = {str(p): p.read_bytes() for p in (root / "state").rglob("*") if p.is_file()}
    result = T.score(**args)
    assert result["status"] == "PASS_SIGNED_SUITE", result
    assert result["validation"]["expert_passed"] == result["validation"]["expert_cases"] == 12
    after = {str(p): p.read_bytes() for p in (root / "state").rglob("*") if p.is_file()}
    assert before == after
    assert stat.S_IMODE(args["out"].stat().st_mode) == 0o700
    assert result["examples"]["status"] == "NOT_MEASURED"
    assert not result["activation_performed"] and not result["expert_identity_verified"]
    board = load(args["out"] / "scoreboard.json")
    assert all(row["session_questions"] == [] for row in board["cases"])


def test_rejected_control_links_the_real_exclusion_question(case):
    root, args = case
    args["answers"] = root / "control.json"
    result = T.score(**args)
    assert result["status"] == "REJECTED_BY_SUITE", result
    assert result["validation"]["expert_passed"] == 11
    board = load(args["out"] / "scoreboard.json")
    failed, = [r for r in board["cases"] if r["id"] == "val-09"]
    owner, = [q for q in load(args["out"] / "questions.json")["questions"] if q["field_path"] == "scope_exclusion_terms.*"]
    link, = [q for q in failed["session_questions"] if q["qid"] == owner["qid"]]
    assert link["citation"] == owner["citation"] and link["quote"] == owner["quote"]
    assert link["edits"] and all(e["qid"] == owner["qid"] for e in link["edits"])
    assert link["relation"] == "field_review_candidate" and not link["root_cause_established"]


def test_all_frozen_attacks_remain_passing(case):
    root, args = case
    args["suite"] = root / "attacks.json"
    result = T.score(**args)
    assert result["status"] == "PASS_SIGNED_SUITE", result
    assert result["validation"]["expert_passed"] == result["validation"]["expert_cases"] == 26
    board = load(args["out"] / "scoreboard.json")
    assert sum(r["id"].startswith("fa-") and r["passed"] for r in board["cases"]) == 6


def test_cli_executes_the_same_flow(case):
    _, args = case
    command = [sys.executable, str(HARNESS / "score_teaching_session.py")]
    for name, value in args.items():
        command += ["--" + ("session" if name == "session_id" else name.replace("_", "-")), str(value)]
    run = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stdout + run.stderr
    assert load(args["out"] / "result.json")["status"] == "PASS_SIGNED_SUITE"


@pytest.mark.parametrize("attack", ["changed_source", "wrong_tenant", "wrong_session_task", "stale_draft",
    "stale_questions", "unknown_question", "missing_answer", "unsupported_number", "forged_signature",
    "changed_label", "suite_tenant", "suite_task", "untrusted_expert", "wrong_key", "same_author",
    "changed_session", "forged_citation", "clearance", "policy", "domain", "duplicate_json", "nonfinite_json", "overflow_json"])
def test_input_and_authority_attacks_fail_closed(case, attack):
    root, args = case
    if attack == "changed_source":
        args["document"].write_bytes(args["document"].read_bytes() + b" ")
    elif attack == "wrong_tenant": args["tenant"] = "other-tenant"
    elif attack == "wrong_session_task": args["session_task"] = "other-task"
    elif attack in ("stale_draft", "stale_questions"):
        edit(args["answers"], lambda x: x.update({"draft_sha256" if attack == "stale_draft" else "questions_sha256": "0" * 64}))
    elif attack == "unknown_question": edit(args["answers"], lambda x: x["answers"][0].update(qid="not-asked"))
    elif attack == "missing_answer": edit(args["answers"], lambda x: x["answers"].pop())
    elif attack == "unsupported_number":
        def number(x):
            a = next(a for a in x["answers"] if a["qid"].endswith("rules[].number") and a["answer"]["against"] == "number")
            a["answer"]["number"] = 987654
        edit(args["answers"], number)
    elif attack == "forged_signature": edit(args["suite"], lambda x: x.update(signature_hex="0" * 128))
    elif attack == "changed_label": edit(args["suite"], lambda x: x["cases"][0].update(expected="FAKE"))
    elif attack == "suite_tenant": edit(args["suite"], lambda x: x.update(tenant="other-tenant"))
    elif attack == "suite_task":
        S.run([args["binary"], "suite-sign", "--key", root / "key.json", "--cases", root / "suite.jsonl",
               "--suite-id", "p0-051/other", "--tenant", args["tenant"], "--task", "different task", "--out", args["suite"]])
    elif attack == "untrusted_expert": edit(args["config"], lambda x: x.update(experts={}))
    elif attack == "wrong_key": edit(args["config"], lambda x: x["experts"].update({E.EXPERT: "00" * 32}))
    elif attack == "same_author":
        edit(root / "key.json", lambda x: x.update(id=RA.AUTHOR))
        edit(args["config"], lambda x: x["experts"].update({RA.AUTHOR: x["experts"][E.EXPERT]}))
        S.run([args["binary"], "suite-sign", "--key", root / "key.json", "--cases", root / "suite.jsonl",
               "--suite-id", "p0-051/self", "--tenant", args["tenant"],
               "--task", load(args["task"])["intended_task"], "--out", args["suite"]])
    elif attack == "changed_session":
        path = root / "state/teach" / args["tenant"] / (args["session_id"] + ".json")
        edit(path, lambda x: x.update(rule="Changed after answers"))
    elif attack == "forged_citation":
        path = root / "state/teach" / args["tenant"] / (args["session_id"] + ".json")
        forged = load(path)
        forged["clauses"][0]["text"] = "x" * len(forged["clauses"][0]["text"])
        forged["session_id"] = T.sha(R.canonical(forged))
        args["session_id"] = forged["session_id"]
        T.write(path.with_name(forged["session_id"] + ".json"), forged)
    elif attack == "clearance": edit(args["task"], lambda x: x.update(clearance="public"))
    elif attack == "policy": edit(args["config"], lambda x: x.update(policy_version="other"))
    elif attack == "domain": edit(args["config"], lambda x: x.update(security_domain="other"))
    elif attack == "duplicate_json": args["answers"].write_text('{"answers":[],"answers":[]}')
    elif attack == "nonfinite_json": args["answers"].write_text('{"number":NaN}')
    elif attack == "overflow_json": args["answers"].write_text('{"number":1e999}')
    result = T.score(**args)
    assert result["status"] in ("REFUSED", "REJECTED_BY_SUITE"), result
    assert result["exit_status"] != 0
    assert not result["activation_performed"] and not result["approval_performed"]
    assert not (root / "state/capabilities").exists()
    if attack == "forged_citation": assert "source span" in result["error"]
    if attack == "same_author": assert "must differ" in result["error"]
    if attack == "suite_task": assert "suite task mismatch" in result["error"]


def test_existing_evidence_is_never_overwritten(case):
    _, args = case
    args["out"].mkdir()
    sentinel = args["out"] / "original"
    sentinel.write_text("retain")
    with pytest.raises(FileExistsError):
        T.score(**args)
    assert sentinel.read_text() == "retain"


@pytest.mark.parametrize("mutation", ["empty", "reordered", "changed_expected", "activated"])
def test_success_exit_cannot_hide_substituted_native_rows(case, mutation):
    _, args = case
    assert T.score(**args)["status"] == "PASS_SIGNED_SUITE"
    board = load(args["out"] / "scoreboard.json")
    if mutation == "empty": board["cases"] = []
    elif mutation == "reordered": board["cases"].reverse()
    elif mutation == "changed_expected": board["cases"][0]["expected"] = "FORGED"
    elif mutation == "activated": board["stored_executable"] = True
    with pytest.raises(T.Refused):
        T.checked_rows(board, load(args["suite"]))


def test_rule_links_distinguish_actual_authorship_from_review_candidates(case):
    _, args = case
    def wrong_reading(x):
        a = next(a for a in x["answers"] if a["qid"].endswith("rules[].value"))
        a["answer"] = "cued_1"
    edit(args["answers"], wrong_reading)
    result = T.score(**args)
    assert result["status"] == "REJECTED_BY_SUITE", result
    board = load(args["out"] / "scoreboard.json")
    links = [q for row in board["cases"] for q in row["session_questions"]]
    assert any(q["relation"] == "fired_rule_author" for q in links)
    assert all(q["root_cause_established"] is False for q in links)
