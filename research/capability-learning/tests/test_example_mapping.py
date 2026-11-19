"""Input-bound binary-label review; real native outcomes, unchanged signed gates."""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

HARNESS = Path(__file__).resolve().parents[1] / "harness"
sys.path.insert(0, str(HARNESS))
import apply_answers as B  # noqa: E402
import draft_from_session as D  # noqa: E402
import example_mapping as M  # noqa: E402
import question_generator as Q  # noqa: E402
import record_answers as RA  # noqa: E402
import record_holdout as H  # noqa: E402
import record_scoreboard as S  # noqa: E402
import score_teaching_session as T  # noqa: E402
import test_session_scoreboard as fixtures  # noqa: E402

case, template = fixtures.case, fixtures.template
edit, load = fixtures.edit, fixtures.load


def review(args):
    first = T.score(**{**args, "out": args["out"].with_name("before-review")})
    assert first["status"] in ("PASS_SIGNED_SUITE", "REJECTED_BY_SUITE"), first
    mapping = {"schema": M.SCHEMA, "bindings": {
        "session_id": first["session_id"], "capability_hash": first["capability_hash"],
        "source_sha256": first["source_sha256"],
        **{n + "_sha256": first["input_sha256"][n + ".json"] for n in ("task", "answers", "suite")}},
        "review": {"who": RA.AUTHOR, "when_ms": 1, "why": "Explicit synthetic example labels, unchanged."},
        "outcomes": copy.deepcopy(H.EXAMPLE_LABELS)}
    args["example_map"] = args["out"].parent / "example-map.json"
    T.write(args["example_map"], mapping)
    return mapping


def test_explicit_review_scores_examples_separately_from_signed_suite(case):
    root, args = case
    review(args)
    before = {str(p): p.read_bytes() for p in (root / "state").rglob("*") if p.is_file()}
    result = T.score(**args)
    assert result["status"] == "PASS_SESSION_AND_SUITE", result
    assert result["examples"]["passed"] == result["examples"]["total"] == 3
    assert result["validation"]["expert_cases"] == result["validation"]["expert_passed"] == 12
    assert result["examples"]["independent_suite_cases_added"] == 0
    assert not result["activation_performed"] and not result["expert_identity_verified"]
    after = {str(p): p.read_bytes() for p in (root / "state").rglob("*") if p.is_file()}
    assert before == after


def test_passing_examples_cannot_overrule_failed_independent_suite(case):
    root, args = case
    args["answers"] = root / "control.json"
    review(args)
    result = T.score(**args)
    assert result["status"] == "REJECTED_BY_SUITE", result
    assert result["examples"]["passed"] == 3 and result["validation"]["expert_passed"] == 11
    assert result["exit_status"] == 3


@pytest.mark.parametrize("mutation", ["wrong_label", "missing_label", "explicitly_withheld"])
def test_examples_fail_without_changing_suite_expectations(case, mutation):
    _, args = case
    review(args)
    def mutate(x):
        if mutation == "wrong_label": x["outcomes"]["ACCEPT"] = "not_allowed"
        elif mutation == "missing_label": del x["outcomes"]["INVALID_TEST"]
        else: x["outcomes"]["INVALID_TEST"] = "withheld"
    edit(args["example_map"], mutate)
    result = T.score(**args)
    assert result["status"] == "REJECTED_BY_EXAMPLES", result
    assert result["exit_status"] == 3 and result["validation"]["expert_passed"] == 12
    assert result["examples"]["passed"] == 2
    assert result["examples"]["withheld"] == (0 if mutation == "wrong_label" else 1)


@pytest.mark.parametrize("field", sorted(M.BINDINGS))
def test_each_input_binding_is_mandatory(case, field):
    _, args = case
    review(args)
    edit(args["example_map"], lambda x: x["bindings"].update({field: "changed"}))
    result = T.score(**args)
    assert result["status"] == "REFUSED" and "bindings" in result["error"], result


@pytest.mark.parametrize("attack", ["version", "unknown_field", "unknown_reviewer", "timestamp_bool", "timestamp_negative",
    "blank_reason", "control_reason", "undeclared_outcome", "invalid_label", "missing_input_as_negative", "native_refusal_as_negative",
    "empty_map", "duplicate_json", "nonfinite_json"])
def test_malformed_or_unsafe_mapping_is_refused(case, attack):
    _, args = case
    review(args)
    def mutate(x):
        if attack == "version": x["schema"] = "syntriass.teach-example-map/v999"
        elif attack == "unknown_field": x["approved"] = True
        elif attack == "unknown_reviewer": x["review"]["who"] = "someone:else"
        elif attack == "timestamp_bool": x["review"]["when_ms"] = True
        elif attack == "timestamp_negative": x["review"]["when_ms"] = -1
        elif attack == "blank_reason": x["review"]["why"] = " "
        elif attack == "control_reason": x["review"]["why"] = "hidden\x00reason"
        elif attack == "undeclared_outcome": x["outcomes"]["UNDECLARED"] = "allowed"
        elif attack == "invalid_label": x["outcomes"]["ACCEPT"] = "maybe"
        elif attack == "missing_input_as_negative": x["outcomes"]["INSUFFICIENT_INPUT"] = "not_allowed"
        elif attack == "native_refusal_as_negative": x["outcomes"]["NOT_APPLICABLE"] = "not_allowed"
        elif attack == "empty_map": x["outcomes"] = {}
    edit(args["example_map"], mutate)
    if attack == "duplicate_json": args["example_map"].write_text('{"outcomes":{},"outcomes":{}}')
    if attack == "nonfinite_json": args["example_map"].write_text('{"review":NaN}')
    result = T.score(**args)
    assert result["status"] == "REFUSED" and result["exit_status"] == 2, result
    assert not result["approval_performed"] and not result["activation_performed"]


def new_negative_example(root, args, text):
    examples = [json.loads(x) for x in (root / "examples.jsonl").read_text().splitlines()]
    examples[-1].update(text=text, reason="Adversarial example: a refusal must remain withheld.")
    (root / "examples.jsonl").write_text("".join(json.dumps(x) + "\n" for x in examples))
    started = json.loads(S.run([args["binary"], "teach", "start", "--config", args["config"],
        "--tenant", args["tenant"], "--task", args["session_task"], "--expert", H.EXPERT,
        "--doc", args["document"], "--page", "1", "--clauses", root / "clauses.json",
        "--rule-file", root / "rule.txt", "--examples", root / "examples.jsonl"]).stdout)
    args["session_id"] = started["session_id"]
    session = json.loads(S.run([args["binary"], "teach", "show", "--config", args["config"],
        "--tenant", args["tenant"], "--session", args["session_id"]]).stdout)
    draft = D.draft(session, load(args["task"]))
    edit(args["answers"], lambda x: x.update(session_id=session["session_id"], draft_sha256=B.draft_digest(draft),
        questions_sha256=B.questions_digest(Q.generate(draft, load(args["task"])))))


@pytest.mark.parametrize("text,expected", [
    ("Battery cell B-8: 4 V and 7 mA at 20 C", "NOT_APPLICABLE"),
    ("Distribution transformers TX-14, 11 kV at 20 C", "INSUFFICIENT_INPUT"),
    ("Transformer TX-14, 11 kV: IR 800 megohms at 20 C, DAR 1.6, DAR 1.2", "AMBIGUOUS"),
])
def test_actual_native_refusal_does_not_pass_a_negative_example(case, text, expected):
    root, args = case
    new_negative_example(root, args, text)
    review(args)
    result = T.score(**args)
    assert result["status"] == "REJECTED_BY_EXAMPLES", result
    row = result["examples"]["cases"][-1]
    assert row["native_outcome"] == expected
    assert row["expected"] == "not_allowed" and row["mapped_label"] == "withheld" and row["passed"] is False
    assert result["validation"]["expert_passed"] == 12


@pytest.mark.parametrize("mutation", ["empty", "duplicate", "reorder", "expected", "malformed", "undeclared"])
def test_native_example_replay_cannot_substitute_results(case, mutation):
    _, args = case
    mapping = review(args)
    result = T.score(**args)
    assert result["status"] == "PASS_SESSION_AND_SUITE"
    session = load(args["out"] / "session.stdout")
    cap = load(args["out"] / "bound-capability.json")
    observed = [json.loads(x) for x in (args["out"] / "native-examples.stdout").read_text().splitlines()]
    if mutation == "empty": observed = []
    elif mutation == "duplicate": observed.append(observed[0])
    elif mutation == "reorder": observed.reverse()
    elif mutation == "expected": observed[0]["expected"] = "not_allowed"
    elif mutation == "malformed": observed[0] = []
    elif mutation == "undeclared": observed[0]["got"] = "UNDECLARED"
    with pytest.raises(M.MappingRefused):
        M.evaluate(mapping, mapping["bindings"], session, cap, RA.AUTHOR, observed)


def test_real_cli_accepts_the_explicit_mapping(case):
    _, args = case
    review(args)
    command = [sys.executable, str(HARNESS / "score_teaching_session.py")]
    for name, value in args.items():
        command += ["--" + ("session" if name == "session_id" else name.replace("_", "-")), str(value)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert load(args["out"] / "result.json")["status"] == "PASS_SESSION_AND_SUITE"


@pytest.mark.parametrize("missing", ["NEED_MEASUREMENT", "WAIT_FOR_EVIDENCE"])
def test_missing_input_guard_follows_the_capability_definition(missing):
    bindings = dict.fromkeys(M.BINDINGS, "unit-binding")
    session = {"expert_id": "expert:unit", "examples": [
        {"id": "positive", "text": "complete", "label": "allowed", "reason": "Synthetic positive"},
        {"id": "negative", "text": "incomplete", "label": "not_allowed", "reason": "Synthetic negative"}]}
    cap = {"outcomes": ["ACCEPT", missing], "procedure": {"missing_input_outcome": missing}}
    mapping = {"schema": M.SCHEMA, "bindings": bindings,
               "review": {"who": "expert:unit", "when_ms": 1, "why": "Synthetic unit review"},
               "outcomes": {"ACCEPT": "allowed", missing: "not_allowed"}}
    with pytest.raises(M.MappingRefused, match="missing-input"):
        M.validate(mapping, bindings, session, cap, "expert:unit")
    mapping["outcomes"][missing] = "withheld"
    result = M.evaluate(mapping, bindings, session, cap, "expert:unit", [
        {"id": "positive", "expected": "allowed", "got": "ACCEPT"},
        {"id": "negative", "expected": "not_allowed", "got": missing}])
    assert result["status"] == "FAILED" and result["passed"] == 1 and result["withheld"] == 1
