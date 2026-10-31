import os, sys, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from cascade import Outcome, gate, registered_codes, run_cascade, score

def rec(d, t):
    return {"decision": d, "latency_s": t}

PREDS = {
    "rules_equnit": {"a": rec("ABSTAIN", 0.0), "b": rec("2", 0.0)},
    "enc+gate": {"a": rec("3", 0.05), "b": rec("1", 0.05)},
    "slm+gate": {"a": rec("4", 5.0), "b": rec("2", 5.0)},
}

def test_registered_codes_normalises_aliases():
    assert registered_codes("CP-7 and P7 vib, TX3 oil") == {"p7", "t3"}
    assert registered_codes("P-9 bearing") == set()

def test_r1_uses_rules_when_they_release():
    o = run_cascade("R1", {"id": "b", "text": ""}, PREDS)
    assert o == Outcome("2", 0.0, ("rules",))

def test_r1_falls_back_and_adds_cost():
    o = run_cascade("R1", {"id": "a", "text": ""}, PREDS)
    assert o.decision == "3" and o.cost_s == pytest.approx(0.05)

def test_r2_escalates_only_multi_equipment():
    assert run_cascade("R2", {"id": "a", "text": "P-7 8.1 and V-12 3 bar"}, PREDS).stages == ("slm",)
    assert run_cascade("R2", {"id": "a", "text": "P-7 8.1"}, PREDS).stages == ("enc",)

def test_score_counts_wrong_releases_and_slm_calls():
    items = [{"id": "a", "label": "ABSTAIN"}, {"id": "b", "label": "2"}]
    outs = [Outcome("3", 1.0, ("slm+gate",)), Outcome("2", 1.0, ("rules",))]
    s = score(items, outs)
    assert s["decision_acc"] == 0.5 and s["wrong_release"] == 1 and s["slm_calls"] == 1

def test_gate_abstains_on_unregistered_family_code():
    assert gate(rec("1", 0), "P-9 vibration 9.1")["decision"] == "ABSTAIN"
    assert gate(rec("1", 0), "P-7 vibration 9.1")["decision"] == "1"

def test_unknown_rule_fails_closed():
    with pytest.raises(ValueError):
        run_cascade("R9", {"id": "a", "text": ""}, PREDS)
