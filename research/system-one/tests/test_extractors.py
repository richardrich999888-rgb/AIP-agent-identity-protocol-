"""Extractor building blocks: value picker, equipment+unit rule, registry gate."""
from methods import extractors as X


def test_pick_value_single_and_unit_family():
    assert X.pick_value("P-7 vibration is 8.3 now", "p7_vib") == 8.3
    assert X.pick_value("At 14:30 on WO-55821, P-7 vibration read 6.8 mm/s; 3 technicians", "p7_vib") == 6.8
    assert X.pick_value("two numbers 5 and 6 no units", "p7_vib") is None


def test_rules_equnit_requires_exact_code_and_unit():
    assert X.rules_equnit("P-7 vibration 9.1 mm/s") == [("p7_vib", 9.1)]
    assert X.rules_equnit("P-9 vibration 9.1 mm/s") == []
    assert X.rules_equnit("main coolant pump at 7.4 mm/s") == []


def test_gate_flags_unregistered_family_codes_only():
    assert X.unregistered_equipment("P-9 vibration 9.1 mm/s") == ["P-9"]
    assert X.unregistered_equipment("Chiller CH-2 approach 4.2 C") == ["CH-2"]
    assert X.unregistered_equipment("P7 pump vib 7") == []
    assert X.unregistered_equipment("cp-7 gland 20 dpm") == []
    assert X.unregistered_equipment("gen 2 day tank 50") == []
    # Not equipment families: work orders, panels, tags.
    assert X.unregistered_equipment("WO-55821 PNL-12 TI-305 P-7 vib 3") == []
