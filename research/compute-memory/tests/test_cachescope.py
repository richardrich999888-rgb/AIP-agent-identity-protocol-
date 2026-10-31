import os, sys, dataclasses, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cachescope import CacheScope, SlotTable, decide, invalidate

BASE = dict(model_sha256="m", tokenizer_sha256="t", policy_version="p1",
            source_snapshot="s1", principal_scope="ops:plant-a", security_domain="restricted")

def sc(**kw):
    return CacheScope(**{**BASE, **kw})

def test_same_scope_reuses_after_first_use():
    t = SlotTable(1)
    assert decide(t, sc()).reuse_allowed is False
    d = decide(t, sc())
    assert d.reuse_allowed and not d.erase_first

@pytest.mark.parametrize("field", list(BASE))
def test_any_dependency_change_is_a_miss_and_erases(field):
    t = SlotTable(1)
    decide(t, sc())
    d = decide(t, sc(**{field: BASE[field] + "x"}))
    assert d.erase_first and not d.reuse_allowed

def test_key_is_deterministic_and_field_sensitive():
    assert sc().key() == sc().key()
    assert len({sc(**{f: BASE[f] + "x"}).key() for f in BASE} | {sc().key()}) == len(BASE) + 1

def test_no_field_concatenation_collision():
    a = sc(policy_version="ab", source_snapshot="c")
    b = sc(policy_version="a", source_snapshot="bc")
    assert a.key() != b.key()

def test_empty_slot_used_before_eviction_then_lru():
    t = SlotTable(2)
    a, b, c = sc(principal_scope="A"), sc(principal_scope="B"), sc(principal_scope="C")
    assert decide(t, a).slot == 0 and decide(t, b).slot == 1
    decide(t, a)                      # A more recent than B
    d = decide(t, c)
    assert d.slot == 1 and d.erase_first

def test_invalidate_on_snapshot_change():
    t = SlotTable(2)
    old = sc(); decide(t, old)
    assert invalidate(t, lambda k: k == old.key()) == [0]
    d = decide(t, old)
    assert not d.reuse_allowed  # must recompute

@pytest.mark.parametrize("bad", ["", "a\x1fb", "x" * 513])
def test_rejects_invalid_fields(bad):
    with pytest.raises(ValueError):
        sc(principal_scope=bad)

def test_rejects_non_string_and_bad_slot_count():
    with pytest.raises(ValueError):
        sc(principal_scope=None)
    with pytest.raises(ValueError):
        SlotTable(0)
