"""Unit tests for orphan (pure)."""

import unittest

import orphan as o


def ag(parent=None, owner="alice"):
    return {"parent": parent, "owner": owner}


AGENTS = {"orch": ag(), "child": ag("orch"), "grand": ag("child"), "pay": ag("orch", owner="bob")}
GRANTS = {"orch": "g-root", "child": "g-child", "grand": "g-grand", "pay": "g-pay"}
PEOPLE = {"alice", "bob"}


def st(revoked=(), principals=PEOPLE, agents=AGENTS, grants=GRANTS):
    return {k: v.status for k, v in o.classify(agents, grants, revoked, principals).items()}


class Orphan(unittest.TestCase):
    def test_all_active(self):
        self.assertEqual(set(st().values()), {o.ACTIVE})

    def test_revoking_child_orphans_grandchild_only(self):
        s = st({"g-child"})
        self.assertEqual((s["orch"], s["child"], s["grand"], s["pay"]), (o.ACTIVE, o.REVOKED, o.ORPHANED, o.ACTIVE))

    def test_revoking_root_orphans_every_descendant(self):
        s = st({"g-root"})
        self.assertEqual((s["orch"], s["child"], s["grand"], s["pay"]), (o.REVOKED, o.ORPHANED, o.ORPHANED, o.ORPHANED))

    def test_orphan_names_the_nearest_revoked_ancestor(self):
        f = o.classify(AGENTS, GRANTS, {"g-root", "g-child"}, PEOPLE)["grand"].findings
        self.assertEqual(f, ("ORPHANED: ancestor child revoked",))

    def test_own_revocation_wins_over_orphan(self):
        r = o.classify(AGENTS, GRANTS, {"g-root", "g-grand"}, PEOPLE)["grand"]
        self.assertEqual((r.status, r.enforcement), (o.REVOKED, "PREVENTION"))
        self.assertFalse(any(x.startswith("ORPHANED") for x in r.findings))

    def test_owner_removed_is_unknown_owner_advisory(self):
        r = o.classify(AGENTS, GRANTS, set(), {"alice"})["pay"]
        self.assertEqual((r.status, r.enforcement), (o.UNKNOWN_OWNER, "ADVISORY"))

    def test_orphaned_and_unknown_owner_both_reported(self):
        r = o.classify(AGENTS, GRANTS, {"g-root"}, {"alice"})["pay"]
        self.assertEqual(r.status, o.ORPHANED)
        self.assertEqual(len(r.findings), 2)

    def test_missing_grant_is_unknown_authority_never_active(self):
        g = {k: v for k, v in GRANTS.items() if k != "child"}
        s = st(grants=g)
        self.assertEqual((s["child"], s["grand"], s["orch"]), (o.UNKNOWN_AUTHORITY, o.UNKNOWN_AUTHORITY, o.ACTIVE))

    def test_cycle_is_invalid_lineage(self):
        a = {"x": ag("y"), "y": ag("x")}
        s = st(agents=a, grants={"x": "1", "y": "2"})
        self.assertEqual(s, {"x": o.INVALID_LINEAGE, "y": o.INVALID_LINEAGE})

    def test_authority_chain_is_root_first(self):
        self.assertEqual(o.authority_chain(AGENTS, GRANTS, "grand"), ["g-root", "g-child", "g-grand"])
        self.assertEqual(o.lineage(AGENTS, "grand"), ("orch", "child", "grand"))

    def test_authority_chain_missing_grant_raises(self):
        with self.assertRaises(KeyError):
            o.authority_chain(AGENTS, {"orch": "g"}, "child")


if __name__ == "__main__":
    unittest.main()
