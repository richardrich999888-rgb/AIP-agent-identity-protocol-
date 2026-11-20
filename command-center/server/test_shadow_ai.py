"""Unit tests for shadow_ai (pure; synthetic events shaped like the probe's v13 output)."""

import unittest

import shadow_ai as s

LO = list(s.ipv4("127.0.0.1"))
MODEL = {s.Endpoint(tuple(LO), 8900)}


def sock(pid, old, new, lport, rport, seq=1, proto="Tcp"):
    return {"kind": {"SocketState": {"protocol": proto, "local": {"addr": LO, "is_v6": False, "port": lport},
                                     "remote": {"addr": LO, "is_v6": False, "port": rport},
                                     "old_state": old, "new_state": new, "current_pid": pid}},
            "probe_seq": seq, "bound": None}


def spawn(parent, child, comm, ticks):
    return {"kind": {"ProcessSpawn": {"parent_pid": parent, "child_pid": child, "parent_comm": "bash", "child_comm": comm}},
            "bound": {"process": {"pid": child, "pid_start_time_ticks": ticks}}, "probe_seq": 0}


def run(events, registry=frozenset()):
    return {f.pid: f for f in s.classify(s.observe(events), MODEL, set(registry))}


class Classify(unittest.TestCase):
    def test_unregistered_connect_to_model_is_heuristic(self):
        f = run([spawn(1, 100, "python3", 555), sock(100, 7, 2, 0, 8900, seq=9)])[100]
        self.assertEqual((f.classification, f.model_connects, f.attribution_missing_reason, f.evidence_probe_seqs),
                         (s.HEURISTIC, 1, "no registry row", (9,)))
        self.assertFalse(f.pid_reuse_not_excluded)

    def test_registered_identity_is_not_heuristic(self):
        f = run([spawn(1, 100, "agent", 555), sock(100, 7, 2, 0, 8900)], registry={(100, 555)})[100]
        self.assertEqual(f.classification, s.UNCLASSIFIED)

    def test_registry_needs_matching_start_time(self):
        # A reused pid with a different start time is not the registered process.
        f = run([spawn(1, 100, "x", 999), sock(100, 7, 2, 0, 8900)], registry={(100, 555)})[100]
        self.assertEqual(f.classification, s.HEURISTIC)

    def test_unbound_process_says_no_binding(self):
        f = run([sock(200, 7, 2, 0, 8900)])[200]
        self.assertEqual((f.classification, f.attribution_missing_reason, f.pid_reuse_not_excluded),
                         (s.HEURISTIC, "no binding", True))

    def test_other_port_is_unclassified(self):
        self.assertEqual(run([sock(100, 7, 2, 0, 8080)])[100].classification, s.UNCLASSIFIED)

    def test_server_side_and_softirq_transitions_ignored(self):
        # The listener's states, and transitions whose current_pid is whoever was
        # running (softirq on loopback). Their pid is not trustworthy, so they
        # create no process at all, rather than an "observed" one under a wrong pid.
        ev = [sock(300, 7, 10, 8900, 0), sock(300, 10, 3, 8900, 5555), sock(301, 2, 1, 5555, 8900), sock(0, 4, 5, 5555, 8900)]
        self.assertEqual(run(ev), {})

    def test_local_port_match_is_not_a_connect_to_model(self):
        self.assertEqual(run([sock(100, 7, 2, 8900, 4444)])[100].classification, s.UNCLASSIFIED)

    def test_udp_ignored(self):
        self.assertEqual(run([sock(100, 7, 2, 0, 8900, proto="Udp")]), {})

    def test_names_collected_and_malformed_skipped(self):
        ev = [spawn(1, 100, "sort", 5), {"kind": "junk"}, {"kind": {"A": {}, "B": {}}}]
        self.assertEqual(run(ev)[100].names, ("sort",))

    def test_ipv4(self):
        self.assertEqual(s.ipv4("10.0.0.1")[:5], (10, 0, 0, 1, 0))
        for bad in ("1.2.3", "256.0.0.1", "a.b.c.d"):
            with self.assertRaises(ValueError):
                s.ipv4(bad)


if __name__ == "__main__":
    unittest.main()
