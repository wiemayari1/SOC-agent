import unittest
from soc.agent.beliefs import BeliefState, accumulate


def assess(scenario, facts):
    b = BeliefState(scenario)
    b.revise(facts)
    return b, b.assess(facts)


class TestBeliefs(unittest.TestCase):
    def test_accumulate(self):
        self.assertAlmostEqual(accumulate(0.7, 0.6), 0.88)
        self.assertAlmostEqual(accumulate(0.0, 0.5), 0.5)

    def test_no_evidence_without_facts(self):
        _, r = assess("ssh_bruteforce", {})
        self.assertEqual(r.evidence, [])
        self.assertEqual(r.main(), (None, 0.0))

    def test_threshold_not_reached(self):
        _, r = assess("ssh_bruteforce", {"ssh_failed_in_window": 9, "ssh_distinct_users": 1, "ssh_success_after_failures": False})
        self.assertNotIn("h.brute_force_ssh", r.hypotheses)

    def test_earlier_belief_supports_later_one(self):
        """Brute force établie -> connexion réussie -> compromission : une croyance en appelle une autre."""
        _, r = assess("ssh_bruteforce", {"ssh_failed_in_window": 20, "ssh_distinct_users": 2, "ssh_success_after_failures": True})
        ids = [e.id for e in r.evidence]
        self.assertLess(ids.index("EV-SSH-01"), ids.index("EV-SSH-06"))
        self.assertIn("h.account_compromise", r.hypotheses)
        self.assertEqual(r.severity, "critical")
        self.assertTrue(any(x["action"] == "block_ip" and x["sensitive"] for x in r.recommendations))

    def test_evidence_accumulates(self):
        _, r = assess("ssh_bruteforce", {"ssh_failed_in_window": 45, "ssh_distinct_users": 1, "ssh_success_after_failures": False})
        self.assertAlmostEqual(r.hypotheses["h.brute_force_ssh"], 0.88)

    def test_unknown_fact_is_not_false(self):
        """Un fait inconnu (ex. ip_blacklisted) n'est pas pris pour un « non » : la preuve n'est pas retenue."""
        base = {"ssh_failed_in_window": 15, "ssh_distinct_users": 1, "ssh_success_after_failures": False}
        _, r = assess("ssh_bruteforce", base)
        self.assertNotIn("EV-SSH-04", [e.id for e in r.evidence])
        _, r2 = assess("ssh_bruteforce", dict(base, ip_blacklisted=True))
        self.assertIn("EV-SSH-04", [e.id for e in r2.evidence])

    def test_belief_is_revised_after_new_observation(self):
        """L'agent révise sa croyance quand un outil lui apporte un nouveau fait."""
        facts = {"ssh_failed_in_window": 15, "ssh_distinct_users": 1, "ssh_success_after_failures": False}
        b = BeliefState("ssh_bruteforce")
        b.revise(facts)
        before = b.assess(facts).hypotheses["h.brute_force_ssh"]
        facts["ip_blacklisted"] = True
        new = b.revise(facts)
        self.assertEqual([e.id for e in new], ["EV-SSH-04"])
        self.assertGreater(b.assess(facts).hypotheses["h.brute_force_ssh"], before)

    def test_agent_expresses_information_needs(self):
        _, r = assess("port_scan", {"scan_distinct_ports": 20, "scan_sequential_ratio": 1.0})
        self.assertIn("ip_history", r.wanted)

    def test_explanation_lists_evidence(self):
        _, r = assess("port_scan", {"scan_distinct_ports": 20, "scan_sequential_ratio": 1.0})
        self.assertIn("EV-NET-01", r.explain())
        self.assertIn("EV-NET-02", r.explain())

    def test_scenario_filter(self):
        _, r = assess("ssh_bruteforce", {"scan_distinct_ports": 20})
        self.assertEqual(r.evidence, [])

    def test_no_external_knowledge_base(self):
        import importlib.util
        self.assertIsNone(importlib.util.find_spec("soc.expert"))


if __name__ == "__main__":
    unittest.main()
