import json
import unittest
from soc import pipeline
from soc.agent.tools import ToolBox
from tests.helpers import fresh_run


class TestPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = fresh_run()
        cls.rt = pipeline.build_runtime(cls.ws)

    def inc(self, scenario, key):
        for i in self.rt.db.incidents():
            if i["scenario"] == scenario and (i["src_ip"] == key or key in i["title"] or i["host"] == key):
                return i
        self.fail(f"incident introuvable : {scenario} {key}")

    def decs(self, iid):
        return {(d["action"], d["status"]) for d in self.rt.db.decisions(iid)}

    def test_twelve_incidents(self):
        self.assertEqual(len(self.rt.db.incidents()), 12)

    def test_ssh_simple_is_auto_blocked_and_verified(self):
        i = self.inc("ssh_bruteforce", "198.51.100.23")
        self.assertEqual(i["verdict"], "menace confirmée")
        self.assertIn(("block_ip", "executed"), self.decs(i["id"]))
        self.assertTrue(all(a["verified"] for a in self.rt.db.actions(i["id"])))
        self.assertIn("198.51.100.23", self.rt.executor.state()["blocked"])

    def test_compromise_needs_human_and_is_critical(self):
        i = self.inc("ssh_bruteforce", "203.0.113.77")
        self.assertEqual(i["severity"], "critical")
        self.assertIn(("block_ip", "pending_approval"), self.decs(i["id"]))
        self.assertNotIn("203.0.113.77", self.rt.executor.state()["blocked"])

    def test_agent_adapts_path_to_observations(self):
        """Chemins différents selon l'incident : post_login seulement en cas de succès après échecs."""
        tools = lambda iid: [s["tool"] for s in self.rt.db.steps(iid) if s["kind"] == "action"]
        self.assertIn("search_logs", tools(self.inc("ssh_bruteforce", "203.0.113.77")["id"]))
        self.assertNotIn("search_logs", tools(self.inc("ssh_bruteforce", "198.51.100.23")["id"]))
        self.assertEqual(tools(self.inc("malicious_file", "/tmp/invoice_2026.pdf.exe")["id"]), ["inspect_file_hash", "check_local_ioc"])

    def test_multi_stage_correlation_on_scan(self):
        i = self.inc("port_scan", "203.0.113.77")
        self.assertIn("h.multi_stage", json.loads(i["hypotheses"]))

    def test_false_positives_closed(self):
        for sc, key in (("ssh_bruteforce", "10.0.0.45"), ("web_sqli", "10.0.0.60")):
            i = self.inc(sc, key)
            self.assertTrue(i["verdict"].startswith("bénin"))
            self.assertEqual(self.rt.db.decisions(i["id"]), [])

    def test_malicious_file_quarantined_unknown_file_notified(self):
        i = self.inc("malicious_file", "/tmp/invoice_2026.pdf.exe")
        self.assertIn(("quarantine_file", "executed"), self.decs(i["id"]))
        self.assertFalse((self.ws.sandbox / "tmp/invoice_2026.pdf.exe").exists())
        j = self.inc("malicious_file", "/tmp/update.sh")
        self.assertEqual({a for a, _ in self.decs(j["id"])}, {"notify_analyst", "monitor"})
        self.assertTrue((self.ws.sandbox / "tmp/update.sh").exists())     # pas de quarantaine sans hash connu

    def test_ransomware_isolation_needs_human(self):
        i = self.inc("malicious_file", "srv-files")
        self.assertEqual(i["severity"], "critical")
        self.assertIn(("isolate_host", "pending_approval"), self.decs(i["id"]))

    def test_every_incident_has_report_and_audit(self):
        for i in self.rt.db.incidents():
            self.assertTrue((self.ws.reports / f"{i['id']}.md").exists())
            self.assertTrue(self.rt.db.audit_log(i["id"]))
            self.assertTrue(self.rt.db.evidence(i["id"]) or i["verdict"] != "")

    def test_agent_cannot_call_action_tool_during_investigation(self):
        r = self.rt.toolbox.call("execute_authorized_action", _role="investigation", action="block_ip", target="9.9.9.9")
        self.assertFalse(r.ok)
        self.assertEqual(r.error, "permission")

    def test_tool_failure_is_handled(self):
        r = self.rt.toolbox.call("inspect_file_hash", path="/tmp/inexistant.exe")
        self.assertFalse(r.ok)


class TestApprovalFlow(unittest.TestCase):
    def test_approve_reject_rollback(self):
        ws = fresh_run()
        rt = pipeline.build_runtime(ws)
        pend = rt.db.pending()
        self.assertEqual(len(pend), 3)
        block = [d for d in pend if d["action"] == "block_ip"]
        iso = [d for d in pend if d["action"] == "isolate_host"][0]
        pipeline.approve(rt, block[0]["id"])
        self.assertIn("203.0.113.77", rt.executor.state()["blocked"])
        pipeline.approve(rt, block[1]["id"])                          # idempotent : déjà bloquée
        pipeline.reject(rt, iso["id"])
        self.assertEqual(rt.db.decision(iso["id"])["status"], "rejected")
        self.assertNotIn("srv-files", rt.executor.state()["isolated_hosts"])
        aid = rt.db.actions(block[0]["incident_id"])[-1]["id"]
        pipeline.rollback(rt, aid)
        self.assertNotIn("203.0.113.77", rt.executor.state()["blocked"])
        self.assertEqual(rt.db.pending(), [])


class TestAutonomyLevels(unittest.TestCase):
    def test_level1_never_executes(self):
        rt = pipeline.build_runtime(fresh_run(1))
        self.assertEqual(rt.executor.state()["blocked"], {})
        self.assertTrue(all(d["status"] == "proposed" for d in rt.db.decisions()))

    def test_level2_everything_pending(self):
        rt = pipeline.build_runtime(fresh_run(2))
        self.assertEqual(rt.executor.state()["blocked"], {})
        self.assertTrue(all(d["status"] == "pending_approval" for d in rt.db.decisions()))


if __name__ == "__main__":
    unittest.main()
