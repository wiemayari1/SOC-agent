import tempfile
import unittest
from soc.config import Workspace, load_policy
from soc.response import Executor
from soc.decision import DecisionModule, Proposal
from soc import simulator


class TestExecutor(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(tempfile.mkdtemp())
        simulator.generate(self.ws)
        self.ex = Executor(self.ws, load_policy())

    def test_block_verify_idempotent_rollback(self):
        r = self.ex.execute("block_ip", "1.2.3.4")
        self.assertTrue(r.ok and r.verified)
        self.assertTrue(self.ex.execute("block_ip", "1.2.3.4").already_done)
        self.assertTrue(self.ex.rollback("block_ip", "1.2.3.4").ok)
        self.assertNotIn("1.2.3.4", self.ex.state()["blocked"])

    def test_quarantine_and_restore(self):
        r = self.ex.execute("quarantine_file", "/tmp/invoice_2026.pdf.exe")
        self.assertTrue(r.ok and r.verified)
        self.assertFalse((self.ws.sandbox / "tmp/invoice_2026.pdf.exe").exists())
        self.assertTrue(self.ex.rollback("quarantine_file", "/tmp/invoice_2026.pdf.exe").ok)
        self.assertTrue((self.ws.sandbox / "tmp/invoice_2026.pdf.exe").exists())

    def test_path_traversal_blocked(self):
        with self.assertRaises(PermissionError):
            self.ex.execute("quarantine_file", "/tmp/../../../../etc/passwd")

    def test_missing_file_fails_cleanly(self):
        self.assertFalse(self.ex.execute("quarantine_file", "/tmp/inexistant.exe").ok)


class TestDecision(unittest.TestCase):
    def setUp(self):
        self.dm = DecisionModule(load_policy())

    def p(self, action="block_ip", target="1.2.3.4", sens=False, cf=0.9):
        return Proposal(action, target, sens, cf)

    def test_levels(self):
        self.assertEqual(self.dm.evaluate(self.p(), 1).status, "proposed")
        self.assertEqual(self.dm.evaluate(self.p(), 2).status, "pending_approval")
        self.assertEqual(self.dm.evaluate(self.p(), 3).status, "execute")

    def test_sensitive_and_low_confidence_need_human(self):
        self.assertEqual(self.dm.evaluate(self.p(sens=True), 3).status, "pending_approval")
        self.assertEqual(self.dm.evaluate(self.p(cf=0.4), 3).status, "pending_approval")
        self.assertEqual(self.dm.evaluate(self.p("isolate_host", "srv-files"), 3).status, "pending_approval")

    def test_whitelist_and_protected(self):
        self.assertEqual(self.dm.evaluate(self.p("rm_rf", "/"), 3).status, "denied")
        self.assertEqual(self.dm.evaluate(self.p(target=load_policy()["protected_ips"][0]), 3).status, "denied")


if __name__ == "__main__":
    unittest.main()


class TestWorkspaceReset(unittest.TestCase):
    def test_reset_when_db_cannot_be_deleted(self):
        """Windows : si soc.db est verrouillée (suppression impossible), reset() vide la base au lieu de planter."""
        from pathlib import Path
        from unittest import mock
        from soc import pipeline
        from soc.storage import Database
        ws = Workspace(tempfile.mkdtemp())
        simulator.generate(ws)
        pipeline.run(ws, log=lambda *_: None)
        db = Database(ws.db_path)                       # connexion volontairement laissée ouverte
        self.assertGreater(len(db.incidents()), 0)
        with mock.patch.object(Path, "unlink", side_effect=PermissionError("[WinError 32]")):
            ws.reset()                                  # ne doit pas lever d'exception
        self.assertEqual(db.incidents(), [])
        self.assertEqual(db.pending(), [])
        db.close()
