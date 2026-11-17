import json
import tempfile
import unittest
from datetime import datetime, timedelta

from soc import pipeline
from soc.events import utcnow
from soc.config import Workspace, load_patterns
from soc.live import LiveMonitor, alert_signature
from soc.wazuh import Converter, FileSource, IndexerSource, WazuhError, parse_wazuh_ts
from tests.mock_wazuh import MockIndexer, fim_hit, ssh_fail_hit, ssh_ok_hit, wz_ts


def cfg(url, **kw):
    c = {"mode": "indexer", "poll_seconds": 1, "lookback_minutes": 60, "window_minutes": 60, "settle_seconds": 45, "max_wait_seconds": 300,
         "autonomy_level": 3, "indexer": {"url": url, "user": "admin", "password": "pw", "verify_tls": False, "index_pattern": "wazuh-alerts-*"}}
    c.update(kw)
    return c


class TestConverter(unittest.TestCase):
    def setUp(self):
        self.conv = Converter(load_patterns())

    def test_timestamp_formats(self):
        self.assertEqual(parse_wazuh_ts("2026-11-07T10:15:32.123+0000"), datetime(2026, 11, 7, 10, 15, 32, 123000))
        self.assertEqual(parse_wazuh_ts("2026-11-07T12:15:32.000+0200"), datetime(2026, 11, 7, 10, 15, 32))
        self.assertEqual(parse_wazuh_ts("2026-11-07T10:15:32Z"), datetime(2026, 11, 7, 10, 15, 32))

    def test_ssh_uses_alert_timestamp_and_agent(self):
        dt = datetime(2026, 11, 7, 10, 15, 32)
        ev = self.conv.to_event(ssh_fail_hit(1, dt))
        self.assertEqual((ev.type, ev.src_ip, ev.user, ev.host, ev.ts), ("ssh_failed", "203.0.113.50", "admin", "vm-cible", dt))

    def test_fallback_on_decoded_fields(self):
        h = ssh_fail_hit(1, datetime(2026, 11, 7, 10, 0, 0))
        h["full_log"] = "format journald inattendu"
        self.assertEqual(self.conv.to_event(h).type, "ssh_failed")

    def test_syscheck_events(self):
        dt = datetime(2026, 11, 7, 10, 0, 0)
        e = self.conv.to_event(fim_hit(dt, "/tmp/facture.pdf.exe", "ab" * 32))
        self.assertEqual((e.type, e.details["path"], e.details["sha256"]), ("file_created", "/tmp/facture.pdf.exe", "ab" * 32))
        self.assertEqual(self.conv.to_event(fim_hit(dt, "/home/bob/a.docx.locked", "cd" * 32)).type, "file_renamed")
        self.assertIsNone(self.conv.to_event(fim_hit(dt, "/tmp/x", "ab", event="deleted")))
        self.assertEqual(self.conv.to_event(fim_hit(dt, "C:\\Users\\a\\x.exe", "ab")).details["path"], "C:/Users/a/x.exe")

    def test_unrelated_alert_ignored(self):
        self.assertIsNone(self.conv.to_event({"timestamp": "2026-11-07T10:00:00.000+0000", "rule": {"id": "1002"}, "full_log": "rien"}))


class TestSources(unittest.TestCase):
    def test_indexer_fetch_auth_and_incremental(self):
        now = utcnow()
        m = MockIndexer([ssh_fail_hit(i, now - timedelta(minutes=5) + timedelta(seconds=i)) for i in range(5)])
        try:
            src = IndexerSource(cfg(m.url), 60)
            self.assertEqual(src.ping()["cluster"], "wazuh-cluster")
            first = src.fetch()
            self.assertEqual(len(first), 5)
            sent = m.requests[0][1]
            self.assertEqual(sent["sort"], [{"timestamp": {"order": "asc"}}])
            self.assertIn("epoch_millis", json.dumps(sent))
            m.docs.append(ssh_fail_hit(9, now))
            second = {i for i, _ in src.fetch()}
            self.assertIn("doc5", second)                      # la nouvelle alerte est bien récupérée
        finally:
            m.close()

    def test_bad_password_gives_clear_error(self):
        m = MockIndexer([])
        try:
            c = cfg(m.url)
            c["indexer"]["password"] = "mauvais"
            with self.assertRaises(WazuhError) as e:
                IndexerSource(c, 60).ping()
            self.assertIn("identifiants refusés", str(e.exception))
        finally:
            m.close()

    def test_unreachable_server(self):
        with self.assertRaises(WazuhError):
            IndexerSource(cfg("http://127.0.0.1:9"), 60).fetch()

    def test_file_source_incremental_partial_line_and_rotation(self):
        d = tempfile.mkdtemp()
        p = f"{d}/alerts.json"
        open(p, "w").write(json.dumps({"a": 1}) + "\n" + json.dumps({"a": 2}) + "\n" + '{"a": 3')
        src = FileSource({"file": {"path": p}})
        self.assertEqual(len(src.fetch()), 2)                  # la dernière ligne incomplète est ignorée
        open(p, "a").write("}\n")
        self.assertEqual([x[1]["a"] for x in src.fetch()], [3])
        open(p, "w").write(json.dumps({"a": 4}) + "\n")        # rotation (fichier plus petit)
        self.assertEqual([x[1]["a"] for x in src.fetch()], [4])


class TestLiveMonitor(unittest.TestCase):
    def make(self, docs, **kw):
        m = MockIndexer(docs)
        ws = Workspace(tempfile.mkdtemp())
        mon = LiveMonitor(ws, cfg(m.url, **kw), log=lambda *_: None)
        mon.rt = pipeline.build_runtime(ws, None, load_events=False, live=True)
        mon.rt.toolbox.ctx.events = mon.buffer
        from soc.wazuh import Converter as C
        mon.conv = C(mon.rt.toolbox.ctx.patterns)
        return m, ws, mon

    def test_bruteforce_then_compromise_end_to_end(self):
        now = utcnow()
        t0 = now - timedelta(minutes=10)
        docs = [ssh_fail_hit(i, t0 + timedelta(seconds=3 * i), user=("admin", "root", "test", "deploy")[i % 4]) for i in range(30)]
        m, ws, mon = self.make(docs)
        try:
            self.assertEqual(mon.cycle(now), 1)                # calme depuis > 45 s : l'alerte est mûre
            inc = mon.rt.db.incidents()[0]
            self.assertEqual((inc["scenario"], inc["verdict"]), ("ssh_bruteforce", "menace confirmée"))
            self.assertIn("203.0.113.50", mon.rt.executor.state()["blocked"])        # niveau 3 : blocage simulé exécuté
            self.assertEqual(mon.cycle(now), 0)                # pas de doublon au cycle suivant
            self.assertGreater(len(mon.rt.db.feed(10)), 0)     # le flux Wazuh est alimenté
            self.assertTrue(mon.rt.db.meta_get("live_status")["ok"])
            # puis : connexion réussie => urgence immédiate, nouvel incident critique soumis à validation humaine
            m.docs.append(ssh_ok_hit(now - timedelta(seconds=2), user="deploy"))
            self.assertEqual(mon.cycle(now), 1)
            crit = mon.rt.db.incidents()[-1]
            self.assertEqual(crit["severity"], "critical")
        finally:
            m.close()

    def test_active_attack_is_not_processed_before_settling(self):
        now = utcnow()
        docs = [ssh_fail_hit(i, now - timedelta(seconds=40 - i)) for i in range(15)]      # attaque en cours
        m, ws, mon = self.make(docs)
        try:
            self.assertEqual(mon.cycle(now), 0)
            self.assertEqual(mon.cycle(now + timedelta(seconds=60)), 1)                   # calmée : traitée
        finally:
            m.close()

    def test_alerts_and_archives_duplicates_counted_once(self):
        now = utcnow()
        base = [ssh_fail_hit(i, now - timedelta(minutes=5) + timedelta(seconds=i)) for i in range(12)]
        m, ws, mon = self.make(base + [dict(h) for h in base])       # chaque événement vu deux fois
        try:
            mon.cycle(now)
            self.assertEqual(len(mon.buffer), 12)
        finally:
            m.close()

    def test_fim_file_scenario_live(self):
        now = utcnow()
        from soc.simulator import FAKE_MALWARE_SHA256
        m, ws, mon = self.make([fim_hit(now - timedelta(minutes=3), "/tmp/invoice.pdf.exe", FAKE_MALWARE_SHA256)])
        try:
            self.assertEqual(mon.cycle(now), 1)
            inc = mon.rt.db.incidents()[0]
            self.assertEqual((inc["scenario"], inc["verdict"]), ("malicious_file", "menace confirmée"))
            self.assertIn(("quarantine_file", "executed"), {(d["action"], d["status"]) for d in mon.rt.db.decisions()})
        finally:
            m.close()

    def test_default_live_level_requires_human(self):
        now = utcnow()
        docs = [ssh_fail_hit(i, now - timedelta(minutes=5) + timedelta(seconds=3 * i)) for i in range(20)]
        m, ws, mon = self.make(docs, autonomy_level=2)
        try:
            mon.cycle(now)
            self.assertEqual(mon.rt.executor.state()["blocked"], {})
            self.assertTrue(all(d["status"] == "pending_approval" for d in mon.rt.db.decisions()))
        finally:
            m.close()

    def test_unreachable_wazuh_sets_error_status_and_thread_survives(self):
        ws = Workspace(tempfile.mkdtemp())
        mon = LiveMonitor(ws, cfg("http://127.0.0.1:9", poll_seconds=0.2), log=lambda *_: None)
        mon.start()
        import time
        time.sleep(1.0)
        mon.stop(); mon.join(3)
        from soc.storage import Database
        st = Database(ws.db_path).meta_get("live_status")
        self.assertFalse(st["ok"])
        self.assertIn("connexion impossible", st["message"])

    def test_signature_buckets(self):
        class A: pass
        a = A(); a.scenario, a.key, a.kind = "ssh_bruteforce", "1.2.3.4", ""
        a.facts = {"ssh_failed_count": 5, "ssh_success_after_failures": False}
        b = A(); b.scenario, b.key, b.kind = "ssh_bruteforce", "1.2.3.4", ""
        b.facts = {"ssh_failed_count": 60, "ssh_success_after_failures": False}
        self.assertNotEqual(alert_signature(a), alert_signature(b))


if __name__ == "__main__":
    unittest.main()
