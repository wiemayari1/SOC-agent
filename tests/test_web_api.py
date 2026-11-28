import json
import tempfile
import unittest
import urllib.error
import urllib.request

from soc import pipeline, simulator
from soc.config import Workspace
from soc.web.server import WebApp


class TestWebApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = Workspace(tempfile.mkdtemp())
        simulator.generate(cls.ws)
        pipeline.run(cls.ws, 3, log=lambda *_: None)
        cls.app = WebApp(cls.ws, None, "127.0.0.1", 0)
        cls.app.start(background=True)
        cls.base = f"http://127.0.0.1:{cls.app.port}"

    @classmethod
    def tearDownClass(cls):
        cls.app.stop()

    def get(self, path, headers=None):
        req = urllib.request.Request(self.base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def post(self, path, body=None, token=True):
        h = {"Content-Type": "application/json"}
        if token:
            h["X-CSRF-Token"] = self.app.token
        req = urllib.request.Request(self.base + path, data=json.dumps(body or {}).encode(), headers=h, method="POST")
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_index_has_token_and_security_headers(self):
        code, body, h = self.get("/")
        self.assertEqual(code, 200)
        self.assertIn(self.app.token.encode(), body)
        self.assertIn("script-src 'self'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")

    def test_overview_matches_cli(self):
        o = json.loads(self.get("/api/overview")[1])
        self.assertEqual(o["kpi"]["incidents"], 12)
        self.assertEqual(o["kpi"]["pending"], 3)
        self.assertEqual(o["by_severity"]["critical"], 2)
        self.assertGreaterEqual(len(o["timeline"]), 1)
        self.assertEqual(sum(b["count"] for b in o["timeline"]), o["kpi"]["incidents"])

    def test_incident_list_filters_and_detail(self):
        rows = json.loads(self.get("/api/incidents?severity=critical")[1])
        self.assertEqual({r["id"] for r in rows}, {"INC-0004", "INC-0011"})
        self.assertEqual([r["id"] for r in json.loads(self.get("/api/incidents?q=198.51.100.140")[1])], ["INC-0005"])
        d = json.loads(self.get("/api/incidents/INC-0004")[1])
        self.assertEqual(d["incident"]["severity"], "critical")
        self.assertTrue(d["reasoning"] and d["steps"] and d["decisions"])
        self.assertEqual(self.get("/api/incidents/INC-9999")[0], 404)
        self.assertEqual(self.get("/api/incidents/..%2Fx")[0], 404)

    def test_report_download(self):
        code, body, h = self.get("/api/report/INC-0001")
        self.assertEqual(code, 200)
        self.assertIn("attachment", h["Content-Disposition"])
        self.assertIn(b"# Rapport d'incident INC-0001", body)

    def test_static_path_traversal_blocked(self):
        self.assertEqual(self.get("/static/../server.py")[0], 404)
        self.assertEqual(self.get("/static/%2e%2e/server.py")[0], 404)

    def test_post_requires_csrf_token(self):
        self.assertEqual(self.post("/api/autonomy", {"level": 1}, token=False)[0], 403)

    def test_bad_host_header_rejected(self):
        self.assertEqual(self.get("/api/summary", {"Host": "evil.example.com"})[0], 403)

    def test_z_approve_reject_rollback_and_autonomy_via_api(self):
        pend = json.loads(self.get("/api/pending")[1])
        self.assertEqual(len(pend), 3)
        block = [d for d in pend if d["action"] == "block_ip"][0]
        iso = [d for d in pend if d["action"] == "isolate_host"][0]
        self.assertTrue(self.post(f"/api/decisions/{block['id']}/approve")[1]["ok"])
        self.assertIn("203.0.113.77", json.loads(self.get("/api/firewall")[1])["state"]["blocked"])
        self.post(f"/api/decisions/{iso['id']}/reject")
        d = json.loads(self.get("/api/incidents/INC-0011")[1])
        self.assertEqual(d["decisions"][0]["status"], "rejected")
        d4 = json.loads(self.get("/api/incidents/" + block["incident_id"])[1])
        act = [a for dec in d4["decisions"] for a in dec["actions"] if a["action"] == "block_ip"][0]
        self.post(f"/api/actions/{act['id']}/rollback")
        self.assertNotIn("203.0.113.77", json.loads(self.get("/api/firewall")[1])["state"]["blocked"])
        self.assertEqual(self.post("/api/autonomy", {"level": 2})[1]["autonomy"], 2)
        self.assertEqual(json.loads(self.get("/api/summary")[1])["autonomy"], 2)
        self.assertEqual(self.post("/api/autonomy", {"level": 9})[0], 400)
        self.post("/api/autonomy", {"level": 3})

    def test_effective_autonomy_prefers_wazuh_config_over_policy(self):
        from soc.web.api import Api
        ws = Workspace(tempfile.mkdtemp())
        self.assertEqual(Api(ws, {"autonomy_level": 2})._level(), 2)      # config Wazuh (mode live)
        self.assertEqual(Api(ws, None)._level(), 3)                       # policy.json
        from soc.config import set_runtime_override
        set_runtime_override(ws, autonomy_level=1)
        self.assertEqual(Api(ws, {"autonomy_level": 2})._level(), 1)      # réglage fait dans l'interface

    def test_system_endpoint(self):
        s = json.loads(self.get("/api/system")[1])
        self.assertNotIn("rules", s["knowledge"])
        self.assertIn("block_ip", s["policy"]["actions"])
        self.assertFalse(s["agents"]["configured"])


if __name__ == "__main__":
    unittest.main()
