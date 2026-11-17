"""Test de l'interface dans un navigateur simulé (jsdom). Ignoré si Node.js ou jsdom sont absents."""
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from soc import pipeline, simulator
from soc.config import Workspace
from soc.storage import Database
from soc.web.server import WebApp

SCRIPT = Path(__file__).parent / "ui" / "ui_smoke.js"


def jsdom_available() -> bool:
    node = shutil.which("node")
    if not node:
        return False
    env = dict(os.environ)
    return subprocess.run([node, "-e", "require('jsdom')"], capture_output=True, env=env).returncode == 0


@unittest.skipUnless(jsdom_available(), "Node.js + jsdom absents (npm install jsdom) : test d'interface ignoré")
class TestUi(unittest.TestCase):
    def test_ui_smoke(self):
        ws = Workspace(tempfile.mkdtemp())
        simulator.generate(ws)
        pipeline.run(ws, 3, log=lambda *_: None)
        db = Database(ws.db_path)
        db.meta_set("mode", "demo")
        evil = '<img src=x onerror=window.__xss=1>'
        db.con.execute("UPDATE incidents SET title=?, evidence=? WHERE id='INC-0001'", (evil, json.dumps([evil, "<script>window.__xss=1</script>"])))
        db.con.execute("UPDATE steps SET text=? WHERE incident_id='INC-0001' AND n=1", (evil,))
        db.con.commit(); db.close()
        app = WebApp(ws, None, "127.0.0.1", 0)
        app.start(background=True)
        try:
            r = subprocess.run([shutil.which("node"), str(SCRIPT), f"http://127.0.0.1:{app.port}"], capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        finally:
            app.stop()


if __name__ == "__main__":
    unittest.main()
