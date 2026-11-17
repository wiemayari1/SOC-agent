"""Faux indexeur Wazuh (HTTP) pour tester le connecteur sans serveur réel.
ATTENTION : il reproduit la structure documentée des alertes Wazuh, pas un vrai serveur."""
import base64
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def wz_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+0000"


def ssh_fail_hit(i, dt, ip="203.0.113.50", user="admin"):
    return {"timestamp": wz_ts(dt), "rule": {"id": "5710", "level": 5, "description": "sshd: Attempt to login using a non-existent user",
                                              "groups": ["syslog", "sshd", "authentication_failed"]},
            "agent": {"id": "001", "name": "vm-cible"}, "data": {"srcip": ip, "srcuser": user},
            "full_log": f"{dt.strftime('%b %e %H:%M:%S')} vm-cible sshd[2201]: Failed password for invalid user {user} from {ip} port {40000 + i} ssh2"}


def ssh_ok_hit(dt, ip="203.0.113.50", user="admin"):
    return {"timestamp": wz_ts(dt), "rule": {"id": "5715", "level": 3, "description": "sshd: authentication success.", "groups": ["sshd", "authentication_success"]},
            "agent": {"id": "001", "name": "vm-cible"}, "data": {"srcip": ip, "srcuser": user},
            "full_log": f"{dt.strftime('%b %e %H:%M:%S')} vm-cible sshd[2210]: Accepted password for {user} from {ip} port 50000 ssh2"}


def fim_hit(dt, path, sha, event="added"):
    return {"timestamp": wz_ts(dt), "rule": {"id": "554", "level": 5, "description": "File added to the system.", "groups": ["ossec", "syscheck"]},
            "agent": {"id": "001", "name": "vm-cible"},
            "syscheck": {"path": path, "event": event, "sha256_after": sha, "size_after": "42", "uname_after": "root"},
            "full_log": f"File '{path}' added"}


class MockIndexer:
    def __init__(self, docs=None, user="admin", password="pw"):
        self.docs = list(docs or [])
        self.expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def _send(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

            def do_GET(self):
                if self.headers.get("Authorization") != outer.expected:
                    return self._send(401, {"error": "unauthorized"})
                self._send(200, {"name": "node-1", "cluster_name": "wazuh-cluster", "version": {"number": "2.19.1"}})

            def do_POST(self):
                if self.headers.get("Authorization") != outer.expected:
                    return self._send(401, {"error": "unauthorized"})
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append((self.path, body))
                gte = body["query"]["bool"]["filter"][0]["range"]["timestamp"]["gte"]
                size = body["size"]
                hits = []
                for i, d in enumerate(outer.docs):
                    t = datetime.strptime(d["timestamp"][:23], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
                    if int(t.timestamp() * 1000) >= gte:
                        hits.append((t, i, d))
                hits.sort(key=lambda x: (x[0], x[1]))
                self._send(200, {"hits": {"hits": [{"_id": f"doc{i}", "_source": d} for _, i, d in hits[:size]]}})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()
