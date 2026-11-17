"""Serveur web (bibliothèque standard) : API JSON + interface monopage. Écoute en local par défaut.

Sécurité : écoute sur 127.0.0.1, contrôle de l'en-tête Host (anti DNS-rebinding), jeton CSRF obligatoire pour les
actions (POST), en-têtes de sécurité (CSP stricte, pas de cadre), aucune donnée dynamique injectée en HTML côté serveur.
Pour un accès distant, utilisez un tunnel SSH plutôt que d'exposer le port.
"""
from __future__ import annotations

import hmac
import json
import mimetypes
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .api import Api

STATIC = Path(__file__).resolve().parent / "static"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class WebApp:
    def __init__(self, ws, wcfg=None, host="127.0.0.1", port=8000):
        self.api = Api(ws, wcfg)
        self.token = secrets.token_urlsafe(24)
        self.host, self.port = host, port
        self.httpd = None

    def start(self, background: bool = False):
        app = self
        enforce_host = self.host in LOCAL_HOSTS

        class H(BaseHTTPRequestHandler):
            server_version = "SOC-Agent"

            def log_message(self, *a):
                pass

            # ---------------------------------------------------------------- réponses
            def _send(self, code, body: bytes, ctype="application/json; charset=utf-8", extra=None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", CSP)
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _json(self, obj, code=200):
                self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"))

            def _host_ok(self) -> bool:
                if not enforce_host:
                    return True
                h = (self.headers.get("Host") or "").rsplit(":", 1)[0] if not (self.headers.get("Host") or "").startswith("[") \
                    else (self.headers.get("Host") or "").split("]")[0] + "]"
                return h in LOCAL_HOSTS

            # ---------------------------------------------------------------- GET
            def do_GET(self):
                if not self._host_ok():
                    return self._json({"error": "hôte non autorisé"}, 403)
                u = urlparse(self.path)
                q = parse_qs(u.query)
                try:
                    if u.path in ("/", "/index.html"):
                        html = (STATIC / "index.html").read_text(encoding="utf-8").replace("__CSRF_TOKEN__", app.token)
                        return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
                    if u.path.startswith("/static/"):
                        f = (STATIC / u.path[len("/static/"):]).resolve()
                        if STATIC.resolve() not in f.parents or not f.is_file():
                            return self._json({"error": "introuvable"}, 404)
                        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
                        return self._send(200, f.read_bytes(), ctype + ("; charset=utf-8" if ctype.startswith(("text/", "application/javascript")) else ""))
                    api = app.api
                    if u.path == "/api/summary": return self._json(api.summary())
                    if u.path == "/api/overview": return self._json(api.overview())
                    if u.path == "/api/incidents": return self._json(api.incidents(q))
                    if u.path == "/api/pending": return self._json(api.pending())
                    if u.path == "/api/feed": return self._json(api.feed(min(int((q.get("limit") or ["100"])[0]), 500)))
                    if u.path == "/api/firewall": return self._json(api.firewall())
                    if u.path == "/api/system": return self._json(api.system())
                    m = re.fullmatch(r"/api/incidents/(INC-\d{4})", u.path)
                    if m:
                        d = api.incident(m[1])
                        return self._json(d) if d else self._json({"error": "incident introuvable"}, 404)
                    m = re.fullmatch(r"/api/report/(INC-\d{4})", u.path)
                    if m:
                        r = api.report(m[1])
                        if r is None:
                            return self._json({"error": "incident introuvable"}, 404)
                        return self._send(200, r.encode("utf-8"), "text/markdown; charset=utf-8",
                                          {"Content-Disposition": f'attachment; filename="{m[1]}.md"'})
                    return self._json({"error": "introuvable"}, 404)
                except (ValueError, KeyError) as e:
                    return self._json({"error": f"requête invalide : {e}"}, 400)
                except Exception as e:                                    # ne jamais exposer de trace complète
                    return self._json({"error": f"erreur interne : {type(e).__name__}"}, 500)

            # ---------------------------------------------------------------- POST (actions)
            def do_POST(self):
                if not self._host_ok():
                    return self._json({"error": "hôte non autorisé"}, 403)
                if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), app.token):
                    return self._json({"error": "jeton CSRF invalide"}, 403)
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                    body = json.loads(self.rfile.read(n) or b"{}") if n < 10_000 else {}
                    u = urlparse(self.path)
                    m = re.fullmatch(r"/api/decisions/(\d+)/(approve|reject)", u.path)
                    if m:
                        return self._json(app.api.act(m[2], int(m[1])))
                    m = re.fullmatch(r"/api/actions/(\d+)/rollback", u.path)
                    if m:
                        return self._json(app.api.act("rollback", int(m[1])))
                    if u.path == "/api/autonomy":
                        return self._json(app.api.set_autonomy(int(body.get("level", 0))))
                    return self._json({"error": "introuvable"}, 404)
                except (ValueError, KeyError, TypeError) as e:
                    return self._json({"error": f"requête invalide : {e}"}, 400)
                except Exception as e:
                    return self._json({"error": f"erreur interne : {type(e).__name__}"}, 500)

        self.httpd = ThreadingHTTPServer((self.host, self.port), H)
        self.port = self.httpd.server_address[1]
        if background:
            threading.Thread(target=self.httpd.serve_forever, daemon=True, name="soc-web").start()
        else:
            self.httpd.serve_forever()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
