"""Connecteur Wazuh : lecture des alertes (indexeur Wazuh ou fichier alerts.json) -> événements normalisés.

* IndexerSource : interroge l'indexeur Wazuh (OpenSearch, port 9200) avec authentification de base.
* FileSource    : lit en continu /var/ossec/logs/alerts/alerts.json (agent SOC exécuté sur le serveur Wazuh).
* ManagerApi    : API du serveur Wazuh (port 55000), LECTURE SEULE : état et liste des agents.
* Converter     : alerte Wazuh (JSON) -> Event (SSH, sudo, pare-feu UFW, Nginx, événements FIM/syscheck).

Aucune dépendance : bibliothèque standard uniquement.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .events import Event
from .parsers import parse_auth_line, parse_fw_line, parse_nginx_line

_TZ_FIX = re.compile(r"([+-]\d{2})(\d{2})$")


class WazuhError(Exception):
    pass


def parse_wazuh_ts(raw: str) -> datetime:
    """'2026-11-07T10:15:32.123+0000' -> datetime naïf en UTC (compatible Python 3.10)."""
    raw = raw.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    raw = _TZ_FIX.sub(r"\1:\2", raw)
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _ctx(verify: bool):
    ctx = ssl.create_default_context()
    if not verify:                              # laboratoire : certificat auto-signé de Wazuh
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _basic(user: str, pwd: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()


def _http(method: str, url: str, headers: dict, body: dict | None, verify: bool, timeout: float = 20):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx(verify) if url.startswith("https") else None) as r:
            raw = r.read().decode("utf-8", "replace")
            return json.loads(raw) if raw.strip().startswith(("{", "[")) else raw
    except urllib.error.HTTPError as e:
        raise WazuhError(f"HTTP {e.code} sur {url} ({'identifiants refusés' if e.code == 401 else e.reason})") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise WazuhError(f"connexion impossible à {url} : {getattr(e, 'reason', e)}") from None


# ============================================================================= conversion alerte -> Event
class Converter:
    def __init__(self, patterns: dict):
        self.ransom_ext = tuple(e.lower() for e in patterns["ransomware_extensions"])

    def to_event(self, src: dict) -> Event | None:
        ts = parse_wazuh_ts(src["timestamp"]) if src.get("timestamp") else None
        if ts is None:
            return None
        agent = (src.get("agent") or {}).get("name") or "inconnu"
        if src.get("syscheck"):
            ev = self._syscheck(src["syscheck"], ts, agent)
        else:
            full = src.get("full_log") or ""
            ev = parse_auth_line(full, ts.year) or parse_fw_line(full, ts.year) or parse_nginx_line(full) or self._from_fields(src, ts)
        if ev is None:
            return None
        ev.ts, ev.host = ts, agent             # l'heure de l'alerte (UTC) fait foi : pas d'ambiguïté d'année ni de fuseau
        if not ev.raw:
            ev.raw = json.dumps(src, ensure_ascii=False)[:300]
        return ev

    def _syscheck(self, sc: dict, ts: datetime, agent: str) -> Event | None:
        path, evt = (sc.get("path") or "").replace("\\", "/"), sc.get("event")
        if not path or evt not in ("added", "modified"):
            return None
        details = {"path": path}
        if sc.get("sha256_after"):
            details["sha256"] = sc["sha256_after"]
        if sc.get("size_after") is not None:
            try:
                details["size"] = int(sc["size_after"])
            except (TypeError, ValueError):
                pass
        etype = "file_created" if evt == "added" else "file_modified"
        if evt == "added" and path.lower().endswith(self.ransom_ext):
            etype = "file_renamed"             # fichier chiffré apparu : équivalent d'un renommage vers .locked
        return Event(ts, "file", etype, agent, None, sc.get("uname_after"), details, f"syscheck {evt} {path}")

    def _from_fields(self, src: dict, ts: datetime) -> Event | None:
        """Repli quand full_log n'a pas le format attendu : on s'appuie sur les champs décodés par Wazuh."""
        groups = set((src.get("rule") or {}).get("groups") or [])
        data = src.get("data") or {}
        ip = data.get("srcip")
        if ip and "sshd" in groups:
            user = data.get("srcuser") or data.get("dstuser")
            if groups & {"authentication_failed", "invalid_login"}:
                return Event(ts, "ssh", "ssh_failed", "", ip, user, {"invalid_user": "invalid_login" in groups}, "")
            if "authentication_success" in groups:
                return Event(ts, "ssh", "ssh_success", "", ip, user, {}, "")
        return None


def feed_row(src: dict, ev: Event | None) -> tuple:
    rule = src.get("rule") or {}
    data = src.get("data") or {}
    ts = parse_wazuh_ts(src["timestamp"]).isoformat() if src.get("timestamp") else ""
    desc = rule.get("description") or (f"FIM : {src['syscheck'].get('event')} {src['syscheck'].get('path')}" if src.get("syscheck") else "événement archivé")
    summary = (src.get("full_log") or "")[:220]
    return (ts, (src.get("agent") or {}).get("name") or "inconnu", str(rule.get("id") or ""), int(rule.get("level") or 0),
            desc, (ev.src_ip if ev and ev.src_ip else data.get("srcip")), summary)


# ============================================================================= sources
class IndexerSource:
    """Lit les alertes dans l'indexeur Wazuh (index wazuh-alerts-*, éventuellement wazuh-archives-*)."""
    kind = "indexer"

    def __init__(self, cfg: dict, lookback_minutes: int = 60):
        c = cfg["indexer"]
        self.url = c["url"].rstrip("/")
        self.auth = _basic(c["user"], c["password"])
        self.verify = bool(c.get("verify_tls", False))
        self.index = c.get("index_pattern", "wazuh-alerts-*")
        self.min_level = int(c.get("min_level", 0))
        self.page = int(c.get("page_size", 500))
        self.cursor_ms = int((time.time() - lookback_minutes * 60) * 1000)
        self.description = f"indexeur {self.url} ({self.index})"

    def _post(self, path: str, body: dict) -> dict:
        return _http("POST", f"{self.url}/{path}", {"Authorization": self.auth}, body, self.verify)

    def ping(self) -> dict:
        info = _http("GET", self.url + "/", {"Authorization": self.auth}, None, self.verify)
        return {"cluster": info.get("cluster_name"), "version": (info.get("version") or {}).get("number")}

    def fetch(self) -> list[tuple[str, dict]]:
        out, seen, pages = [], set(), 0
        while pages < 20:
            pages += 1
            flt = [{"range": {"timestamp": {"gte": self.cursor_ms, "format": "epoch_millis"}}}]
            if self.min_level:
                flt.append({"range": {"rule.level": {"gte": self.min_level}}})
            res = self._post(f"{self.index}/_search", {"size": self.page, "sort": [{"timestamp": {"order": "asc"}}],
                                                       "query": {"bool": {"filter": flt}}})
            hits = (res.get("hits") or {}).get("hits") or []
            fresh = [h for h in hits if h["_id"] not in seen]
            for h in fresh:
                seen.add(h["_id"])
                out.append((h["_id"], h["_source"]))
            if hits:
                last = parse_wazuh_ts(hits[-1]["_source"]["timestamp"])
                self.cursor_ms = int(last.replace(tzinfo=timezone.utc).timestamp() * 1000)
            if len(hits) < self.page or not fresh:
                break
        return out


class FileSource:
    """Suit un fichier JSON-lines (alerts.json ou archives.json) : lecture incrémentale, tolérante à la rotation."""
    kind = "file"

    def __init__(self, cfg: dict, lookback_minutes: int = 60):
        self.path = Path(cfg["file"]["path"])
        self.offset = None
        self.description = f"fichier {self.path}"

    def ping(self) -> dict:
        if not self.path.exists():
            raise WazuhError(f"fichier introuvable : {self.path}")
        return {"size": self.path.stat().st_size}

    def fetch(self) -> list[tuple[str, dict]]:
        if not self.path.exists():
            raise WazuhError(f"fichier introuvable : {self.path}")
        size = self.path.stat().st_size
        if self.offset is None:
            self.offset = max(0, size - 20 * 1024 * 1024)       # démarrage : au plus les 20 derniers Mo
        if size < self.offset:                                    # rotation du fichier
            self.offset = 0
        out = []
        with self.path.open("rb") as f:
            f.seek(self.offset)
            chunk = f.read()
        end = chunk.rfind(b"\n")
        if end == -1:
            return out
        self.offset += end + 1
        for line in chunk[:end].decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append((hashlib.sha1(line.encode()).hexdigest(), json.loads(line)))
            except ValueError:
                continue
        return out


class ManagerApi:
    """API du serveur Wazuh : lecture seule (état, agents)."""

    def __init__(self, cfg: dict):
        c = cfg["api"]
        self.url, self.user, self.pwd = c["url"].rstrip("/"), c["user"], c["password"]
        self.verify = bool(c.get("verify_tls", False))

    def _token(self) -> str:
        t = _http("POST", f"{self.url}/security/user/authenticate?raw=true", {"Authorization": _basic(self.user, self.pwd)}, None, self.verify)
        if not isinstance(t, str):
            raise WazuhError("réponse d'authentification inattendue de l'API Wazuh")
        return t.strip()

    def status(self) -> dict:
        tok = self._token()
        h = {"Authorization": f"Bearer {tok}"}
        info = _http("GET", f"{self.url}/", h, None, self.verify)
        ag = _http("GET", f"{self.url}/agents?limit=500&select=id,name,ip,status,os.name,os.version,version,lastKeepAlive", h, None, self.verify)
        items = ((ag.get("data") or {}).get("affected_items")) or []
        agents = [{"id": a.get("id"), "name": a.get("name"), "ip": a.get("ip"), "status": a.get("status"),
                   "os": ((a.get("os") or {}).get("name") or "") + " " + ((a.get("os") or {}).get("version") or ""),
                   "version": a.get("version"), "last_keepalive": a.get("lastKeepAlive")} for a in items]
        return {"version": (info.get("data") or {}).get("api_version"), "agents": agents}


def make_source(cfg: dict):
    mode = cfg.get("mode", "indexer")
    lb = int(cfg.get("lookback_minutes", 60))
    if mode == "file":
        return FileSource(cfg, lb)
    if mode == "indexer":
        return IndexerSource(cfg, lb)
    raise WazuhError(f"mode inconnu : {mode} (attendu : indexer ou file)")
