"""Parseurs : journaux bruts -> événements normalisés.

Formats gérés : auth.log (sshd, sudo), pare-feu UFW, access.log Nginx (combined),
événements fichiers (JSON lines) et, en option, alertes Wazuh (champ full_log).
Les lignes illisibles sont comptées puis ignorées (robustesse).
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from .events import Event

_TS = r"(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z)?|[A-Z][a-z]{2}\s+\d+\s[\d:]{8})"

RE_SSH_FAIL = re.compile(_TS + r"\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for "
                         r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
RE_SSH_OK = re.compile(_TS + r"\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted (?P<method>\w+) for "
                       r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
RE_SUDO = re.compile(_TS + r"\s+(?P<host>\S+)\s+sudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")
RE_FW = re.compile(_TS + r"\s+(?P<host>\S+)\s+kernel:.*\[UFW (?P<action>BLOCK|ALLOW)\]")
RE_NGINX = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+)[^"]*" '
                      r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')


def _ts(s: str, year: int | None = None) -> datetime:
    s = s.strip()
    if re.match(r"\d{4}-\d{2}-\d{2}", s):
        return datetime.fromisoformat(s).replace(tzinfo=None)
    return datetime.strptime(f"{year or datetime.now().year} {s}", "%Y %b %d %H:%M:%S")


def parse_auth_line(line: str, year: int | None = None) -> Event | None:
    if (m := RE_SSH_FAIL.search(line)):
        return Event(_ts(m["ts"], year), "ssh", "ssh_failed", m["host"], m["ip"], m["user"],
                     {"port": int(m["port"]), "invalid_user": bool(m["invalid"])}, line)
    if (m := RE_SSH_OK.search(line)):
        return Event(_ts(m["ts"], year), "ssh", "ssh_success", m["host"], m["ip"], m["user"],
                     {"port": int(m["port"]), "method": m["method"]}, line)
    if (m := RE_SUDO.search(line)):
        return Event(_ts(m["ts"], year), "ssh", "sudo_command", m["host"], None, m["user"],
                     {"command": m["cmd"].strip()}, line)
    return None


def parse_fw_line(line: str, year: int | None = None) -> Event | None:
    m = RE_FW.search(line)
    if not m:
        return None
    kv = dict(re.findall(r"(\w+)=(\S*)", line))
    if "SRC" not in kv or "DPT" not in kv:
        return None
    etype = "fw_block" if m["action"] == "BLOCK" else "fw_allow"
    return Event(_ts(m["ts"], year), "firewall", etype, m["host"], kv["SRC"], None,
                 {"dst": kv.get("DST"), "dport": int(kv["DPT"]), "proto": kv.get("PROTO", "TCP")}, line)


def parse_nginx_line(line: str, host: str = "srv-web") -> Event | None:
    m = RE_NGINX.search(line)
    if not m:
        return None
    ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    return Event(ts, "web", "http_request", host, m["ip"], None,
                 {"method": m["method"], "url": m["url"], "status": int(m["status"]),
                  "size": 0 if m["size"] == "-" else int(m["size"]), "user_agent": m["ua"]}, line)


def parse_file_line(line: str) -> Event | None:
    d = json.loads(line)
    etype = {"created": "file_created", "modified": "file_modified", "renamed": "file_renamed"}.get(d.get("event"))
    if not etype:
        return None
    details = {k: d[k] for k in ("path", "old_path", "sha256", "size") if k in d}
    return Event(_ts(d["ts"]), "file", etype, d.get("host", "srv-01"), None, d.get("user"), details, line)


def parse_wazuh_line(line: str, year: int | None = None) -> Event | None:
    """Alerte Wazuh (alerts.json) : on réutilise la ligne d'origine `full_log`."""
    d = json.loads(line)
    full = d.get("full_log", "")
    return parse_auth_line(full, year) or parse_fw_line(full, year) or parse_nginx_line(full)


def _read(path: Path, fn) -> tuple[list[Event], int]:
    events, skipped = [], 0
    if not path.exists():
        return events, skipped
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            ev = fn(line)
        except Exception:
            ev = None
        if ev is None:
            skipped += 1
        else:
            events.append(ev)
    return events, skipped


def load_all(ws, year: int | None = None) -> tuple[list[Event], dict]:
    """Charge tous les journaux du dossier logs/ ; retourne (événements triés, statistiques)."""
    jobs = {
        "auth.log": lambda l: parse_auth_line(l, year),
        "firewall.log": lambda l: parse_fw_line(l, year),
        "nginx_access.log": parse_nginx_line,
        "file_events.jsonl": parse_file_line,
        "wazuh_alerts.json": lambda l: parse_wazuh_line(l, year),
    }
    events, stats = [], {}
    for name, fn in jobs.items():
        evs, skipped = _read(ws.logs / name, fn)
        if evs or skipped:
            stats[name] = {"events": len(evs), "skipped": skipped}
        events += evs
    events.sort(key=lambda e: e.ts)
    return events, stats
