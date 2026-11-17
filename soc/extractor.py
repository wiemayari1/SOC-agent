"""Module d'analyse : événements normalisés -> alertes candidates + faits pour l'agent.

Rôle : seuil BAS de pré-détection (éviter d'enquêter sur le bruit). La décision "attaque ou non"
revient au raisonnement de l'agent (révision de ses croyances), pas à ce module.
"""
from __future__ import annotations

import ipaddress
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import unquote_plus, urlparse

from .events import Event

_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]

DEFAULT_THRESHOLDS = {"ssh_min_failures": 3, "ssh_window_s": 120, "scan_min_ports": 5,
                      "scan_window_s": 60, "ransom_min_renames": 5, "ransom_window_s": 60}


def is_internal(ip: str | None) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(a in n for n in _INTERNAL)


@dataclass
class Alert:
    scenario: str                  # ssh_bruteforce | port_scan | web_sqli | malicious_file
    key: str
    src_ip: str | None
    host: str
    first_ts: datetime
    last_ts: datetime
    events: list[Event]
    facts: dict
    title: str
    kind: str = ""                 # "ransomware_burst" pour la variante ransomware
    id: str = ""
    extra: dict = field(default_factory=dict)


def max_in_window(times: list[datetime], window_s: float) -> int:
    times = sorted(times)
    best, j = 0, 0
    for i, t in enumerate(times):
        while (t - times[j]).total_seconds() > window_s:
            j += 1
        best = max(best, i - j + 1)
    return best


def max_distinct_in_window(items: list[tuple[datetime, int]], window_s: float) -> int:
    items = sorted(items)
    cnt, best, j = Counter(), 0, 0
    for i, (t, v) in enumerate(items):
        cnt[v] += 1
        while (t - items[j][0]).total_seconds() > window_s:
            cnt[items[j][1]] -= 1
            if cnt[items[j][1]] == 0:
                del cnt[items[j][1]]
            j += 1
        best = max(best, len(cnt))
    return best


def compile_sqli(patterns: dict):
    return [(p["name"], p["strength"], re.compile(p["regex"], re.IGNORECASE)) for p in patterns["sqli"]]


def classify_request(url: str, compiled) -> tuple[str | None, list[str]]:
    """Retourne ('strong'|'weak'|None, noms des motifs) après double décodage de l'URL."""
    decoded = unquote_plus(unquote_plus(url))
    names = [(n, s) for n, s, rx in compiled if rx.search(decoded)]
    if any(s == "strong" for _, s in names):
        return "strong", [n for n, s in names if s == "strong"]
    if names:
        return "weak", [n for n, _ in names]
    return None, []


# ----------------------------------------------------------------------------- SSH
def _ssh_alerts(events, th):
    by_ip = defaultdict(list)
    for e in events:
        if e.source == "ssh" and e.type in ("ssh_failed", "ssh_success") and e.src_ip:
            by_ip[e.src_ip].append(e)
    out = []
    for ip, evs in by_ip.items():
        failed = [e for e in evs if e.type == "ssh_failed"]
        if len(failed) < th["ssh_min_failures"]:
            continue
        users = [e.user for e in failed]
        succ = None
        for s in sorted((e for e in evs if e.type == "ssh_success"), key=lambda e: e.ts):
            if sum(1 for f in failed if f.ts < s.ts) >= th["ssh_min_failures"]:
                succ = s
                break
        facts = {
            "alert_scenario": "ssh_bruteforce", "src_ip": ip, "host": evs[0].host,
            "src_is_internal": is_internal(ip),
            "ssh_failed_count": len(failed),
            "ssh_failed_in_window": max_in_window([e.ts for e in failed], th["ssh_window_s"]),
            "ssh_distinct_users": len(set(users)),
            "ssh_invalid_user_count": sum(1 for e in failed if e.details.get("invalid_user")),
            "ssh_duration_s": int((failed[-1].ts - failed[0].ts).total_seconds()),
            "ssh_root_targeted": "root" in users,
            "ssh_success_after_failures": succ is not None,
            "ssh_success_user": succ.user if succ else None,
            "ssh_success_ts": succ.ts.isoformat() if succ else None,
        }
        out.append(Alert("ssh_bruteforce", ip, ip, evs[0].host, evs[0].ts, evs[-1].ts, evs, facts,
                         f"Tentatives SSH échouées depuis {ip} ({len(failed)} échecs)"))
    return out


# ----------------------------------------------------------------------------- Scan de ports
def _scan_alerts(events, th, patterns):
    by_ip = defaultdict(list)
    for e in events:
        if e.source == "firewall" and e.src_ip:
            by_ip[e.src_ip].append(e)
    sensitive = set(patterns["sensitive_ports"])
    out = []
    for ip, evs in by_ip.items():
        ports = sorted({e.details["dport"] for e in evs})
        if len(ports) < th["scan_min_ports"]:
            continue
        diffs = [b - a for a, b in zip(ports, ports[1:])]
        facts = {
            "alert_scenario": "port_scan", "src_ip": ip, "host": evs[0].host,
            "src_is_internal": is_internal(ip),
            "scan_conn_count": len(evs),
            "scan_distinct_ports": max_distinct_in_window([(e.ts, e.details["dport"]) for e in evs], th["scan_window_s"]),
            "scan_distinct_ports_total": len(ports),
            "scan_sequential_ratio": round(sum(1 for d in diffs if d == 1) / len(diffs), 2) if diffs else 0.0,
            "scan_sensitive_ports_hit": len(sensitive & set(ports)),
            "scan_duration_s": int((evs[-1].ts - evs[0].ts).total_seconds()),
        }
        out.append(Alert("port_scan", ip, ip, evs[0].host, evs[0].ts, evs[-1].ts, evs, facts,
                         f"Connexions vers {len(ports)} ports distincts depuis {ip}"))
    return out


# ----------------------------------------------------------------------------- Web / SQLi
def _web_alerts(events, patterns):
    compiled = compile_sqli(patterns)
    scanners = [s.lower() for s in patterns["scanner_user_agents"]]
    by_ip = defaultdict(list)
    for e in events:
        if e.source == "web" and e.src_ip:
            by_ip[e.src_ip].append(e)
    out = []
    for ip, evs in by_ip.items():
        strong = weak = 0
        names, params, bad_events = set(), set(), []
        for e in evs:
            kind, ns = classify_request(e.details["url"], compiled)
            if kind:
                bad_events.append(e)
                names.update(ns)
                strong += kind == "strong"
                weak += kind == "weak"
                for p in urlparse(e.details["url"]).query.split("&"):
                    if p:
                        params.add(unquote_plus(p.split("=")[0]))
        scanner = any(s in e.details.get("user_agent", "").lower() for e in evs for s in scanners)
        if not bad_events and not scanner:
            continue
        facts = {
            "alert_scenario": "web_sqli", "src_ip": ip, "host": evs[0].host,
            "src_is_internal": is_internal(ip),
            "web_requests_total": len(evs), "web_sqli_strong_hits": strong, "web_sqli_weak_hits": weak,
            "web_sqli_patterns": sorted(names), "web_sqli_params": sorted(params),
            "web_scanner_ua": scanner,
            "web_distinct_endpoints": len({urlparse(e.details["url"]).path for e in evs}),
        }
        shown = bad_events or evs
        out.append(Alert("web_sqli", ip, ip, evs[0].host, shown[0].ts, shown[-1].ts, shown, facts,
                         f"Requêtes web suspectes depuis {ip} ({strong} motifs forts, {weak} faibles)"))
    return out


# ----------------------------------------------------------------------------- Fichiers
def _file_alerts(events, th, patterns):
    sus_ext = set(patterns["suspicious_extensions"])
    exe_ext = set(patterns["executable_extensions"])
    doc_ext = set(patterns["document_extensions"])
    sus_dirs = patterns["suspicious_dirs"]
    ransom_ext = tuple(patterns["ransomware_extensions"])
    notes = {n.lower() for n in patterns["ransom_notes"]}
    out, seen = [], set()
    for e in events:
        if e.source != "file" or e.type not in ("file_created", "file_modified"):
            continue
        path = e.details["path"]
        if path in seen:
            continue
        name = os.path.basename(path)
        root, ext = os.path.splitext(name.lower())
        inner = os.path.splitext(root)[1]
        facts = {
            "alert_scenario": "malicious_file", "host": e.host, "src_ip": None,
            "file_path": path, "file_name": name, "file_ext": ext,
            "file_suspicious_ext": ext in sus_ext,
            "file_in_suspicious_dir": any(path.startswith(d) for d in sus_dirs),
            "file_double_extension": ext in exe_ext and inner in doc_ext,
            "file_size": e.details.get("size"), "file_sha256_logged": e.details.get("sha256"),
        }
        if not (facts["file_suspicious_ext"] or facts["file_in_suspicious_dir"] or facts["file_double_extension"]):
            continue
        seen.add(path)
        out.append(Alert("malicious_file", path, None, e.host, e.ts, e.ts, [e], facts,
                         f"Fichier suspect créé : {path}", kind="suspicious_file"))
    # --- variante ransomware : rafale de renommages vers une extension de chiffrement
    by_host = defaultdict(list)
    for e in events:
        if e.source == "file" and e.type == "file_renamed" and e.details["path"].lower().endswith(ransom_ext):
            by_host[e.host].append(e)
    for host, evs in by_host.items():
        if len(evs) < th["ransom_min_renames"]:
            continue
        note = any(x.source == "file" and x.type == "file_created" and x.host == host
                   and os.path.basename(x.details["path"]).lower() in notes for x in events)
        facts = {
            "alert_scenario": "malicious_file", "host": host, "src_ip": None,
            "file_ransom_burst_count": max_in_window([e.ts for e in evs], th["ransom_window_s"]),
            "file_ransom_ext": os.path.splitext(evs[0].details["path"])[1],
            "file_ransom_note": note,
            "file_distinct_dirs": len({os.path.dirname(e.details["path"]) for e in evs}),
        }
        out.append(Alert("malicious_file", host, None, host, evs[0].ts, evs[-1].ts, evs, facts,
                         f"Renommages massifs ({len(evs)}) vers {facts['file_ransom_ext']} sur {host}", kind="ransomware_burst"))
    return out


def build_alerts(events: list[Event], patterns: dict, thresholds: dict | None = None) -> list[Alert]:
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    alerts = (_ssh_alerts(events, th) + _scan_alerts(events, th, patterns)
              + _web_alerts(events, patterns) + _file_alerts(events, th, patterns))
    alerts.sort(key=lambda a: (a.first_ts, a.scenario, a.key))
    return alerts
