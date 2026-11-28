"""Boîte à outils de l'agent : fonctions Python avec permissions par rôle.

Rôles : investigation (lecture seule) | decision (proposer) | execution (agir).
Toute exception d'un outil est capturée -> ToolResult(ok=False) : l'agent continue (robustesse).
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..decision import DecisionModule, Proposal
from ..extractor import build_alerts, classify_request, compile_sqli
from ..events import Event

TOOL_ROLES = {
    "search_logs": {"investigation"},
    "analyze_ip_activity": {"investigation"},
    "check_local_ioc": {"investigation"},
    "inspect_file_hash": {"investigation"},
    "propose_response": {"decision"},
    "execute_authorized_action": {"execution"},
}


@dataclass
class ToolResult:
    ok: bool
    summary: str
    data: dict = field(default_factory=dict)
    new_facts: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class ToolContext:
    events: list[Event]
    patterns: dict
    ioc: dict
    ws: Any
    policy: dict
    executor: Any
    db: Any = None


class ToolBox:
    def __init__(self, ctx: ToolContext):
        self.ctx = ctx
        self._sqli = compile_sqli(ctx.patterns)
        self._decision = DecisionModule(ctx.policy)

    def call(self, name: str, _role: str = "investigation", **kwargs) -> ToolResult:
        if name not in TOOL_ROLES:
            return ToolResult(False, f"outil inconnu : {name}", error="unknown_tool")
        if _role not in TOOL_ROLES[name]:
            return ToolResult(False, f"permission refusée : le rôle '{_role}' ne peut pas appeler {name}", error="permission")
        try:
            return getattr(self, name)(**kwargs)
        except Exception as exc:          # robustesse : un outil en échec ne casse pas l'enquête
            return ToolResult(False, f"{name} a échoué : {exc}", error=repr(exc))

    # ------------------------------------------------------------------ search_logs
    def search_logs(self, ip=None, user=None, source=None, type=None, host=None, after=None) -> ToolResult:
        after_dt = datetime.fromisoformat(after) if after else None
        evs = [e for e in self.ctx.events
               if (ip is None or e.src_ip == ip) and (user is None or e.user == user)
               and (source is None or e.source == source) and (type is None or e.type == type)
               and (host is None or e.host == host) and (after_dt is None or e.ts >= after_dt)]
        facts: dict = {}
        if source == "web" and ip:
            payload = [e for e in evs if e.details.get("url") and classify_request(e.details["url"], self._sqli)[0] == "strong"]
            facts["web_error_after_sqli"] = sum(1 for e in payload if e.details.get("status", 0) >= 500)
            facts["web_payload_200_count"] = sum(1 for e in payload if e.details.get("status") == 200)
        if type == "sudo_command":
            cmds = [e.details.get("command", "") for e in evs if e.details.get("command")]
            bad = [c for c in cmds if any(s in c for s in self.ctx.patterns["suspicious_commands"])]
            facts["post_login_commands"] = len(cmds)
            facts["post_login_suspicious_cmds"] = len(bad)
        if type == "file_renamed":
            facts["file_affected_total"] = len(evs)
        summary = f"{len(evs)} événement(s) trouvé(s)"
        if facts:
            summary += " ; " + ", ".join(f"{k}={v}" for k, v in facts.items())
        return ToolResult(True, summary, {"count": len(evs), "sample": [e.brief() for e in evs[:5]]}, facts)

    # ------------------------------------------------------------------ analyze_ip_activity
    def analyze_ip_activity(self, ip: str) -> ToolResult:
        evs = [e for e in self.ctx.events if e.src_ip == ip]
        alerts = build_alerts(evs, self.ctx.patterns, self.ctx.policy.get("thresholds"))
        scen_set = {a.scenario for a in alerts}
        past_scen = set()
        if self.ctx.db is not None:
            try:
                for inc in self.ctx.db.incidents():
                    if inc["src_ip"] == ip and not str(inc["verdict"]).startswith("bénin"):
                        past_scen.add(inc["scenario"])
            except Exception:
                pass
        scen = sorted(scen_set | past_scen)
        by_src = dict(Counter(e.source for e in evs))
        facts = {"ip_total_events": len(evs), "ip_scenarios": scen, "ip_multi_stage": len(scen) >= 2}
        txt = f"{len(evs)} événements sur {by_src or 'aucune source'} ; comportements suspects : {scen or 'aucun'}"
        if past_scen - scen_set:
            txt += f" (historique base : {sorted(past_scen - scen_set)})"
        if len(scen) >= 2:
            txt += " → ATTAQUE MULTI-ÉTAPES"
        return ToolResult(True, txt, {"by_source": by_src, "scenarios": scen}, facts)

    # ------------------------------------------------------------------ check_local_ioc
    def check_local_ioc(self, ip: str | None = None, hash: str | None = None) -> ToolResult:
        if ip:
            e = self.ctx.ioc["bad_ips"].get(ip)
            facts = {"ip_blacklisted": e is not None}
            if e:
                facts["ip_blacklist_category"] = e["category"]
            return ToolResult(True, f"IP {ip} : " + (f"présente dans la base IOC ({e['category']})" if e else "absente de la base IOC"),
                              {"entry": e}, facts)
        if hash:
            e = self.ctx.ioc["bad_hashes"].get(hash)
            facts = {"file_hash_known_malicious": e is not None}
            if e:
                facts.update({"file_hash_name": e["name"], "file_hash_family": e["family"]})
            return ToolResult(True, f"hash {hash[:12]}… : " + (f"CONNU ({e['name']})" if e else "inconnu de la base IOC"),
                              {"entry": e}, facts)
        return ToolResult(False, "check_local_ioc : ni ip ni hash fourni", error="bad_args")

    # ------------------------------------------------------------------ inspect_file_hash
    def inspect_file_hash(self, path: str, logged_sha256: str | None = None) -> ToolResult:
        try:
            p = self.ctx.executor.resolve_in_sandbox(path)
            accessible = p.exists()
        except PermissionError:          # chemin hors du bac à sable (ex. fichier d'une machine distante)
            p, accessible = None, False
        if accessible:
            sha = hashlib.sha256(p.read_bytes()).hexdigest()
            facts = {"file_exists": True, "file_sha256": sha, "file_hash_source": "calculé",
                     "file_hash_mismatch": bool(logged_sha256 and logged_sha256 != sha)}
            return ToolResult(True, f"SHA-256 calculé : {sha[:16]}…", {"size": p.stat().st_size}, facts)
        if logged_sha256:   # fichier déjà supprimé : on se rabat sur le hash journalisé
            return ToolResult(True, "fichier absent du disque : utilisation du hash journalisé",
                              {}, {"file_exists": False, "file_sha256": logged_sha256, "file_hash_source": "journal"})
        return ToolResult(False, f"fichier introuvable et aucun hash journalisé : {path}", error="not_found")

    # ------------------------------------------------------------------ propose_response
    def propose_response(self, result, alert) -> ToolResult:
        f = alert.facts
        targets = {"block_ip": alert.src_ip, "monitor": alert.src_ip or f.get("file_path") or alert.host,
                   "quarantine_file": f.get("file_path"), "isolate_host": alert.host, "notify_analyst": alert.id}
        props = []
        for r in sorted(result.recommendations, key=lambda r: -r["cf"]):
            tgt = targets.get(r["action"])
            if tgt:
                props.append(Proposal(r["action"], tgt, r["sensitive"], round(r["cf"], 2), r["rules"]))
        return ToolResult(True, f"{len(props)} action(s) proposée(s)" + (" : " + ", ".join(f"{p.action}({p.target})" for p in props) if props else ""),
                          {"proposals": props})

    # ------------------------------------------------------------------ execute_authorized_action
    def execute_authorized_action(self, action: str, target: str, ttl: int | None = None, note: str = "") -> ToolResult:
        # Défense en profondeur : on revérifie liste blanche et cibles protégées ici aussi.
        if not self._decision.is_whitelisted(action):
            return ToolResult(False, f"{action} refusée : hors liste blanche", error="not_whitelisted")
        if self._decision.is_protected(action, target):
            return ToolResult(False, f"{action} refusée : cible protégée {target}", error="protected")
        r = self.ctx.executor.execute(action, target, ttl, note)
        return ToolResult(r.ok, r.detail, {"action_result": r})