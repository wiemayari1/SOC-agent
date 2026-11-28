"""Surveillance continue : lit Wazuh en boucle, détecte, enquête (agent) et traite les incidents au fil de l'eau.

Cycle (toutes les `poll_seconds`) :
  1. récupérer les nouvelles alertes Wazuh (indexeur ou fichier) ;
  2. les convertir en événements normalisés (dédoublonnés) et les garder dans une fenêtre glissante ;
  3. recalculer les alertes candidates ; une alerte est traitée quand elle est « mûre »
     (plus d'activité depuis `settle_seconds`, ou succès après échecs SSH / fichier suspect = urgence, ou attaque longue) ;
  4. chaque alerte n'est traitée qu'une fois par « signature » (scénario + cible + ordre de grandeur du volume).
"""
from __future__ import annotations

import hashlib
import math
import threading
from datetime import datetime, timedelta

from . import config
from .events import utcnow
from .extractor import Alert, build_alerts
from .pipeline import build_runtime, process_alert
from .wazuh import Converter, WazuhError, feed_row, make_source


def alert_signature(a: Alert) -> str:
    f = a.facts
    if a.scenario == "ssh_bruteforce":
        n, extra = f["ssh_failed_count"], f["ssh_success_after_failures"]
    elif a.scenario == "port_scan":
        n, extra = f["scan_distinct_ports_total"], ""
    elif a.scenario == "web_sqli":
        n, extra = f["web_sqli_strong_hits"] + f["web_sqli_weak_hits"] + int(f["web_scanner_ua"]), ""
    elif a.kind == "ransomware_burst":
        n, extra = f.get("file_ransom_burst_count", 1), ""
    else:
        n, extra = 1, ""
    return f"{a.scenario}|{a.key}|{int(math.log2(max(n, 1)))}|{extra}"


def event_key(ev) -> str:
    return hashlib.sha1(f"{ev.ts.isoformat()}|{ev.source}|{ev.type}|{ev.src_ip}|{ev.user}|{ev.raw}".encode()).hexdigest()


class LiveMonitor(threading.Thread):
    def __init__(self, ws, wcfg: dict, level: int | None = None, log=print, source=None):
        super().__init__(daemon=True, name="soc-live-monitor")
        self.ws, self.cfg, self.level, self.log = ws, wcfg, level, log
        self.source = source or make_source(wcfg)
        self.stop_event = threading.Event()
        self.poll = float(wcfg.get("poll_seconds", 10))
        self.window = timedelta(minutes=float(wcfg.get("window_minutes", 60)))
        self.settle = float(wcfg.get("settle_seconds", 45))
        self.max_wait = float(wcfg.get("max_wait_seconds", 300))
        self.buffer: list = []
        self.seen_hits: dict[str, datetime] = {}
        self.seen_events: dict[str, datetime] = {}
        self.hits_total = 0
        self.incidents_created = 0
        self.last_event_ts = None
        self.started_at = utcnow()
        self.rt = None

    def stop(self):
        self.stop_event.set()

    # ------------------------------------------------------------------ statut visible dans l'interface
    def _status(self, ok: bool, message: str):
        self.rt.db.meta_set("live_status", {
            "mode": "live", "source": self.source.description, "kind": self.source.kind, "ok": ok, "message": message,
            "last_poll": utcnow().isoformat(timespec="seconds"), "poll_seconds": self.poll,
            "last_event_ts": self.last_event_ts.isoformat(timespec="seconds") if self.last_event_ts else None,
            "buffer": len(self.buffer), "hits_total": self.hits_total, "incidents_created": self.incidents_created,
            "started_at": self.started_at.isoformat(timespec="seconds"), "window_minutes": self.window.total_seconds() / 60,
        })

    def is_mature(self, a: Alert, now: datetime) -> bool:
        if a.facts.get("ssh_success_after_failures"):
            return True                                              # urgence : succès après force brute
        if a.scenario == "malicious_file" and a.kind == "suspicious_file":
            return True                                              # fichier suspect isolé : pas de rafale à attendre
        if (now - a.last_ts).total_seconds() >= self.settle:
            return True                                              # l'activité s'est calmée
        return (a.last_ts - a.first_ts).total_seconds() >= self.max_wait   # attaque longue : on n'attend pas la fin

    # ------------------------------------------------------------------ un cycle
    def cycle(self, now: datetime | None = None) -> int:
        now = now or utcnow()
        ov = config.runtime_override(self.ws).get("autonomy_level")
        self.rt.policy["autonomy_level"] = int(ov or self.level or self.cfg.get("autonomy_level") or self.rt.policy["autonomy_level"])
        raw = self.source.fetch()
        conv, rows, new_events = self.conv, [], 0
        for hit_id, src in raw:
            if hit_id in self.seen_hits:
                continue
            self.seen_hits[hit_id] = now
            self.hits_total += 1
            try:
                ev = conv.to_event(src)
                rows.append(feed_row(src, ev))
            except (KeyError, ValueError, TypeError):
                continue
            if ev is None:
                continue
            k = event_key(ev)                                        # alertes + archives : même événement vu deux fois
            if k in self.seen_events:
                continue
            self.seen_events[k] = ev.ts
            self.buffer.append(ev)
            new_events += 1
            if self.last_event_ts is None or ev.ts > self.last_event_ts:
                self.last_event_ts = ev.ts
        if rows:
            self.rt.db.add_feed(rows)
        cutoff = now - self.window
        self.buffer[:] = sorted((e for e in self.buffer if e.ts >= cutoff), key=lambda e: e.ts)
        for d in (self.seen_events, self.seen_hits):
            for k in [k for k, v in d.items() if v < cutoff - timedelta(minutes=5)]:
                del d[k]
        created = 0
        for a in build_alerts(self.buffer, self.rt.toolbox.ctx.patterns, self.rt.policy["thresholds"]):
            sig = alert_signature(a)
            if self.rt.db.has_signature(sig) or not self.is_mature(a, now):
                continue
            iid, inv = process_alert(self.rt, a)
            self.rt.db.add_signature(sig, iid)
            created += 1
            self.incidents_created += 1
            self.log(f"[live] {iid} {a.scenario} {a.key} → {inv.verdict} (certitude {inv.confidence:.2f}, {inv.severity})")
        self._status(True, f"{new_events} nouvel(s) événement(s) converti(s), {created} incident(s) créé(s)")
        return created

    # ------------------------------------------------------------------ boucle
    def run(self):
        self.rt = build_runtime(self.ws, self.level, load_events=False, live=True)
        self.rt.toolbox.ctx.events = self.buffer                     # les outils de l'agent voient la fenêtre glissante
        self.conv = Converter(self.rt.toolbox.ctx.patterns)
        self.log(f"[live] surveillance démarrée : {self.source.description}")
        while not self.stop_event.is_set():
            try:
                self.cycle()
            except WazuhError as e:
                self._status(False, str(e))
                self.log(f"[live] {e}")
            except Exception as e:                                   # ne jamais tuer la surveillance
                self._status(False, f"erreur interne : {e!r}")
                self.log(f"[live] erreur interne : {e!r}")
            self.stop_event.wait(self.poll)
        self.rt.db.close()