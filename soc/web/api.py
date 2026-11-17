"""Logique de l'API web : met en forme les données (SQLite, état du pare-feu simulé, statut Wazuh)."""
from __future__ import annotations

import json
import threading
import time
from collections import Counter
from datetime import datetime

from .. import config, pipeline
from ..events import utcnow
from ..reporting import build_report
from ..response import Executor
from ..storage import Database
from ..wazuh import ManagerApi, WazuhError

SEVERITIES = ["critical", "high", "medium", "low", "info"]


class Api:
    def __init__(self, ws, wcfg: dict | None = None):
        self.ws, self.wcfg = ws, wcfg
        self._agents_cache = (0.0, None)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ utilitaires
    def _db(self) -> Database:
        return Database(self.ws.db_path)

    def _level(self) -> int:
        """Niveau effectif : réglage de l'interface > config/wazuh.json (mode live) > config/policy.json."""
        pol = config.load_policy()
        return int(config.runtime_override(self.ws).get("autonomy_level")
                   or (self.wcfg or {}).get("autonomy_level") or pol["autonomy_level"])

    def live_status(self, db: Database) -> dict:
        st = db.meta_get("live_status")
        if not st:
            return {"mode": db.meta_get("mode", "idle"), "ok": True, "message": ""}
        age = (utcnow() - datetime.fromisoformat(st["last_poll"])).total_seconds()
        st["age_seconds"] = int(age)
        st["stale"] = age > max(30, 4 * float(st.get("poll_seconds", 10)))
        if st.get("last_event_ts"):
            st["last_event_age_seconds"] = int((utcnow() - datetime.fromisoformat(st["last_event_ts"])).total_seconds())
        return st

    @staticmethod
    def _incident_row(i: dict, pending: dict) -> dict:
        return {k: i[k] for k in ("id", "scenario", "title", "src_ip", "host", "severity", "confidence", "verdict", "hypothesis",
                                   "status", "first_ts", "last_ts", "event_count")} | {"pending": pending.get(i["id"], 0)}

    # ------------------------------------------------------------------ lecture
    def summary(self) -> dict:
        db = self._db()
        try:
            incs = db.incidents()
            pend = db.pending()
            st = Executor(self.ws, {"actions": {}}).state()
            return {"incidents": len(incs), "pending": len(pend), "autonomy": self._level(), "live": self.live_status(db),
                    "blocked": len(st["blocked"]), "now": utcnow().isoformat(timespec="seconds")}
        finally:
            db.close()

    def overview(self) -> dict:
        db = self._db()
        try:
            incs, pend = db.incidents(), db.pending()
            pending = Counter(d["incident_id"] for d in pend)
            sev = Counter(i["severity"] for i in incs)
            sc = Counter(i["scenario"] for i in incs)
            decs = db.decisions()
            executed = {d["incident_id"] for d in decs if d["status"] == "executed"}
            st = Executor(self.ws, {"actions": {}}).state()
            timeline = []
            if incs:
                ts = sorted(datetime.fromisoformat(i["first_ts"]) for i in incs)
                lo, hi = ts[0], ts[-1]
                span = max((hi - lo).total_seconds(), 60)
                n = 12
                w = span / n
                buckets = [{"t": (lo.timestamp() + k * w), "count": 0, "critical": 0} for k in range(n)]
                for i in incs:
                    k = min(int((datetime.fromisoformat(i["first_ts"]) - lo).total_seconds() / w), n - 1)
                    buckets[k]["count"] += 1
                    buckets[k]["critical"] += i["severity"] in ("critical", "high")
                timeline = [{"t": datetime.fromtimestamp(b["t"]).isoformat(timespec="seconds"), "count": b["count"], "critical": b["critical"]} for b in buckets]
            return {
                "kpi": {"incidents": len(incs), "critical_high": sev["critical"] + sev["high"], "pending": len(pend),
                        "auto_handled": len(executed - set(pending)), "false_positives": sum(i["verdict"].startswith("bénin") for i in incs),
                        "blocked": len(st["blocked"]), "avg_confidence": round(sum(i["confidence"] for i in incs) / len(incs), 2) if incs else 0},
                "by_severity": {s: sev.get(s, 0) for s in SEVERITIES}, "by_scenario": dict(sc),
                "timeline": timeline, "recent": [self._incident_row(i, pending) for i in sorted(incs, key=lambda x: x["first_ts"], reverse=True)[:6]],
                "pending": [self._pending_row(db, d) for d in pend[:4]],
                "live": self.live_status(db), "autonomy": self._level(),
            }
        finally:
            db.close()

    def incidents(self, q: dict) -> list[dict]:
        db = self._db()
        try:
            pending = Counter(d["incident_id"] for d in db.pending())
            rows = [self._incident_row(i, pending) for i in db.incidents()]
        finally:
            db.close()
        text = (q.get("q") or [""])[0].lower()
        for key in ("severity", "scenario", "status"):
            val = (q.get(key) or [""])[0]
            if val:
                rows = [r for r in rows if r[key] == val]
        if text:
            rows = [r for r in rows if text in json.dumps(r, ensure_ascii=False).lower()]
        return sorted(rows, key=lambda r: r["first_ts"], reverse=True)

    def incident(self, iid: str) -> dict | None:
        db = self._db()
        try:
            inc = db.incident(iid)
            if not inc:
                return None
            acts = db.actions(iid)
            by_dec = {}
            for a in acts:
                by_dec.setdefault(a["decision_id"], []).append(a)
            decisions = [dict(d, actions=by_dec.get(d["id"], [])) for d in db.decisions(iid)]
            return {
                "incident": {k: inc[k] for k in ("id", "scenario", "title", "src_ip", "host", "severity", "confidence", "verdict", "hypothesis",
                                                  "status", "stop_reason", "first_ts", "last_ts", "event_count", "created_at")},
                "facts": json.loads(inc["facts"]), "hypotheses": json.loads(inc["hypotheses"]), "evidence": json.loads(inc["evidence"]),
                "reasoning": [dict(e, observed=json.loads(e["observed"]), effects=json.loads(e["effects"])) for e in db.evidence(iid)],
                "steps": db.steps(iid), "decisions": decisions, "audit": db.audit_log(iid),
            }
        finally:
            db.close()

    def _pending_row(self, db: Database, d: dict) -> dict:
        inc = db.incident(d["incident_id"])
        return dict(d, incident_title=inc["title"], severity=inc["severity"], scenario=inc["scenario"])

    def pending(self) -> list[dict]:
        db = self._db()
        try:
            return [self._pending_row(db, d) for d in db.pending()]
        finally:
            db.close()

    def feed(self, limit: int = 100) -> dict:
        db = self._db()
        try:
            return {"rows": db.feed(limit), "live": self.live_status(db)}
        finally:
            db.close()

    def firewall(self) -> dict:
        st = Executor(self.ws, config.load_policy()).state()
        notes = []
        f = self.ws.state / "notifications.jsonl"
        if f.exists():
            for line in f.read_text(encoding="utf-8").splitlines()[-30:]:
                try:
                    notes.append(json.loads(line))
                except ValueError:
                    pass
        return {"state": st, "notifications": notes[::-1]}

    def system(self) -> dict:
        pol = config.load_policy()
        db = self._db()
        try:
            live = self.live_status(db)
        finally:
            db.close()
        w = None
        if self.wcfg:
            w = {"mode": self.wcfg.get("mode"), "indexer_url": (self.wcfg.get("indexer") or {}).get("url"),
                 "index_pattern": (self.wcfg.get("indexer") or {}).get("index_pattern"), "file": (self.wcfg.get("file") or {}).get("path"),
                 "api_url": (self.wcfg.get("api") or {}).get("url"), "poll_seconds": self.wcfg.get("poll_seconds"),
                 "settle_seconds": self.wcfg.get("settle_seconds"), "window_minutes": self.wcfg.get("window_minutes")}
        return {"policy": {"autonomy_level": self._level(), "actions": pol["actions"], "protected_ips": pol["protected_ips"],
                           "protected_hosts": pol["protected_hosts"], "agent": pol["agent"], "thresholds": pol["thresholds"]},
                "knowledge": {"bad_ips": len(config.load_ioc()["bad_ips"]), "bad_hashes": len(config.load_ioc()["bad_hashes"])},
                "wazuh": w, "live": live, "agents": self._agents()}

    def _agents(self) -> dict:
        if not (self.wcfg and self.wcfg.get("api")):
            return {"configured": False, "agents": []}
        with self._lock:
            ts, cached = self._agents_cache
            if cached is not None and time.time() - ts < 20:
                return cached
            try:
                res = {"configured": True, "ok": True, **ManagerApi(self.wcfg).status()}
            except WazuhError as e:
                res = {"configured": True, "ok": False, "error": str(e), "agents": []}
            self._agents_cache = (time.time(), res)
            return res

    def report(self, iid: str) -> str | None:
        db = self._db()
        try:
            return build_report(db, iid) if db.incident(iid) else None
        finally:
            db.close()

    # ------------------------------------------------------------------ actions (POST)
    def _runtime(self):
        return pipeline.build_runtime(self.ws, load_events=False, live=bool(self.wcfg))

    def act(self, kind: str, ident: int, actor: str = "analyste") -> dict:
        rt = self._runtime()
        try:
            if kind == "approve":
                msg = pipeline.approve(rt, ident, actor)
            elif kind == "reject":
                msg = pipeline.reject(rt, ident, actor)
            else:
                msg = pipeline.rollback(rt, ident, actor)
            return {"ok": True, "message": msg}
        finally:
            rt.db.close()

    def set_autonomy(self, level: int) -> dict:
        if level not in (1, 2, 3):
            raise ValueError("niveau d'autonomie invalide")
        config.set_runtime_override(self.ws, autonomy_level=level)
        db = self._db()
        try:
            db.audit("analyste", f"niveau d'autonomie changé : {level}", None, "")
        finally:
            db.close()
        return {"ok": True, "autonomy": level}
