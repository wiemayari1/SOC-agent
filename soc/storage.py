"""Stockage SQLite : incidents, étapes, preuves retenues par l'agent, décisions, actions, journal d'audit."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, created_at TEXT, scenario TEXT, title TEXT, src_ip TEXT,
  host TEXT, severity TEXT, confidence REAL, verdict TEXT, hypothesis TEXT, status TEXT, facts TEXT, hypotheses TEXT,
  evidence TEXT, stop_reason TEXT, first_ts TEXT, last_ts TEXT, event_count INTEGER);
CREATE TABLE IF NOT EXISTS steps(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, n INTEGER, ts TEXT, kind TEXT,
  tool TEXT, args TEXT, text TEXT);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, step INTEGER, ev_id TEXT,
  label TEXT, detail TEXT, observed TEXT, effects TEXT, weight REAL);
CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, ts TEXT, action TEXT,
  target TEXT, sensitive INTEGER, cf REAL, status TEXT, reason TEXT, level INTEGER, resolved_by TEXT, resolved_at TEXT);
CREATE TABLE IF NOT EXISTS actions(id INTEGER PRIMARY KEY AUTOINCREMENT, decision_id INTEGER, incident_id TEXT, ts TEXT,
  action TEXT, target TEXT, ok INTEGER, detail TEXT, verified INTEGER, verification TEXT, rolled_back INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS signatures(sig TEXT PRIMARY KEY, incident_id TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS feed(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, agent TEXT, rule_id TEXT, level INTEGER,
  description TEXT, src_ip TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, event TEXT, incident_id TEXT, detail TEXT);
"""


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _j(o) -> str:
    return json.dumps(o, ensure_ascii=False, default=str)


class Database:
    def __init__(self, path):
        self.path = str(path)
        self.con = sqlite3.connect(self.path, timeout=30)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)

    def reset(self):
        for t in ("incidents", "steps", "evidence", "decisions", "actions", "audit", "meta", "signatures", "feed"):
            self.con.execute(f"DELETE FROM {t}")
        self.con.commit()

    def close(self):
        self.con.close()

    # ------------------------------------------------------------------ écriture
    def next_incident_id(self) -> str:
        n = self.con.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        return f"INC-{n + 1:04d}"

    def save_incident(self, inv, status: str):
        a, r = inv.alert, inv.result
        self.con.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (a.id, _now(), a.scenario, a.title, a.src_ip, a.host, inv.severity, inv.confidence, inv.verdict,
                          inv.hypothesis, status, _j(inv.facts), _j(r.hypotheses), _j([e.raw for e in a.events[:8]]),
                          inv.stop_reason, a.first_ts.isoformat(), a.last_ts.isoformat(), len(a.events)))
        for e in r.evidence:
            self.con.execute("INSERT INTO evidence(incident_id,step,ev_id,label,detail,observed,effects,weight) VALUES(?,?,?,?,?,?,?,?)",
                             (a.id, e.step, e.id, e.label, e.detail, _j(e.observed), _j(e.effects), e.weight))
        self.con.commit()

    def add_steps(self, incident_id: str, steps, start: int = 0):
        for i, s in enumerate(steps, start=start + 1):
            self.con.execute("INSERT INTO steps(incident_id,n,ts,kind,tool,args,text) VALUES(?,?,?,?,?,?,?)",
                             (incident_id, i, s.ts, s.kind, s.tool, _j(s.args) if s.args else None, s.text))
        self.con.commit()

    def step_count(self, incident_id: str) -> int:
        return self.con.execute("SELECT COUNT(*) FROM steps WHERE incident_id=?", (incident_id,)).fetchone()[0]

    def add_decision(self, incident_id: str, d) -> int:
        cur = self.con.execute("INSERT INTO decisions(incident_id,ts,action,target,sensitive,cf,status,reason,level) VALUES(?,?,?,?,?,?,?,?,?)",
                               (incident_id, _now(), d.action, d.target, int(d.sensitive), d.cf, d.status, d.reason, d.level))
        self.con.commit()
        return cur.lastrowid

    def update_decision(self, decision_id: int, status: str, reason: str | None = None, by: str | None = None):
        self.con.execute("UPDATE decisions SET status=?, reason=COALESCE(?,reason), resolved_by=?, resolved_at=? WHERE id=?",
                         (status, reason, by, _now() if by else None, decision_id))
        self.con.commit()

    def add_action(self, decision_id, incident_id, action, target, r):
        cur = self.con.execute("INSERT INTO actions(decision_id,incident_id,ts,action,target,ok,detail,verified,verification) VALUES(?,?,?,?,?,?,?,?,?)",
                               (decision_id, incident_id, _now(), action, target, int(r.ok), r.detail, int(r.verified), r.verification))
        self.con.commit()
        return cur.lastrowid

    def mark_rolled_back(self, action_id: int):
        self.con.execute("UPDATE actions SET rolled_back=1 WHERE id=?", (action_id,))
        self.con.commit()

    def set_status(self, incident_id: str, status: str):
        self.con.execute("UPDATE incidents SET status=? WHERE id=?", (status, incident_id))
        self.con.commit()

    def audit(self, actor: str, event: str, incident_id: str | None = None, detail: str = ""):
        self.con.execute("INSERT INTO audit(ts,actor,event,incident_id,detail) VALUES(?,?,?,?,?)", (_now(), actor, event, incident_id, detail))
        self.con.commit()

    # ------------------------------------------------------------------ surveillance continue
    def meta_set(self, key: str, value) -> None:
        self.con.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, _j(value)))
        self.con.commit()

    def meta_get(self, key: str, default=None):
        r = self.con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(r[0]) if r else default

    def has_signature(self, sig: str) -> bool:
        return self.con.execute("SELECT 1 FROM signatures WHERE sig=?", (sig,)).fetchone() is not None

    def add_signature(self, sig: str, incident_id: str) -> None:
        self.con.execute("INSERT OR IGNORE INTO signatures(sig,incident_id,ts) VALUES(?,?,?)", (sig, incident_id, _now()))
        self.con.commit()

    def add_feed(self, rows: list[tuple], keep: int = 1000) -> None:
        self.con.executemany("INSERT INTO feed(ts,agent,rule_id,level,description,src_ip,summary) VALUES(?,?,?,?,?,?,?)", rows)
        self.con.execute("DELETE FROM feed WHERE id <= (SELECT MAX(id) FROM feed) - ?", (keep,))
        self.con.commit()

    def feed(self, limit: int = 100):
        return self._rows("SELECT * FROM feed ORDER BY id DESC LIMIT ?", limit)

    # ------------------------------------------------------------------ lecture
    def _rows(self, sql, *a):
        return [dict(r) for r in self.con.execute(sql, a).fetchall()]

    def incidents(self):
        return self._rows("SELECT * FROM incidents ORDER BY id")

    def incident(self, iid):
        r = self._rows("SELECT * FROM incidents WHERE id=?", iid)
        return r[0] if r else None

    def steps(self, iid): return self._rows("SELECT * FROM steps WHERE incident_id=? ORDER BY n", iid)
    def evidence(self, iid): return self._rows("SELECT * FROM evidence WHERE incident_id=? ORDER BY id", iid)
    def decisions(self, iid=None):
        return self._rows("SELECT * FROM decisions" + (" WHERE incident_id=?" if iid else "") + " ORDER BY id", *([iid] if iid else []))
    def decision(self, did):
        r = self._rows("SELECT * FROM decisions WHERE id=?", did)
        return r[0] if r else None
    def actions(self, iid=None):
        return self._rows("SELECT * FROM actions" + (" WHERE incident_id=?" if iid else "") + " ORDER BY id", *([iid] if iid else []))
    def action(self, aid):
        r = self._rows("SELECT * FROM actions WHERE id=?", aid)
        return r[0] if r else None
    def audit_log(self, iid=None):
        return self._rows("SELECT * FROM audit" + (" WHERE incident_id=?" if iid else "") + " ORDER BY id", *([iid] if iid else []))
    def pending(self): return self._rows("SELECT * FROM decisions WHERE status='pending_approval' ORDER BY id")


def compute_status(decisions: list[dict], verdict: str) -> str:
    st = [d["status"] for d in decisions]
    if "pending_approval" in st:
        return "en attente de validation"
    if "failed" in st or "denied" in st:
        return "à traiter par l'analyste"
    if "proposed" in st:
        return "proposition en attente"
    if "executed" in st:
        return "traité (action vérifiée)"
    if verdict.startswith("bénin"):
        return "clos (faux positif)"
    return "clos (aucune action)"
