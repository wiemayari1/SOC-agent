"""Chaîne complète : journaux -> événements -> alertes -> enquête de l'agent -> décision -> réponse -> rapport.
Contient aussi le flux de validation humaine (approve / reject / rollback)."""
from __future__ import annotations

from dataclasses import dataclass

from . import config
from .agent.agent import SocAgent, Step
from .agent.tools import ToolBox, ToolContext
from .decision import Decision, DecisionModule
from .extractor import build_alerts
from .parsers import load_all
from .reporting import write_report
from .response import Executor
from .storage import Database, compute_status


@dataclass
class Runtime:
    ws: object
    policy: dict
    events: list
    stats: dict
    db: Database
    executor: Executor
    toolbox: ToolBox
    agent: SocAgent
    decision: DecisionModule


def build_runtime(ws, level: int | None = None, reset_db: bool = False, load_events: bool = True, live: bool = False) -> Runtime:
    policy = config.load_policy()
    ov = config.runtime_override(ws)
    lvl = level or ov.get("autonomy_level")
    if lvl:
        policy["autonomy_level"] = int(lvl)
    if live:
        policy["live_mode"] = True
    ws.ensure()
    events, stats = load_all(ws) if load_events else ([], {})
    db = Database(ws.db_path)
    if reset_db:
        db.reset()
    executor = Executor(ws, policy)
    ctx = ToolContext(events, config.load_patterns(), config.load_ioc(), ws, policy, executor)
    tb = ToolBox(ctx)
    return Runtime(ws, policy, events, stats, db, executor, tb, SocAgent(tb, policy["agent"]), DecisionModule(policy))


def _refresh(rt: Runtime, iid: str):
    inc = rt.db.incident(iid)
    rt.db.set_status(iid, compute_status(rt.db.decisions(iid), inc["verdict"]))
    write_report(rt.db, rt.ws, iid)


def process_alert(rt: Runtime, alert):
    """Enquête de l'agent -> décisions -> exécution contrôlée -> rapport, pour UNE alerte. Retourne (id incident, enquête)."""
    db = rt.db
    alert.id = db.next_incident_id()
    db.audit("system", "alerte créée", alert.id, alert.title)
    inv = rt.agent.investigate(alert)
    db.save_incident(inv, "en cours")
    db.add_steps(alert.id, inv.steps)
    db.audit("agent", f"enquête terminée : {inv.verdict}", alert.id, f"certitude={inv.confidence:.2f} sévérité={inv.severity}")
    for p in inv.proposals:
        d: Decision = rt.decision.evaluate(p)
        if d.status == "execute":
            out = rt.toolbox.call("execute_authorized_action", _role="execution", action=d.action, target=d.target,
                                  ttl=rt.policy["actions"][d.action].get("ttl_seconds"), note=inv.verdict)
            r = out.data.get("action_result")
            d.status = "executed" if out.ok else "failed"
            d.reason += " | " + out.summary
            did = db.add_decision(alert.id, d)
            if r:
                db.add_action(did, alert.id, d.action, d.target, r)
                ver = f"Vérification : {r.verification}" if r.verified else f"VÉRIFICATION ÉCHOUÉE : {r.verification}"
                db.add_steps(alert.id, [Step("execution", f"{d.action}({d.target}) → {r.detail}"), Step("verification", ver)],
                             db.step_count(alert.id))
                if out.ok and not r.verified:
                    d.status = "failed"
                    db.update_decision(did, "failed", "action exécutée mais non vérifiée")
            db.audit("agent", f"action {d.action} {d.status}", alert.id, d.target)
        else:
            db.add_decision(alert.id, d)
            db.audit("decision-module", f"{d.action} → {d.status}", alert.id, d.reason)
    _refresh(rt, alert.id)
    return alert.id, inv


def run(ws, level: int | None = None, reset: bool = True, log=print) -> list[str]:
    rt = build_runtime(ws, level, reset_db=reset)
    db = rt.db
    alerts = build_alerts(rt.events, rt.toolbox.ctx.patterns, rt.policy["thresholds"])
    log(f"{len(rt.events)} événements chargés, {len(alerts)} alertes candidates, niveau d'autonomie {rt.policy['autonomy_level']}.")
    for name, st in rt.stats.items():
        log(f"  source {name} : {st['events']} événement(s) lu(s), {st['skipped']} ligne(s) ignorée(s)")
    ids = []
    for alert in alerts:
        iid, inv = process_alert(rt, alert)
        inc = db.incident(iid)
        log(f"  {iid} [{alert.scenario:<14}] {alert.key[:28]:<28} {inv.verdict:<32} certitude={inv.confidence:.2f} {inv.severity:<8} → {inc['status']}")
        ids.append(iid)
    db.close()
    return ids


# ------------------------------------------------------------------ validation humaine
def approve(rt: Runtime, decision_id: int, actor: str = "analyste") -> str:
    d = rt.db.decision(decision_id)
    if not d or d["status"] != "pending_approval":
        return "décision introuvable ou déjà traitée"
    out = rt.toolbox.call("execute_authorized_action", _role="execution", action=d["action"], target=d["target"],
                          ttl=rt.policy["actions"].get(d["action"], {}).get("ttl_seconds"), note="validé par un analyste")
    r = out.data.get("action_result")
    ok = out.ok and (r is None or r.verified)
    rt.db.update_decision(decision_id, "executed" if ok else "failed", None if ok else out.summary, by=actor)
    if r:
        rt.db.add_action(decision_id, d["incident_id"], d["action"], d["target"], r)
        rt.db.add_steps(d["incident_id"], [Step("human", f"{actor} a validé {d['action']}({d['target']})"),
                                           Step("execution", f"{d['action']}({d['target']}) → {r.detail}"),
                                           Step("verification", f"Vérification : {r.verification}")], rt.db.step_count(d["incident_id"]))
    rt.db.audit(actor, f"validation de {d['action']} → {'exécutée' if ok else 'échec'}", d["incident_id"], d["target"])
    _refresh(rt, d["incident_id"])
    return out.summary


def reject(rt: Runtime, decision_id: int, actor: str = "analyste") -> str:
    d = rt.db.decision(decision_id)
    if not d or d["status"] != "pending_approval":
        return "décision introuvable ou déjà traitée"
    rt.db.update_decision(decision_id, "rejected", "rejetée par l'analyste", by=actor)
    rt.db.add_steps(d["incident_id"], [Step("human", f"{actor} a REJETÉ {d['action']}({d['target']})")], rt.db.step_count(d["incident_id"]))
    rt.db.audit(actor, f"rejet de {d['action']}", d["incident_id"], d["target"])
    _refresh(rt, d["incident_id"])
    return "décision rejetée"


def rollback(rt: Runtime, action_id: int, actor: str = "analyste") -> str:
    a = rt.db.action(action_id)
    if not a or a["rolled_back"]:
        return "action introuvable ou déjà annulée"
    r = rt.executor.rollback(a["action"], a["target"])
    if r.ok:
        rt.db.mark_rolled_back(action_id)
        rt.db.update_decision(a["decision_id"], "rolled_back", "annulée par l'analyste", by=actor)
    rt.db.audit(actor, f"retour arrière {a['action']} → {'ok' if r.ok else 'échec'}", a["incident_id"], r.detail)
    _refresh(rt, a["incident_id"])
    return r.detail
