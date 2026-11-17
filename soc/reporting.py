"""Module de reporting : rapport Markdown d'incident généré à partir de la base (traçabilité)."""
from __future__ import annotations

import json

KIND_LABEL = {"perception": "Perception", "reasoning": "Raisonnement", "plan": "Planification", "action": "Action",
              "observation": "Observation", "evaluation": "Évaluation", "decision": "Décision", "execution": "Exécution",
              "verification": "Vérification", "human": "Validation humaine"}
STATUS_LABEL = {"executed": "exécutée", "failed": "échec", "pending_approval": "en attente de validation humaine",
                "proposed": "proposée (niveau 1)", "denied": "refusée", "rejected": "rejetée par l'analyste",
                "rolled_back": "annulée (retour arrière)"}


def build_report(db, iid: str) -> str:
    inc = db.incident(iid)
    facts, hyps = json.loads(inc["facts"]), json.loads(inc["hypotheses"])
    L = []
    L.append(f"# Rapport d'incident {iid}\n")
    L.append(f"**{inc['title']}**\n")
    L.append("| Champ | Valeur |\n|---|---|")
    for k, v in [("Scénario", inc["scenario"]), ("Source / cible", inc["src_ip"] or inc["host"]), ("Période", f"{inc['first_ts']} → {inc['last_ts']}"),
                 ("Événements liés", inc["event_count"]), ("Sévérité", inc["severity"].upper()),
                 ("Verdict", inc["verdict"]), ("Certitude (CF)", f"{inc['confidence']:.2f}"), ("Statut", inc["status"])]:
        L.append(f"| {k} | {v} |")
    L.append("\n## 1. Résumé\n")
    L.append(f"L'agent conclut : **{inc['verdict']}**"
             + (f" (hypothèse `{inc['hypothesis']}`, certitude {inc['confidence']:.2f})" if inc["hypothesis"] else "")
             + f", sévérité **{inc['severity']}**. Fin d'enquête : {inc['stop_reason']}.")
    L.append("\n## 2. Preuves (extraits des journaux)\n\n```")
    L += json.loads(inc["evidence"])
    L.append("```")
    L.append("\n## 3. Faits retenus par l'agent\n\n| Fait | Valeur |\n|---|---|")
    for k, v in facts.items():
        L.append(f"| `{k}` | {v} |")
    L.append("\n## 4. Raisonnement de l'agent (révision de ses croyances)\n")
    L.append("| Révision | Preuve | Constat (valeur réelle) | Effet sur les croyances | Poids |\n|---|---|---|---|---|")
    for e in db.evidence(iid):
        obs = " ET ".join(f"`{m['fact']} {m['op']} {m['value']}` (réel : {m['actual']})" for m in json.loads(e["observed"]))
        L.append(f"| {e['step']} | **{e['ev_id']}** {e['label']} | {obs} | {'; '.join(json.loads(e['effects']))} | {e['weight']:.2f} |")
    L.append("\nCertitudes finales : " + (", ".join(f"`{k}` = {v:.2f}" for k, v in hyps.items()) or "aucune hypothèse"))
    L.append("\n## 5. Investigation de l'agent\n")
    for s in db.steps(iid):
        if s["kind"] in ("execution", "verification", "human"):
            continue
        L.append(f"{s['n']}. **{KIND_LABEL.get(s['kind'], s['kind'])}** — {s['text']}")
    L.append("\n## 6. Décisions et actions\n")
    decs = db.decisions(iid)
    if not decs:
        L.append("Aucune action nécessaire.")
    else:
        L.append("| # | Action | Cible | Sensible | CF | Statut | Raison |\n|---|---|---|---|---|---|---|")
        for d in decs:
            L.append(f"| {d['id']} | `{d['action']}` | {d['target']} | {'oui' if d['sensitive'] else 'non'} | {d['cf']:.2f} | "
                     f"{STATUS_LABEL.get(d['status'], d['status'])} | {d['reason']} |")
    acts = db.actions(iid)
    if acts:
        L.append("\n### Vérification après exécution\n\n| Action | Résultat | Vérifiée | Contrôle effectué |\n|---|---|---|---|")
        for a in acts:
            L.append(f"| `{a['action']}` {a['target']} | {a['detail']}{' (annulée)' if a['rolled_back'] else ''} | "
                     f"{'oui' if a['verified'] else 'NON'} | {a['verification']} |")
    L.append("\n## 7. Journal d'audit\n")
    for e in db.audit_log(iid):
        L.append(f"- `{e['ts']}` **{e['actor']}** — {e['event']} {e['detail']}")
    return "\n".join(L) + "\n"


def write_report(db, ws, iid: str):
    ws.reports.mkdir(parents=True, exist_ok=True)
    p = ws.reports / f"{iid}.md"
    p.write_text(build_report(db, iid), encoding="utf-8")
    return p
