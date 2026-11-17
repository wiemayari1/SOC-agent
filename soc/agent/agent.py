"""Agent SOC autonome : cycle Perception -> Raisonnement -> Planification -> Action ->
Observation -> Évaluation -> Adaptation -> Décision.

L'agent a : un OBJECTIF (confirmer ou réfuter l'hypothèse principale), un ÉTAT (faits, outils déjà
utilisés, croyances), des OUTILS, et des CONDITIONS d'arrêt.

Aucun LLM, aucune API externe, aucun système expert : l'agent raisonne lui-même, en révisant ses
croyances (voir beliefs.py) après chaque observation, et choisit seul son prochain outil (planner.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from . import planner
from .beliefs import BeliefState


@dataclass
class Step:
    kind: str                 # perception | reasoning | plan | action | observation | evaluation | decision
    text: str
    tool: str | None = None
    args: dict | None = None
    ts: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


@dataclass
class InvestigationState:
    alert: object
    facts: dict
    beliefs: BeliefState = None
    result: object = None
    done: set = field(default_factory=set)
    steps_taken: int = 0


@dataclass
class Investigation:
    alert: object
    steps: list
    result: object
    facts: dict
    confidence: float
    verdict: str
    severity: str
    hypothesis: str | None
    stop_reason: str
    proposals: list


def verdict_for(result) -> tuple[str, str | None, float]:
    name, cf = result.main()
    b = result.benign()
    if b and max(b.values()) >= 0.6 and cf < 0.3:
        return "bénin (faux positif probable)", max(b, key=b.get), max(b.values())
    if cf >= 0.85:
        return "menace confirmée", name, cf
    if cf >= 0.6:
        return "menace probable", name, cf
    if cf >= 0.3:
        return "menace possible", name, cf
    return "aucune menace identifiée", name, cf


class SocAgent:
    def __init__(self, toolbox, cfg: dict):
        self.tb, self.cfg = toolbox, cfg

    def _reason(self, st: InvestigationState) -> object:
        """Raisonnement : l'agent révise ses croyances avec les faits connus et obtient son appréciation courante."""
        st.beliefs.revise(st.facts)
        st.result = st.beliefs.assess(st.facts)
        return st.result

    def _should_stop(self, st) -> tuple[bool, str]:
        name, cf = st.result.main()
        if st.steps_taken >= self.cfg["max_steps"]:
            return True, "budget d'étapes atteint"
        if st.steps_taken >= self.cfg["min_steps"]:
            if cf >= self.cfg["confirm_cf"]:
                return True, f"hypothèse confirmée (CF {cf:.2f} ≥ {self.cfg['confirm_cf']})"
            if cf < self.cfg["refute_cf"]:
                return True, f"hypothèse réfutée ou absente (CF {cf:.2f} < {self.cfg['refute_cf']})"
        return False, ""

    def investigate(self, alert) -> Investigation:
        st = InvestigationState(alert, dict(alert.facts), BeliefState(alert.scenario))
        steps: list[Step] = []
        steps.append(Step("perception", f"Alerte {alert.id} reçue : {alert.title} ({len(alert.events)} événements, "
                                        f"de {alert.first_ts:%H:%M:%S} à {alert.last_ts:%H:%M:%S})."))
        res = self._reason(st)
        name, cf = res.main()
        steps.append(Step("reasoning", f"Raisonnement de l'agent : {len(res.evidence)} preuve(s) repérée(s) "
                                       f"({', '.join(e.id for e in res.evidence) or 'aucune'}). "
                                       f"Hypothèse principale : {name or 'aucune'} (certitude {cf:.2f}), gravité {res.severity}."))
        stop_reason = ""
        while True:
            stop, why = self._should_stop(st)
            if stop:
                stop_reason = why
                break
            need = planner.next_need(st)
            if need is None:
                stop_reason = "plus aucun besoin d'information"
                break
            steps.append(Step("plan", f"Objectif : confirmer ou réfuter « {name or 'activité suspecte'} ». "
                                      f"Prochaine étape : {need.why}. Outil choisi : {need.tool}.", need.tool, need.args))
            out = self.tb.call(need.tool, _role="investigation", **need.args)
            st.done.add(need.key)               # on n'insiste jamais deux fois sur le même besoin
            st.steps_taken += 1
            steps.append(Step("action", f"Appel de {need.tool}({', '.join(f'{k}={v}' for k, v in need.args.items())})", need.tool, need.args))
            steps.append(Step("observation", out.summary if out.ok else f"ÉCHEC : {out.summary} → l'agent poursuit avec les autres sources.", need.tool))
            before = cf
            before_rules = {e.id for e in res.evidence}
            if out.ok:
                st.facts.update(out.new_facts)
            res = self._reason(st)
            name, cf = res.main()
            new_rules = [e.id for e in res.evidence if e.id not in before_rules]
            steps.append(Step("evaluation", f"Certitude {before:.2f} → {cf:.2f}. "
                                            + (f"Nouvelles preuves : {', '.join(new_rules)}. " if new_rules else "Aucune nouvelle preuve. ")
                                            + (f"Gravité {res.severity}." )))
        verdict, vname, vcf = verdict_for(res)
        steps.append(Step("evaluation", f"Fin d'enquête ({stop_reason}). Verdict : {verdict}"
                                        + (f" — {vname} (CF {vcf:.2f})" if vname else "") + f", gravité {res.severity}."))
        props = self.tb.call("propose_response", _role="decision", result=res, alert=alert).data["proposals"]
        steps.append(Step("decision", "Réponses proposées : " + (", ".join(f"{p.action}({p.target}, CF {p.cf:.2f}"
                                                                       + (", sensible" if p.sensitive else "") + ")" for p in props)
                                                                  or "aucune (pas d'action nécessaire)"), "propose_response"))
        return Investigation(alert, steps, res, st.facts, vcf if vname else 0.0, verdict, res.severity, vname, stop_reason, props)
