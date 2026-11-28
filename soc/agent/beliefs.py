"""Raisonnement INTERNE de l'agent : états de croyance et révision à chaque observation.

Il n'y a ici NI base de connaissances externe, NI moteur d'inférence, NI fichier de règles.
L'agent tient un ÉTAT DE CROYANCE (une certitude par hypothèse) et le RÉVISE chaque fois qu'il perçoit
de nouveaux faits (alerte au départ, puis résultat de chaque outil qu'il appelle) :

    observation -> preuves repérées par l'agent -> mise à jour des croyances
                -> gravité, besoins d'information, réponses envisagées

Une preuve a un poids (0..1). Les preuves qui soutiennent une même hypothèse s'accumulent :
    croyance = a + b x (1 - a)         (plus on a de preuves indépendantes, plus l'agent est sûr)
Chaque preuve garde les valeurs réellement observées : l'agent peut justifier toutes ses conclusions.
Aucun appel réseau, aucun modèle de langage : uniquement Python standard.
"""
from __future__ import annotations

import operator
from dataclasses import dataclass, field
from typing import Any

SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]

_OPS = {">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt,
        "==": operator.eq, "!=": operator.ne}


def accumulate(old: float, new: float) -> float:
    """Accumulation de deux preuves positives indépendantes."""
    return old + new * (1.0 - old)


@dataclass
class Evidence:
    """Une preuve repérée par l'agent, avec ce qu'il a observé et ce qu'elle change."""
    step: int                  # numéro de révision (0 = alerte initiale, 1.. = après chaque outil)
    id: str
    label: str
    detail: str
    observed: list[dict]       # [{fact, op, value, actual}]
    effects: list[str]
    weight: float

    def explain(self) -> str:
        obs = " ET ".join(f"{o['fact']} {o['op']} {o['value']} (réel : {o['actual']})" for o in self.observed)
        return f"[{self.id}] {self.label} — constat : {obs} → {'; '.join(self.effects)} (poids = {self.weight:.2f})"


@dataclass
class Assessment:
    """Appréciation de la situation par l'agent à un instant donné."""
    facts: dict
    hypotheses: dict[str, float]
    severity: str
    recommendations: list[dict]
    wanted: list[str]                      # informations que l'agent aimerait obtenir
    evidence: list[Evidence]
    revisions: int

    def malicious(self) -> dict[str, float]:
        return {k: v for k, v in self.hypotheses.items() if k.startswith("h.")}

    def benign(self) -> dict[str, float]:
        return {k: v for k, v in self.hypotheses.items() if k.startswith("benign.")}

    def main(self) -> tuple[str | None, float]:
        """Hypothèse malveillante la plus certaine (nom, certitude). Exclut 'h.multi_stage' (méta-hypothèse)."""
        cands = {k: v for k, v in self.malicious().items() if k != "h.multi_stage"}
        if not cands:
            return None, 0.0
        k = max(cands, key=cands.get)
        return k, cands[k]

    def explain(self) -> str:
        lines = [f"Révision {e.step} — {e.explain()}" for e in self.evidence]
        lines.append("Croyances : " + (", ".join(f"{k}={v:.2f}" for k, v in self.hypotheses.items()) or "aucune"))
        lines.append(f"Gravité : {self.severity}")
        return "\n".join(lines)


class _Ctx:
    """Ce que l'agent « voit » pendant une révision : faits connus + croyances actuelles."""

    def __init__(self, state: "BeliefState", facts: dict, step: int):
        self.st, self.f, self.step = state, facts, step
        self.new: list[Evidence] = []

    # constat sur un fait observé (None si le fait est inconnu ou si le constat est faux)
    def saw(self, fact: str, op: str, value: Any = True) -> dict | None:
        actual = self.f.get(fact)
        if actual is None or not _OPS[op](actual, value):
            return None
        return {"fact": fact, "op": op, "value": value, "actual": actual}

    # constat sur une croyance de l'agent
    def believes(self, name: str, at_least: float | None = None) -> dict | None:
        cf = self.st.hyps.get(name, 0.0)
        if at_least is None:
            return {"fact": name, "op": "certitude >", "value": 0, "actual": round(cf, 2), "cf": cf} if cf > 0 else None
        return {"fact": name, "op": "certitude ≥", "value": at_least, "actual": round(cf, 2), "cf": cf} if cf >= at_least else None

    def note(self, eid: str, label: str, detail: str, observed: list, weight: float, *, hyp: str | None = None,
             sev: str | None = None, recs: tuple = (), wants: tuple = ()) -> None:
        st = self.st
        if not observed or any(o is None for o in observed):
            return
        w = weight * min(o.get("cf", 1.0) for o in observed)
        if eid in st.done:
            # Preuve déjà notée : si elle ne fait que recommander une réponse, l'agent actualise sa certitude
            # (sa croyance a pu augmenter depuis) sans répéter la preuve.
            if recs and not hyp and w > st.ev_by_id[eid].weight:
                st.ev_by_id[eid].weight = w
                for action, _ in recs:
                    st.recs[action]["cf"] = max(st.recs[action]["cf"], w)
            return
        st.done.add(eid)
        effects = []
        if hyp:
            old = st.hyps.get(hyp, 0.0)
            st.hyps[hyp] = accumulate(old, w)
            effects.append(f"{hyp} : certitude {old:.2f} → {st.hyps[hyp]:.2f}")
        if sev:
            st.sev_idx = max(st.sev_idx, SEVERITY_LEVELS.index(sev))
            effects.append(f"gravité ≥ {sev}")
        for action, sensitive in recs:
            cur = st.recs.get(action)
            if cur is None:
                st.recs[action] = {"action": action, "sensitive": sensitive, "cf": w, "rules": [eid]}
            else:
                cur["sensitive"] = cur["sensitive"] or sensitive
                cur["cf"] = max(cur["cf"], w)
                cur["rules"].append(eid)
            effects.append(f"réponse envisagée : {action}" + (" (sensible)" if sensitive else ""))
        for need in wants:
            st.wanted.append(need)
            effects.append(f"besoin d'information : {need}")
        ev = Evidence(self.step, eid, label, detail, observed, effects, w)
        st.evidence.append(ev)
        st.ev_by_id[eid] = ev
        self.new.append(ev)


# ====================================================================== preuves par type de situation
# Chaque fonction regarde la situation et note les preuves qu'elle y trouve. L'ordre va du plus simple
# (faits bruts) au plus élaboré (croyances déjà formées), si bien qu'une seule passe suffit en général.

def _ssh(c: _Ctx) -> None:
    S = c.saw
    c.note("EV-SSH-01", "Rafale d'échecs SSH", "Au moins 10 échecs depuis la même IP dans une fenêtre de 2 min : force brute potentielle.",
           [S("ssh_failed_in_window", ">=", 10)], 0.7, hyp="h.brute_force_ssh", sev="medium", wants=("ip_history",))
    c.note("EV-SSH-02", "Volume élevé d'échecs", "30 échecs ou plus en 2 min : volume incompatible avec un utilisateur légitime.",
           [S("ssh_failed_in_window", ">=", 30)], 0.6, hyp="h.brute_force_ssh", sev="high")
    c.note("EV-SSH-03", "Plusieurs comptes ciblés", "Au moins 4 comptes différents testés : énumération / password spraying.",
           [S("ssh_distinct_users", ">=", 4), S("ssh_failed_in_window", ">=", 10)], 0.5, hyp="h.brute_force_ssh")
    c.note("EV-SSH-04", "IP présente dans la base IOC", "L'IP source figure dans la liste noire locale : indice supplémentaire.",
           [S("ip_blacklisted", "==", True), c.believes("h.brute_force_ssh")], 0.7, hyp="h.brute_force_ssh", sev="high")
    c.note("EV-SSH-05", "Attaque multi-étapes (SSH)", "La même IP est suspecte dans plusieurs scénarios : reconnaissance puis attaque.",
           [S("ip_multi_stage", "==", True), c.believes("h.brute_force_ssh")], 0.7, hyp="h.multi_stage", sev="high")
    c.note("EV-SSH-06", "Compromission probable", "Connexion réussie après une force brute : le compte est probablement compromis.",
           [c.believes("h.brute_force_ssh", 0.6), S("ssh_success_after_failures", "==", True)], 1.0, hyp="h.account_compromise",
           sev="critical", recs=(("block_ip", True), ("notify_analyst", False)), wants=("post_login",))
    c.note("EV-SSH-07", "Activité post-connexion suspecte", "Commandes sensibles exécutées juste après la connexion suspecte.",
           [c.believes("h.account_compromise"), S("post_login_suspicious_cmds", ">=", 1)], 0.8, hyp="h.account_compromise",
           sev="critical", recs=(("notify_analyst", False),))
    c.note("EV-SSH-08", "Blocage conseillé (force brute)", "Force brute probable sans connexion réussie : blocage temporaire de l'IP.",
           [c.believes("h.brute_force_ssh", 0.6), S("ssh_success_after_failures", "==", False)], 1.0, recs=(("block_ip", False),))
    c.note("EV-SSH-09", "Faute de frappe légitime", "Peu d'échecs suivis d'un succès depuis le réseau interne : utilisateur légitime.",
           [S("ssh_failed_in_window", "<", 5), S("ssh_success_after_failures", "==", True), S("src_is_internal", "==", True)], 0.8,
           hyp="benign.user_typo")


def _scan(c: _Ctx) -> None:
    S = c.saw
    c.note("EV-NET-01", "Balayage de nombreux ports", "15 ports distincts ou plus en 60 s depuis la même IP.",
           [S("scan_distinct_ports", ">=", 15)], 0.7, hyp="h.port_scan", sev="medium", wants=("ip_history",))
    c.note("EV-NET-02", "Ports séquentiels", "Les ports sondés sont consécutifs : balayage automatisé.",
           [S("scan_sequential_ratio", ">=", 0.7), S("scan_distinct_ports", ">=", 10)], 0.5, hyp="h.port_scan")
    c.note("EV-NET-03", "Ports sensibles sondés", "Au moins 3 ports sensibles (SSH, SMB, RDP, bases de données…) ciblés.",
           [S("scan_sensitive_ports_hit", ">=", 3)], 0.3, hyp="h.port_scan", sev="medium")
    c.note("EV-NET-04", "IP présente dans la base IOC", "L'IP du scan figure dans la liste noire locale.",
           [S("ip_blacklisted", "==", True), c.believes("h.port_scan")], 0.6, hyp="h.port_scan", sev="medium")
    c.note("EV-NET-05", "Attaque multi-étapes (scan)", "La même IP est suspecte dans plusieurs scénarios.",
           [S("ip_multi_stage", "==", True), c.believes("h.port_scan")], 0.7, hyp="h.multi_stage", sev="high")
    c.note("EV-NET-06", "Blocage conseillé (scan)", "Scan probable : blocage temporaire de l'IP.",
           [c.believes("h.port_scan", 0.7)], 1.0, recs=(("block_ip", False),))
    c.note("EV-NET-07", "Sondage limité", "Entre 5 et 14 ports distincts : reconnaissance possible, peu de certitude.",
           [S("scan_distinct_ports", ">=", 5), S("scan_distinct_ports", "<", 15)], 0.3, hyp="h.port_scan", sev="low")
    c.note("EV-NET-08", "Surveillance conseillée", "Activité limitée : surveiller l'IP sans la bloquer.",
           [S("scan_distinct_ports", ">=", 5), S("scan_distinct_ports", "<", 15), c.believes("h.port_scan")], 1.0,
           recs=(("monitor", False),))


def _web(c: _Ctx) -> None:
    S = c.saw
    c.note("EV-WEB-01", "Motif d'injection SQL fort", "Au moins une requête contient un motif SQL typique (UNION SELECT, OR 1=1, SLEEP…).",
           [S("web_sqli_strong_hits", ">=", 1)], 0.65, hyp="h.sql_injection", sev="medium", wants=("web_payload_responses",))
    c.note("EV-WEB-02", "Injections répétées", "Au moins 3 requêtes malveillantes : tentative délibérée.",
           [S("web_sqli_strong_hits", ">=", 3)], 0.5, hyp="h.sql_injection", sev="high")
    c.note("EV-WEB-03", "Outil d'attaque détecté", "User-Agent d'un scanner (sqlmap, nikto…).",
           [S("web_scanner_ua", "==", True)], 0.5, hyp="h.sql_injection", sev="medium")
    c.note("EV-WEB-04", "Erreurs serveur après payload", "Des requêtes à payload provoquent des erreurs 5xx : la charge atteint la base de données.",
           [S("web_error_after_sqli", ">=", 1)], 0.4, hyp="h.sql_injection", sev="high")
    c.note("EV-WEB-05", "Apostrophe isolée", "Seulement des caractères suspects faibles (apostrophe) : indice très faible.",
           [S("web_sqli_weak_hits", ">=", 1), S("web_sqli_strong_hits", "==", 0)], 0.2, hyp="h.sql_injection", sev="low")
    c.note("EV-WEB-06", "IP présente dans la base IOC", "L'IP source figure dans la liste noire locale.",
           [S("ip_blacklisted", "==", True), c.believes("h.sql_injection")], 0.5, hyp="h.sql_injection", sev="high")
    c.note("EV-WEB-07", "Blocage conseillé (SQLi)", "Injection SQL probable : blocage temporaire de l'IP.",
           [c.believes("h.sql_injection", 0.6)], 1.0, recs=(("block_ip", False),))
    c.note("EV-WEB-08", "Attaque multi-étapes (web)", "La même IP est suspecte dans plusieurs scénarios.",
           [S("ip_multi_stage", "==", True), c.believes("h.sql_injection")], 0.7, hyp="h.multi_stage", sev="high")
    c.note("EV-WEB-09", "Apostrophe légitime", "Au plus 2 requêtes avec apostrophe et aucun motif fort, depuis le réseau interne.",
           [S("web_sqli_strong_hits", "==", 0), S("web_sqli_weak_hits", "<=", 2), S("src_is_internal", "==", True)], 0.7,
           hyp="benign.legit_apostrophe")
    c.note("EV-WEB-10", "Payloads acceptés (HTTP 200)", "Des requêtes malveillantes ont obtenu une réponse 200 : risque de fuite de données.",
           [S("web_payload_200_count", ">=", 1), c.believes("h.sql_injection", 0.6)], 1.0, sev="high")


def _file(c: _Ctx) -> None:
    S = c.saw
    c.note("EV-FIL-01", "Extension suspecte", "Fichier avec une extension exécutable ou script.",
           [S("file_suspicious_ext", "==", True)], 0.3, hyp="h.malicious_file", sev="low", wants=("file_hash",))
    c.note("EV-FIL-02", "Emplacement inhabituel", "Fichier créé dans un répertoire temporaire (/tmp, /dev/shm…).",
           [S("file_in_suspicious_dir", "==", True)], 0.2, hyp="h.malicious_file")
    c.note("EV-FIL-03", "Double extension", "Nom du type facture.pdf.exe : technique de masquage classique.",
           [S("file_double_extension", "==", True)], 0.4, hyp="h.malicious_file", sev="medium")
    c.note("EV-FIL-04", "Hash connu comme malveillant", "L'empreinte SHA-256 figure dans la base locale d'IOC.",
           [S("file_hash_known_malicious", "==", True)], 0.95, hyp="h.malicious_file", sev="high",
           recs=(("quarantine_file", False), ("notify_analyst", False)))
    c.note("EV-FIL-05", "Fichier suspect inconnu", "Hash absent de la base IOC mais fichier suspect : alerter l'analyste et surveiller.",
           [S("file_hash_known_malicious", "==", False), c.believes("h.malicious_file")], 1.0,
           recs=(("notify_analyst", False), ("monitor", False)))
    c.note("EV-FIL-06", "Incohérence d'empreinte", "Le SHA-256 calculé sur disque diffère du hash journalisé : fichier modifié ou falsifié.",
           [S("file_hash_mismatch", "==", True)], 0.7, hyp="h.malicious_file", sev="high",
           recs=(("notify_analyst", False),))
    c.note("EV-FIL-10", "Rafale de renommages chiffrés", "20 fichiers ou plus renommés avec une extension de ransomware en 60 s.",
           [S("file_ransom_burst_count", ">=", 20)], 0.8, hyp="h.ransomware", sev="critical", wants=("host_file_activity",))
    c.note("EV-FIL-11", "Note de rançon", "Une note de rançon a été déposée sur la machine.",
           [S("file_ransom_note", "==", True), c.believes("h.ransomware")], 0.5, hyp="h.ransomware")
    c.note("EV-FIL-12", "Impact étendu", "30 fichiers chiffrés ou plus sur la machine.",
           [S("file_affected_total", ">=", 30), c.believes("h.ransomware")], 0.5, hyp="h.ransomware")
    c.note("EV-FIL-13", "Isolation conseillée", "Ransomware probable : isoler la machine (action sensible, validation humaine).",
           [c.believes("h.ransomware", 0.7)], 1.0, recs=(("isolate_host", True), ("notify_analyst", False)))


def _cross(c: _Ctx) -> None:
    c.note("EV-MULTI-01", "Réponse à une attaque coordonnée", "Attaque multi-étapes depuis une même IP : blocage soumis à validation humaine.",
           [c.believes("h.multi_stage")], 1.0, sev="high", recs=(("block_ip", True), ("notify_analyst", False)))


_BY_SCENARIO = {"ssh_bruteforce": [_ssh], "port_scan": [_scan], "web_sqli": [_web], "malicious_file": [_file]}


class BeliefState:
    """Mémoire de travail de l'agent pour UNE enquête : ses croyances, ses preuves, ses envies d'information."""

    def __init__(self, scenario: str | None = None):
        self.scenario = scenario
        self.hyps: dict[str, float] = {}
        self.sev_idx = 0
        self.recs: dict[str, dict] = {}
        self.wanted: list[str] = []
        self.evidence: list[Evidence] = []
        self.done: set[str] = set()
        self.ev_by_id: dict[str, Evidence] = {}
        self.revisions = 0

    def revise(self, facts: dict[str, Any]) -> list[Evidence]:
        """Intègre l'état actuel des faits. Retourne les NOUVELLES preuves repérées lors de cette révision."""
        analysers = _BY_SCENARIO.get(self.scenario, [f for fs in _BY_SCENARIO.values() for f in fs]) + [_cross]
        c = _Ctx(self, facts, self.revisions)
        while True:                       # une preuve peut en rendre une autre visible : on repasse jusqu'à stabilité
            before = len(c.new)
            for fn in analysers:
                fn(c)
            if len(c.new) == before:
                break
        self.revisions += 1
        return c.new

    def assess(self, facts: dict[str, Any]) -> Assessment:
        return Assessment(dict(facts), dict(self.hyps), SEVERITY_LEVELS[self.sev_idx], list(self.recs.values()),
                          list(dict.fromkeys(self.wanted)), list(self.evidence), self.revisions)