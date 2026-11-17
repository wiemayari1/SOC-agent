"""Module de décision et de sécurité : liste blanche, permissions, niveaux d'autonomie.

Niveau 1 : l'agent PROPOSE seulement.
Niveau 2 : l'agent PRÉPARE et attend une validation humaine pour chaque action.
Niveau 3 : l'agent EXÉCUTE les actions autorisées, sauf actions sensibles / confiance insuffisante.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Proposal:
    action: str
    target: str
    sensitive: bool
    cf: float
    rules: list[str] = field(default_factory=list)


@dataclass
class Decision:
    action: str
    target: str
    sensitive: bool
    cf: float
    status: str          # execute | pending_approval | proposed | denied   (puis executed | failed)
    reason: str
    level: int


class DecisionModule:
    def __init__(self, policy: dict):
        self.policy = policy

    def is_whitelisted(self, action: str) -> bool:
        return action in self.policy["actions"]

    def is_protected(self, action: str, target: str) -> bool:
        if action in ("block_ip", "monitor") and target in self.policy.get("protected_ips", []):
            return True
        if action == "isolate_host" and target in self.policy.get("protected_hosts", []):
            return True
        return False

    def evaluate(self, p: Proposal, level: int | None = None) -> Decision:
        level = level or self.policy["autonomy_level"]
        mk = lambda status, reason: Decision(p.action, p.target, p.sensitive, p.cf, status, reason, level)
        spec = self.policy["actions"].get(p.action)
        if spec is None:
            return mk("denied", "action absente de la liste blanche")
        if self.is_protected(p.action, p.target):
            return mk("denied", f"cible protégée ({p.target}) : décision laissée à l'analyste")
        if level <= 1:
            return mk("proposed", "niveau 1 : l'agent propose uniquement")
        if level == 2:
            return mk("pending_approval", "niveau 2 : validation humaine requise")
        if p.sensitive:
            return mk("pending_approval", "action sensible : validation humaine requise")
        if not spec.get("auto", False):
            return mk("pending_approval", "action non automatique selon la politique")
        if p.cf < spec.get("min_cf", 0.0):
            return mk("pending_approval", f"certitude {p.cf:.2f} < seuil d'automatisation {spec['min_cf']:.2f}")
        return mk("execute", f"autorisée au niveau 3 (certitude {p.cf:.2f} ≥ {spec.get('min_cf', 0):.2f})")
