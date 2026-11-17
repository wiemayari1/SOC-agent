"""Module de réponse : actions SIMULÉES, vérifiables et réversibles.

Aucune commande système réelle (iptables, kill...) n'est exécutée : le pare-feu est un fichier JSON
(data/state/firewall_sim.json) et la quarantaine ne manipule que le bac à sable (data/sandbox).
"""
from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class ActionResult:
    ok: bool
    detail: str
    verified: bool = False
    verification: str = ""
    already_done: bool = False


class Executor:
    def __init__(self, ws, policy: dict):
        self.ws, self.policy = ws, policy
        self.state_file = ws.state / "firewall_sim.json"

    # ---------------------------------------------------------------- état simulé
    def _load(self) -> dict:
        if self.state_file.exists():
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        return {"blocked": {}, "isolated_hosts": {}, "watchlist": {}, "quarantine": {}}

    def _save(self, st: dict) -> None:
        self.ws.state.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(st, indent=2, ensure_ascii=False), encoding="utf-8")

    def state(self) -> dict:
        return self._load()

    def resolve_in_sandbox(self, path: str) -> Path:
        """Associe /tmp/x.exe -> <sandbox>/tmp/x.exe et interdit toute sortie du bac à sable."""
        root = self.ws.sandbox.resolve()
        p = (root / path.lstrip("/")).resolve()
        if root != p and root not in p.parents:
            raise PermissionError(f"chemin hors du bac à sable : {path}")
        return p

    # ---------------------------------------------------------------- exécution
    def execute(self, action: str, target: str, ttl: int | None = None, note: str = "") -> ActionResult:
        fn = getattr(self, f"_do_{action}", None)
        if fn is None:
            return ActionResult(False, f"action inconnue : {action}")
        return fn(target, ttl, note)

    def _do_block_ip(self, ip, ttl, note):
        st = self._load()
        ttl = ttl or self.policy["actions"]["block_ip"].get("ttl_seconds", 3600)
        if ip in st["blocked"]:
            return ActionResult(True, f"{ip} était déjà bloquée", True, "présente dans la règle de pare-feu simulée", True)
        now = datetime.now()
        st["blocked"][ip] = {"since": now.isoformat(timespec="seconds"),
                             "expires": (now + timedelta(seconds=ttl)).isoformat(timespec="seconds")}
        self._save(st)
        ok = ip in self._load()["blocked"]
        return ActionResult(True, f"IP {ip} bloquée {ttl // 60} min (pare-feu simulé)", ok,
                            "règle retrouvée dans le pare-feu simulé" if ok else "règle INTROUVABLE après écriture")

    def _do_isolate_host(self, host, ttl, note):
        st = self._load()
        if host in st["isolated_hosts"]:
            return ActionResult(True, f"{host} était déjà isolée", True, "déjà dans la liste d'isolation", True)
        st["isolated_hosts"][host] = {"since": datetime.now().isoformat(timespec="seconds")}
        self._save(st)
        ok = host in self._load()["isolated_hosts"]
        return ActionResult(True, f"Machine {host} isolée du réseau (simulation)", ok,
                            "machine présente dans la liste d'isolation" if ok else "isolation non retrouvée")

    def _do_monitor(self, target, ttl, note):
        st = self._load()
        st["watchlist"][target] = {"since": datetime.now().isoformat(timespec="seconds"), "note": note}
        self._save(st)
        ok = target in self._load()["watchlist"]
        return ActionResult(True, f"{target} ajouté à la liste de surveillance", ok, "présent dans la watchlist" if ok else "absent")

    def _do_notify_analyst(self, target, ttl, note):
        self.ws.state.mkdir(parents=True, exist_ok=True)
        f = self.ws.state / "notifications.jsonl"
        with f.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": datetime.now().isoformat(timespec="seconds"),
                                 "incident": target, "message": note}, ensure_ascii=False) + "\n")
        ok = f.exists() and target in f.read_text(encoding="utf-8")
        return ActionResult(True, f"Analyste notifié pour {target}", ok, "notification écrite" if ok else "notification absente")

    def _do_quarantine_file(self, path, ttl, note):
        st = self._load()
        try:
            src = self.resolve_in_sandbox(path)
        except PermissionError:
            src = None
        if (src is None or not src.exists()) and self.policy.get("live_mode"):
            # Mode Wazuh : le fichier est sur la machine surveillée, hors de portée de l'agent SOC -> enregistrement simulé
            st.setdefault("quarantine_sim", {})[path] = {"since": datetime.now().isoformat(timespec="seconds"), "note": note}
            self._save(st)
            return ActionResult(True, f"(simulé) {path} marqué en quarantaine", path in self._load()["quarantine_sim"],
                                "simulation : fichier hébergé sur la machine surveillée, non accessible depuis l'agent SOC")
        if src is None:
            raise PermissionError(f"chemin hors du bac à sable : {path}")
        if not src.exists():
            already = any(v["original"] == path for v in st["quarantine"].values())
            if already:
                return ActionResult(True, f"{path} était déjà en quarantaine", True, "fichier absent de son emplacement d'origine", True)
            return ActionResult(False, f"fichier introuvable : {path}")
        sha = hashlib.sha256(src.read_bytes()).hexdigest()
        qdir = self.ws.sandbox.resolve() / "_quarantine"
        qdir.mkdir(exist_ok=True)
        dest = qdir / f"{sha[:12]}_{src.name}.quarantine"
        shutil.move(str(src), str(dest))
        st["quarantine"][str(dest)] = {"original": path, "sha256": sha}
        self._save(st)
        ok = (not src.exists()) and dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == sha
        return ActionResult(True, f"{path} placé en quarantaine", ok,
                            "original absent, copie en quarantaine intacte (hash identique)" if ok else "vérification échouée")

    # ---------------------------------------------------------------- retour arrière
    def rollback(self, action: str, target: str) -> ActionResult:
        st = self._load()
        if action == "block_ip" and target in st["blocked"]:
            del st["blocked"][target]
            self._save(st)
            return ActionResult(True, f"blocage de {target} levé", target not in self._load()["blocked"], "règle supprimée")
        if action == "isolate_host" and target in st["isolated_hosts"]:
            del st["isolated_hosts"][target]
            self._save(st)
            return ActionResult(True, f"isolation de {target} levée", True, "machine retirée de la liste d'isolation")
        if action == "monitor" and target in st["watchlist"]:
            del st["watchlist"][target]
            self._save(st)
            return ActionResult(True, f"{target} retiré de la surveillance", True, "retiré")
        if action == "quarantine_file":
            for q, meta in list(st["quarantine"].items()):
                if meta["original"] == target and Path(q).exists():
                    dst = self.resolve_in_sandbox(target)
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(q, str(dst))
                    del st["quarantine"][q]
                    self._save(st)
                    return ActionResult(True, f"{target} restauré", dst.exists(), "fichier revenu à son emplacement")
        return ActionResult(False, f"rien à annuler pour {action} sur {target}")
