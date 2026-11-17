"""Chemins du projet et chargement de la configuration / des connaissances."""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KNOWLEDGE_DIR = ROOT / "knowledge"
CONFIG_DIR = ROOT / "config"


@dataclass
class Workspace:
    """Dossier de travail (logs simulés, bac à sable, état, rapports, base SQLite)."""
    root: Path

    def __post_init__(self):
        self.root = Path(self.root)

    @property
    def logs(self) -> Path: return self.root / "logs"
    @property
    def sandbox(self) -> Path: return self.root / "sandbox"
    @property
    def state(self) -> Path: return self.root / "state"
    @property
    def reports(self) -> Path: return self.root / "reports"
    @property
    def db_path(self) -> Path: return self.root / "soc.db"

    def ensure(self) -> None:
        for p in (self.logs, self.sandbox, self.state, self.reports):
            p.mkdir(parents=True, exist_ok=True)

    def reset(self) -> None:
        """Supprime toutes les données générées (jamais les connaissances ni la config)."""
        for p in (self.logs, self.sandbox, self.state, self.reports):
            shutil.rmtree(p, ignore_errors=True)
        if self.db_path.exists():
            try:
                self.db_path.unlink()
            except PermissionError:
                # Windows : la base est encore ouverte par un autre objet -> on vide son contenu
                import sqlite3
                con = sqlite3.connect(self.db_path)
                tables = [r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
                for t in tables:
                    con.execute(f"DELETE FROM {t}")
                try:
                    con.execute("DELETE FROM sqlite_sequence")
                except sqlite3.Error:
                    pass
                con.commit()
                con.close()


def default_workspace() -> Workspace:
    return Workspace(ROOT / "data")


def _load(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_policy(path: Path | None = None) -> dict:
    return _load(path or CONFIG_DIR / "policy.json")


def load_patterns() -> dict:
    return _load(KNOWLEDGE_DIR / "patterns.json")


def load_ioc() -> dict:
    return _load(KNOWLEDGE_DIR / "ioc.json")




def load_wazuh(path: Path | None = None) -> dict | None:
    """Configuration Wazuh (config/wazuh.json). Retourne None si le fichier n'existe pas.
    Les mots de passe peuvent venir de l'environnement : WAZUH_INDEXER_PASSWORD, WAZUH_API_PASSWORD."""
    p = Path(path) if path else CONFIG_DIR / "wazuh.json"
    if not p.exists():
        return None
    cfg = _load(p)
    if os.environ.get("WAZUH_INDEXER_PASSWORD"):
        cfg.setdefault("indexer", {})["password"] = os.environ["WAZUH_INDEXER_PASSWORD"]
    if os.environ.get("WAZUH_API_PASSWORD"):
        cfg.setdefault("api", {})["password"] = os.environ["WAZUH_API_PASSWORD"]
    return cfg


def runtime_override(ws: Workspace) -> dict:
    """Réglages modifiés depuis l'interface web (ex. niveau d'autonomie), stockés dans data/state/runtime.json."""
    f = ws.state / "runtime.json"
    try:
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    except (OSError, ValueError):
        return {}


def set_runtime_override(ws: Workspace, **kw) -> dict:
    ws.state.mkdir(parents=True, exist_ok=True)
    cur = runtime_override(ws)
    cur.update(kw)
    (ws.state / "runtime.json").write_text(json.dumps(cur, indent=2), encoding="utf-8")
    return cur
