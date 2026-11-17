"""Planificateur : choisit le PROCHAIN outil selon l'état de l'enquête.

Ce n'est pas une séquence fixe : la liste des "besoins d'information" dépend des faits connus
(ex. une connexion réussie après échecs fait apparaître le besoin 'post_login' avec priorité maximale),
et la priorité est relevée quand le raisonnement de l'agent exprime lui-même ce besoin d'information.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Need:
    key: str
    tool: str
    args: dict
    priority: int
    why: str


def candidate_needs(st) -> list[Need]:
    a, f, ip = st.alert, st.facts, st.alert.src_ip
    needs: list[Need] = []
    if a.scenario == "ssh_bruteforce" and f.get("ssh_success_after_failures"):
        needs.append(Need("post_login", "search_logs",
                          dict(user=f["ssh_success_user"], type="sudo_command", host=a.host, after=f["ssh_success_ts"]), 90,
                          "une connexion a réussi après des échecs : que s'est-il passé juste après ?"))
    if a.scenario == "web_sqli" and ip:
        needs.append(Need("web_payload_responses", "search_logs", dict(ip=ip, source="web"), 70,
                          "vérifier comment le serveur a répondu aux requêtes à payload (erreurs 5xx ? réponses 200 ?)"))
    if a.scenario == "malicious_file":
        if a.kind == "ransomware_burst":
            needs.append(Need("host_file_activity", "search_logs",
                              dict(host=a.host, source="file", type="file_renamed"), 80,
                              "mesurer l'étendue des fichiers renommés sur la machine"))
        else:
            needs.append(Need("file_hash", "inspect_file_hash",
                              dict(path=f["file_path"], logged_sha256=f.get("file_sha256_logged")), 95,
                              "calculer l'empreinte SHA-256 du fichier"))
            if "file_sha256" in f:
                needs.append(Need("hash_ioc", "check_local_ioc", dict(hash=f["file_sha256"]), 90,
                                  "comparer l'empreinte avec la base IOC locale"))
    if ip:
        needs.append(Need("ip_history", "analyze_ip_activity", dict(ip=ip), 60,
                          "chercher l'activité de cette IP sur toutes les sources (corrélation)"))
        needs.append(Need("ip_reputation", "check_local_ioc", dict(ip=ip), 50,
                          "vérifier la réputation de l'IP dans la base IOC locale"))
    return [n for n in needs if n.key not in st.done]


def next_need(st) -> Need | None:
    needs = candidate_needs(st)
    if not needs:
        return None
    asked = set(st.result.wanted) if st.result else set()
    for n in needs:
        if n.key in asked:
            n.priority += 25          # l'agent a lui-même exprimé ce besoin en raisonnant
            n.why += " (besoin exprimé par le raisonnement de l'agent)"
    return max(needs, key=lambda n: n.priority)
