"""Interface en ligne de commande :  python -m soc.main <commande>"""
from __future__ import annotations

import argparse
import json
import sys
import time
import webbrowser
from collections import Counter

from . import pipeline, simulator
from .config import default_workspace, load_patterns, load_wazuh, set_runtime_override
from .reporting import build_report


def _wazuh_check() -> int:
    """Diagnostic pas à pas de la connexion Wazuh (à lancer avant `serve --live`)."""
    from .wazuh import Converter, ManagerApi, WazuhError, make_source
    cfg = load_wazuh()
    if not cfg:
        print("[ECHEC] config/wazuh.json introuvable. Copiez config/wazuh.example.json en config/wazuh.json et adaptez-le.")
        return 1
    print(f"[ OK ] configuration chargée (mode : {cfg.get('mode', 'indexer')})")
    try:
        src = make_source(cfg)
        print(f"[ OK ] source : {src.description}")
        print(f"[ OK ] connexion : {src.ping()}")
        hits = src.fetch()
    except WazuhError as e:
        print(f"[ECHEC] {e}")
        print("        Astuce : l'indexeur Wazuh écoute souvent sur 127.0.0.1 seulement -> tunnel SSH (README, section 10).")
        return 1
    print(f"[ OK ] {len(hits)} alerte(s) lue(s) sur les {cfg.get('lookback_minutes', 60)} dernières minutes")
    conv, kinds, skipped = Converter(load_patterns()), Counter(), Counter()
    for _id, h in hits:
        try:
            ev = conv.to_event(h)
        except (KeyError, ValueError, TypeError):
            ev = None
        if ev:
            kinds[f"{ev.source}/{ev.type}"] += 1
        else:
            skipped[str((h.get("rule") or {}).get("id") or "archive")] += 1
    print("       converties en événements :", dict(kinds) or "aucune")
    if skipped:
        print("       ignorées (règles Wazuh non exploitables) :", dict(skipped.most_common(8)))
    if hits and not kinds:
        print("[ATTENTION] des alertes arrivent mais aucune n'est exploitable : vérifiez SSH/UFW/Nginx/FIM (README, section 10).")
    if cfg.get("api"):
        try:
            st = ManagerApi(cfg).status()
            print(f"[ OK ] API Wazuh {st['version']} : {len(st['agents'])} agent(s) -> " + ", ".join(f"{a['name']}({a['status']})" for a in st["agents"]))
        except WazuhError as e:
            print(f"[ECHEC] API Wazuh : {e}")
    return 0


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):          # Windows : évite les erreurs d'accents / de flèches
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(prog="soc", description="Agent SOC autonome (IA agentique, sans LLM ni API externe)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate", help="génère les journaux simulés des 4 scénarios")
    p = sub.add_parser("run", help="analyse les journaux présents dans data/logs (simulés ou export Wazuh)")
    p.add_argument("--level", type=int, choices=(1, 2, 3), help="niveau d'autonomie (défaut : config/policy.json)")
    p = sub.add_parser("demo", help="réinitialise, génère les journaux simulés puis lance l'analyse")
    p.add_argument("--level", type=int, choices=(1, 2, 3))
    p = sub.add_parser("serve", help="lance l'interface web (et la surveillance Wazuh avec --live)")
    p.add_argument("--live", action="store_true", help="surveillance continue de Wazuh (config/wazuh.json)")
    p.add_argument("--demo", action="store_true", help="charge d'abord les données simulées")
    p.add_argument("--reset", action="store_true", help="efface les incidents existants avant de démarrer (avec --live)")
    p.add_argument("--level", type=int, choices=(1, 2, 3), help="niveau d'autonomie initial")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-browser", action="store_true")
    sub.add_parser("wazuh-check", help="teste la connexion à Wazuh et la conversion des alertes")
    sub.add_parser("list", help="liste les incidents")
    p = sub.add_parser("show", help="affiche le rapport d'un incident"); p.add_argument("id")
    p = sub.add_parser("explain", help="affiche le raisonnement détaillé de l'agent pour un incident"); p.add_argument("id")
    sub.add_parser("pending", help="liste les actions en attente de validation")
    sub.add_parser("actions", help="liste les actions exécutées (ID à utiliser avec rollback)")
    for name in ("approve", "reject", "rollback"):
        p = sub.add_parser(name, help=f"{name} (id de décision pour approve/reject, id d'action pour rollback)")
        p.add_argument("id", type=int)
    sub.add_parser("state", help="affiche l'état du pare-feu simulé")
    a = ap.parse_args(argv)
    ws = default_workspace()

    if a.cmd == "generate":
        ws.reset()
        print("Journaux générés :", simulator.generate(ws))
    elif a.cmd == "run":
        pipeline.run(ws, a.level)
    elif a.cmd == "demo":
        ws.reset()
        print("Journaux générés :", simulator.generate(ws))
        pipeline.run(ws, a.level)
        rt = pipeline.build_runtime(ws)
        print(f"\n{len(rt.db.pending())} action(s) en attente de validation humaine. Voir : python -m soc.main pending")
        print("Rapports dans :", ws.reports)
        rt.db.close()
    elif a.cmd == "wazuh-check":
        return _wazuh_check()
    elif a.cmd == "serve":
        from .live import LiveMonitor
        from .storage import Database
        from .web.server import WebApp
        if a.live and a.demo:
            print("--live et --demo sont incompatibles : choisissez l'un des deux.")
            return 2
        ws.ensure()
        wcfg = None
        if a.live:
            wcfg = load_wazuh()
            if not wcfg:
                print("config/wazuh.json introuvable : copiez config/wazuh.example.json et adaptez-le (README, section 10).")
                return 2
            if a.reset:
                ws.reset()
                ws.ensure()
        elif a.demo:
            ws.reset()
            ws.ensure()
            print("Génération des données de démonstration…")
            simulator.generate(ws)
            pipeline.run(ws, a.level, log=lambda *_: None)
            db = Database(ws.db_path)
            db.meta_set("mode", "demo")
            db.close()
        if a.level:
            set_runtime_override(ws, autonomy_level=a.level)     # l'interface affiche le même niveau que celui appliqué
        monitor = None
        if a.live:
            monitor = LiveMonitor(ws, wcfg, level=a.level)
            monitor.start()
        app = WebApp(ws, wcfg, a.host, a.port)
        url = f"http://{a.host if a.host not in ('0.0.0.0', '::') else '127.0.0.1'}:{a.port}"
        if a.host not in ("127.0.0.1", "localhost", "::1"):
            print("ATTENTION : l'interface est exposée sur le réseau et n'a pas d'authentification. Préférez un tunnel SSH.")
        print(f"Interface SOC : {url}   (Ctrl+C pour arrêter)")
        if not a.no_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        try:
            app.start()
        except KeyboardInterrupt:
            pass
        finally:
            if monitor:
                monitor.stop()
                monitor.join(5)
            app.stop()
        return 0
    else:
        rt = pipeline.build_runtime(ws)
        if a.cmd == "list":
            for i in rt.db.incidents():
                print(f"{i['id']}  {i['scenario']:<15} {(i['src_ip'] or i['host']):<22} {i['verdict']:<32} {i['severity']:<8} {i['status']}")
        elif a.cmd == "show":
            print(build_report(rt.db, a.id))
        elif a.cmd == "explain":
            for e in rt.db.evidence(a.id):
                print(f"Révision {e['step']} [{e['ev_id']}] {e['label']} : {e['detail']}")
                print("   constat :", "; ".join(f"{m['fact']} {m['op']} {m['value']} (réel {m['actual']})" for m in json.loads(e['observed'])))
                print("   effets  :", "; ".join(json.loads(e['effects'])), f"(poids {e['weight']:.2f})")
        elif a.cmd == "pending":
            for d in rt.db.pending():
                print(f"décision {d['id']}  {d['incident_id']}  {d['action']}({d['target']})  certitude={d['cf']:.2f}  raison : {d['reason']}")
            if not rt.db.pending():
                print("Aucune action en attente.")
        elif a.cmd == "actions":
            for x in rt.db.actions():
                print(f"action {x['id']}  {x['incident_id']}  {x['action']}({x['target']})  vérifiée={'oui' if x['verified'] else 'non'}"
                      + ("  [annulée]" if x["rolled_back"] else ""))
        elif a.cmd == "approve":
            print(pipeline.approve(rt, a.id))
        elif a.cmd == "reject":
            print(pipeline.reject(rt, a.id))
        elif a.cmd == "rollback":
            print(pipeline.rollback(rt, a.id))
        elif a.cmd == "state":
            print(json.dumps(rt.executor.state(), indent=2, ensure_ascii=False))
        rt.db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
