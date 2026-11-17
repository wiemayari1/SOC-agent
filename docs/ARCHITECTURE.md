# Architecture technique

## Vue d'ensemble

Le projet est une **IA agentique pure** : pas de système expert (ni base de règles, ni moteur d'inférence) et pas de modèle de
langage ni d'API externe. L'agent raisonne et planifie lui-même, en Python standard.

```
 journaux simulés (auth.log, firewall.log, …) — OU — alertes Wazuh en continu (indexeur / alerts.json)
        │
        ▼
 ┌──────────────┐   Event normalisé    ┌──────────────┐  Alert + faits   ┌──────────────────────────────┐
 │ parsers.py   │ ───────────────────► │ extractor.py │ ───────────────► │ AGENT (agent/agent.py)       │
 │ (collecte)   │                      │ (analyse)    │                  │  perception → raisonnement   │
 └──────────────┘                      └──────────────┘                  │  → plan → outil → observation│
                                                                          │  → évaluation → adaptation   │
   état interne de l'agent                                                │  → décision                  │
 ┌──────────────────────────┐   révise ses croyances                      └──────┬───────────────┬───────┘
 │ agent/beliefs.py         │ ◄────────────────────────────────────────────────┤               │ propositions
 │ croyances (1 par hypoth.)│                                                    │ outils        │
 │ preuves + poids          │                                         ┌──────────▼───────┐ ┌─────▼──────────┐
 │ besoins d'information    │ ──► agent/planner.py (choisit l'outil)  │ agent/tools.py   │ │ decision.py    │
 └──────────────────────────┘                                         │ search_logs      │ │ liste blanche, │
                                                                       │ analyze_ip_activ.│ │ niveaux 1/2/3, │
                                                                       │ check_local_ioc  │ │ IP protégées   │
                                                                       │ inspect_file_hash│ └─────┬──────────┘
                                                                       │ propose_response │       │ execute / pending
                                                                       │ execute_authorized│  ┌───▼────────────┐
                                                                       └──────────────────┘──►│ response.py    │
                                                                                               │ actions simulées│
        storage.py (SQLite) ◄── incidents, étapes, preuves, décisions, actions, audit ◄───────│ + vérification │
        reporting.py ───────► data/reports/INC-xxxx.md        web/ (API + interface)        │ + retour arrière│
                                                                 └─► supervision + validation humaine
```

## Correspondance avec les modules du cahier des charges

| Module (cahier des charges) | Fichier |
|---|---|
| Collecte | `soc/parsers.py` (+ `soc/simulator.py` pour les logs simulés) |
| Analyse | `soc/extractor.py` |
| Raisonnement de l'agent (croyances, preuves) | `soc/agent/beliefs.py` |
| Agent autonome (boucle) et planification | `soc/agent/agent.py`, `soc/agent/planner.py` |
| Outils d'investigation | `soc/agent/tools.py` |
| Renseignement local (IOC, motifs) | `knowledge/ioc.json`, `knowledge/patterns.json` (données, pas de règles) |
| Décision et sécurité | `soc/decision.py`, `config/policy.json` |
| Réponse | `soc/response.py` |
| Reporting et traçabilité | `soc/reporting.py`, `soc/storage.py` |
| Collecte en continu (Wazuh) | `soc/wazuh.py`, `soc/live.py` |
| Interface | `soc/web/` (serveur, API, page web), `soc/main.py` (CLI) |

## Ce qui fait de lui un agent (et pas un système expert)

| Caractéristique d'un agent | Où dans le code |
|---|---|
| **Objectif** : confirmer ou réfuter l'hypothèse principale | `agent.investigate` |
| **État interne** : faits connus, outils déjà utilisés, croyances | `InvestigationState`, `BeliefState` |
| **Perception** de son environnement (journaux, IOC, fichiers) | `tools.py` |
| **Choix de l'action** selon l'état (pas de séquence fixe) | `planner.next_need` |
| **Boucle** observation → évaluation → adaptation | `agent.investigate` |
| **Conditions d'arrêt** : confirmé, réfuté, plus de besoin, budget | `_should_stop` |
| **Autonomie encadrée** : exécute seul ou demande validation | `decision.py`, niveaux 1/2/3 |
| **Robustesse** : un outil en échec ne casse pas l'enquête | `ToolBox.call` |

## Flux de données d'une enquête

1. L'extracteur crée une **alerte candidate** (seuil bas) avec des **faits observés** (ex. `ssh_failed_in_window = 45`).
2. **Perception puis raisonnement** : l'agent révise ses croyances (`BeliefState.revise`) : il repère des **preuves** et obtient des hypothèses `h.*` avec une certitude.
3. Le planificateur liste les **besoins d'information** non satisfaits (dont ceux que le raisonnement de l'agent a lui-même exprimés) et choisit le plus prioritaire.
4. L'outil renvoie un `ToolResult` (résumé + **nouveaux faits**). L'agent les intègre à son état et **révise ses croyances** : de nouvelles preuves peuvent apparaître.
5. Arrêt : certitude ≥ 0,85 (confirmée), < 0,25 (réfutée), plus de besoin, ou 8 étapes (minimum 2).
6. `propose_response` transforme les réponses envisagées par l'agent en propositions (action + cible + certitude + sensible ?).
7. Le module de décision applique la politique : **executed / pending_approval / proposed / denied**.
8. L'action est exécutée par le module de réponse, **vérifiée**, enregistrée ; un rapport est généré.

## Croyances et certitudes

* Une **preuve** a un poids (0 à 1). Son effet = poids × minimum des certitudes des croyances dont elle dépend (un fait observé vaut 1,0).
* Deux preuves qui soutiennent la même hypothèse s'**accumulent** : `certitude = a + b × (1 − a)`.
  Exemple SSH : 0,70 (EV-SSH-01) puis 0,60 (EV-SSH-02) → 0,88 puis 0,50 (EV-SSH-03) → 0,94.
* Seuils de verdict : ≥ 0,85 confirmée · ≥ 0,60 probable · ≥ 0,30 possible · sinon aucune menace identifiée.
* Un fait **inconnu** (outil pas encore appelé) n'est jamais pris pour un « non » : la preuve correspondante n'est simplement pas retenue.
* Chaque preuve garde les valeurs réellement observées : l'agent peut **justifier** son verdict (onglet « Raisonnement de l'agent »).

## Contrôle de l'autonomie (défense en profondeur)

1. L'agent d'investigation n'a accès qu'aux outils en **lecture** (rôles dans `TOOL_ROLES`).
2. `decision.py` vérifie : liste blanche → cible protégée → niveau → action sensible → seuil de certitude.
3. `execute_authorized_action` **revérifie** liste blanche et cibles protégées avant d'agir.
4. `response.py` interdit toute sortie du bac à sable (anti path traversal) et **vérifie** le résultat.
5. Tout est journalisé (table `audit`), avec possibilité de **retour arrière** (`rollback`).
