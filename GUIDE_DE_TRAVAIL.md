# GUIDE DE TRAVAIL — Agent SOC autonome (3 semaines)

> **Votre rôle** : piloter, exécuter, tester, comprendre, décider, présenter.
> **Rôle de l'assistant** : écrire et corriger le code à votre demande. Le code livré est déjà complet et testé
> (69 tests automatiques). Votre vrai travail est donc de **le maîtriser au point de pouvoir le défendre et le modifier**.

---

## 0. À lire avant de commencer

### 0.1 Ce que vous avez entre les mains

Un prototype fonctionnel de bout en bout : journaux simulés → détection → **agent** qui perçoit, raisonne (il révise ses croyances à partir de preuves),
planifie son investigation et choisit ses outils → décision encadrée (3 niveaux d'autonomie) → réponse simulée
et vérifiée → rapport Markdown + journal d'audit + interface web de supervision (tableau de bord, validation humaine) et surveillance Wazuh en continu.

### 0.2 Ce qui est volontairement simplifié par rapport au cahier des charges « version réduite »

| Cahier des charges | Dans le projet livré | À écrire dans le rapport |
|---|---|---|
| Wazuh (collecte) | **Deux modes** : simulation (démo reproductible) et **surveillance Wazuh en continu** (`serve --live`, README §10). Le mode Wazuh est testé contre un faux serveur, **pas** contre un vrai Wazuh | « Wazuh alimente l'agent en temps réel ; le mode simulé garantit une démonstration reproductible. » |
| Base SQLite ou PostgreSQL | SQLite | Choix conforme au cahier (« SQLite ou PostgreSQL »). |
| React ou interface simple | Interface web monopage (HTML/CSS/JS natifs, sans dépendance) servie par Python + ligne de commande | Conforme (« interface simple ») ; sans build ni paquet à installer. |
| LangGraph ou Python | **Boucle agentique en Python pur** | Conforme (« Python ou LangGraph »). LangGraph = perspective. |
| Docker | `Dockerfile` + `docker-compose.yml` fournis, **non testés** | Déploiement optionnel, à valider sur votre machine. |
| Machine Learning | Absent (retiré dans la version réduite) | Perspective : Isolation Forest sur les comptes de connexions. |
| Réponses réelles | **Simulées**, même en mode Wazuh (pare-feu JSON, quarantaine dans un bac à sable) | Choix de sécurité du laboratoire isolé ; l'agent décide et vérifie, l'exécution réelle est une perspective. |

### 0.3 Règles d'or

1. **Un module à la fois, un test à chaque étape.** Ne passez pas au jour suivant si le critère « terminé » n'est pas atteint.
2. **Ne modifiez pas en aveugle.** Avant de changer une preuve, un poids ou un seuil, relancez `python -m soc.main demo` et notez le résultat avant/après.
3. **Lisez le code que vous présenterez.** Chaque jour contient des « questions d'auto-test » : si vous ne savez pas y répondre, relisez le fichier ou demandez-moi de l'expliquer.
4. **Gelez les fonctionnalités à la fin du jour 14.** La semaine 3 sert à fiabiliser, tester et rédiger.
5. **Sauvegardez** (git recommandé : `git init && git add -A && git commit -m "jour N"` chaque soir).

### 0.4 Comment me demander du code ou une correction

Un message efficace contient : (1) le **fichier** concerné, (2) la **commande** lancée, (3) la **sortie ou l'erreur complète**, (4) ce que vous **attendiez**.

```
Contexte : jour 11, scénario injection SQL, fichier knowledge/patterns.json.
Commande : python -m soc.main demo
Problème : la requête /products?id=1%20AND%20SLEEP(5) n'est pas détectée.
Attendu : un motif "time_based" classé strong. Voici la sortie : ...
```

Pour une nouvelle fonctionnalité : « Ajoute une preuve qui... avec ce seuil..., et un test qui prouve... ».

---

## 1. Installation et premier lancement (à faire en premier, 20 minutes)

**Prérequis** : Python 3.10 ou plus (`python3 --version`). Aucun paquet n'est nécessaire pour le cœur du projet.

```bash
unzip soc_agent.zip && cd soc_agent
python3 -m venv .venv
source .venv/bin/activate              # Windows : .venv\Scripts\activate
python -m soc.main demo                # tout le pipeline en quelques secondes
python -m unittest discover -s tests -t .      # doit afficher : Ran 69 tests ... OK
```

**Résultat attendu de `demo`** (12 incidents) :

| ID | Scénario | Source | Verdict | Certitude | Sévérité | Issue |
|---|---|---|---|---|---|---|
| INC-0001 | Force brute SSH | 198.51.100.23 | confirmée | 0,94 | high | IP **bloquée automatiquement**, vérifiée |
| INC-0002 | Scan de ports | 192.0.2.88 (IOC) | probable | 0,83 | medium | IP bloquée automatiquement |
| INC-0003 | Scan de ports | 203.0.113.77 | confirmée | 0,90 | high | **Validation humaine** (attaque multi-étapes) |
| INC-0004 | Force brute SSH + succès | 203.0.113.77 | confirmée | 0,95 | **critical** | **Validation humaine** (compromission) |
| INC-0005 | Injection SQL (sqlmap) | 198.51.100.140 | confirmée | 0,95 | high | IP bloquée automatiquement |
| INC-0006 | Injection SQL manuelle | 203.0.113.200 | probable | 0,82 | high | IP bloquée automatiquement |
| INC-0007 | Apostrophe légitime | 10.0.0.60 | bénin | 0,70 | low | **Faux positif** clos |
| INC-0008 | Fichier `facture.pdf.exe` | /tmp | confirmée | 0,98 | high | **Quarantaine** automatique, vérifiée |
| INC-0009 | Fautes de frappe SSH | 10.0.0.45 | bénin | 0,80 | info | **Faux positif** clos |
| INC-0010 | Script inconnu | /tmp/update.sh | possible | 0,44 | low | Analyste notifié + surveillance (pas de quarantaine) |
| INC-0011 | Ransomware (35 renommages) | srv-files | confirmée | 0,93 | critical | **Validation humaine** (isolation machine) |
| INC-0012 | Sondage limité (6 ports) | 192.0.2.99 | possible | 0,51 | medium | Surveillance seulement |

Puis explorez : `python -m soc.main list`, `show INC-0004`, `explain INC-0004`, `pending`, `state`.

---

## 2. Plan de travail jour par jour

Format de chaque jour : **Objectif · À faire · À comprendre · Exercice · Livrable · Terminé quand…**
Temps indicatif : 2 à 4 h par jour. Les jours 7, 14 et 21 sont des points de contrôle plus légers.

### SEMAINE 1 — Le socle : données, faits, raisonnement de l'agent

#### Jour 1 — Installation et vue d'ensemble
* **Objectif** : le projet tourne chez vous ; vous connaissez l'arborescence.
* **À faire** : section 1 de ce guide ; lire `README.md` et `docs/ARCHITECTURE.md` ; ouvrir `data/reports/INC-0004.md`.
* **À comprendre** : le schéma d'architecture (8 modules) et le scénario de bout en bout.
* **Auto-test** : qu'est-ce qui distingue un agent d'un simple programme de détection ? (Réponse : tableau de `docs/ARCHITECTURE.md`.)
* **Livrable** : dépôt git initialisé, capture d'écran de la sortie de `demo`.
* **Terminé quand** : les 69 tests passent chez vous et vous savez lancer `demo`, `list`, `show`.

#### Jour 2 — Événements normalisés et parseurs
* **Objectif** : comprendre comment des lignes de logs deviennent des objets exploitables.
* **À faire** : lire `soc/events.py` et `soc/parsers.py` ; ouvrir `data/logs/auth.log` et `nginx_access.log` ; lancer `python -m unittest tests.test_parsers_extractor -v`.
* **À comprendre** : un seul format `Event` (ts, source, type, ip, user, details) pour 4 sources ; les lignes illisibles sont comptées puis ignorées (robustesse, besoin non fonctionnel).
* **Exercice** : ajoutez une ligne invalide dans `data/logs/auth.log`, relancez `python -m soc.main run` : rien ne plante. Regardez `stats` dans `load_all`.
* **Livrable** : une demi-page « format d'événement normalisé » pour le rapport (tableau des champs).
* **Terminé quand** : vous pouvez expliquer pourquoi la normalisation permet de réutiliser le même agent pour 4 scénarios.

#### Jour 3 — Simulateur et scénarios
* **Objectif** : savoir quelles données alimentent chaque scénario.
* **À faire** : lire `soc/simulator.py` ; relancer `python -m soc.main generate` ; comparer `data/logs/*` avec le tableau des 12 incidents.
* **À comprendre** : bruit de fond + scénarios + **faux positifs volontaires** (INC-0007, INC-0009). Déterminisme : graine fixe, même résultat à chaque fois.
* **Exercice** : dans `simulator.py`, passez le nombre d'échecs du scénario SSH 1a de 45 à 8, relancez `demo` : l'alerte existe encore (≥ 3 échecs) mais l'agent ne conclut plus à une force brute. Remettez 45.
* **Livrable** : tableau des 4 scénarios (source de logs, indicateurs, attendu) pour le rapport.
* **Terminé quand** : vous savez dire, pour chaque incident, pourquoi il existe dans les données.

#### Jour 4 — Extraction des faits (module d'analyse)
* **Objectif** : comprendre la frontière entre « détection » et « raisonnement ».
* **À faire** : lire `soc/extractor.py`, surtout `max_in_window` et `_ssh_alerts` ; lancer `tests.test_parsers_extractor`.
* **À comprendre** : l'extracteur a un **seuil bas** (3 échecs SSH, 5 ports, un motif SQL…) : il crée des alertes *candidates*. **C'est l'agent qui décide** (par son raisonnement) si c'est une attaque. Les faits sont des valeurs simples (`ssh_failed_in_window = 45`).
* **Auto-test** : pourquoi calculer le nombre d'échecs *dans une fenêtre de 120 s* plutôt que le total ? (Un total sur une journée peut être normal ; une rafale ne l'est pas.)
* **Exercice** : changez `ssh_window_s` dans `config/policy.json` de 120 à 20 ; relancez `demo` : INC-0001 devient « aucune menace identifiée » (certitude 0,00), car l'attaque (1 échec toutes les 2,5 s) n'atteint plus 10 échecs en 20 s. Leçon : un seuil mal réglé laisse passer une vraie attaque (faux négatif). Restaurez 120.
* **Livrable** : liste des faits par scénario (tableau).
* **Terminé quand** : vous pouvez citer 3 faits de chaque scénario.

#### Jour 5 — Le raisonnement de l'agent (croyances et preuves)
* **Objectif** : comprendre l'algorithme central du projet.
* **À faire** : lire `soc/agent/beliefs.py` en entier (≈ 200 lignes) ; repérer les preuves SSH-01 à SSH-09 ; lancer `python -m unittest tests.test_beliefs -v` ; `python -m soc.main explain INC-0004`.
* **À comprendre** :
  1. une **preuve** = un constat sur les faits observés + un poids + un effet (hypothèse soutenue, gravité, réponse envisagée, besoin d'information) ;
  2. l'agent tient un **état de croyance** (une certitude par hypothèse) et le **révise** à chaque observation ; une croyance déjà formée (`h.brute_force_ssh`) peut rendre une autre preuve visible (EV-SSH-06 : compromission) ;
  3. la révision s'arrête quand plus aucune nouvelle preuve n'apparaît ; l'agent peut alors choisir un outil pour obtenir de nouveaux faits ;
  4. chaque preuve est enregistrée avec les valeurs observées → **explicabilité**.
* **Auto-test** : dans `test_earlier_belief_supports_later_one`, quelle preuve en rend une autre possible ? (EV-SSH-01 → croyance → EV-SSH-06.)
* **Exercice** : dessinez à la main le raisonnement d'INC-0004 (faits → preuves → croyances → réponse envisagée).
* **Livrable** : le schéma de la révision des croyances pour le rapport (indispensable en soutenance).
* **Terminé quand** : vous expliquez l'algorithme sans regarder le code.

#### Jour 6 — Certitudes et écriture d'une preuve
* **Objectif** : savoir lire et écrire une preuve ; comprendre l'accumulation des certitudes.
* **À faire** : relire la section « Croyances et certitudes » de `docs/ARCHITECTURE.md` ; lancer `python -m soc.main explain INC-0001`.
* **À comprendre** : `certitude = a + b × (1 − a)`. Exemple : 0,70 puis 0,60 → 0,88. Un fait inconnu n'est jamais pris pour un « non » : la preuve n'est pas retenue.
* **Exercice 1** : ajoutez dans `_ssh` (`beliefs.py`) une preuve `EV-SSH-10` : « root ciblé » — si `ssh_root_targeted == True` ET `ssh_failed_in_window >= 10`, poids 0,2 sur `h.brute_force_ssh`. Relancez `demo` : la certitude d'INC-0001 passe de 0,94 à 0,95. (Ce fait existe déjà dans l'extracteur.)
* **Exercice 2** : écrivez un test dans `tests/test_beliefs.py` qui vérifie cette preuve. Demandez de l'aide si besoin.
* **Livrable** : 3 preuves expliquées en langage naturel (une par type : seuil, corrélation, faux positif).
* **Terminé quand** : vous avez ajouté et testé votre propre preuve.

#### Jour 7 — Point de contrôle semaine 1
* Relancer toute la suite de tests. Rédiger la partie « Raisonnement de l'agent » du rapport (croyances, preuves, accumulation des certitudes, justification).
* **Contrôle** : cahier des charges section 5.1 → chaque phrase est démontrable avec un fichier ou une commande.

### SEMAINE 2 — L'agent et les quatre scénarios

#### Jour 8 — Le cycle de l'agent
* **Objectif** : comprendre ce qui rend l'agent *agentique*.
* **À faire** : lire `soc/agent/agent.py` ; lancer `python -m soc.main show INC-0004` et lire la section « Investigation de l'agent ».
* **À comprendre** : l'agent possède un **objectif** (confirmer ou réfuter l'hypothèse principale), un **état** (faits, outils déjà utilisés, certitude), des **outils**, et des **conditions d'arrêt** (confirmé, réfuté, plus de besoin, budget). Cycle : perception → raisonnement → planification → action → observation → évaluation → adaptation → décision.
* **Auto-test** (question probable du jury) : *« En quoi est-ce un agent et pas une suite de if ? »* — Réponse : la liste des actions possibles dépend de l'état ; deux incidents du même scénario suivent des chemins différents (voir `test_agent_adapts_path_to_observations` : INC-0004 appelle `search_logs`, INC-0001 non).
* **Livrable** : diagramme du cycle de l'agent annoté avec des extraits réels du rapport INC-0004.
* **Terminé quand** : vous racontez l'enquête INC-0004 étape par étape.

#### Jour 9 — Le planificateur
* **Objectif** : comprendre comment l'agent choisit son prochain outil.
* **À faire** : lire `soc/agent/planner.py` (≈ 50 lignes).
* **À comprendre** : `candidate_needs` construit la liste des **besoins d'information** selon l'état (ex. `post_login` n'apparaît que si `ssh_success_after_failures` est vrai) ; `next_need` choisit la **priorité** la plus haute, **+25** si le raisonnement de l'agent a lui-même exprimé ce besoin (`wants=` dans `beliefs.py`). Un besoin n'est jamais répété.
* **Exercice** : changez la priorité de `ip_reputation` de 50 à 99 : l'ordre des outils change dans le rapport d'INC-0001. Restaurez.
* **Livrable** : tableau « besoin → outil → priorité → condition d'apparition ».
* **Terminé quand** : vous prévoyez l'ordre des outils d'un incident avant de lancer le programme.

#### Jour 10 — Les outils
* **Objectif** : connaître les 6 outils et leurs permissions.
* **À faire** : lire `soc/agent/tools.py`.
* **À comprendre** : chaque outil renvoie un `ToolResult` (succès, résumé, **nouveaux faits**). Les faits retournés sont réinjectés dans l'état de l'agent, qui révise ses croyances. Les **rôles** (`investigation`, `decision`, `execution`) empêchent l'agent d'agir pendant l'enquête. Toute exception est capturée : l'agent continue (robustesse).
* **Exercice** : lancez `python -c "from soc.pipeline import *; from soc.config import default_workspace; rt=build_runtime(default_workspace()); print(rt.toolbox.call('execute_authorized_action', _role='investigation', action='block_ip', target='1.1.1.1'))"` : permission refusée.
* **Livrable** : tableau des 6 outils (entrées, sorties, faits produits, rôle autorisé).
* **Terminé quand** : vous expliquez pourquoi `execute_authorized_action` n'est pas appelable pendant l'enquête.

#### Jour 11 — Scénarios « scan de ports » et « injection SQL »
* **Objectif** : maîtriser les preuves `NET-*` et `WEB-*`.
* **À faire** : lire les preuves EV-NET-01 à 08 et EV-WEB-01 à 10 dans `beliefs.py` ; lire `knowledge/patterns.json`.
* **À comprendre** : le scan se détecte par **ports distincts en 60 s** et **ports séquentiels** ; l'injection par **motifs forts/faibles** après double décodage d'URL. INC-0007 : une apostrophe seule (`O'Brien`) est un indice faible ; la preuve EV-WEB-09 la classe bénigne.
* **Exercice** : ajoutez un motif `"extractvalue"` (strong) dans `patterns.json`, puis ajoutez au simulateur une requête qui l'utilise, vérifiez la détection. Demandez-moi le test correspondant.
* **Livrable** : tableau « indicateur → preuve → poids » pour ces deux scénarios.
* **Terminé quand** : vous justifiez chaque seuil par un raisonnement, pas par un chiffre magique.

#### Jour 12 — Scénario « fichiers suspects » et ransomware
* **Objectif** : maîtriser le scénario 4 (hash, IOC, quarantaine).
* **À faire** : lire les preuves EV-FIL-01 à 13 ; `python -m soc.main show INC-0008` puis `INC-0010` puis `INC-0011`.
* **À comprendre** : 3 fichiers, 3 issues — hash **connu** → quarantaine automatique ; hash **inconnu** → notification seulement (pas de quarantaine sans preuve) ; **rafale de renommages** → isolation proposée mais **validée par un humain** (action sensible).
* **Attention** : aucun vrai malware n'est utilisé. N'ajoutez **pas** le fichier de test EICAR dans le dossier du projet (les antivirus le suppriment, y compris l'archive).
* **Option (demi-journée, seulement si tout le reste est solide)** : démarrer l'intégration Wazuh avec `docs/WAZUH.md`.
* **Livrable** : tableau des 3 issues du scénario 4 avec justification.
* **Terminé quand** : vous expliquez pourquoi `update.sh` n'est pas mis en quarantaine.

#### Jour 13 — Corrélation multi-étapes
* **Objectif** : comprendre la valeur ajoutée de l'agent sur la simple détection par seuils.
* **À faire** : relire INC-0003 et INC-0004 (même IP `203.0.113.77`) ; lire SSH-005, NET-005, WEB-008, MULTI-001.
* **À comprendre** : l'extracteur crée deux alertes séparées (scan, puis SSH). C'est l'outil `analyze_ip_activity` qui relie l'IP aux deux comportements (`ip_multi_stage = True`). L'agent forme alors la croyance `h.multi_stage` → gravité haute et blocage **soumis à validation**.
* **Exercice** : ajoutez une preuve de corrélation `EV-WEB-11` (injection SQL + force brute depuis la même IP). Ajoutez au simulateur une IP qui fait les deux, vérifiez qu'elle est classée multi-étapes.
* **Livrable** : une page « corrélation entre scénarios » (c'est votre meilleur argument de valeur ajoutée).
* **Terminé quand** : vous expliquez pourquoi le scan seul (INC-0003) n'est pas bloqué automatiquement.

#### Jour 14 — Point de contrôle et gel des fonctionnalités
* Tous les scénarios tournent, tous les tests passent. **Plus de nouvelles fonctionnalités après aujourd'hui.**
* Rédiger la partie « Agent » du rapport. Faire relire le planning à votre encadrant.

### SEMAINE 3 — Contrôle, interface, validation, soutenance

#### Jour 15 — Décision, permissions, niveaux d'autonomie
* **Objectif** : maîtriser l'autonomie contrôlée.
* **À faire** : lire `soc/decision.py` et `config/policy.json` ; lancer les trois niveaux :
  `python -m soc.main demo --level 1` (propose seulement), `--level 2` (tout attend une validation), `--level 3` (exécute le permis).
* **À comprendre** : ordre des contrôles : liste blanche → cible protégée → niveau → action sensible → seuil de certitude (`min_cf`). Les IP protégées (`10.0.0.1`, `10.0.0.2`) ne sont jamais bloquées.
* **Exercice** : mettez `block_ip.min_cf` à 0,95 : INC-0001, INC-0002 et INC-0006 passent en attente de validation (leur certitude est < 0,95) alors qu'INC-0005 (0,95) reste automatique. Restaurez 0,65.
* **Livrable** : tableau « action × niveau × condition » pour le rapport.
* **Terminé quand** : vous prévoyez la décision pour un cas donné (confiance, sensibilité, niveau).

#### Jour 16 — Réponse, vérification, retour arrière
* **Objectif** : comprendre comment une action est exécutée, vérifiée et annulée.
* **À faire** : lire `soc/response.py` ; `python -m soc.main demo` ; `pending` ; `approve <id>` ; `state` ; `actions` (liste des ID d'action) puis `rollback <id d'action>`.
* **À comprendre** : actions **simulées** (fichier JSON, bac à sable) ; chaque action est **vérifiée** (relecture de l'état, hash du fichier en quarantaine) ; idempotence (bloquer deux fois ne casse rien) ; blocage du *path traversal*.
* **Exercice** : validez INC-0004 (blocage), puis annulez-le, puis validez INC-0003 (même IP).
* **Livrable** : séquence de captures « proposition → validation → vérification → retour arrière ».
* **Terminé quand** : vous expliquez pourquoi on revérifie la liste blanche dans `execute_authorized_action` (défense en profondeur).

#### Jour 17 — Stockage, audit, rapports
* **Objectif** : exploiter la traçabilité.
* **À faire** : lire `soc/storage.py` et `soc/reporting.py` ; ouvrir `data/soc.db` avec un outil SQLite (`sqlite3 data/soc.db "select * from audit limit 20"`).
* **À comprendre** : 6 tables (incidents, steps, evidence, decisions, actions, audit) ; le rapport est **reconstruit depuis la base** — il est donc toujours cohérent avec ce qui s'est réellement passé.
* **Exercice** : écrivez une requête SQL qui liste, pour chaque incident, les preuves retenues et le statut final.
* **Livrable** : un rapport d'incident exemple commenté (INC-0004) à mettre en annexe.
* **Terminé quand** : vous retrouvez, pour une action donnée, qui l'a décidée, quand, et pourquoi.

#### Jour 18 — Interface de supervision
* **Objectif** : disposer d'une interface propre pour la démonstration.
* **À faire** : `python -m soc.main serve --demo` (ouvre `http://127.0.0.1:8000`) ; parcourir le tableau de bord, la liste des incidents (filtres, recherche), le détail d'un incident (6 onglets), les validations, la page Réponse et la page Système ; approuver une action depuis l'interface (double clic de confirmation) ; changer le niveau d'autonomie (N1/N2/N3) en haut à droite.
* **Exercice** : ouvrez `soc/web/static/app.js`, repérez la fonction `viewOverview` et ajoutez un indicateur (par exemple « Certitude moyenne », déjà fourni par l'API : `kpi.avg_confidence`). Demandez de l'aide si besoin.
* **Livrable** : 4 captures d'écran pour le rapport.
* **Terminé quand** : vous pouvez dérouler la démonstration sans toucher au terminal.

#### Jour 19 — Tests et validation
* **Objectif** : prouver chaque critère du cahier des charges.
* **À faire** : lancer les tests ; remplir le tableau de la section 4 de ce guide (critère → preuve).
* **Exercice** : écrivez un 39ᵉ test pour un cas limite de votre choix (par exemple : IP protégée ciblée par une attaque → décision `denied`).
* **Livrable** : « Rapport de tests sur les quatre scénarios » (livrable n° 8 du cahier) = tableau de la section 1 + sortie des tests + captures.
* **Terminé quand** : 100 % des critères de la section 13 du cahier sont associés à une preuve.

#### Jour 20 — Rapport et soutenance
* **À faire** : assembler le rapport (plan en section 6) ; préparer 10 à 12 diapositives ; mettre à jour la section 10 du cahier (contrainte « données simulées ») et la section 13 (critère chiffré : chaque scénario produit conclusion, investigation, action, rapport).
* **Livrable** : rapport complet + diapositives.

#### Jour 21 — Répétition
* Répéter la démonstration deux fois à voix haute, chronométrée (section 5). Répondre à voix haute aux questions de `docs/QUESTIONS_SOUTENANCE.md`. Préparer un **plan B** (captures et vidéo de la démo) en cas de panne.

---

## 3. Correspondance cahier des charges ↔ projet

### 3.1 Besoins fonctionnels

| ID | Besoin | Où / preuve |
|---|---|---|
| BF01 | Collecter les événements | `soc/parsers.py`, `data/logs/` ; `python -m soc.main run` affiche le nombre d'événements |
| BF02 | Détecter les activités suspectes | `soc/extractor.py` (alertes candidates) |
| BF03 | Identifier et classifier les menaces | Hypothèses `h.*` de l'agent ; verdict dans `list` |
| BF04 | Évaluer la criticité | Gravité déterminée par les preuves ; colonne Sévérité |
| BF05 | Consulter la base de connaissances | `knowledge/*.json`, outil `check_local_ioc` |
| BF06 | Raisonner de façon justifiable | `soc/agent/beliefs.py` ; `explain <ID>` |
| BF07 | Planifier les investigations | `soc/agent/planner.py` |
| BF08 | Choisir les outils selon l'incident | `candidate_needs` ; chemins différents (jour 8) |
| BF09 | Analyser les résultats des outils | étape « Évaluation » du rapport |
| BF10 | Adapter le plan selon les observations | besoin `post_login`, corrélation IP (jours 8 et 13) |
| BF11 | Proposer une stratégie de réponse | `propose_response` |
| BF12 | Exécuter les actions autorisées | `soc/response.py` + `soc/decision.py` |
| BF13 | Vérifier les résultats | champ « Vérifiée » du rapport, section 6 |
| BF14 | Générer des rapports | `data/reports/INC-*.md` |
| BF15 | Consulter l'historique | table `audit`, `list`, interface web |

### 3.2 Besoins non fonctionnels

| Besoin | Réalisation |
|---|---|
| Sécurité | liste blanche, rôles d'outils, IP protégées, bac à sable, actions simulées |
| Fiabilité | déterminisme (graine fixe), 69 tests |
| Traçabilité | table `audit`, preuves de l'agent enregistrées, rapports reconstruits depuis la base |
| Explicabilité | `explain`, tableau « Raisonnement de l'agent » dans chaque rapport |
| Performance | 479 événements → 12 incidents en moins d'une seconde |
| Autonomie contrôlée | 3 niveaux, actions sensibles toujours validées par un humain |
| Robustesse | lignes illisibles ignorées, exceptions d'outils capturées, fichier supprimé géré |

---

## 4. Critères de validation (section 13 du cahier) → preuves

| Critère | Preuve à fournir |
|---|---|
| Événements correctement collectés | sortie de `demo` (« 479 événements chargés ») ; `tests.test_parsers_extractor` |
| Quatre scénarios simulés et analysés | tableau des 12 incidents ; `tests.test_pipeline` |
| Alertes identifiées et classifiées | colonnes Verdict / Sévérité de `list` |
| Raisonnement de l'agent pertinent | `soc/agent/beliefs.py` (preuves par scénario) ; tableaux des jours 6, 11, 12 |
| Révision des croyances correcte | `tests.test_beliefs` (10 tests) ; schéma du jour 5 |
| Conclusions justifiées | `explain <ID>` ; section 4 des rapports |
| Agent choisit un objectif et planifie | section 5 des rapports (« Planification ») |
| Agent sélectionne les outils adaptés | chemins d'outils différents par incident (jour 8) |
| Agent exploite les résultats et adapte | étape « Évaluation » : certitude avant → après, nouvelles preuves |
| Réponses conformes aux permissions | `tests.test_response_decision`, niveaux 1/2/3 |
| Actions vérifiées après exécution | section 6 des rapports, colonne « Vérifiée » |
| Décisions et actions enregistrées et consultables | table `audit`, rapports, interface |
| Fonctionne sans API d'IA externe | `soc/` n'importe aucune bibliothèque réseau ni LLM ; cœur = bibliothèque standard |

Pour le critère chiffré suggéré : « chaque scénario produit une conclusion, une investigation, une action (ou une absence d'action justifiée) et un rapport » → vérifié par `test_every_incident_has_report_and_audit`.

---

## 5. Script de démonstration (10 minutes)

1. **(1 min)** Présenter l'architecture (diagramme de `docs/ARCHITECTURE.md`).
2. **(1 min)** `python -m soc.main demo` : 12 incidents traités.
3. **(2 min)** **Scénario 1** : `show INC-0001` — force brute, certitude 0,94, blocage automatique **vérifié**. Montrer `explain INC-0001` (preuves EV-SSH-01 → 02 → 03 → 08).
4. **(2 min)** **Cas critique** : `show INC-0004` — l'agent découvre une connexion réussie, interroge les commandes post-connexion, relie l'IP au scan précédent. Action **sensible** → `pending`.
5. **(1 min)** `approve <id>` puis `state` : l'IP est bloquée ; `rollback` pour montrer le retour arrière.
6. **(1 min)** **Faux positifs** : INC-0007 et INC-0009 clos sans action (le système sait ne rien faire).
7. **(1 min)** **Fichiers** : INC-0008 (quarantaine auto) vs INC-0010 (hash inconnu → analyste notifié seulement).
8. **(1 min)** Changer le niveau d'autonomie : `demo --level 2` → plus aucune action automatique. Conclusion sur l'autonomie contrôlée.

Option : tout depuis l'interface web (`python -m soc.main serve --demo`), ou en mode réel sur votre Wazuh (`serve --live`).

---

## 6. Plan du rapport (proposition)

1. Introduction, contexte, problématique, objectifs
2. Cahier des charges et périmètre (4 scénarios, exclusions, simplifications assumées)
3. Étude des besoins (acteurs, BF01–BF15, besoins non fonctionnels)
4. Conception : architecture, format d'événement normalisé, flux de données
5. Raisonnement de l'agent : croyances, preuves, accumulation des certitudes, justification
6. Agent autonome : cycle, état, planification, outils, adaptation, arrêt
7. Contrôle de l'autonomie : niveaux, liste blanche, validation humaine, vérification, retour arrière
8. Réalisation : technologies, arborescence, interface
9. Tests et validation : 69 tests, 12 incidents, critères du cahier
10. Limites et perspectives (section 8)
11. Conclusion
Annexes : preuves de l'agent, exemple de rapport d'incident, captures d'écran

---

## 7. Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| `ModuleNotFoundError: soc` | Mauvais dossier | Lancer depuis la racine du projet (là où se trouve `soc/`), avec `python -m soc.main ...` |
| L'interface ne s'ouvre pas | Port 8000 déjà pris | `python -m soc.main serve --demo --port 8010` |
| `python: command not found` | Sur Linux/macOS | Utiliser `python3` (ou activer le venv) |
| « Aucune donnée » dans l'interface | Démo jamais lancée | Bouton « Générer les logs et lancer la démo » |
| `pending` vide après une 2ᵉ exécution | Les décisions ont été traitées | `python -m soc.main demo` repart de zéro |
| `décision introuvable ou déjà traitée` | Mauvais ID | Utiliser l'ID de la colonne « décision » affichée par `pending` (pas l'ID d'incident) |
| Résultats différents du tableau | Preuve, poids, seuil ou graine modifiés | `git diff` ; relancer les tests pour voir ce qui casse |
| Tests en échec après modification | Un test encode le comportement attendu | Lire le message : soit votre changement est volontaire (adapter le test), soit c'est une régression |

---

## 8. Limites et perspectives (à assumer dans le rapport)

**Limites** : données simulées (les taux de faux positifs réels ne sont pas mesurés) ; seuils fixés à la main ;
facteurs de certitude heuristiques (non calibrés statistiquement) ; une seule machine et un seul fichier de log par source ;
actions simulées uniquement ; pas d'authentification utilisateur dans l'interface.

**Perspectives** :
1. **Machine Learning** : Isolation Forest sur des caractéristiques de connexion (heure, volume, IP rare) — le score devient un **fait** que l'agent intègre à ses croyances.
2. **LangGraph** : le cycle de l'agent se transpose directement en graphe (un nœud par étape : raisonnement, planification, outil, évaluation) ; les outils restent identiques.
3. **Wazuh en production de laboratoire** : `docs/WAZUH.md`, avec décodeurs dédiés aux événements de fichiers (FIM).
4. **Threat intelligence** externe (VirusTotal, AbuseIPDB) comme outil supplémentaire — hors périmètre car dépendance réseau.
5. **Authentification et rôles** (administrateur / analyste) dans l'interface.
6. Apprentissage des **seuils** à partir de données réelles ; calibration des poids des preuves.

---

## 9. Glossaire

| Terme | Définition |
|---|---|
| SOC | Centre des opérations de sécurité |
| IOC | Indicateur de compromission (IP, hash, motif…) |
| Agent | Programme qui poursuit un objectif : il perçoit, raisonne, choisit ses actions, observe le résultat et s'adapte |
| Croyance | Certitude (0 à 1) que l'agent accorde à une hypothèse à un instant donné |
| Preuve | Constat sur les faits observés, avec un poids, qui renforce ou crée une croyance |
| Hypothèse | Explication possible de ce qui est observé (`h.brute_force_ssh`), portée par une croyance |
| Agent | Programme avec un objectif, un état, des outils et une boucle perception-action |
| Faux positif | Alerte sur une activité légitime |
| Action sensible | Action toujours soumise à validation humaine |
| Idempotence | Répéter une action produit le même résultat que l'exécuter une fois |
