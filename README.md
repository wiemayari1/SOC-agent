# 🛡️ Agent SOC autonome — IA agentique

Un **agent SOC** qui surveille un Wazuh (ou des journaux simulés), **détecte, investigue, décide et répond** sur 4 scénarios
d'attaque, avec un **raisonnement d'agent explicable** (croyances révisées après chaque observation) et une **autonomie contrôlée**
(liste blanche, validation humaine, vérification, retour arrière), le tout supervisé depuis une **interface web**.

* **IA agentique uniquement.** Pas de système expert (ni base de règles, ni moteur d'inférence), **pas de LLM, aucune API d'IA externe** (Gemini, Claude, OpenAI…) : l'agent raisonne et planifie lui-même, en Python.
* **Aucune dépendance à installer** : bibliothèque standard Python 3.10+ uniquement (interface web comprise).
* **Les actions de réponse sont simulées**, même en mode Wazuh : aucun `iptables`, aucune commande système.

## Sommaire

1. [Ce que fait le projet](#1-ce-que-fait-le-projet) · 2. [Prérequis](#2-prérequis) · 3. [Installation](#3-installation) ·
4. [Démarrage rapide](#4-démarrage-rapide-démonstration) · 5. [L'interface web](#5-linterface-web) · 6. [Toutes les commandes](#6-toutes-les-commandes) ·
7. [Arborescence](#7-arborescence--que-contient-chaque-dossier-et-chaque-fichier) · 8. [Comment ça marche](#8-comment-ça-marche) ·
9. [Configuration](#9-configuration-et-personnalisation) · 10. [**Wazuh : installation et mode réel**](#10-wazuh--installation-et-surveillance-en-continu) ·
11. [Tests](#11-tests) · 12. [Dépannage](#12-dépannage) · 13. [Sécurité et limites](#13-sécurité-et-limites) · 14. [Les démarches](#14-les-démarches-de-zéro-à-la-soutenance)

---

## 1. Ce que fait le projet

```
Wazuh (ou logs simulés) → événements → alertes + faits → agent (perception → raisonnement → plan → outil → observation → évaluation) → décision → réponse → rapport
                                                                                    ↑ validation humaine (interface web)
```

| Scénario | Détection | Exemple de réponse |
|---|---|---|
| 1. Force brute SSH | rafale d'échecs de connexion depuis une IP, succès après échecs | blocage de l'IP, notification |
| 2. Scan de ports | nombreux ports distincts en 60 s (journal pare-feu UFW) | blocage ou surveillance |
| 3. Injection SQL | `UNION SELECT`, `OR 1=1`, `SLEEP()`… dans les logs Nginx | blocage de l'IP |
| 4. Fichiers suspects / ransomware | hash connu (FIM Wazuh), double extension, rafale de fichiers `.locked` | quarantaine, isolation de la machine |

Deux modes de fonctionnement :

| Mode | Commande | Usage |
|---|---|---|
| **Démonstration** | `python -m soc.main serve --demo` | Données simulées reproductibles (12 incidents), idéal pour tester et présenter |
| **Wazuh en continu** | `python -m soc.main serve --live` | Lit les alertes de **votre** Wazuh en boucle et traite les incidents au fil de l'eau |

## 2. Prérequis

| Besoin | Détail |
|---|---|
| Python | **3.10 ou plus** (`python3 --version`). Sous Windows : `py -0` liste les versions, utilisez `py -3.12` si `python` pointe vers une version trop ancienne |
| Navigateur | Chrome, Edge, Firefox ou Safari récents |
| Wazuh | facultatif (mode `--live`), voir section 10 |
| Node.js | facultatif, uniquement pour le test automatique de l'interface |

## 3. Installation

```bash
unzip soc_agent.zip
cd soc_agent
```

C'est tout : **il n'y a rien à installer** (pas de `pip install`, pas de `npm`).
Windows PowerShell : avant de lancer, tapez `$env:PYTHONUTF8 = "1"` (le programme force aussi l'UTF-8 lui-même), et remplacez `python` par `py -3.12`.

## 4. Démarrage rapide (démonstration)

```bash
python -m soc.main serve --demo        # génère les données simulées, traite les 12 incidents, ouvre http://127.0.0.1:8000
```

Ou en ligne de commande seule :

```bash
python -m soc.main demo                # génère + analyse
python -m soc.main list                # liste des incidents
python -m soc.main show INC-0004       # rapport complet (compromission SSH)
python -m soc.main explain INC-0004    # raisonnement de l'agent, preuve par preuve
python -m soc.main pending             # actions en attente de validation
python -m soc.main approve 5           # valider (ID de la colonne « décision » de pending)
python -m unittest discover -s tests -t .      # 69 tests
```

**Résultat attendu** (12 incidents) :

| ID | Scénario | Source | Verdict | Certitude | Sévérité | Issue |
|---|---|---|---|---|---|---|
| INC-0001 | Force brute SSH | 198.51.100.23 | confirmée | 0,94 | high | blocage automatique vérifié |
| INC-0002 | Scan de ports | 192.0.2.88 | probable | 0,83 | medium | blocage automatique |
| INC-0003 | Scan de ports | 203.0.113.77 | confirmée | 0,90 | high | **validation humaine** (multi-étapes) |
| INC-0004 | Force brute + succès | 203.0.113.77 | confirmée | 0,95 | critical | **validation humaine** (compromission) |
| INC-0005 | Injection SQL (sqlmap) | 198.51.100.140 | confirmée | 0,95 | high | blocage automatique |
| INC-0006 | Injection SQL manuelle | 203.0.113.200 | probable | 0,82 | high | blocage automatique |
| INC-0007 | Apostrophe légitime | 10.0.0.60 | bénin | 0,70 | low | faux positif clos |
| INC-0008 | `facture.pdf.exe` | /tmp | confirmée | 0,98 | high | quarantaine automatique |
| INC-0009 | Fautes de frappe SSH | 10.0.0.45 | bénin | 0,80 | info | faux positif clos |
| INC-0010 | Script inconnu | /tmp/update.sh | possible | 0,44 | low | analyste notifié |
| INC-0011 | Ransomware | srv-files | confirmée | 0,93 | critical | **validation humaine** (isolation) |
| INC-0012 | Sondage limité | 192.0.2.99 | possible | 0,51 | medium | surveillance |

## 5. L'interface web

Lancée par `serve` ; adresse par défaut `http://127.0.0.1:8000` (option `--port`).

| Page | Contenu |
|---|---|
| **Tableau de bord** | Indicateurs (incidents, critiques, à valider, traités automatiquement, faux positifs, IP bloquées), courbe dans le temps, répartition par sévérité et scénario, incidents récents |
| **Incidents** | Liste filtrable (recherche, sévérité, scénario, statut) ; clic = détail |
| **Détail d'un incident** | Synthèse (verdict, certitude, hypothèses, faits clés) · **Raisonnement de l'agent** (preuves retenues, constats avec valeurs réelles, effet sur ses croyances) · **Investigation** (chronologie des étapes de l'agent et outils utilisés) · **Réponse** (décisions, validation, vérification, annulation) · Preuves (extraits de journaux) · Audit · téléchargement du rapport |
| **Validations** | Actions sensibles en attente : *Approuver* / *Rejeter* (double clic de confirmation) |
| **Flux Wazuh** | Alertes reçues en direct (agent, règle, niveau, IP) |
| **Réponse** | IP bloquées, machines isolées, surveillance, quarantaine, notifications (journal des actions simulées) |
| **Système** | État de la connexion Wazuh, **agents Wazuh** (via l'API), niveau d'autonomie, liste blanche des actions, renseignement local (IOC) |

En haut : l'état de la source (**Wazuh connecté / injoignable / démonstration**), le **sélecteur d'autonomie N1 / N2 / N3** (appliqué immédiatement),
le thème clair/sombre. L'interface se rafraîchit seule toutes les 5 secondes.

Sécurité de l'interface : écoute **locale** uniquement (`127.0.0.1`), contrôle de l'en-tête `Host`, jeton **anti-CSRF** sur toutes les actions,
**CSP stricte**, et **aucune donnée issue des journaux n'est interprétée comme du HTML** (testé avec une charge XSS). Pour y accéder à distance,
utilisez un tunnel SSH (`ssh -L 8000:127.0.0.1:8000 utilisateur@machine`) plutôt que `--host 0.0.0.0` (aucune authentification intégrée).

## 6. Toutes les commandes

| Commande | Effet |
|---|---|
| `serve --demo` | Interface web + données simulées |
| `serve --live [--level N] [--reset]` | Interface web + **surveillance Wazuh en continu** (`config/wazuh.json`) |
| `serve [--host H] [--port P] [--no-browser]` | Options du serveur web |
| `wazuh-check` | **Diagnostic pas à pas** de la connexion Wazuh (à lancer avant `--live`) |
| `generate` / `run [--level N]` / `demo [--level N]` | Données simulées / analyse de `data/logs/` / les deux |
| `list`, `show ID`, `explain ID` | Incidents, rapport, raisonnement |
| `pending`, `approve ID`, `reject ID` | Validation humaine (ID de décision) |
| `actions`, `rollback ID` | Actions exécutées, retour arrière (ID d'action) |
| `state` | État du pare-feu simulé |

**Niveaux d'autonomie** : **1** = l'agent propose seulement · **2** = toute action attend une validation humaine ·
**3** = l'agent exécute les actions autorisées (sauf actions sensibles ou certitude insuffisante). En mode `--live`, le niveau par défaut est **2** (`config/wazuh.json`).

## 7. Arborescence : que contient chaque dossier et chaque fichier

```
soc_agent/
├── README.md, GUIDE_DE_TRAVAIL.md, requirements.txt, Dockerfile, docker-compose.yml, .gitignore
├── config/        policy.json · wazuh.example.json (→ copier en wazuh.json)
├── knowledge/     patterns.json · ioc.json   (données de renseignement, pas de règles)
├── soc/           le code (voir ci-dessous)
│   ├── agent/     agent.py · beliefs.py · planner.py · tools.py
│   └── web/       server.py · api.py · static/ (index.html, style.css, app.js)
├── tests/         69 tests (dont mock_wazuh.py, ui/ui_smoke.js)
├── docs/          ARCHITECTURE.md · QUESTIONS_SOUTENANCE.md · WAZUH.md
└── data/          généré à l'exécution (logs, bac à sable, état, rapports, soc.db)
```

| Fichier | Rôle |
|---|---|
| `config/policy.json` | Politique : niveau d'autonomie par défaut, **liste blanche d'actions** (`auto`, `min_cf`), IP/machines protégées, paramètres de l'agent, seuils |
| `config/wazuh.example.json` | Modèle de configuration Wazuh (indexeur, API, fichier, intervalle, niveau d'autonomie) |
| `knowledge/patterns.json` | Motifs d'injection SQL, scanners, extensions suspectes, ports sensibles… |
| `knowledge/ioc.json` | IP et hash malveillants connus (exemples de laboratoire) |
| `soc/main.py` | Ligne de commande |
| `soc/config.py` | Chemins, `Workspace`, chargement des configurations, réglages modifiés depuis l'interface |
| `soc/events.py` | **Format d'événement normalisé** |
| `soc/parsers.py` | Collecte : `auth.log`, UFW, Nginx, événements fichiers, export Wazuh |
| `soc/simulator.py` | Génère les journaux simulés (déterministes) |
| `soc/wazuh.py` | **Connecteur Wazuh** : indexeur (OpenSearch), fichier `alerts.json`, API du serveur (lecture seule), conversion des alertes (SSH, sudo, UFW, Nginx, FIM) |
| `soc/live.py` | **Surveillance continue** : fenêtre glissante, maturité des alertes, dédoublonnage, traitement au fil de l'eau |
| `soc/extractor.py` | Analyse : alertes candidates et **faits** |
| `soc/agent/agent.py` · `beliefs.py` · `planner.py` · `tools.py` | **Agent** (cycle perception→décision), **raisonnement par croyances et preuves**, **planification**, **6 outils** à permissions par rôle |
| `soc/decision.py` | Liste blanche, cibles protégées, niveaux 1/2/3, actions sensibles |
| `soc/response.py` | Actions **simulées**, vérifiées, réversibles |
| `soc/storage.py` | SQLite : incidents, étapes, preuves de l'agent, décisions, actions, audit, flux Wazuh |
| `soc/reporting.py` | Rapports Markdown reconstruits depuis la base |
| `soc/pipeline.py` | Chaîne complète, traitement d'une alerte, validation humaine |
| `soc/web/server.py` · `api.py` · `static/*` | Serveur web sécurisé, API JSON, interface monopage |
| `tests/` | Raisonnement de l'agent, parseurs, réponses, pipeline, connecteur Wazuh (faux serveur), surveillance continue, API web, interface (jsdom) |

## 8. Comment ça marche

1. **Collecte** : Wazuh (en continu) ou logs simulés → événements normalisés, dédoublonnés, en **UTC**.
2. **Analyse** : fenêtre glissante → *alertes candidates* + **faits** (`ssh_failed_in_window = 45`…).
3. **Maturité** (mode live) : une alerte est traitée quand l'activité s'est calmée (45 s), en urgence si un **succès SSH suit des échecs**, ou si l'attaque dure plus de 5 min. Une même attaque ne crée pas dix incidents.
4. **Raisonnement de l'agent** (`beliefs.py`) : l'agent repère des **preuves** dans ce qu'il observe et **révise ses croyances** (une certitude par hypothèse). Les preuves s'accumulent : 0,70 puis 0,60 → 0,88 (`a + b × (1 − a)`). Une croyance déjà formée peut rendre une autre preuve visible (brute force établie + connexion réussie → compromission). Il n'y a ni fichier de règles ni moteur d'inférence.
5. **Agent** : objectif = confirmer ou réfuter l'hypothèse principale. Il **choisit lui-même** son prochain outil selon son état (ex. *une connexion a réussi après des échecs → que s'est-il passé ensuite ?*), **révise ses croyances** avec chaque observation, s'arrête quand c'est confirmé, réfuté ou que son budget d'étapes est atteint.
6. **Décision** : liste blanche → cible protégée → niveau → action sensible → seuil de certitude.
7. **Réponse** : action simulée, **vérifiée**, enregistrée, réversible ; **rapport** et **audit**.

Verdicts : ≥ 0,85 **confirmée** · ≥ 0,60 **probable** · ≥ 0,30 **possible** · sinon **aucune menace** ; une hypothèse « bénigne » forte donne **faux positif**.

## 9. Configuration et personnalisation

| Je veux… | Je modifie… |
|---|---|
| Changer l'autonomie | l'interface (N1/N2/N3), ou `config/policy.json` → `autonomy_level`, ou `config/wazuh.json` (mode live) |
| Rendre le blocage plus prudent | `policy.json` → `actions.block_ip.min_cf` |
| Protéger une IP ou une machine | `policy.json` → `protected_ips` / `protected_hosts` (indispensable : votre poste et la passerelle) |
| Régler un seuil de détection | `policy.json` → `thresholds` |
| Ajouter un type de preuve | une fonction dans `soc/agent/beliefs.py` (appel `c.note(...)`) |
| Ajouter une IP/un hash malveillant | `knowledge/ioc.json` |
| Ajuster la réactivité en live | `config/wazuh.json` → `poll_seconds`, `settle_seconds`, `window_minutes` |

Exemple de preuve dans `soc/agent/beliefs.py` :

```python
c.note("EV-SSH-01", "Rafale d'échecs SSH", "Au moins 10 échecs depuis la même IP dans une fenêtre de 2 min.",
       [S("ssh_failed_in_window", ">=", 10)], 0.7,
       hyp="h.brute_force_ssh", sev="medium", wants=("ip_history",))
```

Lecture : *si l'agent constate au moins 10 échecs, il retient cette preuve (poids 0,7), augmente sa croyance « force brute », relève la gravité et exprime le besoin de connaître l'historique de l'IP* (que le planificateur ira chercher avec un outil).

## 10. Wazuh : installation et surveillance en continu

> **Statut de test — à lire.** Le connecteur, la surveillance continue, le serveur web et l'interface sont testés automatiquement
> (69 tests) contre un **faux serveur Wazuh** qui reproduit la structure documentée des alertes. **Ils n'ont pas été testés contre un vrai Wazuh.**
> La commande `wazuh-check` (10.7) vérifie en une minute que tout fonctionne sur votre laboratoire ; si un champ diffère de votre version, envoyez-moi sa sortie.

### 10.1 Architecture du laboratoire

| Machine | Rôle |
|---|---|
| **VM-Wazuh** (Ubuntu 24.04, 4 vCPU / 8 Go RAM / 50 Go) | Serveur + indexeur + tableau de bord Wazuh |
| **VM-Cible** (Ubuntu 24.04, 2 Go RAM) | Machine surveillée : SSH, Nginx, UFW + agent Wazuh |
| **VM-Attaquant** (Kali/Ubuntu, optionnelle) | Génère des attaques **dans le laboratoire uniquement** |
| **Votre PC** | Exécute l'agent SOC (ce projet) et l'interface web |

Réseau : *host-only* ou *réseau interne* (jamais en pont vers un réseau réel pour les attaques). Exemple : VM-Wazuh `192.168.56.10`, VM-Cible `192.168.56.20`, VM-Attaquant `192.168.56.30`.
Ports : `1514/tcp` et `1515/tcp` (agents → serveur), `443/tcp` (tableau de bord), `9200/tcp` (indexeur), `55000/tcp` (API).

### 10.2 Installer le serveur Wazuh (VM-Wazuh)

Si Wazuh est déjà installé, passez à 10.3. Sinon (procédure « Quickstart » officielle, version 4.14 à la rédaction — vérifiez la version courante) :

```bash
sudo apt update && sudo apt install -y curl
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt      # mots de passe (admin, API…)
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard                      # tout doit être « active (running) »
```

Tableau de bord : `https://192.168.56.10` (acceptez l'avertissement de certificat). Gardez le fichier de mots de passe : il sert à `config/wazuh.json`.

### 10.3 Installer l'agent sur la machine surveillée (VM-Cible)

**Recommandé** : tableau de bord → *Endpoints* → **Deploy new agent** → *Linux / DEB amd64*, adresse du serveur, nom `vm-cible`, puis copiez la commande générée sur la VM-Cible. Équivalent manuel :

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo WAZUH_MANAGER="192.168.56.10" apt install -y wazuh-agent
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
```

L'agent doit apparaître **Active** dans *Endpoints*.

### 10.4 Configurer les sources de logs de la VM-Cible

```bash
sudo apt install -y openssh-server nginx ufw rsyslog
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp          # AVANT d'activer UFW, sinon vous perdez l'accès SSH
sudo ufw enable && sudo ufw logging medium               # journal : /var/log/ufw.log
```

Dans `/var/ossec/etc/ossec.conf` **de l'agent**, avant `</ossec_config>` (le journal `auth.log` est déjà collecté par défaut) :

```xml
<localfile><log_format>syslog</log_format><location>/var/log/ufw.log</location></localfile>
<localfile><log_format>apache</log_format><location>/var/log/nginx/access.log</location></localfile>
```

Pour le **scénario 4** (fichiers), dans la section `<syscheck>` existante de ce même fichier, ajoutez la surveillance temps réel de `/tmp` et `/home` (par défaut Wazuh ne surveille que `/etc`, `/bin`, `/usr/bin`…) :

```xml
<directories realtime="yes">/tmp,/home</directories>
```

Puis `sudo systemctl restart wazuh-agent`.

### 10.5 Recevoir *tous* les événements, pas seulement les alertes Wazuh

`wazuh-alerts-*` ne contient que les événements ayant déclenché une règle Wazuh : le trafic pare-feu et web non alerté en est absent, ce qui prive l'agent de contexte (scan de ports, injection SQL).
Pour tout recevoir, sur **VM-Wazuh** :

1. `/var/ossec/etc/ossec.conf`, section `<global>` : `<logall_json>yes</logall_json>`, puis `sudo systemctl restart wazuh-manager`.
2. `/etc/filebeat/filebeat.yml` : dans le module `wazuh`, passer `archives:` à `enabled: true`, puis `sudo systemctl restart filebeat`.
3. Dans `config/wazuh.json` : `"index_pattern": "wazuh-alerts-*,wazuh-archives-*"` (les doublons alerte/archive sont éliminés automatiquement).

### 10.6 Relier votre PC à Wazuh (tunnel SSH)

Dans une installation « tout-en-un », l'indexeur (9200) écoute souvent **uniquement en local** sur la VM-Wazuh. Le plus simple et le plus sûr est un **tunnel SSH**
(le client OpenSSH est inclus dans Windows 10/11) — **laissez cette fenêtre ouverte** :

```powershell
ssh -N -L 9200:127.0.0.1:9200 -L 55000:127.0.0.1:55000 utilisateur@192.168.56.10
```

Ensuite, copiez `config/wazuh.example.json` en `config/wazuh.json` et renseignez les mots de passe du fichier `wazuh-passwords.txt` :

```json
{
  "mode": "indexer", "autonomy_level": 2, "poll_seconds": 10, "lookback_minutes": 60,
  "window_minutes": 60, "settle_seconds": 45, "max_wait_seconds": 300,
  "indexer": {"url": "https://127.0.0.1:9200", "user": "admin", "password": "…", "verify_tls": false,
              "index_pattern": "wazuh-alerts-*,wazuh-archives-*", "min_level": 0},
  "api": {"url": "https://127.0.0.1:55000", "user": "wazuh-wui", "password": "…", "verify_tls": false}
}
```

* `verify_tls: false` : le certificat de Wazuh est auto-signé (laboratoire).
* Les mots de passe peuvent aussi venir de l'environnement : `WAZUH_INDEXER_PASSWORD`, `WAZUH_API_PASSWORD`. **Ne partagez jamais `wazuh.json`** (déjà exclu de git).
* L'utilisateur de l'API est donné dans `wazuh-passwords.txt` ; la section `api` est facultative (elle alimente la page *Système*).
* **Variante sans tunnel** : exécuter l'agent SOC **sur la VM-Wazuh** avec `"mode": "file"` et `"file": {"path": "/var/ossec/logs/archives/archives.json"}` (lecture réservée : lancer avec `sudo`).

### 10.7 Diagnostiquer puis démarrer

```powershell
py -3.12 -m soc.main wazuh-check        # Windows ;  Linux/macOS : python3 -m soc.main wazuh-check
```

Sortie attendue : `[ OK ]` pour la configuration, la connexion, le nombre d'alertes lues, **les événements convertis par type**, et l'état des agents.
Si des alertes arrivent mais qu'aucune n'est « convertie », revoyez 10.4 et 10.5. Quand tout est vert :

```powershell
py -3.12 -m soc.main serve --live       # ouvre http://127.0.0.1:8000
```

Le bandeau passe à **« Wazuh connecté »** ; le *Flux Wazuh* se remplit ; les incidents apparaissent seuls, avec leurs validations.
Les incidents sont conservés d'un démarrage à l'autre (`--reset` pour repartir de zéro).

### 10.8 Générer des attaques de test (laboratoire isolé UNIQUEMENT, sur vos propres machines)

Depuis **VM-Attaquant** contre **VM-Cible** (`192.168.56.20`) :

```bash
printf "123456\npassword\nadmin\nroot\nletmein\nqwerty\n" > pw.txt
hydra -l admin -P pw.txt -t 4 ssh://192.168.56.20                                   # 1. force brute SSH
nmap -p 1-200 192.168.56.20                                                          # 2. scan de ports
curl "http://192.168.56.20/products?id=1%27%20OR%20%271%27%3D%271"                   # 3. injection SQL
curl "http://192.168.56.20/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
```

Sur **VM-Cible**, scénario 4 :

```bash
printf 'SOC-LAB-FAKE-MALWARE-SAMPLE-v1 (fichier inoffensif de simulation)' > /tmp/facture.pdf.exe   # hash présent dans knowledge/ioc.json
mkdir -p /tmp/docs && for i in $(seq 1 25); do touch /tmp/docs/f$i.docx.locked; done                # simulation d'une rafale « ransomware »
```

Attendez ≈ 1 minute (délai de stabilisation) : les incidents apparaissent. **Ajoutez votre propre poste et la passerelle dans `protected_ips`** pour éviter qu'ils soient visés par une décision.

### 10.9 Limites de l'intégration (à dire en soutenance)

* Seules les lignes SSH / sudo / UFW / Nginx et les événements FIM `added`/`modified` sont convertis. Hôtes **Windows** surveillés : non gérés.
* Le scénario 4 dépend du **FIM** (10.4) : sans surveillance de `/tmp`, aucun événement fichier ne remonte.
* Les réponses restent **simulées** : l'agent décide, vérifie et journalise, mais n'envoie aucun ordre à Wazuh ni à un pare-feu réel (choix de sécurité du laboratoire).
* Non testé contre un vrai Wazuh (voir l'encadré d'ouverture). Plan de secours de la soutenance : `serve --demo`.

## 11. Tests

```bash
python -m unittest discover -s tests -t .       # 69 tests, ~10 secondes
```

Le test de l'interface (`tests/test_web_ui.py`) utilise Node.js + jsdom et est **ignoré automatiquement** s'ils sont absents (`npm install jsdom` pour l'activer).
Les tests encodent le comportement attendu : si vous modifiez volontairement une règle ou un seuil, adaptez le test concerné.

## 12. Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| `SyntaxError` sur une chaîne `f"..."` | Python 2.7 lancé par `python` | `py -3.12 -m soc.main …` |
| `ModuleNotFoundError: soc` | mauvais dossier | `cd soc_agent`, puis `python -m soc.main …` |
| L'interface ne s'ouvre pas | port déjà pris | `serve --port 8010` |
| Pastille « Wazuh injoignable » | tunnel fermé, mauvais mot de passe, mauvaise URL | `wazuh-check` donne le message exact (« identifiants refusés », « connexion impossible »…) |
| `wazuh-check` : 0 alerte | rien reçu dans la période | générer une attaque (10.8) ou augmenter `lookback_minutes` |
| Alertes lues mais « ignorées » | règles Wazuh sans SSH/UFW/Nginx/FIM | 10.4 et 10.5 |
| Aucun incident de scan / SQL | pas d'archives | 10.5 |
| Aucun incident fichier | FIM ne surveille pas `/tmp` | 10.4 (`<directories realtime="yes">`) |
| Un incident met ≈ 1 min à apparaître | délai de stabilisation (`settle_seconds`) | normal ; le réduire dans `wazuh.json` |
| Agent « Disconnected » dans Wazuh | ports 1514/1515, mauvaise IP serveur | `sudo systemctl status wazuh-agent`, heure synchronisée (`timedatectl set-ntp true`) |
| `décision introuvable ou déjà traitée` | mauvais ID | `pending` → ID de la colonne « décision » |

## 13. Sécurité et limites

* Actions **simulées** uniquement. Aucun vrai malware : les « fichiers malveillants » du simulateur sont du texte inoffensif (**n'ajoutez pas le fichier EICAR** au projet : les antivirus suppriment l'archive).
* Interface : accès local, jeton anti-CSRF, CSP stricte, pas d'injection HTML. **Pas d'authentification** : ne l'exposez pas sur un réseau partagé.
* `config/wazuh.json` contient des mots de passe : à ne jamais versionner ni partager.
* À ne **jamais** brancher sur une production ; attaques de test uniquement sur vos propres machines, en laboratoire isolé.
* Limites : seuils et poids des preuves fixés à la main (non calibrés), taux de faux positifs réels non mesurés, pas de Machine Learning (perspective : Isolation Forest), réponses non exécutées en réel.

## 14. Les démarches : de zéro à la soutenance

Le plan détaillé jour par jour (21 jours) est dans **`GUIDE_DE_TRAVAIL.md`**. Résumé :

| Étape | Quand | Vous faites | Preuve |
|---|---|---|---|
| 1. Installer et lancer | Jour 1 | `serve --demo`, 69 tests | captures |
| 2. Comprendre données et faits | Jours 2-4 | `parsers.py`, `simulator.py`, `extractor.py` | tableau des scénarios et des faits |
| 3. Maîtriser le raisonnement de l'agent | Jours 5-7 | `beliefs.py`, `planner.py`, **votre** preuve + test | schéma de la révision des croyances |
| 4. Maîtriser l'agent | Jours 8-10 | `agent.py`, `planner.py`, `tools.py` | cycle annoté |
| 5. Les 4 scénarios et la corrélation | Jours 11-13 | preuves NET / WEB / FIL, multi-étapes | tableaux indicateur → preuve → poids |
| 6. Gel des fonctionnalités | Jour 14 | — | revue |
| 7. Autonomie contrôlée | Jours 15-16 | `decision.py`, `response.py`, niveaux, rollback | captures |
| 8. Traçabilité et interface | Jours 17-18 | SQLite, rapports, **interface web** | captures |
| 9. **Brancher votre Wazuh** | à partir du jour 12, avant le jour 19 | **section 10** de ce README | `wazuh-check` + captures du bandeau « Wazuh connecté » |
| 10. Valider, rédiger, répéter | Jours 19-21 | tableau « critères → preuves », rapport, démo | `docs/QUESTIONS_SOUTENANCE.md` |

**Règle d'or** : gardez toujours `serve --demo` comme plan de secours le jour de la soutenance.
