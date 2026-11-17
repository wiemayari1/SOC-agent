# Intégration Wazuh — statut et limites

La **procédure complète** (installation, agent, sources de logs, FIM, tunnel SSH, configuration, diagnostic, démarrage)
se trouve dans le **README, section 10**. Ce fichier ne garde que le statut de test et les limites.

## Statut de test (honnête)

* **Testé** (suite automatique, 66 tests) : conversion des alertes (SSH, sudo, UFW, Nginx, FIM/syscheck), lecture incrémentale
  de l'indexeur et d'un fichier alerts.json, authentification, erreurs de connexion, surveillance continue
  (maturité des alertes, dédoublonnage, niveaux d'autonomie), serveur web et interface.
  **Tous ces tests utilisent un FAUX serveur Wazuh** (`tests/mock_wazuh.py`) qui reproduit la structure documentée des alertes.
* **Non testé** : un vrai serveur Wazuh (versions, différences de champs, volume), le module FIM réel, l'API du serveur réel.
  La commande `python -m soc.main wazuh-check` est faite pour vérifier cela sur votre laboratoire en une minute.

## Limites

* Seules les lignes SSH / sudo / UFW / Nginx et les événements FIM `added`/`modified` sont convertis.
* `wazuh-alerts-*` ne contient que les événements ayant déclenché une règle Wazuh ; pour les journaux non alertés (pare-feu, web),
  activer les archives (README §10.5).
* Hôtes Windows surveillés : non gérés (chemins et journaux différents).
* Les réponses restent **simulées** : aucun ordre n'est envoyé à Wazuh ni à un pare-feu réel.
* Les horodatages sont ceux de Wazuh, convertis en UTC.
