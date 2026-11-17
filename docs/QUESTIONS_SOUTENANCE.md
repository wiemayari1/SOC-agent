# Questions probables du jury et éléments de réponse

**1. Qu'est-ce qui rend votre agent « agentique » et pas une suite de `if` ?**
L'agent a un objectif (confirmer ou réfuter l'hypothèse principale), un état (faits, outils déjà utilisés, croyances) et choisit
dynamiquement son prochain outil parmi les besoins d'information ouverts. Deux incidents du même scénario suivent des chemins
différents : INC-0004 appelle `search_logs` (car une connexion a réussi) alors qu'INC-0001 ne le fait pas. Les observations
modifient les faits, l'agent révise ses croyances, et sa certitude décide de la suite (`test_agent_adapts_path_to_observations`).

**2. Pourquoi ne pas utiliser un LLM ni une API externe (Gemini, Claude…) ?**
Dans un SOC, une décision automatique doit être vérifiable, reproductible et explicable, et ne doit pas dépendre d'un service tiers
(confidentialité des journaux, disponibilité, coût). Ici l'agent est entièrement local : mêmes faits, même verdict, à chaque exécution.
Chaque conclusion s'appuie sur des preuves dont on peut afficher les valeurs observées. Un LLM pourrait, en perspective, rédiger le
rapport final, jamais prendre la décision.

**3. Votre agent n'est-il pas un système expert déguisé ?**
Non : il n'y a ni base de règles chargée depuis un fichier, ni moteur d'inférence qui balaie des règles jusqu'au point fixe. L'agent
tient un état de croyance et le révise à chaque observation ; surtout, il décide lui-même de l'action suivante (planificateur),
agit sur son environnement via des outils, évalue le résultat et s'adapte. Un système expert se contente de déduire à partir des
faits qu'on lui donne ; il n'enquête pas pour en obtenir d'autres. Les poids des preuves sont du savoir de l'agent écrit en
code, ce qui est une limite assumée (voir question 12).

**4. Comment l'agent calcule-t-il sa certitude ?**
Chaque preuve a un poids (0 à 1). Les preuves qui soutiennent la même hypothèse s'accumulent par a + b(1 − a) : 0,70 puis 0,60
donne 0,88. Une preuve qui dépend d'une croyance est pondérée par la certitude de cette croyance. Ce ne sont pas des probabilités
calibrées, mais des degrés de confiance heuristiques (limite assumée).

**5. D'où viennent vos seuils (10 échecs, 15 ports…) ?**
Ce sont des valeurs de départ inspirées de pratiques courantes (fail2ban : quelques échecs en quelques minutes ; scanners : dizaines
de ports par minute), placées dans `config/policy.json`, modifiables. Ils ne sont pas calibrés sur du trafic réel : c'est
une limite, et la certitude sert précisément à exprimer cette incertitude plutôt qu'un oui/non brutal.

**6. Que se passe-t-il si l'agent se trompe ?**
Trois protections : (1) les actions sensibles et à faible certitude passent par un humain ; (2) toute action est vérifiée après
exécution et réversible (`rollback`) ; (3) les IP protégées ne peuvent jamais être bloquées. Les faux positifs INC-0007 et INC-0009
montrent que le système sait conclure « bénin ».

**7. Comment gérez-vous les erreurs des outils ?**
Toute exception est capturée et renvoyée comme un `ToolResult(ok=False)`. L'agent note l'échec, ne retente pas le même besoin et
poursuit avec les autres sources. Si le fichier a disparu, `inspect_file_hash` se rabat sur le hash journalisé.

**8. Vos données sont simulées : est-ce représentatif ?**
Non, et c'est assumé : la simulation garantit une démonstration reproductible et permet d'inclure des cas pièges (faux positifs).
L'architecture sépare la collecte du raisonnement : brancher Wazuh ou de vrais logs ne modifie que les parseurs (voir `docs/WAZUH.md`).

**9. Pourquoi aucune commande système réelle ?**
Laboratoire isolé et sécurité : le pare-feu est un fichier JSON, la quarantaine ne touche que le bac à sable, avec contrôle
anti path traversal. Passer en réel consisterait à remplacer le corps de `soc/response.py`, la politique et la validation humaine
restant identiques.

**10. Comment ajouter un nouveau scénario ?**
(1) fonction d'extraction de faits dans `extractor.py` ; (2) une fonction de preuves pour ce scénario dans `soc/agent/beliefs.py` (appels `c.note(...)`) ; (3) éventuellement un
besoin dans `planner.py` et un outil ; (4) un parseur si nouvelle source. L'agent, la décision, la réponse et le reporting ne changent pas.

**11. Quelle différence entre votre agent et Wazuh/un SIEM ?**
Un SIEM détecte et alerte avec ses règles ; il n'enquête pas. Ici l'agent enrichit l'alerte (réputation, historique, corrélation
entre sources), révise sa certitude et propose une réponse justifiée.

**12. Quelles sont les limites de votre travail ?**
Voir `GUIDE_DE_TRAVAIL.md`, section 8 : données simulées, seuils et poids des preuves non calibrés, actions simulées, pas de ML.
