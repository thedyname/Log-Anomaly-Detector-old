# Guide de prise en main

## Où travailler ?

Sur Kali Linux, dans le dossier du projet. Le serveur Wazuh peut rester éteint pour la démonstration. Aucun paquet Python externe n'est nécessaire.

## Lancer la démonstration

```bash
python3 -m logdetector samples/ssh_demo.log --output reports
xdg-open reports/dashboard.html
```

- `python3` lance Python.
- `-m logdetector` exécute le package et son fichier `__main__.py`.
- `samples/ssh_demo.log` est le fichier d'entrée synthétique.
- `--output reports` choisit le dossier des résultats.
- `xdg-open` ouvre le tableau de bord dans le navigateur par défaut.

## Vérifier les tests

```bash
python3 -m unittest discover -s tests -v
```

`unittest` est l'outil de tests intégré à Python. `discover` recherche les tests, `-s tests` indique leur dossier et `-v` affiche chaque résultat.

## Comprendre ensuite, dans cet ordre

1. Lire `samples/ssh_demo.log` et repérer utilisateur, IP, date et résultat.
2. Lire `parser.py` : une ligne devient un événement structuré.
3. Lire `detector.py` : une fenêtre glissante conserve les échecs récents.
4. Lire `report.py` : les alertes deviennent JSON, CSV et HTML.
5. Modifier un seuil et expliquer le changement obtenu.
6. Ajouter votre propre scénario synthétique et un test correspondant.

## Publication depuis une copie Git déjà clonée

Décompresser l'archive, puis copier son contenu dans le dossier du dépôt existant. Ne pas ajouter de vrais logs. Vérifier avant de publier :

```bash
git status
python3 -m unittest discover -s tests -v
git add README.md .gitignore .github logdetector tests samples docs
git diff --cached --stat
git commit -m "Add offline SSH detection, reports and regression tests"
git push origin main
```

- `git status` montre les fichiers modifiés et nouveaux.
- `git add` prépare uniquement les chemins nommés pour le commit.
- `git diff --cached --stat` résume ce qui sera enregistré.
- `git commit -m` crée un enregistrement local avec un message.
- `git push origin main` envoie les commits à GitHub sur la branche main.

Git peut demander de configurer votre nom et votre adresse de commit. Utiliser vos propres informations ou votre adresse GitHub noreply. Pour l'authentification, employer une méthode GitHub autorisée (par exemple SSH ou un gestionnaire d'identifiants), et ne jamais intégrer de jeton au code ou à l'URL du dépôt.

Alternative : dans GitHub, utiliser **Add file → Upload files**, déposer les fichiers et dossiers extraits (pas le ZIP seul), puis enregistrer le commit. Vérifier que `.github/workflows/tests.yml` et `.gitignore`, parfois masqués par l'explorateur, sont bien présents. Les tests Actions ne s'exécuteront qu'après publication du workflow.

## CV : formulation après exécution et compréhension

« Projet personnel SOC — Développement assisté par IA et validation d'un analyseur Python de journaux SSH : corrélation temporelle, détection par règles, rapports JSON/CSV, tableau de bord HTML et tests automatisés. »

Ne pas présenter cette version comme une plateforme de production, un modèle d'IA ou une intégration complète de Wazuh.
