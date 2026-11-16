# XD-IDS

**Cadre expérimental pour la détection d’intrusions dans les réseaux IoT**

XD-IDS est un projet de recherche académique (Master — systèmes de sécurité et intelligence artificielle) consacré à l’évaluation de la détection d’attaques IoT à partir de traces réseau. Le dépôt automatise l’audit des captures PCAP, leur extraction avec Zeek, la préparation de fenêtres temporelles, la création de partitions d’évaluation et l’entraînement de modèles de référence.

> **État du projet : expérimental.** Les résultats générés ne sont pas déclarés déployables. La capture de démonstration est trop petite pour évaluer des performances : elle ne fournit pas deux classes dans des partitions indépendantes. Aucun résultat de performance n’est revendiqué à ce stade.

## Sommaire

- [Fonctionnement](#fonctionnement)
- [Prérequis et installation](#prérequis-et-installation)
- [Lancer le pipeline complet](#lancer-le-pipeline-complet)
- [Préparer une capture Zeek directement](#préparer-une-capture-zeek-directement)
- [Étapes détaillées](#étapes-détaillées)
- [Tests et qualité](#tests-et-qualité)
- [Structure du dépôt](#structure-du-dépôt)
- [Données et reproductibilité](#données-et-reproductibilité)
- [Limites méthodologiques](#limites-méthodologiques)
- [Documentation complémentaire](#documentation-complémentaire)

## Fonctionnement

Le pipeline suit les étapes suivantes :

1. **Audit des PCAP** : inventaire des captures disponibles et génération de métadonnées.
2. **Extraction Zeek hors ligne** : conversion des traces réseau en journaux de connexions.
3. **Préparation des fenêtres** : agrégation des flux en fenêtres temporelles par appareil désigné.
4. **Partitions d’évaluation** : création des protocoles E1 et E2, avec contrôles contre les fuites de données.
5. **Entraînement et rapport** : entraînement des baselines Random Forest et XGBoost, puis génération d’un rapport d’évaluation.

Les paramètres sont centralisés dans `configs/`. Les sorties de données, partitions, modèles et rapports sont enregistrées séparément dans `data/`, `splits/`, `results/` et `docs/`.

## Prérequis et installation

- Python et `pip`, compatibles avec les versions épinglées dans `requirements.txt`.
- GNU Make pour utiliser les commandes `make`.
- [Zeek](https://zeek.org/) installé et accessible dans le `PATH` pour traiter des captures PCAP.
- Les captures/datasets nécessaires, placés dans le répertoire configuré (par défaut `madatasets/`).

Clonez le dépôt et installez les dépendances Python dans un environnement virtuel :

```bash
git clone https://github.com/hafidmendil/XD-IDS-Project.git
cd XD-IDS-Project
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt
```

Les versions des bibliothèques Python sont épinglées dans `requirements.txt`. Zeek est une dépendance système séparée et doit être installé indépendamment.

## Lancer le pipeline complet

Placez les captures PCAP dans `madatasets/` (ou indiquez un autre dossier avec `DATASET_ROOT`), puis lancez :

```bash
make phase1
```

Cette commande exécute l’audit, l’extraction Zeek, la préparation des fenêtres, la génération des partitions, l’entraînement et la production du rapport. Les principales cibles Make sont :

```bash
make audit       # auditer les PCAP
make zeek        # extraire les journaux avec Zeek
make windows     # préparer les fenêtres et les partitions
make train       # entraîner les modèles de référence
make report      # générer le rapport de Phase 1
make test        # lancer les tests
make lint        # vérifier le code avec Ruff
make acceptance  # pipeline, tests et lint
```

Quelques paramètres peuvent être personnalisés, par exemple :

```bash
make phase1 DATASET_ROOT=/chemin/vers/mes_pcap
make phase1 WINDOW_SECONDS=60 DEVICE_SIDE=orig
```

Les autres variables et leurs valeurs par défaut sont définies au début du `Makefile` : `CAPTURE_CONFIG`, `DATASETS_CONFIG`, `WINDOW_SECONDS`, `DEVICE_SIDE` et `NEAR_TOLERANCE`.

## Préparer une capture Zeek directement

Pour transformer un `conn.log` existant en fenêtres sans étape CSV intermédiaire :

```bash
python scripts/preprocessing/prepare_zeek_windows.py \
  data/processed_zeek/sample_test/conn.log \
  --capture-id sample_test \
  --label 0 \
  --window-seconds 60 \
  --device-side orig \
  --near-tolerance 0.01 \
  --output data/processed_features/sample_test_windows.csv
```

Le label doit être fourni explicitement : par capture (`--label 0` ou `1`) ou à partir d’une liste d’adresses d’attaquants (`--attacker-ips`). Consultez l’aide du script pour les options disponibles :

```bash
python scripts/preprocessing/prepare_zeek_windows.py --help
```

Les colonnes d’adresses et de ports servent de métadonnées et doivent être exclues des caractéristiques utilisées par les modèles.

## Étapes détaillées

### Fenêtres temporelles et partitions

Les statistiques d’un flux dans `conn.log` ne sont disponibles qu’à la clôture du flux, à l’instant `ts + duration`. Les durées inconnues, non numériques, infinies ou négatives sont exclues et comptabilisées, jamais remplacées par zéro. Les flux sont agrégés par fenêtre et par adresse désignée comme appareil ; le choix `orig` ou `resp` doit correspondre à la topologie documentée. Une fenêtre est étiquetée comme attaque si au moins un flux qu’elle contient est étiqueté attaque.

Exemple de préparation et de création des partitions à partir de fichiers de flux déjà extraits :

```bash
python scripts/preprocessing/preprocess_data.py \
  /chemin/vers/conn.log \
  --capture-id sample_test --label 0 \
  --output /tmp/sample_test_features.csv

python scripts/preprocessing/build_windows.py \
  /tmp/sample_test_features.csv \
  --config configs/windows.yaml \
  --output /tmp/sample_test_windows.csv

# Pour un jeu multi-session, fournir tous les CSV de flux au même appel.
python scripts/preprocessing/build_windows.py \
  data/processed_features/sessions/*.csv \
  --config configs/windows.yaml \
  --output data/processed_features/windows_all.csv

python scripts/preprocessing/make_splits.py \
  data/processed_features/windows_all.csv \
  --config configs/splits.yaml --protocol E2 \
  --output splits/E2.csv

python scripts/preprocessing/make_splits.py \
  data/processed_features/windows_all.csv \
  --config configs/splits.yaml --protocol E1 --seed 42 \
  --output splits/E1.csv
```

### Baselines Random Forest et XGBoost

Chaque protocole s’exécute séparément. L’entraînement utilise la partition `train` et mesure les performances sur `validation` et `test`, sans ajuster les seuils ni les hyperparamètres sur ces partitions :

```bash
python scripts/models/train_zeek.py splits/E1.csv \
  --protocol E1 --config configs/models.yaml \
  --output-dir results/phase_b/E1

python scripts/models/train_zeek.py splits/E2.csv \
  --protocol E2 --config configs/models.yaml \
  --output-dir results/phase_b/E2
```

Les paramètres de référence et les graines sont définis dans [`configs/models.yaml`](configs/models.yaml). Les sorties incluent les modèles expérimentaux, les métriques par graine (`metrics.csv`), les agrégats (`metrics_summary.csv`) et un manifeste JSON.

Les métriques comprennent Macro-F1, précision/rappel/F1 par classe, FPR, average precision (PR-AUC attaque), ECE binaire (diagnostique, sans calibration) et latence p95 de prédiction par fenêtre.

## Tests et qualité

Exécuter l’ensemble des tests et l’analyse statique :

```bash
make test lint
```

Ou lancer directement les tests Python :

```bash
python -m pytest -q
```

## Structure du dépôt

```text
configs/       Configurations des captures, datasets, modèles, splits et fenêtres
 data/         Métadonnées et données générées localement
 docs/         Documentation, fiches de données et rapport de Phase 1
 results/      Résultats expérimentaux et artefacts des modèles
 scripts/data/ Audit des PCAP et gestion des datasets
 scripts/extraction/ Extraction des journaux réseau avec Zeek
 scripts/preprocessing/ Préparation des données, fenêtres et partitions
 scripts/models/ Entraînement des modèles
 scripts/evaluation/ Entraînement et rapport de Phase 1
 splits/       Fichiers de partitions générés
 tests/        Tests automatisés
```

## Données et reproductibilité

- Les manifestes des sorties enregistrent des empreintes SHA-256 des entrées, des configurations et des résultats, ainsi que des versions logicielles lorsque pertinent.
- `make fetch-datasets` ne télécharge que les URL HTTP(S) directes explicitement configurées avec une empreinte SHA-256 attendue. Les sources sans accès direct restent à obtenir manuellement.
- Aucun dataset n’est téléchargé automatiquement par `make phase1`.
- Les données et résultats sont spécifiques aux captures et paramètres utilisés ; vérifiez les manifestes associés pour pouvoir reproduire une expérience.

Pour lancer le téléchargement des seules sources configurées :

```bash
make fetch-datasets
```

## Limites méthodologiques

- **E1** est un split aléatoire stratifié par classe lorsque le nombre de groupes distincts le permet. Il sert de référence favorable et ne garantit pas une séparation des sessions.
- **E2** affecte des `capture_id` entières à des partitions chronologiques et purge les fenêtres proches des frontières. Il est déclaré non valide si les partitions d’apprentissage ou de validation ne contiennent pas les deux classes.
- Les vecteurs de caractéristiques exactement identiques sont regroupés avant le split. La tolérance actuelle de quasi-doublon est de `0.01` en distance L-infinie absolue ; comme elle n’a pas été préenregistrée avant les premières expériences, les résultats qui l’utilisent restent exploratoires.
- Les contrôles rejettent notamment les caractéristiques non numériques, manquantes ou infinies, les colonnes d’identifiants résiduelles et les groupes de doublons partagés entre partitions.
- Une seule capture de démonstration ne suffit pas à construire des splits valides ni à établir des performances représentatives.

Les décisions et limites sont détaillées dans [`docs/decisions.md`](docs/decisions.md) et le rapport de Phase 1 dans [`docs/phase1_report.md`](docs/phase1_report.md).

## Documentation complémentaire

- [Rapport de Phase 1](docs/phase1_report.md)
- [Décisions de conception](docs/decisions.md)
- [Taxonomie des labels](docs/labels_taxonomy.md)
- [Variables Zeek](docs/variables_zeek.md)
- [Carte des données](docs/data_card_madatasets.md)
- [Registre des datasets](configs/datasets.yaml)
