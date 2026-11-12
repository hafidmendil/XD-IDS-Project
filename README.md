# XD-IDS: Un cadre hybride multi-niveaux pour la détection d'intrusions IoT inter-domaines

Projet de recherche académique / Master - Systèmes de Sécurité et Intelligence Artificielle.

## Structure du Projet
- `data/` : Contient les métadonnées et les environnements de test.
- `scripts/extraction/` : Automatisation de l'extraction des logs réseau via Zeek (garantissant l'homogénéité des caractéristiques).
- `scripts/preprocessing/` : Protocoles anti-fuite (*anti-leakage splits*) et préparation des données.
- `scripts/models/` : Implémentation des branches (Paquet, Flux, Séquence) et de la fusion probabiliste.

## Phase A — fenêtres causales et splits

Les statistiques de `conn.log` ne sont connues qu'à la clôture d'un flux.
`build_windows.py` les rend disponibles à `ts + duration`; un flux dont la
durée est inconnue est exclu et comptabilisé, jamais imputé à zéro. Il agrège
les flux par fenêtre et par adresse désignée comme appareil. Le choix `orig`
ou `resp` doit correspondre à la topologie documentée; les adresses restent
des métadonnées et ne sont pas agrégées comme features. Le label de fenêtre
vaut 1 si au moins un flux de cette fenêtre est étiqueté attaque.

```bash
python scripts/extraction/zeek_processor.py \
  data/raw_pcap/sample_test.pcap --output /tmp/xdids_zeek
python scripts/preprocessing/preprocess_data.py \
  /tmp/xdids_zeek/sample_test/conn.log \
  --capture-id sample_test --label 0 \
  --output /tmp/xdids_sample_test_features.csv
python scripts/preprocessing/build_windows.py \
  /tmp/xdids_sample_test_features.csv \
  --config configs/windows.yaml \
  --output /tmp/xdids_sample_test_windows.csv

# Pour un jeu multi-session, fournir tous les CSV de flux au même appel :
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

# Tests ciblés
python -m pytest -q tests/test_preprocessing_windows.py
```

Le manifeste JSON de chaque sortie conserve les empreintes SHA-256 des entrées,
de la configuration et de la sortie. E1 est un split aléatoire stratifié par
classe quand au moins trois groupes distincts par classe le permettent; il
reste une référence favorable, sans séparation des sessions. E2 affecte des
`capture_id` entières à des partitions chronologiques et purge les fenêtres
proches des frontières. Les vecteurs de features exactement identiques restent
dans le même groupe avant le split. Une capture de démonstration
produit 2 flux Zeek, exclut le flux UDP à durée inconnue, puis donne 1 fenêtre
de 60 s pour `192.168.1.50`, `[1794086100, 1794086160]`. Cette capture seule ne
suffit pas à créer un split E1 ou E2. La tolérance de quasi-doublon actuelle
est `0.01` en distance L-infinie absolue. Comme elle n'a pas été préenregistrée
avant les premières expériences, les résultats qui l'utilisent restent
exploratoires.

## Phase B — baselines RF et XGBoost

Les versions des bibliothèques directes sont épinglées dans
`requirements.txt`; le manifeste de résultat enregistre aussi les versions
effectivement utilisées, dont Python.

`train_zeek.py` lit le CSV publié par `make_splits.py`, entraîne séparément
Random Forest et XGBoost sur `train`, puis mesure `validation` et `test`.
Il n'ajuste ni seuil ni hyperparamètre sur ces partitions. Les cinq graines
et paramètres de référence sont dans [models.yaml](./configs/models.yaml).
E1 et E2 doivent être lancés séparément. Chaque exécution sauvegarde les
modèles expérimentaux, les métriques par graine (`metrics.csv`), les
moyennes/écarts-types (`metrics_summary.csv`) et un manifeste JSON avec les
empreintes SHA-256, versions et colonnes utilisées.

```bash
python scripts/models/train_zeek.py splits/E1.csv \
  --protocol E1 --config configs/models.yaml \
  --output-dir results/phase_b/E1
python scripts/models/train_zeek.py splits/E2.csv \
  --protocol E2 --config configs/models.yaml \
  --output-dir results/phase_b/E2
python -m pytest -q tests/test_preprocessing_windows.py tests/test_train_zeek.py
```

Les résultats comprennent Macro-F1, précision/rappel/F1 par classe, FPR,
average precision (PR-AUC attaque), ECE binaire (diagnostique, sans calibration)
et latence p95 de prédiction par fenêtre. Les contrôles rejettent notamment les
features non numériques, manquantes, infinies, les colonnes d'identifiants
résiduelles, les groupes de doublons partagés et les sessions E2 recoupées.
Les artefacts portent le statut expérimental et ne sont pas déclarés déployables.
L'évaluation sur le PCAP de démonstration n'est pas valide : il ne contient
qu'une fenêtre exploitable et n'offre pas les deux classes dans des partitions
indépendantes. Aucun résultat de performance n'est revendiqué à ce stade.

## Préparation directe d'un conn.log Zeek

Pour transformer un log Zeek brut en fenêtres sans étape CSV intermédiaire :

```bash
python scripts/preprocessing/prepare_zeek_windows.py \
  data/processed_zeek/sample_test/conn.log \
  --capture-id sample_test --label 0 \
  --window-seconds 60 --device-side orig \
  --near-tolerance 0.01 \
  --output data/processed_features/sample_test_windows.csv
```

Le label doit être fourni explicitement : soit par capture (`--label 0` ou `1`),
soit avec la règle « un flux est une attaque si l'une de ses extrémités est
dans `--attacker-ips` ». Le CSV contient `device_id`, les IP voisines et ports
observés uniquement comme métadonnées; ces colonnes sont à exclure des features.
Chaque fenêtre est alignée sur l'époque Unix et affecte un flux à l'intervalle
disjoint `(t-T, t]`, où `t` est arrondi au prochain multiple de `T`. La statistique
du flux n'est disponible qu'à `ts + duration`. Les durées inconnues, non
numériques, infinies ou négatives sont exclues et comptabilisées.

Le manifeste `.audit.json` contient les empreintes des fichiers, le compte des
exclusions et l'audit de déduplication. La tolérance de quasi-doublon est une
tolérance absolue commune, mesurée en distance L-infinie sur les features
numériques; sa valeur et son caractère exploratoire sont documentés dans
`docs/decisions.md`. Les lignes aux labels contradictoires sont conservées et
signalées, jamais fusionnées. Commande de validation :

```bash
python -m pytest -q tests/test_prepare_zeek_windows.py
```

## Rejouer la Phase 1

La cible complète suit audit PCAP → extraction Zeek hors ligne → fenêtres et
splits → entraînement admissible → rapport. L'extraction est idempotente quand
l'empreinte PCAP et la version Zeek sont inchangées. E2 est enregistré comme
non valide sans entraîner de modèle si ses partitions d'apprentissage ou de
validation n'ont pas les deux classes.

```bash
make phase1
make test lint
```

Le registre `configs/datasets.yaml` et les fiches `docs/datasets/` décrivent les
sources externes et leurs limites. `make fetch-datasets` ne télécharge que des
URL HTTP(S) directes explicitement configurées avec un SHA-256 attendu; les
sources sans accès direct restent manuelles. Aucun fichier de dataset n'est
téléchargé par `make phase1`.
