# Guide de téléchargement manuel

Aucun fichier n'est téléchargé depuis une page d'information ou une source qui demande une authentification. Pour chaque entrée sans `download_url` direct et SHA-256 attendu, télécharger depuis le site source manuellement, vérifier licence/annotations, puis renseigner l'URL directe et le checksum dans `configs/datasets.yaml` avant de relancer le script.

## Étapes

1. Ouvrir la page source et vérifier les droits/licence.
2. Télécharger le PCAP et son fichier d'annotations/manifeste sans renommer les originaux.
3. Vérifier la correspondance label-capture dans la documentation de la version téléchargée.
4. Calculer `sha256sum <fichier>` et enregistrer l'URL/version/checksum.
5. Ajouter uniquement une URL de fichier directe et le checksum attendu dans le registre.
6. Relancer `python scripts/data/fetch_datasets.py --dataset <id>`; un checksum différent empêche la publication du fichier.

## MQTT-IoTIDS2020
- Source : https://doi.org/10.21227/bhxy-ep04
- Accès : Accès déclaré via DOI/DataPort; accès direct téléchargeable non confirmé.
- Blocage : URL directe ou SHA-256 attendu NON DISPONIBLE.
- Après téléchargement, vérifier la licence, conserver le manifeste source, calculer le SHA-256 et documenter le label/topologie.

## Bot-IoT
- Source : https://research.unsw.edu.au/projects/bot-iot-dataset
- Accès : Le site du projet est la source de référence; l'accès direct aux PCAP originaux n'est pas vérifié.
- Blocage : URL directe ou SHA-256 attendu NON DISPONIBLE.
- Après téléchargement, vérifier la licence, conserver le manifeste source, calculer le SHA-256 et documenter le label/topologie.

## ToN_IoT
- Source : https://research.unsw.edu.au/projects/toniot-datasets
- Accès : Le site du projet est la source de référence; accès direct aux fichiers non vérifié.
- Blocage : URL directe ou SHA-256 attendu NON DISPONIBLE.
- Après téléchargement, vérifier la licence, conserver le manifeste source, calculer le SHA-256 et documenter le label/topologie.

## CICIoT2023
- Source : https://www.unb.ca/cic/datasets/iotdataset-2023.html
- Accès : Conditions d'accès et URL directe des fichiers non vérifiées.
- Blocage : URL directe ou SHA-256 attendu NON DISPONIBLE.
- Après téléchargement, vérifier la licence, conserver le manifeste source, calculer le SHA-256 et documenter le label/topologie.

## CIC-IDS2017
- Source : https://www.unb.ca/cic/datasets/ids-2017.html
- Accès : Les CSV présents localement proviennent de madatasets; provenance/licence originale non documentée.
- Blocage : URL directe ou SHA-256 attendu NON DISPONIBLE.
- Après téléchargement, vérifier la licence, conserver le manifeste source, calculer le SHA-256 et documenter le label/topologie.

## madatasets
- Source : NON DISPONIBLE
- Accès : Fichiers déjà présents localement; provenance d'origine à documenter.
- Blocage : URL directe ou SHA-256 attendu NON DISPONIBLE.
- Après téléchargement, vérifier la licence, conserver le manifeste source, calculer le SHA-256 et documenter le label/topologie.
