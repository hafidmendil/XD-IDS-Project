# CIC-IDS2017

- **Source :** [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html).
- **Licence et accès :** NON DISPONIBLE pour les copies présentes; les CSV locaux sont dans `madatasets/` sans manifeste de provenance.
- **Taille et format :** huit CSV CICFlowMeter présents dans `madatasets/`; la taille exacte doit être calculée depuis les fichiers. La documentation initiale de la mission donne une estimation d'environ 800 Mo.
- **PCAP local :** aucun PCAP associé confirmé dans ce dépôt; seuls les CSV de flux sont repérés.
- **Labels :** lire et comparer les colonnes Label des CSV à la documentation originale avant tout usage. Ne pas reconstruire la vérité terrain depuis le seul nom de fichier.
- **Classes et déséquilibre :** NON DISPONIBLES sans audit des colonnes et des étiquettes source.
- **Risques de fuite :** sessions/jours/scénarios, doublons, colonnes d'identifiants et différences CICFlowMeter vs Zeek.
- **Topologie :** NON DISPONIBLE pour ces copies locales.
- **Statut :** CSV disponibles localement; usage RESTREINT à l'illustration de la critique d'évaluation, exclu du noyau expérimental.
- **Checksum :** NON DISPONIBLE; calculer les empreintes des CSV locaux avant toute analyse.
- **Admissibilité E3 :** non admissible; absence de PCAP local vérifié et exclusion explicite du noyau.

Voir le registre [datasets.yaml](../../configs/datasets.yaml) et le [guide de récupération](./manual_download_guide.md).
