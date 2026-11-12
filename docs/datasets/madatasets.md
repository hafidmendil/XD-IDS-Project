# madatasets — collection locale

- **Source :** provenance d'origine **À DOCUMENTER**; aucune URL ou référence primaire fiable n'est fournie dans le dépôt.
- **Licence et accès :** NON DISPONIBLE.
- **Taille et format :** fichiers PCAP et huit CSV CICFlowMeter; tailles PCAP, nombres de paquets, plages temporelles et SHA-256 sont inventoriés dans [captures.csv](../../data/metadata/captures.csv).
- **PCAP local :** oui. Les captures canoniques courantes figurent dans [captures.yaml](../../configs/captures.yaml); fichiers source dupliqués non supprimés.
- **Labels :** `normal*` est étiqueté 0 et les autres noms PCAP 1 par hypothèse. Ce mapping par nom n'est pas une annotation de vérité terrain vérifiée.
- **Classes et déséquilibre :** binaire de travail normal/attaque. Compter les fenêtres depuis le dataset produit et consulter les manifestes; les captures ne garantissent pas des sessions indépendantes.
- **Risques de fuite :** biais de confusion capture/label, provenance inconnue, caractéristiques de scénario et doublons/quasi-doublons. L'E2 courant n'a pas les deux classes en train/validation.
- **Topologie :** inconnue; `device_side: orig` est une hypothèse opérationnelle à valider.
- **Statut :** présent localement; admissible pour audit et essais de pipeline uniquement, pas pour revendiquer des performances généralisables.
- **Checksum :** SHA-256 par PCAP dans les métadonnées et le registre; vérifier à chaque nouvel audit.
- **Admissibilité E3 :** non admissible jusqu'à documentation de provenance et validation des annotations.

Voir la [data card](../data_card_madatasets.md), le registre [datasets.yaml](../../configs/datasets.yaml) et le [guide de récupération](./manual_download_guide.md).
