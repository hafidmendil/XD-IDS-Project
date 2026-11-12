# Taxonomie des labels — socle Phase 1

## Principe

Le seul label cible de la Phase 1 est binaire : `0 = normal`, `1 = attaque`.
La conversion d'un label source ne doit être faite que si sa sémantique est
vérifiée. Des familles d'attaques de significations différentes ne sont jamais
fusionnées en un label multi-classes ou une famille commune sans protocole
explicite. Les labels de capture ne doivent pas être présentés comme une
annotation vérifiée des flux.

| Dataset / label source | Label binaire | Confiance | Règle et statut |
|---|---:|---|---|
| madatasets, nom de fichier contenant `normal` | 0 | Faible | Hypothèse fondée sur le nom; pas d'annotation indépendante disponible. |
| madatasets, autres noms PCAP retenus | 1 | Faible | Hypothèse de travail; la signification/activité doit être confirmée par provenance ou annotations. |
| MQTT-IoTIDS2020, normal | 0 | NON DISPONIBLE | Conversion attendue seulement après validation du manifeste et des captures source. |
| MQTT-IoTIDS2020, scan | 1 | NON DISPONIBLE | Binaire attaque possible; conserver la famille `scan` séparément dans les métadonnées. |
| MQTT-IoTIDS2020, brute force SSH/MQTT | 1 | NON DISPONIBLE | Ne pas confondre les familles SSH et MQTT dans une analyse multi-classes. |
| Bot-IoT, labels source | NON DISPONIBLE | NON DISPONIBLE | Reconstruction nécessaire depuis annotations/scénarios originaux; aucun mapping n'est fourni ici. |
| ToN_IoT, labels source | NON DISPONIBLE | NON DISPONIBLE | N'établir le binaire qu'après validation de l'alignement PCAP-label. |
| CICIoT2023, 33 attaques / 7 classes | NON DISPONIBLE | NON DISPONIBLE | Conserver les 7 classes et les labels d'origine; les noms et mapping précis de la version ne sont pas dans le dépôt. |
| CIC-IDS2017, labels dans CSV CICFlowMeter | NON DISPONIBLE | NON DISPONIBLE | Vérifier les valeurs et leur documentation source; données restreintes à la critique méthodologique. |

## Métadonnées à préserver pour la suite

Lorsqu'elles sont disponibles et vérifiées, conserver `dataset`, `label_source`,
`label_family`, `capture_id`, `session` et la source de l'annotation comme
métadonnées. Elles ne deviennent pas des features. Pour préparer le
leave-one-family-out, une classe/famille non vérifiée reste NON DISPONIBLE et ne
doit pas être créée depuis le seul nom d'un fichier.

## Limite actuelle

La collection locale madatasets utilise des labels heuristiques au niveau
capture. Un modèle peut apprendre les caractéristiques de la capture ou du
scénario plutôt que celles de l'attaque (biais de confusion capture/label).
Ce jeu ne justifie donc pas, seul, une taxonomie multi-classes fiable ou une
comparaison inter-domaines.
