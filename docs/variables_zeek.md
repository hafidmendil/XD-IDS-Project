# Dictionnaire des variables de `windows_all.csv`

Le dictionnaire décrit le schéma effectivement produit dans
`data/processed_features/windows_all.csv` : 59 colonnes, dont six métadonnées et
53 variables numériques. Les métadonnées ne sont pas des variables de modèle.
Les 52 colonnes préfixées `sum__` ou `mean__` sont des agrégats par fenêtre des
features de flux calculées à partir de `conn.log`.

## Métadonnées — exclues des features

| Colonne | Type | Définition / usage |
|---|---|---|
| `capture_id` | texte | Identifiant stable de la capture/session; regroupement E2 et traçabilité, jamais feature. |
| `device_id` | texte | Adresse choisie par `device_side` (`orig` dans le registre actuel); appareil de regroupement, jamais feature. |
| `window_start` | nombre, secondes Unix | Borne gauche de la fenêtre alignée à l'époque Unix. La fenêtre est `(window_start, window_end]`; jamais feature. |
| `window_end` | nombre, secondes Unix | Borne droite inclusive et instant de décision causal; jamais feature. |
| `label` | entier binaire | Label de fenêtre : 0 normal, 1 attaque; maximum des labels de flux de la fenêtre, cible et jamais feature. |
| `duplicate_group_id` | texte, SHA-256 | Identifiant du groupe de fenêtres ayant un vecteur numérique identique; audit anti-fuite, jamais feature. |

## Variables numériques de fenêtre

| Colonne | Type | Définition |
|---|---|---|
| `flow_count` | entier | Nombre de flux retenus dans la fenêtre. Un flux est placé à l'instant `ts + duration`; les durées manquantes, non numériques, infinies ou négatives sont exclues. |
| `sum__duration` | nombre | Somme des durées des flux de la fenêtre, en secondes. |
| `mean__duration` | nombre | Durée moyenne des flux de la fenêtre, en secondes. |
| `sum__orig_bytes` | nombre | Somme des octets émis par l'origine des flux (`orig_bytes`). Les champs numériques manquants de bytes/paquets sont remplacés par zéro lors de l'ingénierie actuelle. |
| `mean__orig_bytes` | nombre | Moyenne des octets émis par l'origine, par flux. |
| `sum__resp_bytes` | nombre | Somme des octets émis par le répondant (`resp_bytes`). |
| `mean__resp_bytes` | nombre | Moyenne des octets émis par le répondant, par flux. |
| `sum__orig_pkts` | nombre | Somme des paquets émis par l'origine (`orig_pkts`). |
| `mean__orig_pkts` | nombre | Moyenne des paquets émis par l'origine, par flux. |
| `sum__resp_pkts` | nombre | Somme des paquets émis par le répondant (`resp_pkts`). |
| `mean__resp_pkts` | nombre | Moyenne des paquets émis par le répondant, par flux. |
| `sum__total_bytes` | nombre | Somme, sur les flux, de `orig_bytes + resp_bytes`. |
| `mean__total_bytes` | nombre | Moyenne par flux de `orig_bytes + resp_bytes`. |
| `sum__total_pkts` | nombre | Somme, sur les flux, de `orig_pkts + resp_pkts`. |
| `mean__total_pkts` | nombre | Moyenne par flux de `orig_pkts + resp_pkts`. |
| `sum__bytes_ratio` | nombre | Somme par flux de `orig_bytes / (total_bytes + 1)`. |
| `mean__bytes_ratio` | nombre | Moyenne par flux de `orig_bytes / (total_bytes + 1)`. |
| `sum__pkts_per_sec` | nombre | Somme par flux de `total_pkts / (duration + 1e-6)`, indicateur d'intensité de paquets. |
| `mean__pkts_per_sec` | nombre | Moyenne par flux de `total_pkts / (duration + 1e-6)`. |
| `sum__bytes_per_pkt` | nombre | Somme par flux de `total_bytes / (total_pkts + 1)`. |
| `mean__bytes_per_pkt` | nombre | Moyenne par flux de `total_bytes / (total_pkts + 1)`. |

## Variables one-hot Zeek agrégées

Pour chacune des variables ci-dessous, `sum__<nom>` est le nombre de flux de la
fenêtre ayant la catégorie (le compte des indicateurs 0/1) et `mean__<nom>` est
la proportion de flux correspondante. Ces variables sont encodées avec des
catégories fixes et ne nécessitent pas d'ajustement appris sur validation/test.

| Colonnes générées | Champ Zeek source | Interprétation |
|---|---|---|
| `sum__proto_tcp`, `mean__proto_tcp` | `proto` | Flux TCP : nombre puis proportion. |
| `sum__proto_udp`, `mean__proto_udp` | `proto` | Flux UDP : nombre puis proportion. |
| `sum__proto_icmp`, `mean__proto_icmp` | `proto` | Flux ICMP : nombre puis proportion. |
| `sum__state_S0`, `mean__state_S0` | `conn_state` | Tentative sans réponse : nombre puis proportion. |
| `sum__state_S1`, `mean__state_S1` | `conn_state` | Connexion établie, fermeture non observée : nombre puis proportion. |
| `sum__state_SF`, `mean__state_SF` | `conn_state` | Connexion établie et terminée normalement : nombre puis proportion. |
| `sum__state_REJ`, `mean__state_REJ` | `conn_state` | Tentative rejetée : nombre puis proportion. |
| `sum__state_S2`, `mean__state_S2` | `conn_state` | Connexion établie; fermeture initiée par l'origine observée : nombre puis proportion. |
| `sum__state_S3`, `mean__state_S3` | `conn_state` | Connexion établie; fermeture initiée par le répondant observée : nombre puis proportion. |
| `sum__state_RSTO`, `mean__state_RSTO` | `conn_state` | Réinitialisation par l'origine : nombre puis proportion. |
| `sum__state_RSTR`, `mean__state_RSTR` | `conn_state` | Réinitialisation par le répondant : nombre puis proportion. |
| `sum__state_RSTOS0`, `mean__state_RSTOS0` | `conn_state` | Réinitialisation origine avant réponse : nombre puis proportion. |
| `sum__state_RSTRH`, `mean__state_RSTRH` | `conn_state` | Répondant a envoyé SYN/ACK puis RST avant l'ACK de l'origine : nombre puis proportion. |
| `sum__state_SH`, `mean__state_SH` | `conn_state` | SYN origine suivi d'un FIN origine : nombre puis proportion. |
| `sum__state_SHR`, `mean__state_SHR` | `conn_state` | SYN/ACK répondant suivi d'un FIN répondant : nombre puis proportion. |
| `sum__state_OTH`, `mean__state_OTH` | `conn_state` | Trafic observé sans SYN (flux capturé au milieu de l'échange) ou état manquant ramené à `OTH` : nombre puis proportion. |

Ce tableau énumère les 32 noms exacts de colonnes d'agrégats one-hot.

## Variables et champs explicitement exclus

`ts`, `uid`, adresses IP, ports, `capture_id`, `device_id`, horodatages, labels,
split et métadonnées de déduplication ne doivent pas être utilisés comme
features. Les adresses et ports peuvent servir au regroupement, à l'étiquetage
explicitement configuré ou à la traçabilité seulement. `service`, `history`,
`orig_ip_bytes` et `resp_ip_bytes` sont des champs Zeek non présents dans le
schéma courant de `windows_all.csv`.

Les sens précis des états sont ceux de Zeek et dépendent de l'observation du
trafic; les agréger par fenêtre ne constitue pas une interprétation applicative
ni une preuve de comportement malveillant.
