# Rapport Phase 1 — XD-IDS

- Généré (UTC) : 2026-11-11T20:30:06.994691+00:00
- Commit Git : `8d85023145e3c7e08f8c520d0a41c120b349d091`
- Fenêtres source : `data/processed_features/windows_all.csv` (SHA-256 `6a733c807fe41fc60f8bfedfd84468d118cadeb540eb9479edf12cdef2a85f34`)
- Split E1 : `splits/E1.csv` (SHA-256 `ff74c16dd1cd4b873596dc80fa0f389349eb33d4f7b525ccb8b1cc131c67cc67`)
- Split E2 : `splits/E2.csv` (NON DISPONIBLE : E2 non valide; voir `splits/E2.status.json`)

## Portée et limites

Les résultats ci-dessous décrivent uniquement les captures PCAP locales inscrites dans le registre courant. La provenance et la licence de madatasets restent NON DISPONIBLES dans le dépôt. Les labels sont des hypothèses de travail dérivées des noms de fichiers, pas une vérité terrain vérifiée. Ces résultats ne démontrent ni généralisation inter-domaines ni supériorité par rapport à d'autres méthodes.

Le fichier de fenêtres contient 178 lignes. Les colonnes d'identité, de capture, d'appareil et de temps ne sont pas utilisées comme features par le script d'entraînement.

## Résultats E1 — référence aléatoire favorable

Statut : `experimental_baselines_not_validated_for_deployment`. Graines enregistrées : [42, 43, 44, 45, 46].

| Partition | Fenêtres normales (0) | Fenêtres attaque (1) |
|---|---:|---:|
| train | 3 | 121 |
| validation | 1 | 26 |
| test | 1 | 26 |

| Modèle | Partition | Graines | Macro-F1 moyen ± écart-type | FPR moyen ± écart-type | PR-AUC attaque moyen ± écart-type | ECE moyen ± écart-type | Latence p95 moyenne ± écart-type (ms) |
|---|---|---:|---:|---:|---:|---:|---:|
| random_forest | test | 5 | 0.4847 ± 0.0054 | 1.0000 ± 0.0000 | 0.9916 ± 0.0022 | 0.0929 ± 0.0114 | 105.4405 ± 15.4775 |
| random_forest | validation | 5 | 0.4906 ± 0.0000 | 1.0000 ± 0.0000 | 0.9878 ± 0.0038 | 0.0337 ± 0.0004 | 115.5379 ± 23.4589 |
| xgboost | test | 5 | 0.4906 ± 0.0000 | 1.0000 ± 0.0000 | 0.9997 ± 0.0006 | 0.0424 ± 0.0149 | 19.9126 ± 4.6785 |
| xgboost | validation | 5 | 0.4906 ± 0.0000 | 1.0000 ± 0.0000 | 0.9895 ± 0.0017 | 0.0360 ± 0.0073 | 16.5207 ± 0.6775 |

Les prédictions E1 sont disponibles dans `results/phase_b/E1/predictions.csv` pour les partitions validation et test, séparément par modèle et graine.

E1 répartit aléatoirement et stratifie par classe les groupes de features identiques lorsque la composition le permet, mais ne garantit pas l'indépendance des sessions entre partitions. Il est donc seulement une référence favorable, pas le résultat principal anti-fuite.

## Résultat E2 — chronologique par capture

- Validité structurelle (captures entières et ordre chronologique) : NON.
- Entraînement binaire et validation binaire possibles : NON.

| Partition | Fenêtres normales (0) | Fenêtres attaque (1) |
|---|---:|---:|
| train | NON DISPONIBLE | NON DISPONIBLE |
| validation | NON DISPONIBLE | NON DISPONIBLE |
| test | NON DISPONIBLE | NON DISPONIBLE |


Contrôles structurels échoués :
- Les intervalles des sessions se chevauchent : un split chronologique E2 non ambigu n'est pas possible.

E2 n'a pas été entraîné : aucun split chronologique valide n'a été produit.
Aucun `splits/E2.csv` n'a été publié : la construction du split chronologique a échoué à cause des intervalles de sessions chevauchants. Le statut et la raison sont consignés dans `splits/E2.status.json`.
Les métriques E2 sont NON DISPONIBLES. Cette limite est publiée plutôt que de modifier les partitions ou d'inventer une évaluation.
Statut d'exécution E2 : Les intervalles des sessions se chevauchent : un split chronologique E2 non ambigu n'est pas possible.

## RQ1 — écart E1 − E2

Résumé tabulaire : `results/phase1/summary.csv`.
Un écart E1−E2 numérique est NON DISPONIBLE car aucune métrique E2 binaire valide n'est présente; aucun écart n'est estimé.

## Admissibilité E3 — plan de transferts

Domaines actuellement admissibles (PCAP et labels fiables vérifiés) : AUCUN
Transferts dirigés réalisables actuellement : 0; tests LODO : 0.
À titre de planification uniquement, 3 domaines validés permettraient 6 transferts dirigés et 3 tests LODO.
Blocages actuels : aucun domaine externe n'est présent avec PCAP, licence, provenance, topologie et labels fiables vérifiés. madatasets reste non admissible tant que sa provenance et ses labels heuristiques ne sont pas validés. E3 n'a pas été exécuté.


## Conclusion

Seules les baselines E1 ont été mesurées. Aucun résultat principal anti-fuite E2 valide n'est disponible avec la composition actuelle des captures. Les sessions qui se chevauchent empêchent un split chronologique valide; la faible représentation normale (5 fenêtres issues de 2 captures) limite également E1. Ces problèmes doivent être résolus avant toute conclusion de performance.
