# XD-IDS: Un cadre hybride multi-niveaux pour la détection d'intrusions IoT inter-domaines

Projet de recherche académique / Master - Systèmes de Sécurité et Intelligence Artificielle.

## Structure du Projet
- `data/` : Contient les métadonnées et les environnements de test.
- `scripts/extraction/` : Automatisation de l'extraction des logs réseau via Zeek (garantissant l'homogénéité des caractéristiques).
- `scripts/preprocessing/` : Protocoles anti-fuite (*anti-leakage splits*) et préparation des données.
- `scripts/models/` : Implémentation des branches (Paquet, Flux, Séquence) et de la fusion probabiliste.
