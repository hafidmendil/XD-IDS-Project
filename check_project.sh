#!/bin/bash
echo "===================================================="
echo "      VÉRIFICATION DE L'ENVIRONNEMENT XD-IDS        "
echo "===================================================="

echo -e "\n[1] Vérification des outils système :"
for cmd in python3 pip zeek git; do
    if command -v $cmd &> /dev/null; then
        echo "  [OK] $cmd est installé ($(which $cmd))"
    else
        echo "  [ERREUR] $cmd N'EST PAS installé ou manquant dans le PATH."
    fi
done

echo -e "\n[2] Vérification des bibliothèques Python (Scapy, Pandas, Numpy, Sklearn, XGBoost) :"
python3 -c "
libs = ['scapy', 'pandas', 'numpy', 'sklearn', 'xgboost']
for lib in libs:
    try:
        __import__(lib)
        print(f'  [OK] Python package: {lib}')
    except ImportError:
        print(f'  [ATTENTION] Python package MANQUANT : {lib} (à installer via pip install {lib})')
"

echo -e "\n[3] Vérification de l'arborescence du projet :"
PROJECT_DIR="$HOME/XD-IDS_Project"
if [ -d "$PROJECT_DIR" ]; then
    echo "  [OK] Dossier racine trouvé : $PROJECT_DIR"
    echo "--- Structure des dossiers ---"
    find "$PROJECT_DIR" -maxdepth 3 -not -path '*/.*' | sed 's|[^/]*/|  ├── |g'
else
    echo "  [ERREUR] Le dossier $PROJECT_DIR n'existe pas."
fi

echo -e "\n[4] Vérification du contenu des fichiers scripts principaux :"
if [ -f "$PROJECT_DIR/scripts/extraction/zeek_processor.py" ]; then
    echo "  [OK] zeek_processor.py existe et pèse $(wc -c < "$PROJECT_DIR/scripts/extraction/zeek_processor.py") octets."
else
    echo "  [ATTENTION] zeek_processor.py est introuvable."
fi

if [ -f "$PROJECT_DIR/scripts/preprocessing/create_sample_pcap.py" ]; then
    echo "  [OK] create_sample_pcap.py existe."
else
    echo "  [ATTENTION] create_sample_pcap.py est introuvable."
fi

echo -e "\n[5] Vérification du statut Git distant :"
cd "$PROJECT_DIR" 2>/dev/null && git remote -v
echo "===================================================="
