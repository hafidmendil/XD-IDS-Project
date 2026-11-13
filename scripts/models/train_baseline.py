import argparse
import glob
import os

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split


def load_cic_dataset(path_pattern):
  print(f"[*] Recherche des fichiers avec le motif : {path_pattern}")
  all_files = []
  for p in path_pattern.split(","):
    p = p.strip()
    found = glob.glob(p)
    all_files.extend(found)

  all_files = sorted(list(set(all_files)))

  if not all_files:
    raise ValueError(f"Aucun fichier trouvé avec le motif : {path_pattern}")

  print(f"[+] {len(all_files)} fichier(s) trouvé(s) à charger :")
  for f in all_files:
    print(f"    -> {os.path.basename(f)}")

  df_list = []
  for filename in all_files:
    df = pd.read_csv(filename, low_memory=False)
    # Nettoyage crucial des espaces dans les noms de colonnes
    df.columns = df.columns.str.strip()
    df_list.append(df)

  combined_df = pd.concat(df_list, ignore_index=True)
  return combined_df


def main():
  parser = argparse.ArgumentParser(
      description="Entraînement Multi-Dataset IDS sur CIC-IDS2017"
  )
  parser.add_argument(
      "--data",
      type=str,
      required=True,
      help=(
          "Chemin ou motif glob (ex: 'madatasets/*[Ww]orking*.csv' ou"
          " 'madatasets/Wednesday*.csv,madatasets/Friday*.csv')"
      ),
  )
  parser.add_argument(
      "--sample_frac",
      type=float,
      default=0.1,
      help=(
          "Fraction de chaque dataset à échantillonner pour préserver la RAM"
      ),
  )
  args = parser.parse_args()

  # 1. Chargement global
  df = load_cic_dataset(args.data)
  print(f"[+] Dataset combiné chargé. Dimensions initiales : {df.shape}")

  # 2. Échantillonnage pour la maîtrise de la RAM
  if args.sample_frac < 1.0:
    df = df.sample(frac=args.sample_frac, random_state=42)
    print(
        f"[i] Échantillonnage appliqué ({int(args.sample_frac*100)}%). Nouvelles"
        f" dimensions : {df.shape}"
    )

  # 3. Nettoyage des valeurs infinies ou NaN
  df.replace([float("inf"), float("-inf")], pd.NA, inplace=True)
  df.dropna(inplace=True)

  # 4. Séparation Features / Label
  if "Label" not in df.columns:
    raise KeyError(
        "La colonne 'Label' est introuvable dans les colonnes :"
        f" {list(df.columns)}"
    )

  X = df.drop(columns=["Label"])

  # Transformation binaire globale (0: Normal, 1: Attaque)
  y = df["Label"].apply(lambda val: 0 if str(val).strip() == "BENIGN" else 1)

  print(
      "[+] Distribution globale des classes (0 = Normal, 1 = Attaque) :"
      f"\n{y.value_counts()}"
  )

  # 5. Division Train / Test
  X_train, X_test, y_train, y_test = train_test_split(
      X, y, test_size=0.2, random_state=42, stratify=y
  )

  # 6. Entraînement du Modèle
  print(
      "[*] Entraînement du modèle Random Forest sur le trafic combiné en"
      " cours..."
  )
  model = RandomForestClassifier(
      n_estimators=100, max_depth=20, random_state=42, n_jobs=-1
  )
  model.fit(X_train, y_train)

  # 7. Évaluation
  print("[*] Évaluation du modèle combiné sur le jeu de test...")
  y_pred = model.predict(X_test)

  f1 = f1_score(y_test, y_pred, average="macro")
  print(f"\n[RÉSULTAT GLOBAL] Macro-F1 Score : {f1:.4f}\n")
  print("--- Matrice de Confusion ---")
  print(confusion_matrix(y_test, y_pred))
  print("\n--- Rapport de Classification ---")
  print(classification_report(y_test, y_pred))


if __name__ == "__main__":
  main()