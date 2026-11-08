#!/usr/bin/env python3
"""Baseline Random Forest / XGBoost + évaluation (Précision, Rappel, Macro-F1)."""
import argparse
import glob
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

META = ["label", "capture_id", "ts"]


def split_data(df, mode, test_size, seed):
    if mode == "group":      # captures entières -> test (anti-fuite maximal)
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
        tr, te = next(gss.split(df, df["label"], groups=df["capture_id"]))
        return df.iloc[tr], df.iloc[te]
    if mode == "temporal":   # passé -> train, futur -> test
        df = df.sort_values("ts")
        cut = int(len(df) * (1 - test_size))
        return df.iloc[:cut], df.iloc[cut:]
    return train_test_split(df, test_size=test_size, stratify=df["label"],
                            random_state=seed)  # stratified


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed_features/*.csv")
    ap.add_argument("--model", choices=["rf", "xgb"], default="rf")
    ap.add_argument("--split", choices=["group", "temporal", "stratified"],
                    default="stratified")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--max-depth", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="outputs/baseline")
    args = ap.parse_args()

    files = sorted(glob.glob(str(Path(args.data).expanduser())))
    df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    print(f"[INFO] {len(df)} flux, {len(files)} fichier(s)")

    train, test = split_data(df, args.split, args.test_size, args.seed)
    feats = [c for c in df.columns if c not in META]
    Xtr, ytr, Xte, yte = train[feats], train["label"], test[feats], test["label"]
    print(f"[INFO] Train={len(train)} Test={len(test)} | split={args.split}")

    if args.model == "rf":
        clf = RandomForestClassifier(
            n_estimators=args.n_estimators, max_depth=args.max_depth,
            class_weight="balanced", n_jobs=-1, random_state=args.seed)
    else:
        from xgboost import XGBClassifier
        spw = (ytr == 0).sum() / max((ytr == 1).sum(), 1)  # déséquilibre
        clf = XGBClassifier(
            n_estimators=args.n_estimators, max_depth=min(args.max_depth, 8),
            learning_rate=0.1, scale_pos_weight=spw,
            eval_metric="logloss", random_state=args.seed)

    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)

    metrics = {
        "precision_attack": precision_score(yte, pred, zero_division=0),
        "recall_attack": recall_score(yte, pred, zero_division=0),
        "macro_f1": f1_score(yte, pred, average="macro", zero_division=0),
        "confusion_matrix": confusion_matrix(yte, pred).tolist(),
    }
    print("\n", classification_report(yte, pred, target_names=["normal", "attaque"],
                                      zero_division=0))
    print("Matrice de confusion [[TN FP],[FN TP]] :\n", metrics["confusion_matrix"])
    print(f"Macro-F1 = {metrics['macro_f1']:.4f}")

    if hasattr(clf, "feature_importances_"):
        imp = pd.Series(clf.feature_importances_, index=feats).sort_values(ascending=False)
        print("\nTop 10 features :\n", imp.head(10).to_string())

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, out / f"{args.model}.joblib")
    (out / f"{args.model}_metrics.json").write_text(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()