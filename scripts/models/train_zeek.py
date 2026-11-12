#!/usr/bin/env python3
"""Entraîne et évalue les baselines RF/XGBoost sur les fenêtres Zeek."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score
from xgboost import XGBClassifier


DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "configs" / "models.yaml"
SPLITS = ("train", "validation", "test")
METADATA_COLUMNS = {
    "label",
    "split",
    "capture_id",
    "device_id",
    "src_ip",
    "dst_ip",
    "window_start",
    "window_end",
    "duplicate_group_id",
}
FORBIDDEN_FEATURE_TOKENS = {
    "addr",
    "address",
    "capture",
    "device",
    "duplicate",
    "id",
    "identifier",
    "ip",
    "label",
    "port",
    "session",
    "split",
    "target",
    "time",
    "timestamp",
    "ts",
    "uid",
    "uuid",
}
METRIC_COLUMNS = (
    "macro_f1",
    "precision_macro",
    "recall_macro",
    "precision_normal",
    "recall_normal",
    "f1_normal",
    "precision_attack",
    "recall_attack",
    "f1_attack",
    "fpr",
    "pr_auc_attack",
    "ece_attack",
    "inference_latency_p95_ms",
)


def sha256_file(path):
    """Calcule l'empreinte SHA-256 d'un fichier par blocs."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _environment_version(command, arguments):
    """Return a version string or an explicit unavailable reason."""
    executable = shutil.which(command)
    if executable is None:
        return "NON DISPONIBLE (exécutable absent du PATH)"
    result = subprocess.run(
        [executable, *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return "NON DISPONIBLE (commande de version en échec)"
    return (result.stdout or result.stderr).strip()


def _git_commit():
    """Return the current repository commit when available."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "NON DISPONIBLE"


def load_config(path):
    """Charge la configuration et vérifie les paramètres des deux modèles."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)
    if not isinstance(config, dict):
        raise ValueError(f"La configuration YAML doit être un objet : {path}")
    expected = {"seeds", "ece_bins", "random_forest", "xgboost"}
    unknown = set(config).difference(expected)
    missing = expected.difference(config)
    if unknown or missing:
        raise ValueError(
            f"Configuration modèles invalide; clés absentes={sorted(missing)}, "
            f"inconnues={sorted(unknown)}."
        )
    seeds = config["seeds"]
    if (
        not isinstance(seeds, list)
        or not seeds
        or any(not isinstance(seed, int) or seed < 0 for seed in seeds)
        or len(set(seeds)) != len(seeds)
    ):
        raise ValueError("seeds doit être une liste non vide d'entiers uniques >= 0.")
    bins = config["ece_bins"]
    if not isinstance(bins, int) or bins < 2:
        raise ValueError("ece_bins doit être un entier >= 2.")
    for model_name in ("random_forest", "xgboost"):
        if not isinstance(config[model_name], dict):
            raise ValueError(f"{model_name} doit être un objet YAML.")
    return config


def _is_forbidden_feature(column):
    """Détecte un identifiant ou une métadonnée même si elle est numérique."""
    tokens = {
        token
        for token in "".join(
            character.lower() if character.isalnum() else " "
            for character in column
        ).split()
    }
    return bool(tokens.intersection(FORBIDDEN_FEATURE_TOKENS))


def select_feature_columns(frame):
    """Sélectionne les features numériques et rejette les identifiants résiduels."""
    candidates = [column for column in frame.columns if column not in METADATA_COLUMNS]
    forbidden = [column for column in candidates if _is_forbidden_feature(column)]
    if forbidden:
        raise ValueError(
            "Colonnes candidates contenant un identifiant ou une métadonnée "
            "interdite : " + ", ".join(sorted(forbidden))
        )
    if not candidates:
        raise ValueError("Aucune feature disponible après exclusion des métadonnées.")
    non_numeric = [
        column
        for column in candidates
        if not pd.api.types.is_numeric_dtype(frame[column])
    ]
    if non_numeric:
        raise ValueError(
            "Les features doivent être numériques; colonnes non numériques : "
            + ", ".join(sorted(non_numeric))
        )
    values = frame[candidates].to_numpy(dtype=float)
    if not np.isfinite(values).all():
        raise ValueError("Les features contiennent des valeurs absentes ou infinies.")
    return candidates


def validate_split_data(frame, protocol):
    """Valide les partitions, labels, fuites de groupes et l'ordre E2."""
    required = {"split", "label", "capture_id", "window_start", "window_end"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(
            "Colonnes obligatoires absentes du CSV de split : "
            + ", ".join(sorted(missing))
        )
    if frame.empty:
        raise ValueError("Le CSV de split est vide.")

    data = frame.copy()
    data["split"] = data["split"].astype("string").str.strip()
    if data["split"].isna().any() or not set(data["split"]).issubset(SPLITS):
        raise ValueError("La colonne split ne contient que train/validation/test.")
    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    for column in ("window_start", "window_end"):
        data[column] = pd.to_numeric(data[column], errors="coerce")
    for column in ("label", "window_start", "window_end"):
        values = data[column].to_numpy(dtype=float)
        if not np.isfinite(values).all():
            raise ValueError(f"La colonne {column} contient des valeurs invalides.")
    if not data["label"].isin([0, 1]).all():
        raise ValueError("Les labels doivent être binaires (0=normal, 1=attaque).")
    if data["window_end"].le(data["window_start"]).any():
        raise ValueError("Une fenêtre de décision a une durée nulle ou négative.")

    counts = data["split"].value_counts()
    empty = [name for name in SPLITS if counts.get(name, 0) == 0]
    if empty:
        raise ValueError("Partitions vides : " + ", ".join(empty))
    for name in SPLITS:
        labels = set(data.loc[data["split"].eq(name), "label"])
        if labels != {0, 1}:
            raise ValueError(
                f"La partition {name} doit contenir les deux classes; "
                f"classes trouvées : {sorted(labels)}."
            )

    if "duplicate_group_id" in data.columns:
        group_counts = data.groupby("duplicate_group_id")["split"].nunique()
        if group_counts.gt(1).any():
            raise ValueError(
                "Un groupe de doublons exact est partagé entre des partitions."
            )

    if protocol == "E2":
        if "capture_id" not in data:
            raise ValueError("E2 exige la colonne capture_id.")
        data["capture_id"] = data["capture_id"].astype("string").str.strip()
        if data["capture_id"].isna().any() or data["capture_id"].eq("").any():
            raise ValueError("E2 exige des capture_id non vides.")
        session_splits = data.groupby("capture_id")["split"].nunique()
        if session_splits.gt(1).any():
            raise ValueError("E2 interdit le partage d'une session entre splits.")
        temporal = {}
        for name in SPLITS:
            subset = data.loc[data["split"].eq(name)]
            temporal[name] = (
                float(subset["window_start"].min()),
                float(subset["window_end"].max()),
            )
        if not (
            temporal["train"][1] <= temporal["validation"][0]
            and temporal["validation"][1] <= temporal["test"][0]
        ):
            raise ValueError(
                "E2 exige train, validation et test strictement chronologiques "
                "et sans chevauchement temporel."
            )
    elif protocol != "E1":
        raise ValueError("protocol doit valoir E1 ou E2.")

    features = select_feature_columns(data)
    return data, features


def expected_calibration_error(y_true, attack_probability, bins=15):
    """Calcule l'ECE binaire à partir des probabilités d'attaque."""
    y_true = np.asarray(y_true, dtype=np.int8)
    probabilities = np.asarray(attack_probability, dtype=float)
    if y_true.shape != probabilities.shape or y_true.ndim != 1:
        raise ValueError("Les labels et probabilités doivent être des vecteurs égaux.")
    if not np.isfinite(probabilities).all() or (
        (probabilities < 0).any() or (probabilities > 1).any()
    ):
        raise ValueError("Les probabilités doivent être finies et dans [0, 1].")
    if bins < 2:
        raise ValueError("Il faut au moins deux bins pour calculer l'ECE.")
    bin_ids = np.minimum((probabilities * bins).astype(int), bins - 1)
    ece = 0.0
    for bin_id in range(bins):
        mask = bin_ids == bin_id
        if mask.any():
            ece += mask.mean() * abs(
                probabilities[mask].mean() - y_true[mask].mean()
            )
    return float(ece)


def inference_latency_p95_ms(model, features):
    """Mesure le p95 de la latence predict_proba sur une fenêtre isolée."""
    latencies = np.empty(len(features), dtype=float)
    for index in range(len(features)):
        sample = features.iloc[[index]]
        start = time.perf_counter_ns()
        model.predict_proba(sample)
        latencies[index] = (time.perf_counter_ns() - start) / 1_000_000
    return float(np.percentile(latencies, 95))


def evaluate_model(model, features, labels, ece_bins):
    """Calcule les métriques IDS sans réajuster le modèle."""
    probabilities = np.asarray(model.predict_proba(features), dtype=float)
    classes = list(model.classes_)
    if 0 not in classes or 1 not in classes:
        raise ValueError("Le modèle doit fournir les probabilités des classes 0 et 1.")
    attack_probability = probabilities[:, classes.index(1)]
    predictions = np.asarray(model.predict(features), dtype=np.int8)
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (
        int(value) for value in matrix.ravel()
    )

    def safe_ratio(numerator, denominator):
        return numerator / denominator if denominator else 0.0

    precision_normal = safe_ratio(
        true_negative, true_negative + false_negative
    )
    recall_normal = safe_ratio(true_negative, true_negative + false_positive)
    precision_attack = safe_ratio(
        true_positive, true_positive + false_positive
    )
    recall_attack = safe_ratio(true_positive, true_positive + false_negative)
    return {
        "sample_count": int(len(labels)),
        "macro_f1": float(f1_score(labels, predictions, average="macro")),
        "precision_macro": float((precision_normal + precision_attack) / 2),
        "recall_macro": float((recall_normal + recall_attack) / 2),
        "precision_normal": float(precision_normal),
        "recall_normal": float(recall_normal),
        "f1_normal": float(
            2 * precision_normal * recall_normal
            / (precision_normal + recall_normal)
            if precision_normal + recall_normal
            else 0
        ),
        "precision_attack": float(precision_attack),
        "recall_attack": float(recall_attack),
        "f1_attack": float(
            2 * precision_attack * recall_attack
            / (precision_attack + recall_attack)
            if precision_attack + recall_attack
            else 0
        ),
        "fpr": float(false_positive / (false_positive + true_negative)),
        "pr_auc_attack": float(average_precision_score(labels, attack_probability)),
        "ece_attack": expected_calibration_error(
            labels, attack_probability, bins=ece_bins
        ),
        "confusion_matrix": {
            "labels": ["normal", "attack"],
            "matrix": matrix.tolist(),
            "tn": true_negative,
            "fp": false_positive,
            "fn": false_negative,
            "tp": true_positive,
        },
        "inference_latency_p95_ms": inference_latency_p95_ms(model, features),
    }


def _new_model(model_name, params, seed):
    """Construit un classifieur avec un état aléatoire explicitement fixé."""
    if model_name == "random_forest":
        return RandomForestClassifier(**params, random_state=seed)
    if model_name == "xgboost":
        return XGBClassifier(**params, random_state=seed)
    raise ValueError(f"Modèle inconnu : {model_name}")


def train_and_evaluate(
    frame,
    protocol,
    config,
    output_dir,
    split_sha256=None,
    config_sha256=None,
):
    """Entraîne les deux baselines sur train, puis mesure validation et test."""
    data, feature_columns = validate_split_data(frame, protocol)
    output_dir = Path(output_dir)
    model_dir = output_dir / "models"
    model_dir.mkdir(parents=True, exist_ok=True)

    train_mask = data["split"].eq("train")
    X_train = data.loc[train_mask, feature_columns]
    y_train = data.loc[train_mask, "label"].astype("int8")
    metrics_rows = []
    prediction_rows = []
    runs = []
    model_parameters = {
        "random_forest": config["random_forest"],
        "xgboost": config["xgboost"],
    }
    for model_name, parameters in model_parameters.items():
        for seed in config["seeds"]:
            model = _new_model(model_name, parameters, seed)
            fit_started = time.perf_counter()
            model.fit(X_train, y_train)
            fit_seconds = time.perf_counter() - fit_started

            model_filename = f"{protocol}_{model_name}_seed{seed}.joblib"
            model_path = model_dir / model_filename
            joblib.dump(model, model_path)
            run = {
                "protocol": protocol,
                "model": model_name,
                "seed": int(seed),
                "training_rows": int(len(X_train)),
                "feature_count": int(len(feature_columns)),
                "feature_names": feature_columns,
                "training_duration_seconds": float(fit_seconds),
                "model_file": str(model_path.relative_to(output_dir)),
                "model_sha256": sha256_file(model_path),
                "experimental_only": True,
                "metrics": {},
            }
            for split_name in ("validation", "test"):
                mask = data["split"].eq(split_name)
                X_eval = data.loc[mask, feature_columns]
                y_eval = data.loc[mask, "label"].astype("int8").to_numpy()
                measured = evaluate_model(
                    model, X_eval, y_eval, ece_bins=config["ece_bins"]
                )
                probabilities = np.asarray(model.predict_proba(X_eval), dtype=float)
                classes = list(model.classes_)
                predictions = np.asarray(model.predict(X_eval), dtype=np.int8)
                attack_probability = probabilities[:, classes.index(1)]
                identifiers = [
                    column
                    for column in (
                        "capture_id",
                        "device_id",
                        "window_start",
                        "window_end",
                    )
                    if column in data.columns
                ]
                for position, row_index in enumerate(data.index[mask]):
                    prediction = {
                        "protocol": protocol,
                        "model": model_name,
                        "seed": int(seed),
                        "split": split_name,
                        "y_true": int(y_eval[position]),
                        "y_pred": int(predictions[position]),
                        "probability_attack": float(attack_probability[position]),
                    }
                    prediction.update(
                        {
                            column: data.at[row_index, column]
                            for column in identifiers
                        }
                    )
                    prediction_rows.append(prediction)
                measured["split"] = split_name
                measured["seed"] = int(seed)
                measured["protocol"] = protocol
                measured["model"] = model_name
                metrics_rows.append(measured)
                run["metrics"][split_name] = measured
            runs.append(run)

    metric_frame = pd.DataFrame(metrics_rows)
    metric_path = output_dir / "metrics.csv"
    metric_frame.to_csv(metric_path, index=False, float_format="%.12g")
    predictions_path = output_dir / "predictions.csv"
    pd.DataFrame(prediction_rows).to_csv(
        predictions_path, index=False, float_format="%.12g"
    )
    aggregate_rows = []
    for keys, subset in metric_frame.groupby(
        ["protocol", "model", "split"], sort=True
    ):
        row = dict(zip(("protocol", "model", "split"), keys, strict=True))
        row["seed_count"] = int(subset["seed"].nunique())
        for metric in METRIC_COLUMNS:
            row[f"{metric}_mean"] = float(subset[metric].mean())
            standard_deviation = subset[metric].std(ddof=1)
            row[f"{metric}_std"] = (
                float(standard_deviation)
                if pd.notna(standard_deviation)
                else None
            )
        aggregate_rows.append(row)
    aggregate_frame = pd.DataFrame(aggregate_rows)
    aggregate_path = output_dir / "metrics_summary.csv"
    aggregate_frame.to_csv(aggregate_path, index=False, float_format="%.12g")

    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "protocol": protocol,
        "status": "experimental_baselines_not_validated_for_deployment",
        "split_sha256": split_sha256,
        "config_sha256": config_sha256,
        "feature_names": feature_columns,
        "excluded_metadata_columns": sorted(
            set(data.columns).difference(feature_columns)
        ),
        "seeds": config["seeds"],
        "metrics_definition": {
            "fpr": "FP / (FP + TN)",
            "pr_auc_attack": "Average precision pour la classe attaque (1)",
            "ece_attack": (
                f"ECE binaire à {config['ece_bins']} bins, calculé sur "
                "la probabilité d'attaque; aucune calibration n'est appliquée."
            ),
            "inference_latency_p95_ms": (
                "p95 de predict_proba mesuré par fenêtre isolée sur le jeu évalué."
            ),
        },
        "software_versions": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "zeek": _environment_version("zeek", ["--version"]),
        },
        "runs": runs,
        "aggregate_metrics": aggregate_rows,
        "metrics_csv": metric_path.name,
        "metrics_sha256": sha256_file(metric_path),
        "summary_csv": aggregate_path.name,
        "summary_sha256": sha256_file(aggregate_path),
        "predictions_csv": predictions_path.name,
        "predictions_sha256": sha256_file(predictions_path),
    }
    manifest_path = output_dir / "metrics.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def main():
    """Point d'entrée CLI."""
    parser = argparse.ArgumentParser(
        description="Entraîne RF/XGBoost sur train et évalue E1 ou E2."
    )
    parser.add_argument("splits_csv", help="CSV publié par make_splits.py")
    parser.add_argument("--protocol", choices=("E1", "E2"), required=True)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument(
        "-o",
        "--output-dir",
        required=True,
        help="Dossier de sortie propre à ce protocole, par ex. results/phase_b/E2",
    )
    parser.add_argument(
        "--seeds",
        type=int,
        nargs="+",
        help="Surcharge facultative; sinon les cinq graines YAML sont utilisées.",
    )
    args = parser.parse_args()

    try:
        split_path = Path(args.splits_csv).expanduser().resolve()
        config_path = Path(args.config).expanduser().resolve()
        config = load_config(config_path)
        if args.seeds is not None:
            if not args.seeds or any(seed < 0 for seed in args.seeds):
                raise ValueError("--seeds exige des entiers >= 0.")
            if len(set(args.seeds)) != len(args.seeds):
                raise ValueError("--seeds ne doit pas contenir de doublons.")
            config["seeds"] = args.seeds
        output_dir = Path(args.output_dir).expanduser().resolve()
        manifest = train_and_evaluate(
            pd.read_csv(split_path),
            args.protocol,
            config,
            output_dir,
            split_sha256=sha256_file(split_path),
            config_sha256=sha256_file(config_path),
        )
        print(
            f"[OK] {args.protocol}: {len(manifest['runs'])} entraînements "
            f"(2 modèles × {len(config['seeds'])} graines)."
        )
        print(f"[OK] Métriques détaillées : {output_dir / 'metrics.csv'}")
        print(f"[OK] Agrégats moyenne/écart-type : {output_dir / 'metrics_summary.csv'}")
        print(f"[OK] Prédictions validation/test : {output_dir / 'predictions.csv'}")
        print(f"[OK] Manifeste : {output_dir / 'metrics.json'}")
        print(
            "[AVERTISSEMENT] Ces modèles sont des baselines expérimentales; "
            "ils ne sont pas validés pour le déploiement."
        )
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        print(f"[ERREUR] {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
