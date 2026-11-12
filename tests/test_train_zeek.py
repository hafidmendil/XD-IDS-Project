"""Tests de l'entraînement des baselines Zeek sans fuite de partition."""

import numpy as np
import pandas as pd
import pytest

from scripts.models.train_zeek import (
    expected_calibration_error,
    select_feature_columns,
    train_and_evaluate,
    validate_split_data,
)


def sample_splits(protocol="E1", rows_per_split=20):
    """Construit un jeu synthétique équilibré pour tester le pipeline."""
    rows = []
    base_by_split = {"train": 0, "validation": 1000, "test": 2000}
    for split_name, base in base_by_split.items():
        for index in range(rows_per_split):
            label = index % 2
            start = float(base + index * 10)
            row = {
                "capture_id": f"{split_name}-session-{index // 5}",
                "device_id": f"device-{index % 2}",
                "window_start": start,
                "window_end": start + 10,
                "label": label,
                "split": split_name,
                "flow_count": 1 + 4 * label + index % 3,
                "mean__bytes": 2.0 + 8.0 * label + index * 0.01,
            }
            if protocol == "E2":
                row["capture_id"] = f"session-{base + index // 5:05d}"
            rows.append(row)
    return pd.DataFrame(rows)


def tiny_config():
    """Fournit de petits modèles déterministes pour le test d'intégration."""
    return {
        "seeds": [11],
        "ece_bins": 5,
        "random_forest": {
            "n_estimators": 12,
            "max_depth": 4,
            "min_samples_leaf": 1,
            "class_weight": None,
            "n_jobs": 1,
        },
        "xgboost": {
            "n_estimators": 12,
            "max_depth": 2,
            "learning_rate": 0.1,
            "subsample": 1.0,
            "colsample_bytree": 1.0,
            "reg_lambda": 1.0,
            "objective": "binary:logistic",
            "eval_metric": "logloss",
            "tree_method": "hist",
            "n_jobs": 1,
        },
    }


def test_select_features_excludes_identifiers_and_labels():
    """Les champs numériques d'identité ne deviennent jamais des features."""
    frame = pd.DataFrame(
        {
            "sum__bytes": [1.0, 2.0],
            "capture_id": ["a", "b"],
            "window_start": [10, 20],
            "label": [0, 1],
            "split": ["train", "test"],
        }
    )
    assert select_feature_columns(frame) == ["sum__bytes"]


def test_select_features_rejects_unexpected_identifier_columns():
    """Une colonne d'identité inattendue produit une erreur explicite."""
    frame = pd.DataFrame({"sum__bytes": [1.0], "numeric_device_id": [123]})
    with pytest.raises(ValueError, match="numeric_device_id"):
        select_feature_columns(frame)


def test_ece_attack_probability():
    """L'ECE compare confiance de classe positive et fréquence observée."""
    assert expected_calibration_error(
        np.array([0, 1]), np.array([0.1, 0.9]), bins=5
    ) == pytest.approx(0.1)


def test_validation_rejects_feature_missing_values():
    """Les entrées invalides ne sont ni imputées ni silencieusement éliminées."""
    frame = sample_splits()
    frame.loc[0, "mean__bytes"] = np.nan
    with pytest.raises(ValueError, match="valeurs absentes ou infinies"):
        validate_split_data(frame, "E1")


def test_e2_validation_rejects_session_split_leakage():
    """Une session E2 ne peut pas se retrouver dans deux partitions."""
    frame = sample_splits(protocol="E2")
    frame.loc[0, "capture_id"] = "session-01000"
    with pytest.raises(ValueError, match="partage d'une session"):
        validate_split_data(frame, "E2")


def test_training_fits_only_train_and_writes_reproducible_outputs(tmp_path):
    """Le pipeline produit des métriques et des artefacts expérimentaux."""
    config = tiny_config()
    manifest = train_and_evaluate(
        sample_splits(),
        "E1",
        config,
        tmp_path,
        split_sha256="input-hash",
        config_sha256="config-hash",
    )

    assert manifest["status"] == "experimental_baselines_not_validated_for_deployment"
    assert manifest["split_sha256"] == "input-hash"
    assert len(manifest["runs"]) == 2
    assert {run["model"] for run in manifest["runs"]} == {
        "random_forest",
        "xgboost",
    }
    assert all(run["training_rows"] == 20 for run in manifest["runs"])
    assert all(set(run["metrics"]) == {"validation", "test"} for run in manifest["runs"])
    for run in manifest["runs"]:
        test_metrics = run["metrics"]["test"]
        assert test_metrics["sample_count"] == 20
        assert len(test_metrics["confusion_matrix"]["matrix"]) == 2
        assert 0 <= test_metrics["fpr"] <= 1
        assert 0 <= test_metrics["ece_attack"] <= 1
        assert (tmp_path / run["model_file"]).is_file()
    assert (tmp_path / "metrics.csv").is_file()
    assert (tmp_path / "metrics_summary.csv").is_file()
    assert (tmp_path / "metrics.json").is_file()
    predictions = pd.read_csv(tmp_path / "predictions.csv")
    assert len(predictions) == 80
    assert set(predictions.columns).issuperset(
        {
            "protocol",
            "model",
            "seed",
            "split",
            "capture_id",
            "device_id",
            "window_start",
            "window_end",
            "y_true",
            "y_pred",
            "probability_attack",
        }
    )
    assert predictions["split"].isin(["validation", "test"]).all()
    assert predictions["probability_attack"].between(0, 1).all()


def test_e2_validation_requires_nonoverlapping_chronological_partitions():
    """E2 vérifie l'ordre temporel avant tout apprentissage."""
    frame = sample_splits(protocol="E2")
    frame.loc[frame["split"].eq("validation"), "window_start"] = 1
    frame.loc[frame["split"].eq("validation"), "window_end"] = 2
    with pytest.raises(ValueError, match="strictement chronologiques"):
        validate_split_data(frame, "E2")
