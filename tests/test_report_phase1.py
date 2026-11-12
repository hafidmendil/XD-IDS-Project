"""Tests for factual Phase 1 reporting with incomplete E2 class coverage."""

import json
import hashlib

import pandas as pd

from scripts.evaluation.report_phase1 import build_report


def _write_split(path, single_class_train=False):
    rows = []
    for split, start in (("train", 0), ("validation", 100), ("test", 200)):
        labels = [1, 1] if single_class_train and split in {"train", "validation"} else [0, 1]
        for index, label in enumerate(labels):
            window_start = start + index * 10
            rows.append(
                {
                    "capture_id": f"{split}-{index}",
                    "window_start": window_start,
                    "window_end": window_start + 10,
                    "label": label,
                    "split": split,
                    "feature": float(index + label),
                }
            )
    pd.DataFrame(rows).to_csv(path, index=False)


def test_report_marks_e2_unavailable_when_train_and_validation_are_single_class(tmp_path):
    windows_path = tmp_path / "windows_all.csv"
    pd.DataFrame(
        {
            "capture_id": ["a"],
            "window_start": [0],
            "window_end": [10],
            "label": [1],
            "feature": [1.0],
        }
    ).to_csv(windows_path, index=False)

    splits_dir = tmp_path / "splits"
    splits_dir.mkdir()
    _write_split(splits_dir / "E1.csv")
    _write_split(splits_dir / "E2.csv", single_class_train=True)
    e1_sha256 = hashlib.sha256((splits_dir / "E1.csv").read_bytes()).hexdigest()

    results_dir = tmp_path / "results"
    e1_dir = results_dir / "E1"
    e1_dir.mkdir(parents=True)
    metrics = {
        "protocol": "E1",
        "status": "experimental_baselines_not_validated_for_deployment",
        "seeds": [42],
        "split_sha256": e1_sha256,
    }
    (e1_dir / "metrics.json").write_text(json.dumps(metrics), encoding="utf-8")
    pd.DataFrame(
        [
            {
                "model": "random_forest",
                "split": "test",
                "seed_count": 1,
                **{
                    f"{metric}_{stat}": 0.5 if stat == "mean" else 0.1
                    for metric in (
                        "macro_f1",
                        "fpr",
                        "pr_auc_attack",
                        "ece_attack",
                        "inference_latency_p95_ms",
                    )
                    for stat in ("mean", "std")
                },
            }
        ]
    ).to_csv(e1_dir / "metrics_summary.csv", index=False)

    report_path = tmp_path / "phase1_report.md"
    report = build_report(
        windows_path,
        splits_dir,
        results_dir,
        report_path,
        root=tmp_path,
    )

    assert report_path.read_text(encoding="utf-8") == report
    assert "Entraînement binaire et validation binaire possibles : NON." in report
    assert "Les métriques E2 sont NON DISPONIBLES." in report
    assert "0.5000 ± 0.1000" in report
