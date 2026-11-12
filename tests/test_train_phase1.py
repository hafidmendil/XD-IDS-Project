"""Tests for skipping non-trainable E2 without suppressing E1 errors."""

import json

import pandas as pd

from scripts.evaluation.train_phase1 import train_phase1


def test_invalid_e2_is_recorded_and_not_trained(tmp_path, monkeypatch):
    splits = tmp_path / "splits"
    splits.mkdir()
    rows = []
    for split, labels in (
        ("train", [1, 1]),
        ("validation", [1]),
        ("test", [0, 1]),
    ):
        for index, label in enumerate(labels):
            rows.append(
                {
                    "split": split,
                    "label": label,
                    "capture_id": f"{split}-{index}",
                }
            )
    pd.DataFrame(rows).to_csv(splits / "E2.csv", index=False)
    e1_rows = [
        {"split": split, "label": label}
        for split in ("train", "validation", "test")
        for label in (0, 1)
    ]
    pd.DataFrame(e1_rows).to_csv(splits / "E1.csv", index=False)
    config = tmp_path / "models.yaml"
    config.write_text("seeds: [42]\n", encoding="utf-8")

    calls = []
    monkeypatch.setattr(
        "scripts.evaluation.train_phase1._train",
        lambda protocol, *_args: calls.append(protocol),
    )
    results = tmp_path / "results" / "phase_b"

    status = train_phase1(splits, config, results)

    assert calls == ["E1"]
    assert status["E2"]["status"] == "not_run_invalid_class_coverage"
    assert status["E2"]["class_counts"]["train"] == {0: 0, 1: 2}
    saved = json.loads(
        (results / "E2" / "status.json").read_text(encoding="utf-8")
    )
    assert saved["split_sha256"]
    assert "train" in saved["reason"]
