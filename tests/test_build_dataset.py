"""Tests for recording an invalid E2 split without losing the E1 artifact."""

import pandas as pd

from scripts.preprocessing.build_dataset import build_splits_and_report


def test_overlapping_sessions_write_e2_status_and_keep_e1(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    windows_dir = repo / "data" / "processed_features"
    windows_dir.mkdir(parents=True)
    (windows_dir / "windows_all.csv").write_text("capture_id\n", encoding="utf-8")
    monkeypatch.setattr("scripts.preprocessing.build_dataset.REPO_ROOT", repo)

    config = repo / "configs" / "splits.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(
        "fractions:\n  train: 0.70\n  validation: 0.15\n  test: 0.15\n"
        "seed: 42\npurge_seconds: 0\n",
        encoding="utf-8",
    )
    rows = []
    for session, base in (("a", 0), ("b", 1), ("c", 2)):
        for index, label in enumerate((0, 1)):
            rows.append(
                {
                    "capture_id": session,
                    "window_start": base + index * 2,
                    "window_end": base + index * 2 + 1,
                    "label": label,
                    "feature": float(len(rows)),
                }
            )
    splits_dir = repo / "splits"
    splits_dir.mkdir()
    stale_e2 = splits_dir / "E2.csv"
    stale_e2.write_text("stale\n", encoding="utf-8")

    result = build_splits_and_report(pd.DataFrame(rows), config, splits_dir)

    assert "E1" in result
    assert "E2.status" in result
    assert (splits_dir / "E1.csv").is_file()
    assert not stale_e2.exists()
    status = (splits_dir / "E2.status.json").read_text(encoding="utf-8")
    assert "sessions se chevauchent" in status
