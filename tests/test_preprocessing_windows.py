"""Tests des fenêtres causales et des splits temporels XD-IDS."""

import numpy as np
import pandas as pd
import pytest

from scripts.preprocessing.build_windows import build_windows
from scripts.preprocessing.make_splits import make_splits


def sample_flows():
    """Retourne des flux dont les temps de disponibilité sont contrôlés."""
    return pd.DataFrame(
        {
            "ts": [100.0, 108.0, 110.0],
            "duration": [5.0, 4.0, 0.0],
            "capture_id": ["cap-a"] * 3,
            "src_ip": ["device-a"] * 3,
            "dst_ip": ["broker"] * 3,
            "bytes": [10.0, 20.0, 30.0],
            "label": [0, 1, 0],
        }
    )


def test_window_uses_flow_close_time_and_keeps_ids_out_of_features():
    """Un flux ne peut apparaître qu'après sa clôture Zeek."""
    result = build_windows(sample_flows(), window_seconds=10, device_side="orig")

    assert result[["window_start", "window_end"]].values.tolist() == [
        [100.0, 110.0],
        [110.0, 120.0],
    ]
    first_window = result.iloc[0]
    assert first_window["flow_count"] == 2
    assert first_window["sum__bytes"] == 40
    assert first_window["label"] == 0
    assert result.iloc[1]["label"] == 1
    assert "src_ip" not in result.columns
    assert "dst_ip" not in result.columns
    assert result["device_id"].eq("device-a").all()


def test_window_can_group_on_explicit_responder_side():
    """Le côté choisi détermine le regroupement, pas les features."""
    flows = sample_flows()
    flows.loc[1, "dst_ip"] = "broker-b"
    result = build_windows(flows, window_seconds=10, device_side="resp")
    assert set(result["device_id"]) == {"broker", "broker-b"}


def test_window_rejects_missing_endpoint_metadata():
    """L'absence de métadonnée de regroupement est explicite."""
    with pytest.raises(ValueError, match="src_ip"):
        build_windows(
            sample_flows().drop(columns="src_ip"),
            window_seconds=10,
            device_side="orig",
        )


def test_window_excludes_flows_with_unknown_duration():
    """Une durée inconnue n'est jamais assimilée à une disponibilité immédiate."""
    flows = sample_flows()
    flows.loc[0, "duration"] = np.nan
    result = build_windows(flows, window_seconds=10, device_side="orig")
    assert result["flow_count"].sum() == 2
    assert result.attrs["excluded_unknown_duration_flows"] == 1


def make_session_windows(session_count=20):
    """Crée des sessions chronologiques sans recouvrement ni doublons."""
    rows = []
    for session in range(session_count):
        base = session * 100.0
        for index in range(3):
            start = base + index * 10.0
            rows.append(
                {
                    "capture_id": f"session-{session:02d}",
                    "device_id": "device-a",
                    "window_start": start,
                    "window_end": start + 10.0,
                    "flow_count": 1,
                    "label": session % 2,
                    "feature_a": float(session * 3 + index),
                    "feature_b": float(index),
                }
            )
    return pd.DataFrame(rows)


def test_e2_keeps_sessions_separate_and_purges_boundaries():
    """E2 garde chaque session entière et écarte les fenêtres frontières."""
    result, details = make_splits(
        make_session_windows(),
        protocol="E2",
        fractions={"train": 0.70, "validation": 0.15, "test": 0.15},
        seed=42,
        purge_seconds=40,
    )

    assert set(result["split"]) == {"train", "validation", "test"}
    assert details["purged_windows"] > 0
    assert details["sessions_per_split"]["train"] > 0
    split_by_session = result.groupby("capture_id")["split"].nunique()
    assert split_by_session.eq(1).all()
    assert result["duplicate_group_id"].nunique() == len(result)
    assert np.isfinite(result["feature_a"]).all()


def test_e2_keeps_exact_duplicates_in_one_partition():
    """Un doublon inter-session relie ses sessions avant les coupures E2."""
    windows = make_session_windows()
    duplicate = windows.loc[
        windows["capture_id"].eq("session-00")
        & windows["window_start"].eq(0)
    ].iloc[0]
    target_index = windows.index[
        windows["capture_id"].eq("session-05")
        & windows["window_start"].eq(500)
    ][0]
    windows.loc[target_index, ["feature_a", "feature_b"]] = [
        duplicate["feature_a"],
        duplicate["feature_b"],
    ]

    result, _ = make_splits(
        windows,
        protocol="E2",
        fractions={"train": 0.70, "validation": 0.15, "test": 0.15},
        purge_seconds=10,
    )
    duplicate_rows = result.loc[
        result["duplicate_group_id"].eq(
            result.loc[
                result["capture_id"].eq("session-00")
                & result["window_start"].eq(0),
                "duplicate_group_id",
            ].iloc[0]
        )
    ]
    assert duplicate_rows["split"].nunique() == 1


def test_e1_is_reproducible_and_groups_exact_duplicates():
    """E1 reste aléatoire, mais ne sépare jamais des features identiques."""
    windows = make_session_windows()
    windows.loc[1, "feature_a"] = windows.loc[0, "feature_a"]
    windows.loc[1, "feature_b"] = windows.loc[0, "feature_b"]
    parameters = {
        "protocol": "E1",
        "fractions": {"train": 0.70, "validation": 0.15, "test": 0.15},
        "seed": 17,
    }
    first, _ = make_splits(windows, **parameters)
    second, _ = make_splits(windows, **parameters)

    pd.testing.assert_frame_equal(first, second)
    grouped = first.groupby("duplicate_group_id")["split"].nunique()
    assert grouped.eq(1).all()
    assert first.groupby("split")["label"].nunique().eq(2).all()


def test_e1_stratifies_rare_classes_when_three_distinct_groups_exist():
    """Chaque partition E1 reçoit les deux classes si assez de groupes existent."""
    windows = pd.DataFrame(
        [
            {
                "capture_id": f"capture-{label}-{index}",
                "window_start": float(index),
                "window_end": float(index + 1),
                "label": label,
                "feature": float(label * 100 + index),
            }
            for label, count in ((0, 5), (1, 30))
            for index in range(count)
        ]
    )
    result, details = make_splits(
        windows,
        protocol="E1",
        fractions={"train": 0.70, "validation": 0.15, "test": 0.15},
        seed=42,
    )

    assert result.groupby("split")["label"].nunique().eq(2).all()
    assert details["stratified_class_coverage"] is True


def test_e2_rejects_too_few_sessions():
    """Un unique capture ne peut pas justifier un split E2."""
    windows = make_session_windows(session_count=1)
    with pytest.raises(ValueError, match="au moins trois capture_id"):
        make_splits(
            windows,
            protocol="E2",
            fractions={"train": 0.70, "validation": 0.15, "test": 0.15},
        )


def test_e2_rejects_overlapping_session_intervals():
    """Les sessions qui se chevauchent ne sont pas présentées comme chronologiques."""
    windows = make_session_windows(session_count=4)
    windows.loc[windows["capture_id"].eq("session-01"), "window_start"] = 5
    windows.loc[windows["capture_id"].eq("session-01"), "window_end"] = 15
    with pytest.raises(ValueError, match="se chevauchent"):
        make_splits(
            windows,
            protocol="E2",
            fractions={"train": 0.70, "validation": 0.15, "test": 0.15},
        )
