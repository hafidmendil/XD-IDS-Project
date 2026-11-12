"""Tests de l'ingestion Zeek et de la préparation des fenêtres causales."""

import json

import numpy as np
import pandas as pd
import pytest

from scripts.preprocessing.prepare_zeek_windows import (
    build_causal_windows,
    identify_and_remove_duplicates,
    load_conn_log,
    process_conn_log,
)


def zeek_frame():
    """Construit des flux avec valeurs manquantes et identifiants réseau."""
    return pd.DataFrame(
        {
            "ts": ["100", "108", "120", "130"],
            "duration": ["5", "4", "-", "2"],
            "id.orig_h": ["device-a", "device-a", "device-a", "device-b"],
            "id.orig_p": ["1200", "1201", "1202", "1203"],
            "id.resp_h": ["broker", "broker", "broker", "broker"],
            "id.resp_p": ["1883", "1883", "1883", "1883"],
            "proto": ["tcp", "tcp", "udp", "tcp"],
            "conn_state": ["SF", "SF", "S0", "SF"],
            "orig_bytes": ["10", "20", "-", "30"],
            "resp_bytes": ["5", "10", "-", "15"],
            "orig_pkts": ["2", "3", "1", "4"],
            "resp_pkts": ["2", "3", "0", "4"],
        }
    )


def test_load_conn_log_parses_zeek_tsv_and_missing_values(tmp_path):
    """Les champs '-', '(empty)' et vides deviennent des valeurs manquantes."""
    path = tmp_path / "conn.log"
    path.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
        "\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state"
        "\torig_pkts\tresp_pkts\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring"
        "\tinterval\tcount\tcount\tstring\tcount\tcount\n"
        "100.0\tu1\tdevice-a\t1200\tbroker\t1883\ttcp\t-\t2\t-\t\tSF\t2\t2\n",
        encoding="utf-8",
    )

    loaded = load_conn_log(path)
    assert pd.isna(loaded.loc[0, "service"])
    assert pd.isna(loaded.loc[0, "orig_bytes"])
    assert pd.isna(loaded.loc[0, "resp_bytes"])
    assert loaded.loc[0, "ts"] == "100.0"


def test_load_conn_log_reports_missing_and_empty_files(tmp_path):
    """Les erreurs de fichier et de contenu vide sont explicites."""
    with pytest.raises(FileNotFoundError):
        load_conn_log(tmp_path / "missing.log")

    empty = tmp_path / "empty.log"
    empty.write_text("#separator \\x09\n#fields\tts\n", encoding="utf-8")
    with pytest.raises(pd.errors.EmptyDataError):
        load_conn_log(empty)


def test_causal_window_excludes_invalid_durations_and_metadata_is_not_feature():
    """Durée inconnue écartée, et IP/ports confinés aux métadonnées."""
    windows, excluded = build_causal_windows(
        zeek_frame(),
        capture_id="capture-a",
        label=0,
        window_seconds=10,
        device_side="orig",
    )

    assert excluded["invalid_duration"] == 1
    assert windows["flow_count"].sum() == 3
    assert set(windows["device_id"]) == {"device-a", "device-b"}
    assert "device_id" in windows
    assert "ports_seen" in windows
    assert "peer_ips" in windows
    assert not any(
        column in windows.columns
        for column in ("src_ip", "dst_ip", "id.orig_p", "id.resp_p")
    )
    assert "sum__duration" in windows
    assert windows.loc[windows["device_id"].eq("device-a"), "label"].eq(0).all()


def test_attacker_ip_label_marks_either_endpoint():
    """La règle de label marque le flux si l'IP attaquante est à l'un des bouts."""
    frame = zeek_frame()
    windows, _ = build_causal_windows(
        frame,
        capture_id="capture-a",
        attacker_ips=["device-a"],
        window_seconds=60,
        device_side="orig",
    )
    assert windows.loc[windows["device_id"].eq("device-a"), "label"].eq(1).all()


def test_duplicate_audit_removes_exact_and_near_duplicates():
    """Les quasi-doublons respectent une tolérance absolue par feature."""
    frame = pd.DataFrame(
        {
            "label": [0, 0, 0, 1],
            "flow_count": [5.0, 5.0, 5.005, 5.0],
            "sum__bytes": [100.0, 100.0, 100.004, 100.0],
            "capture_id": ["a", "b", "c", "d"],
            "device_id": ["one", "two", "three", "four"],
        }
    )

    result, audit = identify_and_remove_duplicates(frame, near_tolerance=0.01)

    assert len(result) == 2
    assert audit["exact_duplicates_removed"] == 1
    assert audit["near_duplicates_removed"] == 1
    assert audit["label_conflict_rows_kept"] == 1
    assert audit["groups_with_conflicting_labels"] == 1
    assert result["duplicate_group_id"].nunique() == 1


def test_duplicate_audit_zero_tolerance_only_removes_exact_rows():
    """Une tolérance nulle ne rapproche pas deux vecteurs distincts."""
    frame = pd.DataFrame(
        {"label": [0, 0], "feature": [1.0, 1.00001]}
    )
    result, audit = identify_and_remove_duplicates(frame, near_tolerance=0)
    assert len(result) == 2
    assert audit["exact_duplicates_removed"] == 0
    assert audit["near_duplicates_removed"] == 0


def test_cli_pipeline_writes_csv_and_audit_manifest(tmp_path):
    """Le pipeline enregistre le hash, les exclusions et les résultats d'audit."""
    input_path = tmp_path / "conn.log"
    input_path.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
        "\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state"
        "\torig_pkts\tresp_pkts\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring"
        "\tinterval\tcount\tcount\tstring\tcount\tcount\n"
        "100\tu1\tdevice-a\t1200\tbroker\t1883\ttcp\t-\t1\t10\t5\tSF\t2\t2\n"
        "101\tu2\tdevice-a\t1201\tbroker\t1883\ttcp\t-\t1\t10\t5\tSF\t2\t2\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "output" / "windows.csv"

    result, manifest = process_conn_log(
        input_path,
        output_path,
        label=0,
        capture_id="capture-a",
        window_seconds=60,
        near_tolerance=0,
    )

    saved = pd.read_csv(output_path)
    audit = json.loads(output_path.with_suffix(".csv.audit.json").read_text())
    assert len(result) == len(saved) == 1
    assert manifest["excluded_flows"]["invalid_duration"] == 0
    assert manifest["duplicate_audit"]["exact_duplicates_removed"] == 0
    assert audit["input_sha256"]
    assert audit["output_sha256"]


def test_invalid_duration_variants_are_counted():
    """Durée négative, non numérique et infinie sont des exclusions explicites."""
    frame = zeek_frame()
    frame["duration"] = ["-1", "not-a-number", "inf", "2"]
    windows, excluded = build_causal_windows(
        frame,
        capture_id="capture-a",
        label=0,
        window_seconds=60,
    )
    assert excluded["invalid_duration"] == 3
    assert windows["flow_count"].sum() == 1
    assert np.isfinite(windows.select_dtypes(include="number").to_numpy()).all()
