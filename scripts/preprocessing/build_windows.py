#!/usr/bin/env python3
"""Construit des fenêtres causales à partir des flux finalisés par Zeek."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

DEFAULT_CONFIG = (
    Path(__file__).resolve().parents[2] / "configs" / "windows.yaml"
)
INPUT_METADATA = {
    "ts",
    "capture_id",
    "src_ip",
    "dst_ip",
    "label",
}


def sha256_file(path):
    """Calcule le SHA-256 d'un fichier par blocs."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_config(path):
    """Charge une configuration YAML et vérifie sa forme générale."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)
    if not isinstance(config, dict):
        raise ValueError(f"La configuration YAML doit être un objet : {path}")
    unknown = set(config).difference({"window_seconds", "device_side"})
    if unknown:
        raise ValueError(
            "Clés inconnues dans la configuration : "
            + ", ".join(sorted(unknown))
        )
    return config


def build_windows(flows, window_seconds, device_side):
    """
    Agrège les flux clos dans des fenêtres de durée fixe et non chevauchantes.

    Les statistiques d'un flux Zeek ne sont disponibles qu'à sa clôture :
    elles ne sont donc utilisées qu'à partir de ts + duration. Les fenêtres
    sont ancrées sur l'époque Unix et chaque flux est affecté à une seule
    fenêtre, dont la borne de droite est inclusive. Le label d'une fenêtre
    vaut 1 dès qu'au moins un flux qu'elle contient porte le label 1.
    """
    if not np.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds doit être un nombre positif et fini.")
    if device_side not in {"orig", "resp"}:
        raise ValueError("device_side doit valoir 'orig' ou 'resp'.")

    required = {
        "ts",
        "duration",
        "capture_id",
        "src_ip",
        "dst_ip",
        "label",
    }
    missing = required.difference(flows.columns)
    if missing:
        raise ValueError(
            "Colonnes absentes du CSV de flux : " + ", ".join(sorted(missing))
        )
    if flows.empty:
        raise ValueError("Le CSV de flux ne contient aucune ligne.")

    frame = flows.copy()
    for column in ("capture_id", "src_ip", "dst_ip"):
        frame[column] = frame[column].astype("string").str.strip()
        if frame[column].isna().any() or frame[column].eq("").any():
            raise ValueError(f"La colonne {column} contient une valeur vide.")

    frame["ts"] = pd.to_numeric(frame["ts"], errors="coerce")
    frame["duration"] = pd.to_numeric(frame["duration"], errors="coerce")
    frame["label"] = pd.to_numeric(frame["label"], errors="coerce")
    for column in ("ts", "label"):
        if not np.isfinite(frame[column].to_numpy(dtype=float)).all():
            raise ValueError(f"La colonne {column} contient une valeur non finie.")
    if np.isinf(frame["duration"].to_numpy(dtype=float)).any():
        raise ValueError("La colonne duration contient une valeur infinie.")
    if frame["duration"].dropna().lt(0).any():
        raise ValueError("Une durée de flux négative est invalide.")
    if not frame["label"].isin([0, 1]).all():
        raise ValueError("Les labels doivent être binaires (0 ou 1).")

    unknown_duration = frame["duration"].isna()
    excluded_unknown_duration = int(unknown_duration.sum())
    frame = frame.loc[~unknown_duration].copy()
    if frame.empty:
        raise ValueError(
            "Aucun flux n'a une durée connue; impossible de construire "
            "des fenêtres causales."
        )

    non_feature_columns = INPUT_METADATA
    feature_columns = [
        column for column in frame.columns if column not in non_feature_columns
    ]
    non_numeric = [
        column
        for column in feature_columns
        if not pd.api.types.is_numeric_dtype(frame[column])
    ]
    if non_numeric:
        raise ValueError(
            "Les colonnes de features doivent être numériques; colonnes "
            "inattendues : " + ", ".join(non_numeric)
        )
    if not feature_columns:
        raise ValueError("Aucune feature numérique à agréger.")
    feature_values = frame[feature_columns].to_numpy(dtype=float)
    if not np.isfinite(feature_values).all():
        raise ValueError("Les features contiennent des valeurs manquantes ou infinies.")

    frame["device_id"] = frame["src_ip" if device_side == "orig" else "dst_ip"]
    frame["available_at"] = frame["ts"] + frame["duration"]
    frame["window_end"] = (
        np.ceil(frame["available_at"] / window_seconds) * window_seconds
    )
    frame["window_start"] = frame["window_end"] - window_seconds

    keys = [
        "capture_id",
        "device_id",
        "window_start",
        "window_end",
    ]
    aggregations = {
        "label": ("label", "max"),
        "flow_count": ("label", "size"),
    }
    for column in feature_columns:
        aggregations[f"sum__{column}"] = (column, "sum")
        aggregations[f"mean__{column}"] = (column, "mean")
    windows = (
        frame.groupby(keys, sort=True, as_index=False)
        .agg(**aggregations)
        .sort_values(keys, kind="stable")
        .reset_index(drop=True)
    )
    windows["label"] = windows["label"].astype("int8")
    windows["flow_count"] = windows["flow_count"].astype("int64")
    windows.attrs["excluded_unknown_duration_flows"] = excluded_unknown_duration
    return windows


def main():
    parser = argparse.ArgumentParser(
        description="Agrège les flux Zeek en fenêtres causales."
    )
    parser.add_argument(
        "features_csv",
        nargs="+",
        help="Un ou plusieurs CSV produits par preprocess_data.py",
    )
    parser.add_argument(
        "-o", "--output", required=True, help="CSV des fenêtres en sortie"
    )
    parser.add_argument(
        "--config", default=str(DEFAULT_CONFIG), help="Configuration YAML"
    )
    parser.add_argument("--window-seconds", type=float)
    parser.add_argument("--device-side", choices=("orig", "resp"))
    args = parser.parse_args()

    try:
        config_path = Path(args.config).expanduser().resolve()
        config = load_config(config_path)
        window_seconds = (
            args.window_seconds
            if args.window_seconds is not None
            else config.get("window_seconds")
        )
        device_side = args.device_side or config.get("device_side")
        if window_seconds is None or device_side is None:
            raise ValueError(
                "window_seconds et device_side doivent être définis dans "
                "la configuration ou sur la ligne de commande."
            )

        input_paths = [
            Path(path).expanduser().resolve() for path in args.features_csv
        ]
        output_path = Path(args.output).expanduser().resolve()
        input_frames = [pd.read_csv(path) for path in input_paths]
        expected_columns = list(input_frames[0].columns)
        if any(list(frame.columns) != expected_columns for frame in input_frames[1:]):
            raise ValueError(
                "Les CSV d'entrée doivent avoir le même schéma et le même ordre "
                "de colonnes."
            )
        flows = pd.concat(input_frames, ignore_index=True)
        windows = build_windows(flows, float(window_seconds), device_side)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        windows.to_csv(output_path, index=False, float_format="%.12g")
        manifest = {
            "inputs": [
                {"file": path.name, "sha256": sha256_file(path)}
                for path in input_paths
            ],
            "config_file": config_path.name,
            "config_sha256": sha256_file(config_path),
            "output_file": output_path.name,
            "output_sha256": sha256_file(output_path),
            "window_seconds": float(window_seconds),
            "device_side": device_side,
            "label_policy": "max_flow_label",
            "input_flows": int(len(flows)),
            "excluded_unknown_duration_flows": int(
                windows.attrs["excluded_unknown_duration_flows"]
            ),
            "output_windows": int(len(windows)),
            "label_counts": {
                str(label): int(count)
                for label, count in windows["label"].value_counts().sort_index().items()
            },
        }
        manifest_path = output_path.with_suffix(
            output_path.suffix + ".manifest.json"
        )
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            f"[OK] {len(windows)} fenêtres écrites dans {output_path} "
            f"(T={window_seconds:g}s, côté appareil={device_side})."
        )
        if manifest["excluded_unknown_duration_flows"]:
            print(
                "[AVERTISSEMENT] "
                f"{manifest['excluded_unknown_duration_flows']} flux exclus "
                "car leur durée est inconnue."
            )
        print(f"[OK] Manifeste : {manifest_path}")
    except (OSError, ValueError, KeyError, yaml.YAMLError) as error:
        print(f"[ERREUR] {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
