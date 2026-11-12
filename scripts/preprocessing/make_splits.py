#!/usr/bin/env python3
"""Produit des splits E1/E2 reproductibles sans partager les sessions E2."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import yaml


DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "configs" / "splits.yaml"
SPLITS = ("train", "validation", "test")
METADATA_COLUMNS = {
    "capture_id",
    "device_id",
    "window_start",
    "window_end",
    "label",
    "split",
    "duplicate_group_id",
}


def sha256_file(path):
    """Calcule le SHA-256 d'un fichier par blocs."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_config(path):
    """Charge et valide la configuration YAML des splits."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)
    if not isinstance(config, dict):
        raise ValueError(f"La configuration YAML doit être un objet : {path}")
    unknown = set(config).difference(
        {"protocol", "seed", "fractions", "purge_seconds"}
    )
    if unknown:
        raise ValueError(
            "Clés inconnues dans la configuration : "
            + ", ".join(sorted(unknown))
        )
    fractions = config.get("fractions")
    if not isinstance(fractions, dict) or set(fractions) != set(SPLITS):
        raise ValueError(
            "fractions doit contenir exactement train, validation et test."
        )
    fractions = {name: float(fractions[name]) for name in SPLITS}
    if any(not np.isfinite(value) or value <= 0 for value in fractions.values()):
        raise ValueError("Chaque fraction doit être positive et finie.")
    if not np.isclose(sum(fractions.values()), 1.0):
        raise ValueError("La somme des fractions doit valoir 1.")
    config["fractions"] = fractions
    return config


def _validate_windows(windows):
    """Vérifie les champs de regroupement et les intervalles des fenêtres."""
    required = {"capture_id", "window_start", "window_end", "label"}
    missing = required.difference(windows.columns)
    if missing:
        raise ValueError(
            "Colonnes absentes du CSV de fenêtres : "
            + ", ".join(sorted(missing))
        )
    if windows.empty:
        raise ValueError("Le CSV de fenêtres ne contient aucune ligne.")

    frame = windows.copy()
    frame["capture_id"] = frame["capture_id"].astype("string").str.strip()
    if frame["capture_id"].isna().any() or frame["capture_id"].eq("").any():
        raise ValueError("capture_id ne peut pas être vide.")
    for column in ("window_start", "window_end", "label"):
        frame[column] = pd.to_numeric(frame[column], errors="coerce")
        if not np.isfinite(frame[column].to_numpy(dtype=float)).all():
            raise ValueError(f"{column} contient une valeur absente ou non finie.")
    if frame["window_end"].le(frame["window_start"]).any():
        raise ValueError("Chaque fenêtre doit avoir une durée positive.")
    if not frame["label"].isin([0, 1]).all():
        raise ValueError("Les labels doivent être binaires (0 ou 1).")
    return frame


def _feature_columns(frame):
    """Retourne les colonnes de modèle, hors identifiants et labels."""
    columns = [
        column
        for column in frame.columns
        if column not in METADATA_COLUMNS
    ]
    non_numeric = [
        column
        for column in columns
        if not pd.api.types.is_numeric_dtype(frame[column])
    ]
    if non_numeric:
        raise ValueError(
            "Features non numériques inattendues : " + ", ".join(non_numeric)
        )
    if not columns:
        raise ValueError("Aucune feature numérique disponible pour le split.")
    values = frame[columns].to_numpy(dtype=float)
    if not np.isfinite(values).all():
        raise ValueError("Les features contiennent des valeurs absentes ou infinies.")
    return columns


def _add_exact_duplicate_groups(frame, feature_columns):
    """Attribue le même groupe aux vecteurs de features exactement identiques."""
    values = frame[feature_columns].to_numpy(dtype="<f8")
    frame = frame.copy()
    frame["duplicate_group_id"] = [
        hashlib.sha256(row.tobytes()).hexdigest() for row in values
    ]
    return frame


def _best_contiguous_cuts(group_sizes, fractions):
    """Choisit deux coupures contiguës proches des proportions demandées."""
    group_count = len(group_sizes)
    if group_count < 3:
        raise ValueError(
            "Il faut au moins trois groupes indépendants pour obtenir "
            "train/validation/test non vides."
        )
    cumulative = np.concatenate(([0], np.cumsum(group_sizes)))
    total = int(cumulative[-1])
    target_train = fractions["train"] * total
    target_train_validation = (
        fractions["train"] + fractions["validation"]
    ) * total
    candidates = []
    for first_cut in range(1, group_count - 1):
        for second_cut in range(first_cut + 1, group_count):
            cost = (
                (cumulative[first_cut] - target_train) ** 2
                + (cumulative[second_cut] - target_train_validation) ** 2
            )
            candidates.append((cost, first_cut, second_cut))
    _, first_cut, second_cut = min(candidates)
    return first_cut, second_cut


def _split_e1(frame, fractions, seed):
    """Répartit les groupes de doublons de façon aléatoire et stratifiée."""
    group_sizes = frame.groupby("duplicate_group_id", sort=True).size()
    groups = group_sizes.index.to_numpy(copy=True)
    if len(groups) < 3:
        raise ValueError(
            "E1 exige au moins trois groupes de fenêtres distincts pour "
            "produire trois partitions non vides."
        )
    rng = np.random.default_rng(seed)
    rng.shuffle(groups)
    group_labels = (
        frame.groupby(["duplicate_group_id", "label"], sort=True)
        .size()
        .unstack(fill_value=0)
        .reindex(columns=(0, 1), fill_value=0)
        .reindex(index=groups)
    )
    groups_per_label = group_labels.gt(0).sum(axis=0)
    group_split = {}
    assigned_counts = {
        split: np.zeros(2, dtype=float) for split in SPLITS
    }
    target_counts = {
        split: np.array(
            [
                fractions[split] * int(group_labels[label].sum())
                for label in (0, 1)
            ],
            dtype=float,
        )
        for split in SPLITS
    }

    def allocation_cost(split: str, group: str) -> float:
        projected = {
            name: counts.copy() for name, counts in assigned_counts.items()
        }
        projected[split] += group_labels.loc[group, [0, 1]].to_numpy(dtype=float)
        totals = np.array(
            [int(group_labels[label].sum()) for label in (0, 1)],
            dtype=float,
        )
        return sum(
            float(
                np.square(
                    (projected[name] - target_counts[name])
                    / np.maximum(totals, 1)
                ).sum()
            )
            for name in SPLITS
        )

    # First reserve distinct groups for every class in every partition when possible.
    if groups_per_label.ge(len(SPLITS)).all():
        for label in groups_per_label.sort_values().index:
            for split in SPLITS:
                if assigned_counts[split][int(label)] > 0:
                    continue
                candidates = [
                    group
                    for group in groups
                    if group not in group_split and group_labels.loc[group, label] > 0
                ]
                if not candidates:
                    break
                group = min(candidates, key=lambda item: allocation_cost(split, item))
                group_split[group] = split
                assigned_counts[split] += group_labels.loc[
                    group, [0, 1]
                ].to_numpy(dtype=float)

    if len(group_split) < len(SPLITS) or any(
        assigned_counts[split].sum() == 0 for split in SPLITS
    ):
        group_split.clear()
        assigned_counts = {
            split: np.zeros(2, dtype=float) for split in SPLITS
        }
        # Preserve a deterministic, unstratified split when class coverage is impossible.
        for index, group in enumerate(groups[: len(SPLITS)]):
            group_split[group] = SPLITS[index]
            assigned_counts[SPLITS[index]] += group_labels.loc[
                group, [0, 1]
            ].to_numpy(dtype=float)

    remaining_groups = [group for group in groups if group not in group_split]
    remaining_groups.sort(key=lambda group: -int(group_sizes.loc[group]))
    while remaining_groups:
        group = remaining_groups.pop(0)
        destination = min(
            SPLITS,
            key=lambda split: allocation_cost(split, group),
        )
        group_split[group] = destination
        assigned_counts[destination] += group_labels.loc[
            group, [0, 1]
        ].to_numpy(dtype=float)

    frame = frame.copy()
    frame["split"] = frame["duplicate_group_id"].map(group_split)
    return frame, {
        "purged_windows": 0,
        "sessions_per_split": None,
        "stratified_class_coverage": bool(
            all((assigned_counts[split] > 0).all() for split in SPLITS)
        ),
    }


def _split_e2(frame, fractions, seed, purge_seconds):
    """Répartit des sessions chronologiques entières et purge leurs frontières."""
    del seed  # E2 est déterministe par construction chronologique.
    sessions = (
        frame.groupby("capture_id", sort=False)
        .agg(session_start=("window_start", "min"), session_end=("window_end", "max"))
        .sort_values(["session_start", "capture_id"], kind="stable")
        .reset_index()
    )
    if len(sessions) < 3:
        raise ValueError(
            "E2 exige au moins trois capture_id (sessions) distincts; "
            f"{len(sessions)} trouvé(s)."
        )
    session_starts = sessions["session_start"].to_numpy(dtype=float)
    session_ends = sessions["session_end"].to_numpy(dtype=float)
    if np.any(session_ends[:-1] > session_starts[1:]):
        raise ValueError(
            "Les intervalles des sessions se chevauchent : un split "
            "chronologique E2 non ambigu n'est pas possible."
        )

    duplicate_sessions = (
        frame[["duplicate_group_id", "capture_id"]]
        .drop_duplicates()
        .groupby("duplicate_group_id", sort=False)["capture_id"]
        .agg(list)
    )
    session_positions = {
        capture_id: position
        for position, capture_id in enumerate(sessions["capture_id"])
    }
    intervals = []
    for captures in duplicate_sessions:
        positions = sorted({session_positions[capture] for capture in captures})
        intervals.append((positions[0], positions[-1]))
    intervals.sort()

    # Des sessions liées par un doublon exact deviennent un bloc contigu,
    # afin qu'aucun groupe identique ne soit envoyé dans plusieurs partitions.
    components = []
    current_start, current_end = intervals[0]
    for start, end in intervals[1:]:
        if start <= current_end:
            current_end = max(current_end, end)
        else:
            components.append((current_start, current_end))
            current_start, current_end = start, end
    components.append((current_start, current_end))
    component_sizes = [
        end - start + 1 for start, end in components
    ]
    first_cut, second_cut = _best_contiguous_cuts(component_sizes, fractions)

    session_split = {}
    component_ranges = (
        (0, first_cut, "train"),
        (first_cut, second_cut, "validation"),
        (second_cut, len(components), "test"),
    )
    boundaries = []
    for component_start, component_end, split_name in component_ranges:
        for start, end in components[component_start:component_end]:
            for position in range(start, end + 1):
                session_split[sessions.loc[position, "capture_id"]] = split_name
    for cut in (first_cut, second_cut):
        left_session = components[cut - 1][1]
        right_session = components[cut][0]
        boundary = (
            session_ends[left_session] + session_starts[right_session]
        ) / 2.0
        boundaries.append(boundary)

    frame = frame.copy()
    frame["split"] = frame["capture_id"].map(session_split)
    before_purge = len(frame)
    purge_mask = pd.Series(False, index=frame.index)
    for boundary in boundaries:
        purge_mask |= (
            frame["window_start"].le(boundary + purge_seconds)
            & frame["window_end"].ge(boundary - purge_seconds)
        )
    frame = frame.loc[~purge_mask].copy()
    if frame["split"].nunique() != len(SPLITS):
        raise ValueError(
            "La purge temporelle vide au moins une partition; réduisez "
            "purge_seconds ou fournissez des sessions suffisamment longues."
        )

    session_counts = {
        name: int(
            frame.loc[frame["split"].eq(name), "capture_id"].nunique()
        )
        for name in SPLITS
    }
    return frame, {
        "purged_windows": before_purge - len(frame),
        "sessions_per_split": session_counts,
    }


def make_splits(windows, protocol, fractions, seed=42, purge_seconds=None):
    """Ajoute la colonne split après groupement des fenêtres identiques."""
    frame = _validate_windows(windows)
    feature_columns = _feature_columns(frame)
    frame = _add_exact_duplicate_groups(frame, feature_columns)
    fractions = {name: float(fractions[name]) for name in SPLITS}
    if (
        any(not np.isfinite(value) or value <= 0 for value in fractions.values())
        or not np.isclose(sum(fractions.values()), 1.0)
    ):
        raise ValueError("Les fractions doivent être positives et sommer à 1.")
    if protocol == "E1":
        result, details = _split_e1(frame, fractions, seed)
    elif protocol == "E2":
        if purge_seconds is None:
            durations = frame["window_end"] - frame["window_start"]
            if not np.allclose(durations, durations.iloc[0]):
                raise ValueError(
                    "Les fenêtres n'ont pas toutes la même durée; "
                    "précisez purge_seconds explicitement."
                )
            purge_seconds = float(durations.iloc[0])
        if not np.isfinite(purge_seconds) or purge_seconds < 0:
            raise ValueError("purge_seconds doit être positif ou nul.")
        result, details = _split_e2(
            frame, fractions, seed, float(purge_seconds)
        )
    else:
        raise ValueError("protocol doit valoir E1 ou E2.")

    result = result.sort_values(
        ["window_start", "capture_id"], kind="stable"
    ).reset_index(drop=True)
    details["rows_per_split"] = {
        name: int(result["split"].eq(name).sum()) for name in SPLITS
    }
    details["duplicate_groups"] = int(result["duplicate_group_id"].nunique())
    return result, details


def main():
    parser = argparse.ArgumentParser(
        description="Produit les splits E1 aléatoire ou E2 chronologique."
    )
    parser.add_argument("windows_csv", help="CSV produit par build_windows.py")
    parser.add_argument("-o", "--output", required=True, help="CSV publié")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--protocol", choices=("E1", "E2"))
    parser.add_argument("--seed", type=int)
    parser.add_argument("--purge-seconds", type=float)
    args = parser.parse_args()

    try:
        config_path = Path(args.config).expanduser().resolve()
        config = load_config(config_path)
        protocol = args.protocol or config.get("protocol", "E2")
        seed = args.seed if args.seed is not None else int(config.get("seed", 42))
        purge_seconds = (
            args.purge_seconds
            if args.purge_seconds is not None
            else config.get("purge_seconds")
        )
        input_path = Path(args.windows_csv).expanduser().resolve()
        output_path = Path(args.output).expanduser().resolve()
        windows = pd.read_csv(input_path)
        splits, details = make_splits(
            windows,
            protocol,
            config["fractions"],
            seed=seed,
            purge_seconds=purge_seconds,
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        splits.to_csv(output_path, index=False, float_format="%.12g")
        manifest = {
            "input_file": input_path.name,
            "input_sha256": sha256_file(input_path),
            "config_file": config_path.name,
            "config_sha256": sha256_file(config_path),
            "output_file": output_path.name,
            "output_sha256": sha256_file(output_path),
            "protocol": protocol,
            "seed": seed,
            "fractions": config["fractions"],
            "purge_seconds": (
                float(purge_seconds)
                if purge_seconds is not None
                else (
                    float(windows["window_end"].iloc[0])
                    - float(windows["window_start"].iloc[0])
                    if protocol == "E2"
                    else None
                )
            ),
            **details,
        }
        manifest_path = output_path.with_suffix(
            output_path.suffix + ".manifest.json"
        )
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            f"[OK] Split {protocol}: {len(splits)} fenêtres; "
            + ", ".join(
                f"{name}={details['rows_per_split'][name]}"
                for name in SPLITS
            )
        )
        print(
            f"[OK] {details['duplicate_groups']} groupes de doublons exacts; "
            f"{details['purged_windows']} fenêtres purgées."
        )
        print(f"[OK] CSV publié : {output_path}")
        print(f"[OK] Manifeste : {manifest_path}")
    except (OSError, ValueError, KeyError, yaml.YAMLError) as error:
        print(f"[ERREUR] {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
