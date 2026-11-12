#!/usr/bin/env python3
"""Transforme des logs Zeek conn.log en fenêtres causales pour un IDS IoT."""

import argparse
import hashlib
import json
import logging
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.spatial import cKDTree

try:
    from .preprocess_data import engineer_features
except ImportError:
    from preprocess_data import engineer_features


LOGGER = logging.getLogger("xdids.zeek_preprocessing")
ZEEK_FIELDS = {
    "ts": "ts",
    "duration": "duration",
    "origin_ip": "id.orig_h",
    "origin_port": "id.orig_p",
    "responder_ip": "id.resp_h",
    "responder_port": "id.resp_p",
}
WINDOW_METADATA = {
    "capture_id",
    "device_id",
    "peer_ips",
    "ports_seen",
    "window_start",
    "window_end",
    "label",
    "duplicate_group_id",
    "duplicate_kind",
    "duplicate_count",
}


def configure_logging(level=logging.INFO):
    """Configure un journal lisible sur la sortie standard."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
        force=True,
    )


def load_conn_log(path):
    """Charge un conn.log TSV ou JSON-lines en conservant les valeurs brutes."""
    path = Path(path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"Fichier conn.log introuvable : {path}")

    with path.open("r", encoding="utf-8") as file:
        first_content_line = next(
            (line.strip() for line in file if line.strip()), ""
        )
    if not first_content_line:
        raise pd.errors.EmptyDataError(f"Le fichier conn.log est vide : {path}")

    if first_content_line.startswith("{"):
        frame = pd.read_json(path, lines=True, dtype=False)
    else:
        fields = None
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                if line.startswith("#fields"):
                    fields = line.rstrip("\r\n").split("\t")[1:]
                    break
        if not fields:
            raise ValueError(
                f"En-tête Zeek '#fields' absent ou vide dans {path}."
            )
        frame = pd.read_csv(
            path,
            sep="\t",
            comment="#",
            names=fields,
            dtype="string",
            na_values=["-", "(empty)", ""],
            keep_default_na=True,
            low_memory=False,
        )

    if frame.empty:
        raise pd.errors.EmptyDataError(
            f"Aucune ligne de flux trouvée dans conn.log : {path}"
        )
    return frame.replace({"-": pd.NA, "(empty)": pd.NA, "": pd.NA})


def assign_labels(frame, label=None, attacker_ips=None):
    """Attribue les labels avec une règle explicite, sans valeur par défaut."""
    if (label is None) == (not attacker_ips):
        raise ValueError(
            "Fournir exactement une stratégie de label : label global ou "
            "liste d'IP attaquantes."
        )
    if label is not None:
        if label not in (0, 1):
            raise ValueError("Le label global doit valoir 0 ou 1.")
        return pd.Series(label, index=frame.index, dtype="int8")

    required = {"id.orig_h", "id.resp_h"}
    if isinstance(attacker_ips, str):
        attacker_ips = attacker_ips.split(",")
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(
            "Champs IP nécessaires à la règle de label absents : "
            + ", ".join(sorted(missing))
        )
    attackers = {str(ip).strip() for ip in attacker_ips if str(ip).strip()}
    if not attackers:
        raise ValueError("La liste d'IP attaquantes ne peut pas être vide.")
    origin = frame["id.orig_h"].astype("string")
    responder = frame["id.resp_h"].astype("string")
    return (origin.isin(attackers) | responder.isin(attackers)).astype("int8")


def _validate_arguments(window_seconds, device_side, near_tolerance):
    """Valide les paramètres temporels et la tolérance absolue."""
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds doit être positif et fini.")
    if device_side not in {"orig", "resp"}:
        raise ValueError("device_side doit valoir 'orig' ou 'resp'.")
    if not math.isfinite(near_tolerance) or near_tolerance < 0:
        raise ValueError("near_tolerance doit être fini et positif ou nul.")


def _serialize_metadata(values):
    """Sérialise déterministement une collection de métadonnées."""
    return json.dumps(
        sorted({str(value) for value in values if pd.notna(value)}),
        ensure_ascii=False,
        separators=(",", ":"),
    )


def build_causal_windows(
    frame,
    capture_id,
    label=None,
    attacker_ips=None,
    window_seconds=60.0,
    device_side="orig",
):
    """
    Crée les fenêtres à l'instant de disponibilité ts + duration.

    Les flux dont la durée manque, est non numérique, infinie ou négative sont
    exclus. Les champs numériques manquants autres que la durée sont imputés à
    zéro par la fonction d'ingénierie existante; les IP et ports ne deviennent
    que des clés ou métadonnées de traçabilité.
    """
    _validate_arguments(window_seconds, device_side, 0.0)
    if frame.empty:
        raise pd.errors.EmptyDataError("Le DataFrame conn.log est vide.")

    required_fields = set(ZEEK_FIELDS.values()) | {
        "proto",
        "conn_state",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
    }
    missing = required_fields.difference(frame.columns)
    if missing:
        raise ValueError(
            "Champs Zeek obligatoires absents : " + ", ".join(sorted(missing))
        )
    labels = assign_labels(frame, label=label, attacker_ips=attacker_ips)
    flows = frame.copy()
    flows["ts"] = pd.to_numeric(flows["ts"], errors="coerce")
    flows["duration"] = pd.to_numeric(flows["duration"], errors="coerce")

    duration_values = flows["duration"].to_numpy(dtype=float)
    invalid_duration = (
        ~np.isfinite(duration_values) | (duration_values < 0)
    )
    invalid_timestamp = ~np.isfinite(flows["ts"].to_numpy(dtype=float))
    origin_ip = flows["id.orig_h"].astype("string").str.strip()
    responder_ip = flows["id.resp_h"].astype("string").str.strip()
    invalid_endpoint = (
        origin_ip.isna()
        | responder_ip.isna()
        | origin_ip.eq("")
        | responder_ip.eq("")
    ).to_numpy()
    excluded = {
        "invalid_duration": int(invalid_duration.sum()),
        "invalid_timestamp": int((~invalid_duration & invalid_timestamp).sum()),
        "missing_endpoint": int(
            (~invalid_duration & ~invalid_timestamp & invalid_endpoint).sum()
        ),
    }

    valid_mask = ~(invalid_duration | invalid_timestamp | invalid_endpoint)
    flows = flows.loc[valid_mask].copy()
    labels = labels.loc[valid_mask]
    origin_ip = origin_ip.loc[valid_mask]
    responder_ip = responder_ip.loc[valid_mask]
    if flows.empty:
        raise ValueError(
            "Aucun flux causal exploitable après exclusion des durées, "
            "horodatages et adresses invalides."
        )

    flows["src_ip"] = origin_ip
    flows["dst_ip"] = responder_ip
    flows["capture_id"] = str(capture_id)
    flows["label"] = labels.astype("int8")

    origin_port = flows["id.orig_p"].astype("string").fillna("")
    responder_port = flows["id.resp_p"].astype("string").fillna("")
    flows["orig_port_metadata"] = origin_port
    flows["resp_port_metadata"] = responder_port

    engineered = engineer_features(flows)
    engineered_values = engineered.to_numpy(dtype=float)
    invalid_features = ~np.isfinite(engineered_values)
    if invalid_features.any():
        counts = invalid_features.sum(axis=0)
        details = {
            column: int(count)
            for column, count in zip(engineered.columns, counts, strict=True)
            if count
        }
        LOGGER.warning(
            "Features dérivées non finies remplacées par zéro : %s",
            details,
        )
        engineered = engineered.replace([np.inf, -np.inf], np.nan).fillna(0)

    flows["available_at"] = flows["ts"] + flows["duration"]
    invalid_availability = ~np.isfinite(
        flows["available_at"].to_numpy(dtype=float)
    )
    excluded["invalid_availability"] = int(invalid_availability.sum())
    if invalid_availability.any():
        keep = ~invalid_availability
        flows = flows.loc[keep].copy()
        engineered = engineered.loc[keep].copy()
        if flows.empty:
            raise ValueError("Aucun flux ne possède un instant de disponibilité valide.")

    flows["window_end"] = (
        np.ceil(flows["available_at"] / window_seconds) * window_seconds
    )
    flows["window_start"] = flows["window_end"] - window_seconds
    flows["device_id"] = flows[
        "src_ip" if device_side == "orig" else "dst_ip"
    ]
    flows["peer_ip"] = flows[
        "dst_ip" if device_side == "orig" else "src_ip"
    ]
    for column in engineered.columns:
        flows[column] = engineered[column]

    feature_columns = list(engineered.columns)
    keys = ["capture_id", "device_id", "window_start", "window_end"]
    grouped = flows.groupby(keys, sort=True, dropna=False)
    output_rows = []
    for key_values, group in grouped:
        row = dict(zip(keys, key_values, strict=True))
        row["label"] = int(group["label"].max())
        row["flow_count"] = int(len(group))
        for column in feature_columns:
            row[f"sum__{column}"] = float(group[column].sum())
            row[f"mean__{column}"] = float(group[column].mean())
        row["peer_ips"] = _serialize_metadata(group["peer_ip"])
        row["ports_seen"] = json.dumps(
            {
                "orig": sorted(
                    {
                        value
                        for value in group["orig_port_metadata"].dropna().astype(str)
                        if value
                    }
                ),
                "resp": sorted(
                    {
                        value
                        for value in group["resp_port_metadata"].dropna().astype(str)
                        if value
                    }
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        output_rows.append(row)

    windows = pd.DataFrame(output_rows)
    windows["label"] = windows["label"].astype("int8")
    windows["flow_count"] = windows["flow_count"].astype("int64")
    return windows, excluded


def _duplicate_features(frame, feature_columns):
    """Retourne une matrice finie, normalisée pour le hash exact."""
    values = frame[feature_columns].to_numpy(dtype=np.float64)
    if not np.isfinite(values).all():
        raise ValueError("Les features de déduplication doivent être finies.")
    values[values == 0] = 0.0
    return values


def identify_and_remove_duplicates(frame, near_tolerance=0.01):
    """
    Regroupe les lignes identiques ou proches et ne conserve qu'un représentant.

    La proximité est une distance L-infinie : chaque feature numérique doit
    différer d'au plus near_tolerance (tolérance absolue commune). Les colonnes
    de métadonnées et le label sont exclus de la comparaison. Les groupes qui
    contiennent des labels contradictoires sont signalés mais ne sont pas
    fusionnés, afin de ne pas supprimer une vérité terrain différente.
    """
    if not math.isfinite(near_tolerance) or near_tolerance < 0:
        raise ValueError("near_tolerance doit être fini et positif ou nul.")
    if frame.empty:
        raise ValueError("Le DataFrame à dédupliquer est vide.")
    if "label" not in frame.columns:
        raise ValueError("La colonne label est requise pour la déduplication.")

    feature_columns = [
        column for column in frame.columns if column not in WINDOW_METADATA
    ]
    if not feature_columns:
        raise ValueError("Aucune feature numérique à comparer.")
    non_numeric = [
        column
        for column in feature_columns
        if not pd.api.types.is_numeric_dtype(frame[column])
    ]
    if non_numeric:
        raise ValueError(
            "Features non numériques pour la déduplication : "
            + ", ".join(sorted(non_numeric))
        )
    values = _duplicate_features(frame, feature_columns)
    labels = pd.to_numeric(frame["label"], errors="coerce").to_numpy()
    if not np.isfinite(labels).all() or not np.isin(labels, [0, 1]).all():
        raise ValueError("Les labels de la déduplication doivent valoir 0 ou 1.")

    tree = cKDTree(values) if near_tolerance > 0 else None
    kept_indices = []
    row_group_ids = [None] * len(frame)
    row_kinds = [None] * len(frame)
    duplicate_counts = {}
    duplicate_kinds = {}
    exact_removed = 0
    near_removed = 0
    label_conflict_rows_kept = 0

    for index, vector in enumerate(values):
        if tree is None:
            candidates = [
                candidate
                for candidate in kept_indices
                if np.array_equal(values[candidate], vector)
            ]
        else:
            candidates = [
                int(candidate)
                for candidate in tree.query_ball_point(
                    vector, r=near_tolerance, p=np.inf
                )
                if candidate < index and candidate in duplicate_counts
                and np.all(
                    np.abs(values[candidate] - vector) <= near_tolerance
                )
            ]
        candidates.sort()
        if not candidates:
            representative = index
            kept_indices.append(index)
            duplicate_counts[index] = 1
            duplicate_kinds[index] = set()
            row_group_ids[index] = hashlib.sha256(
                vector.tobytes()
            ).hexdigest()
            row_kinds[index] = "unique"
            continue

        group_representative = candidates[0]
        group_id = row_group_ids[group_representative]
        same_label = next(
            (candidate for candidate in candidates if labels[candidate] == labels[index]),
            None,
        )
        if same_label is None:
            label_conflict_rows_kept += 1
            representative = index
            kept_indices.append(index)
            duplicate_counts[index] = 1
            duplicate_kinds[index] = set()
            row_group_ids[index] = group_id
            row_kinds[index] = "label_conflict"
            continue

        representative = same_label
        row_group_ids[index] = group_id
        if np.array_equal(values[representative], vector):
            exact_removed += 1
            duplicate_counts[representative] += 1
            duplicate_kinds[representative].add("exact")
            row_kinds[index] = "exact_duplicate"
        else:
            near_removed += 1
            duplicate_counts[representative] += 1
            duplicate_kinds[representative].add("near")
            row_kinds[index] = "near_duplicate"

    result = frame.iloc[kept_indices].copy().reset_index(drop=True)
    result["duplicate_group_id"] = [
        row_group_ids[index] for index in kept_indices
    ]
    result["duplicate_kind"] = [
        (
            "+".join(sorted(duplicate_kinds[index]))
            if duplicate_kinds[index]
            else row_kinds[index]
        )
        for index in kept_indices
    ]
    result["duplicate_count"] = [
        duplicate_counts[index] for index in kept_indices
    ]
    labels_by_group = {}
    for group_id, label_value in zip(row_group_ids, labels, strict=True):
        labels_by_group.setdefault(group_id, set()).add(int(label_value))
    conflicting_groups = sum(
        len(group_labels) > 1 for group_labels in labels_by_group.values()
    )
    audit = {
        "rows_before": int(len(frame)),
        "rows_after": int(len(result)),
        "exact_duplicates_removed": exact_removed,
        "near_duplicates_removed": near_removed,
        "exact_duplicate_groups": sum(
            "exact" in kinds for kinds in duplicate_kinds.values()
        ),
        "near_duplicate_groups": sum(
            "near" in kinds for kinds in duplicate_kinds.values()
        ),
        "label_conflict_rows_kept": label_conflict_rows_kept,
        "groups_with_conflicting_labels": int(conflicting_groups),
        "near_tolerance_absolute_linf": float(near_tolerance),
        "features_compared": feature_columns,
    }
    return result, audit


def sha256_file(path):
    """Calcule le SHA-256 d'un fichier en lecture par blocs."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def process_conn_log(
    input_path,
    output_path,
    label=None,
    attacker_ips=None,
    capture_id=None,
    window_seconds=60.0,
    device_side="orig",
    near_tolerance=0.01,
):
    """Exécute ingestion, fenêtrage causal, audit et écriture des artefacts."""
    input_path = Path(input_path).expanduser().resolve()
    output_path = Path(output_path).expanduser().resolve()
    if not input_path.is_file():
        raise FileNotFoundError(f"Fichier conn.log introuvable : {input_path}")
    if not output_path.parent.exists():
        output_path.parent.mkdir(parents=True, exist_ok=True)

    capture_id = capture_id or input_path.stem
    LOGGER.info("Lecture de %s", input_path)
    source = load_conn_log(input_path)
    LOGGER.info("%d flux Zeek lus.", len(source))
    windows, exclusions = build_causal_windows(
        source,
        capture_id=capture_id,
        label=label,
        attacker_ips=attacker_ips,
        window_seconds=window_seconds,
        device_side=device_side,
    )
    LOGGER.info(
        "Fenêtres construites; exclusions: durée=%d, horodatage=%d, "
        "adresses=%d, disponibilité=%d.",
        exclusions["invalid_duration"],
        exclusions["invalid_timestamp"],
        exclusions["missing_endpoint"],
        exclusions["invalid_availability"],
    )

    cleaned, duplicate_audit = identify_and_remove_duplicates(
        windows, near_tolerance=near_tolerance
    )
    cleaned.to_csv(output_path, index=False, float_format="%.12g")
    manifest_path = output_path.with_suffix(
        output_path.suffix + ".audit.json"
    )
    manifest = {
        "input_file": str(input_path),
        "input_sha256": sha256_file(input_path),
        "output_file": str(output_path),
        "output_sha256": sha256_file(output_path),
        "capture_id": str(capture_id),
        "window_seconds": float(window_seconds),
        "device_side": device_side,
        "label_policy": (
            {"type": "attacker_ip", "attacker_ips": sorted(attacker_ips)}
            if attacker_ips
            else {"type": "global", "value": int(label)}
        ),
        "causal_availability": "ts + duration",
        "window_assignment": "left_open_right_closed_epoch_aligned",
        "label_aggregation": "max_flow_label",
        "excluded_flows": exclusions,
        "duplicate_audit": duplicate_audit,
        "metadata_columns_excluded_from_comparison": sorted(WINDOW_METADATA),
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    LOGGER.info(
        "Écriture terminée : %s (%d lignes; %d doublons supprimés).",
        output_path,
        len(cleaned),
        duplicate_audit["exact_duplicates_removed"]
        + duplicate_audit["near_duplicates_removed"],
    )
    LOGGER.info("Audit détaillé : %s", manifest_path)
    return cleaned, manifest


def main():
    """Point d'entrée de ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Prépare un conn.log Zeek en fenêtres causales IDS."
    )
    parser.add_argument("conn_log", help="Fichier conn.log Zeek TSV ou JSON-lines")
    parser.add_argument("-o", "--output", required=True, help="CSV des fenêtres")
    label_group = parser.add_mutually_exclusive_group(required=True)
    label_group.add_argument(
        "--label",
        type=int,
        choices=(0, 1),
        help="Label global : 0 normal ou 1 attaque",
    )
    label_group.add_argument(
        "--attacker-ips",
        help="Liste d'IP attaquantes séparées par des virgules",
    )
    parser.add_argument("--capture-id", help="Identifiant stable de la capture/session")
    parser.add_argument("--window-seconds", type=float, default=60.0)
    parser.add_argument("--device-side", choices=("orig", "resp"), default="orig")
    parser.add_argument(
        "--near-tolerance",
        type=float,
        default=0.01,
        help=(
            "Tolérance absolue L-infinie appliquée à chaque feature numérique "
            "(défaut : 0.01; 0 désactive les quasi-doublons)."
        ),
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    configure_logging(logging.DEBUG if args.verbose else logging.INFO)
    try:
        ips = (
            [ip.strip() for ip in args.attacker_ips.split(",") if ip.strip()]
            if args.attacker_ips is not None
            else None
        )
        process_conn_log(
            args.conn_log,
            args.output,
            label=args.label,
            attacker_ips=ips,
            capture_id=args.capture_id,
            window_seconds=args.window_seconds,
            device_side=args.device_side,
            near_tolerance=args.near_tolerance,
        )
    except FileNotFoundError as error:
        LOGGER.error("%s", error)
        return 2
    except pd.errors.EmptyDataError as error:
        LOGGER.error("Aucun enregistrement Zeek exploitable : %s", error)
        return 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        LOGGER.error("Prétraitement impossible : %s", error)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
