#!/usr/bin/env python3
"""Train E1 and train E2 only when its class coverage permits binary learning."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _train(protocol: str, split_path: Path, config_path: Path, output_dir: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "models" / "train_zeek.py"),
            str(split_path),
            "--protocol",
            protocol,
            "--config",
            str(config_path),
            "--output-dir",
            str(output_dir),
        ],
        cwd=REPO_ROOT,
        check=True,
    )


def _class_counts(frame: pd.DataFrame) -> dict[str, dict[int, int]]:
    return {
        split: {
            label: int(
                ((frame["split"] == split) & (pd.to_numeric(frame["label"]) == label)).sum()
            )
            for label in (0, 1)
        }
        for split in ("train", "validation", "test")
    }


def _missing_class_splits(counts: dict[str, dict[int, int]]) -> list[str]:
    return [
        split
        for split, labels in counts.items()
        if any(labels[label] == 0 for label in (0, 1))
    ]


def _write_status(
    path: Path,
    protocol: str,
    status: str,
    reason: str,
    counts: dict[str, dict[int, int]],
    split_path: Path,
    config_path: Path,
) -> dict:
    record = {
        "protocol": protocol,
        "status": status,
        "reason": reason,
        "class_counts": counts,
        "split_sha256": _sha256(split_path),
        "config_sha256": _sha256(config_path),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return record


def train_phase1(splits_dir: Path, config_path: Path, results_dir: Path) -> dict:
    e1_path = splits_dir / "E1.csv"
    e2_path = splits_dir / "E2.csv"
    if not e1_path.is_file():
        raise FileNotFoundError(f"Split E1 introuvable : {e1_path}")
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration modèles introuvable : {config_path}")

    e1 = pd.read_csv(e1_path)
    e1_counts = _class_counts(e1)
    e1_status_path = results_dir / "E1" / "status.json"
    e1_missing = _missing_class_splits(e1_counts)
    if e1_missing:
        e1_status = _write_status(
            e1_status_path,
            "E1",
            "not_run_invalid_class_coverage",
            "E1 non valide pour l'évaluation binaire: partitions sans les deux "
            f"classes: {', '.join(e1_missing)}. Aucun score n'est calculé.",
            e1_counts,
            e1_path,
            config_path,
        )
        print(f"[NON VALIDE] {e1_status['reason']}", file=sys.stderr)
    else:
        _train("E1", e1_path, config_path, results_dir / "E1")
        e1_status_path.unlink(missing_ok=True)

    e2_status_path = results_dir / "E2" / "status.json"
    if not e2_path.is_file():
        split_status_path = splits_dir / "E2.status.json"
        split_status = (
            json.loads(split_status_path.read_text(encoding="utf-8"))
            if split_status_path.is_file()
            else {}
        )
        reason = split_status.get(
            "reason",
            "E2 non valide : le CSV E2 n'a pas été produit par make_splits.",
        )
        status = _write_status(
            e2_status_path,
            "E2",
            "not_run_invalid_split",
            reason,
            split_status.get("class_counts", {}),
            splits_dir / "E2.status.json"
            if split_status_path.is_file()
            else e1_path,
            config_path,
        )
        status["split_sha256"] = "NON DISPONIBLE (aucun split E2 valide produit)"
        status["windows_sha256"] = split_status.get("input_sha256", "NON DISPONIBLE")
        e2_status_path.write_text(
            json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"[NON VALIDE] {reason}", file=sys.stderr)
        return {"E1": {"status": "invalid" if e1_missing else "trained"}, "E2": status}

    e2 = pd.read_csv(e2_path)
    split_counts = _class_counts(e2)
    missing_coverage = _missing_class_splits(split_counts)
    if missing_coverage:
        reason = (
            "E2 non valide pour l'entraînement binaire: les partitions "
            + ", ".join(missing_coverage)
            + " ne contiennent pas les deux classes. Aucun score E2 n'est calculé."
        )
        e2_status = _write_status(
            e2_status_path,
            "E2",
            "not_run_invalid_class_coverage",
            reason,
            split_counts,
            e2_path,
            config_path,
        )
        print(f"[NON VALIDE] {reason}", file=sys.stderr)
        return {"E1": {"status": "invalid" if e1_missing else "trained"}, "E2": e2_status}

    _train("E2", e2_path, config_path, results_dir / "E2")
    e2_status_path.unlink(missing_ok=True)
    return {
        "E1": {"status": "invalid" if e1_missing else "trained"},
        "E2": {"status": "trained", "class_counts": split_counts},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Entraîne les protocoles E1 et E2 admissibles.")
    parser.add_argument("--splits-dir", default=str(REPO_ROOT / "splits"))
    parser.add_argument("--config", default=str(REPO_ROOT / "configs" / "models.yaml"))
    parser.add_argument("--results-dir", default=str(REPO_ROOT / "results" / "phase_b"))
    args = parser.parse_args()
    try:
        status = train_phase1(
            Path(args.splits_dir).expanduser().resolve(),
            Path(args.config).expanduser().resolve(),
            Path(args.results_dir).expanduser().resolve(),
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"[ERREUR] Échec entraînement Phase 1 : {error}", file=sys.stderr)
        return 2
    print(
        f"[OK] Statuts : E1={status['E1']['status']}, "
        f"E2={status['E2']['status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
