#!/usr/bin/env python3
"""Build the causal-window dataset and E1/E2 splits from the capture registry."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import yaml

if __package__ in (None, ""):
    REPO_ROOT = Path(__file__).resolve().parents[2]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

from scripts.extraction.run_zeek_batch import run_batch
from scripts.preprocessing.make_splits import make_splits
from scripts.preprocessing.prepare_zeek_windows import process_conn_log

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_capture_registry(path: Path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "captures" in data:
            return data["captures"]
        if "id" in data and "path" in data:
            return [data]
    raise ValueError(f"Capture registry invalid: {path}")


def _load_yaml(path: Path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"YAML invalid: {path}")
    return data


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "NON DISPONIBLE"


def _software_versions() -> dict[str, str]:
    versions = {"python": sys.version.split()[0], "pandas": pd.__version__}
    for package, distribution in (
        ("scikit_learn", "scikit-learn"),
        ("xgboost", "xgboost"),
    ):
        try:
            versions[package] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "NON DISPONIBLE"
    executable = shutil.which("zeek")
    if executable is None:
        versions["zeek"] = "NON DISPONIBLE (exécutable absent du PATH)"
    else:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        versions["zeek"] = (
            (result.stdout or result.stderr).strip()
            if result.returncode == 0
            else "NON DISPONIBLE (commande de version en échec)"
        )
    return versions


def _aggregate_audits(window_files: list[Path]) -> dict:
    excluded = {}
    duplicate = {}
    for window_file in window_files:
        audit_path = window_file.with_suffix(window_file.suffix + ".audit.json")
        if not audit_path.is_file():
            raise FileNotFoundError(f"Manifeste de fenêtre absent : {audit_path}")
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        for key, value in audit["excluded_flows"].items():
            excluded[key] = excluded.get(key, 0) + int(value)
        for key, value in audit["duplicate_audit"].items():
            if (
                key.endswith("_removed")
                or key.endswith("_rows_kept")
                or key.endswith("_groups")
                or key.startswith("groups_with_")
            ):
                duplicate[key] = duplicate.get(key, 0) + int(value)
    return {
        "capture_audit_count": len(window_files),
        "excluded_flows": excluded,
        "duplicate_audit": duplicate,
    }


def ensure_zeek_logs(config_path: Path, output_root: Path) -> None:
    manifests = run_batch(config_path, output_root)
    failed = [item for item in manifests if item.get("status") == "failed"]
    if failed:
        failures = "; ".join(
            f"{item['capture_id']}: {item['error']}" for item in failed
        )
        raise RuntimeError(f"Échecs d'extraction Zeek: {failures}")


def _resolve_capture_path(base_root: Path, captured_value: str | Path) -> Path:
    candidate = Path(captured_value).expanduser()
    if candidate.is_absolute():
        return candidate
    direct = (base_root / candidate).resolve()
    if direct.exists():
        return direct
    dataset_candidate = (base_root / "madatasets" / candidate).resolve()
    if dataset_candidate.exists():
        return dataset_candidate
    return direct


def build_windows_for_registry(
    capture_config: Path,
    output_dir: Path,
    window_seconds: float,
    device_side: str,
    near_tolerance: float,
) -> list[Path]:
    registry = load_capture_registry(capture_config)
    processed_root = Path(output_dir).expanduser().resolve()
    processed_root.mkdir(parents=True, exist_ok=True)
    windows_files: list[Path] = []
    for record in registry:
        capture_id = str(record.get("id") or record.get("capture_id") or record.get("path"))
        if not capture_id:
            raise ValueError(f"Capture sans identifiant dans le registre: {record}")
        zeek_dir = REPO_ROOT / "data" / "processed_zeek" / capture_id
        conn_log = zeek_dir / "conn.log"
        if not conn_log.exists():
            raise FileNotFoundError(f"conn.log introuvable pour {capture_id}: {conn_log}")
        window_path = processed_root / f"{capture_id}_windows.csv"
        capture_device_side = record.get("device_side", device_side)
        process_conn_log(
            conn_log,
            window_path,
            capture_id=capture_id,
            label=int(record.get("label", 0)),
            window_seconds=float(window_seconds),
            device_side=capture_device_side,
            near_tolerance=float(near_tolerance),
        )
        windows_files.append(window_path)
    return windows_files


def combine_windows(
    window_files: list[Path],
    output_path: Path,
    config_paths: tuple[Path, ...] = (),
) -> pd.DataFrame:
    frames = [pd.read_csv(path) for path in window_files]
    if not frames:
        raise ValueError("Aucune fenêtre produite, impossible de construire le dataset.")
    combined = pd.concat(frames, ignore_index=True)
    metadata_columns = {"capture_id", "device_id", "window_start", "window_end", "label", "duplicate_group_id"}
    feature_columns = [
        column for column in combined.columns
        if column not in metadata_columns
        and column not in {"peer_ips", "ports_seen", "duplicate_kind", "duplicate_count"}
        and pd.api.types.is_numeric_dtype(combined[column])
    ]
    keep_columns = list(metadata_columns) + feature_columns
    combined = combined[keep_columns].copy()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(output_path, index=False, float_format="%.12g")
    audit_summary = _aggregate_audits(window_files)
    config_hashes = {
        str(path.relative_to(REPO_ROOT)): _sha256_file(path)
        for path in config_paths
        if path.is_file()
    }
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "inputs": {
            str(path.relative_to(REPO_ROOT)): _sha256_file(path)
            for path in window_files
        },
        "output_file": str(output_path.relative_to(REPO_ROOT)),
        "output_sha256": _sha256_file(output_path),
        "window_count": int(len(combined)),
        "capture_count": int(combined["capture_id"].nunique()),
        "class_counts": {
            str(label): int(count)
            for label, count in combined["label"].value_counts().sort_index().items()
        },
        "config_sha256": config_hashes,
        "audit_summary": audit_summary,
        "software_versions": _software_versions(),
    }
    manifest_path = output_path.with_suffix(output_path.suffix + ".manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    combined.attrs["audit_summary"] = audit_summary
    return combined


def print_window_summary(frame: pd.DataFrame) -> None:
    print("[OK] Nombre de fenêtres par classe:")
    print(frame["label"].value_counts().sort_index().to_string())
    print("[OK] Nombre de fenêtres par capture:")
    print(frame.groupby("capture_id").size().sort_index().to_string())


def build_splits_and_report(frame: pd.DataFrame, config_path: Path, split_output_dir: Path) -> dict[str, pd.DataFrame]:
    config = _load_yaml(config_path)
    split_output_dir.mkdir(parents=True, exist_ok=True)
    protocols = ["E1", "E2"]
    results = {}
    for protocol in protocols:
        output_path = split_output_dir / f"{protocol}.csv"
        try:
            result, details = make_splits(
                frame,
                protocol=protocol,
                fractions={
                    "train": float(config["fractions"]["train"]),
                    "validation": float(config["fractions"]["validation"]),
                    "test": float(config["fractions"]["test"]),
                },
                seed=int(config.get("seed", 42)),
                purge_seconds=config.get("purge_seconds"),
            )
        except ValueError as error:
            if protocol != "E2":
                raise
            output_path.unlink(missing_ok=True)
            output_path.with_suffix(".csv.manifest.json").unlink(missing_ok=True)
            status = {
                "protocol": "E2",
                "status": "NON VALIDE",
                "reason": str(error),
                "window_count": int(len(frame)),
                "class_counts": {
                    str(label): int(count)
                    for label, count in frame["label"].value_counts().sort_index().items()
                },
                "input_sha256": _sha256_file(
                    REPO_ROOT / "data" / "processed_features" / "windows_all.csv"
                ),
                "config_file": str(config_path.relative_to(REPO_ROOT)),
                "config_sha256": _sha256_file(config_path),
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
            }
            status_path = split_output_dir / "E2.status.json"
            status_path.write_text(
                json.dumps(status, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            results["E2.status"] = status
            print(f"[WARN] E2 non valide : {error}")
            continue

        result.to_csv(output_path, index=False, float_format="%.12g")
        if protocol == "E2":
            (split_output_dir / "E2.status.json").unlink(missing_ok=True)
        manifest = {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "git_commit": _git_commit(),
            "protocol": protocol,
            "input_sha256": _sha256_file(
                REPO_ROOT / "data" / "processed_features" / "windows_all.csv"
            ),
            "config_file": str(config_path.relative_to(REPO_ROOT)),
            "config_sha256": _sha256_file(config_path),
            "output_file": str(output_path.relative_to(REPO_ROOT)),
            "output_sha256": _sha256_file(output_path),
            "details": details,
            "software_versions": _software_versions(),
        }
        manifest_path = output_path.with_suffix(output_path.suffix + ".manifest.json")
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        results[protocol] = result
        print(f"[OK] {protocol}: {len(result)} lignes; {details['rows_per_split']}")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the dataset and E1/E2 splits for XD-IDS.")
    parser.add_argument("--capture-config", default=str(REPO_ROOT / "configs" / "captures.yaml"), help="Capture registry YAML.")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "data" / "processed_features"), help="Directory for per-capture windows.")
    parser.add_argument("--windows-output", default=str(REPO_ROOT / "data" / "processed_features" / "windows_all.csv"), help="Combined windows CSV.")
    parser.add_argument("--splits-dir", default=str(REPO_ROOT / "splits"), help="Where to write E1 and E2 CSVs.")
    parser.add_argument("--window-seconds", type=float, default=60.0, help="Window duration in seconds.")
    parser.add_argument("--device-side", choices=("orig", "resp"), default="orig")
    parser.add_argument("--near-tolerance", type=float, default=0.01)
    parser.add_argument("--splits-config", default=str(REPO_ROOT / "configs" / "splits.yaml"), help="Split configuration YAML.")
    args = parser.parse_args()

    config_path = Path(args.capture_config).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    windows_output = Path(args.windows_output).expanduser().resolve()
    splits_dir = Path(args.splits_dir).expanduser().resolve()
    split_config = Path(args.splits_config).expanduser().resolve()

    try:
        ensure_zeek_logs(config_path, REPO_ROOT / "data" / "processed_zeek")
        windows_files = build_windows_for_registry(
            config_path,
            output_dir,
            args.window_seconds,
            args.device_side,
            args.near_tolerance,
        )
        combined = combine_windows(
            windows_files,
            windows_output,
            config_paths=(
                config_path,
                REPO_ROOT / "configs" / "windows.yaml",
                split_config,
            ),
        )
        print_window_summary(combined)
        audit_summary = combined.attrs["audit_summary"]
        print(f"[OK] Flux exclus (durée/horodatage/endpoint) : {audit_summary['excluded_flows']}")
        print(f"[OK] Audit doublons/labels : {audit_summary['duplicate_audit']}")
        results = build_splits_and_report(combined, split_config, splits_dir)
        e2_valid = "E2" in results and "E2.status" not in results
        print(f"[OK] E2 valid: {e2_valid}")
        print(f"[OK] Windows all: {windows_output}")
        print(f"[OK] Splits: {splits_dir}")
        return 0
    except Exception as exc:
        print(f"[ERREUR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
