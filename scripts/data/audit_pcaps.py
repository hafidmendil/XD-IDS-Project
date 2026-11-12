#!/usr/bin/env python3
"""Audit PCAP files and derive a deduplicated capture registry."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Iterable
from datetime import datetime, timezone

import pandas as pd
import yaml
from scapy.all import PcapReader

REPO_ROOT = Path(__file__).resolve().parents[2]


def sha256_file(path: Path) -> str:
    """Compute the SHA-256 digest of a file."""
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
    versions = {"python": sys.version.split()[0]}
    for package, distribution in (
        ("pandas", "pandas"),
        ("scikit_learn", "scikit-learn"),
        ("xgboost", "xgboost"),
        ("zeek", None),
    ):
        if distribution:
            try:
                versions[package] = importlib.metadata.version(distribution)
            except importlib.metadata.PackageNotFoundError:
                versions[package] = "NON DISPONIBLE"
        else:
            executable = shutil.which("zeek")
            if executable is None:
                versions[package] = "NON DISPONIBLE (exécutable absent du PATH)"
            else:
                result = subprocess.run(
                    [executable, "--version"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                versions[package] = (
                    (result.stdout or result.stderr).strip()
                    if result.returncode == 0
                    else "NON DISPONIBLE (commande de version en échec)"
                )
    return versions


def iter_pcap_files(root: Path) -> list[Path]:
    """Return all .pcap and .pcapng files under root, sorted deterministically."""
    if not root.exists():
        raise FileNotFoundError(f"Répertoire introuvable : {root}")
    candidates = [
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}
    ]
    return sorted(candidates, key=lambda item: str(item.relative_to(root)))


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return math.nan


def read_pcap_window(path: Path) -> tuple[int, float, float]:
    """Return packet_count, t_min and t_max for a PCAP file."""
    packet_count = 0
    t_min = math.inf
    t_max = -math.inf
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                packet_count += 1
                timestamp = _safe_float(getattr(packet, "time", math.nan))
                if not math.isfinite(timestamp):
                    continue
                t_min = min(t_min, timestamp)
                t_max = max(t_max, timestamp)
    except Exception as exc:  # pragma: no cover - depends on libpcap support
        raise ValueError(f"Impossible d'ouvrir le PCAP {path}: {exc}") from exc

    if packet_count == 0:
        return 0, math.nan, math.nan
    return packet_count, float(t_min), float(t_max)


def audit_pcap_directory(root: Path) -> pd.DataFrame:
    """Audit a directory containing pcap files and return metadata rows."""
    rows: list[dict[str, object]] = []
    for path in iter_pcap_files(root):
        packet_count, t_min, t_max = read_pcap_window(path)
        rows.append(
            {
                "capture_id": path.stem,
                "relative_path": str(path.relative_to(root)),
                "file_name": path.name,
                "sha256": sha256_file(path),
                "file_size_bytes": int(path.stat().st_size),
                "packet_count": int(packet_count),
                "t_min": float(t_min) if math.isfinite(t_min) else math.nan,
                "t_max": float(t_max) if math.isfinite(t_max) else math.nan,
                "dataset": root.name,
            }
        )
    frame = pd.DataFrame(rows)
    if frame.empty:
        raise ValueError(f"Aucun PCAP trouvé sous {root}.")
    return frame.sort_values(["file_size_bytes", "file_name"], kind="stable").reset_index(drop=True)


def infer_label(file_name: str) -> int:
    """Heuristic label assignment from file names. Keep conservative and explicit."""
    lowered = file_name.lower()
    if "normal" in lowered:
        return 0
    if lowered.startswith("0day") or lowered.startswith("mirai"):
        return 1
    if any(token in lowered for token in [
        "attack",
        "ddos",
        "scan",
        "infilter",
        "webattack",
        "hydra",
        "blackenergy",
        "zeus",
        "replay",
        "ruby",
        "backdoor",
        "rmi",
        "ftp",
        "ssh",
        "smtp",
        "tomcat",
        "vsftpd",
        "netbios",
        "unreal",
    ]):
        return 1
    return 1


def flag_duplicates(frame: pd.DataFrame) -> pd.DataFrame:
    """Mark exact file duplicates using SHA-256; similar sizes are not proof."""
    work = frame.copy()
    work["duplicate_kind"] = "unique"
    work["duplicate_of"] = ""
    work["is_duplicate"] = False

    for _, group in work.groupby("sha256", sort=False):
        if len(group) > 1:
            canonical = group.sort_values("file_name", kind="stable").iloc[0]
            for _, row in group.iterrows():
                if row["file_name"] != canonical["file_name"]:
                    work.loc[row.name, "duplicate_kind"] = "exact_duplicate"
                    work.loc[row.name, "duplicate_of"] = canonical["file_name"]
                    work.loc[row.name, "is_duplicate"] = True

    work["capture_id"] = work["file_name"].str.replace("\\.pcap$|\\.pcapng$", "", regex=True)
    work["label"] = work["file_name"].map(infer_label)
    return work


def build_capture_registry(frame: pd.DataFrame) -> list[dict[str, object]]:
    """Convert the deduplicated metadata into the canonical capture registry."""
    retained = frame.loc[~frame["is_duplicate"]].copy().sort_values("file_name", kind="stable")
    records: list[dict[str, object]] = []
    for _, row in retained.iterrows():
        stem = Path(row["relative_path"]).stem
        records.append(
            {
                "id": stem,
                "dataset": row["dataset"],
                "path": str(Path(row["relative_path"])),
                "label": int(infer_label(str(row["file_name"]))),
                "device_side": "orig",
                "role": "source",
                "session": f"{row['dataset']}-{stem}",
                "topology_status": "à valider — topologie non documentée",
                "capture_id": stem,
                "sha256": str(row["sha256"]),
                "file_size_bytes": int(row["file_size_bytes"]),
                "packet_count": int(row["packet_count"]),
                "t_min": float(row["t_min"]) if pd.notna(row["t_min"]) else None,
                "t_max": float(row["t_max"]) if pd.notna(row["t_max"]) else None,
            }
        )
    return records


def write_capture_csv(frame: pd.DataFrame, output_path: Path) -> None:
    """Write metadata for every audited file, including exact duplicates."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    audited = frame.copy()
    audited = audited[
        [
            "capture_id",
            "relative_path",
            "file_name",
            "sha256",
            "file_size_bytes",
            "packet_count",
            "t_min",
            "t_max",
            "dataset",
            "label",
            "duplicate_kind",
            "duplicate_of",
            "is_duplicate",
        ]
    ]
    audited = audited.sort_values("capture_id", kind="stable").reset_index(drop=True)
    audited.to_csv(output_path, index=False)


def write_capture_yaml(registry: Iterable[dict[str, object]], output_path: Path) -> None:
    """Write the deduplicated capture registry as YAML."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"captures": list(registry)}
    output_path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_dataset_card(root: Path, csv_path: Path, config_path: Path, output_path: Path) -> None:
    """Write a short markdown data card for the audited dataset."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame = pd.read_csv(csv_path)
    retained = frame.loc[~frame["is_duplicate"]]
    excluded = frame.loc[frame["is_duplicate"]]
    normal_count = int((frame["label"] == 0).sum())
    attack_count = int((frame["label"] == 1).sum())
    dup_count = int(frame["is_duplicate"].sum())
    lines = [
        "# Data Card — madatasets",
        "",
        "## Scope",
        f"- Source directory: `{root}`",
        f"- PCAP files audited: {len(frame)}",
        f"- Canonical PCAP captures retained: {len(retained)}",
        f"- Working normal labels: {normal_count}",
        f"- Working attack labels: {attack_count}",
        f"- Exact duplicate files excluded from canonical registry: {dup_count}",
        "",
        "## Provenance and validity",
        "- Provenance is not fully documented in the repository; the dataset is treated as a local working corpus only.",
        "- The audit script records SHA-256, file size, packet count, and time range for every PCAP, including excluded exact duplicates.",
        "- Only byte-identical SHA-256 matches are excluded. Similar sizes or packet counts alone are not considered proof of a duplicate.",
        "",
        "## Canonical registry",
        "- Registry file: `" + str(config_path.relative_to(REPO_ROOT)) + "`",
        "- Metadata file: `" + str(csv_path.relative_to(REPO_ROOT)) + "`",
        "",
        "## Notes",
        "- `device_side` is set to `orig` as a provisional assumption because the capture topology is not documented; validate before scientific evaluation.",
        "- Labels are derived from file names and therefore remain a working assumption until the capture provenance is verified.",
        "",
        "## Canonical captures retained",
    ]
    for _, row in retained.sort_values("capture_id", kind="stable").iterrows():
        lines.append(
            f"- `{row['capture_id']}` — label={int(row['label'])}; "
            f"packets={int(row['packet_count'])}; t_min={row['t_min']}; t_max={row['t_max']}"
        )
    lines.extend(["", "## Fichiers exclus (doublons exacts)"])
    if excluded.empty:
        lines.append("- Aucun doublon exact détecté.")
    for _, row in excluded.sort_values("capture_id", kind="stable").iterrows():
        lines.append(f"- `{row['file_name']}` — doublon exact de `{row['duplicate_of']}`.")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit PCAP files and publish a deduplicated capture registry.")
    parser.add_argument("root", nargs="?", default=str(REPO_ROOT / "madatasets"), help="Root directory containing PCAP files.")
    parser.add_argument("--csv-output", default=str(REPO_ROOT / "data" / "metadata" / "captures.csv"), help="CSV metadata output path.")
    parser.add_argument("--config-output", default=str(REPO_ROOT / "configs" / "captures.yaml"), help="YAML registry output path.")
    parser.add_argument("--docs-output", default=str(REPO_ROOT / "docs" / "data_card_madatasets.md"), help="Dataset card output path.")
    args = parser.parse_args()

    root = Path(args.root).expanduser().resolve()
    csv_path = Path(args.csv_output).expanduser().resolve()
    yaml_path = Path(args.config_output).expanduser().resolve()
    docs_path = Path(args.docs_output).expanduser().resolve()

    inventory = audit_pcap_directory(root)
    flagged = flag_duplicates(inventory)
    write_capture_csv(flagged, csv_path)

    registry = build_capture_registry(flagged)
    write_capture_yaml(registry, yaml_path)
    write_dataset_card(root, csv_path, yaml_path, docs_path)
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "inputs": {
            str(root / relative_path): digest
            for relative_path, digest in zip(
                flagged["relative_path"], flagged["sha256"], strict=True
            )
        },
        "outputs": {
            str(path.relative_to(REPO_ROOT)): sha256_file(path)
            for path in (csv_path, yaml_path, docs_path)
        },
        "output_count": int(len(flagged)),
        "canonical_capture_count": int(len(registry)),
        "exact_duplicates_excluded": int(flagged["is_duplicate"].sum()),
        "software_versions": _software_versions(),
    }
    manifest_path = csv_path.with_suffix(".manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"[OK] Audited {len(flagged)} PCAP files under {root}; "
        f"retained={len(registry)}, exact_duplicates={int(flagged['is_duplicate'].sum())}"
    )
    print(f"[OK] CSV written to {csv_path}")
    print(f"[OK] YAML registry written to {yaml_path}")
    print(f"[OK] Dataset card written to {docs_path}")
    print(f"[OK] Audit manifest written to {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
