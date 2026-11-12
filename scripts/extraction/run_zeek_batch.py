#!/usr/bin/env python3
"""Run Zeek over a capture registry and save one log set per capture."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_capture_registry(path: Path):
    """Load a YAML capture registry.

    Accepts either a list of captures or a mapping with a top-level `captures` key.
    """
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        captures = data.get("captures")
        if captures is not None:
            return captures
        if "id" in data and "path" in data:
            return [data]
    raise ValueError(f"Capture registry invalid: {path}")


def _expand_capture_path(base_root: Path, value: str | Path) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_absolute():
        return candidate
    direct = (base_root / candidate).resolve()
    if direct.exists():
        return direct
    dataset_candidate = (base_root / "madatasets" / candidate).resolve()
    if dataset_candidate.exists():
        return dataset_candidate
    return direct


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_zeek_version(zeek_bin: str) -> str:
    result = subprocess.run(
        [zeek_bin, "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"Impossible de lire la version de Zeek: {result.stderr.strip()}"
        )
    return (result.stdout or result.stderr).strip()


def run_zeek_capture(
    pcap_path: Path,
    output_dir: Path,
    timeout: int | None = None,
    zeek_bin: str | None = None,
    zeek_version: str | None = None,
) -> dict:
    """Run Zeek on a single pcap and return a manifest record."""
    zeek_bin = zeek_bin or shutil.which("zeek")
    if zeek_bin is None:
        raise RuntimeError(
            "Zeek n'est pas installé ou n'est pas dans PATH. "
            "Commande d'installation : sudo apt-get update && sudo apt-get install -y zeek"
        )
    zeek_version = zeek_version or get_zeek_version(zeek_bin)
    input_sha256 = sha256_file(pcap_path)
    manifest_path = output_dir / "processing_metadata.json"
    if manifest_path.is_file():
        previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        existing_logs = [
            output_dir / (entry["file"] if isinstance(entry, dict) else entry)
            for entry in previous.get("logs", [])
        ]
        if (
            previous.get("input_sha256") == input_sha256
            and previous.get("zeek_version") == zeek_version
            and existing_logs
            and all(path.is_file() for path in existing_logs)
        ):
            return {**previous, "status": "ignored_unchanged"}

    output_dir.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc)
    result = subprocess.run(
        [zeek_bin, "-r", str(pcap_path)],
        cwd=str(output_dir),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    finished_at = datetime.now(timezone.utc)
    logs = sorted(output_dir.glob("*.log"))
    if result.returncode != 0:
        raise RuntimeError(
            f"Zeek a échoué pour {pcap_path}: {result.stderr.strip() or result.stdout.strip()}"
        )
    if not logs:
        raise RuntimeError(f"Aucun log Zeek généré pour {pcap_path}")
    manifest = {
        "status": "ok",
        "capture_id": output_dir.name,
        "pcap_path": str(pcap_path),
        "input_sha256": input_sha256,
        "zeek_version": zeek_version,
        "output_dir": str(output_dir),
        "started_at_utc": started_at.isoformat(),
        "finished_at_utc": finished_at.isoformat(),
        "return_code": result.returncode,
        "logs": [
            {"file": path.name, "sha256": sha256_file(path)}
            for path in logs
        ],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def run_batch(config_path: Path, output_root: Path, timeout: int | None = None) -> list[dict]:
    """Run Zeek on every capture declared in the registry."""
    registry = load_capture_registry(config_path)
    if not registry:
        raise ValueError(f"Aucune capture trouvée dans {config_path}")
    base_root = config_path.parent.parent
    zeek_bin = shutil.which("zeek")
    if zeek_bin is None:
        raise RuntimeError(
            "Zeek n'est pas installé ou n'est pas dans PATH. "
            "Commande d'installation : sudo apt-get update && sudo apt-get install -y zeek"
        )
    zeek_version = get_zeek_version(zeek_bin)
    manifests: list[dict] = []
    for entry in registry:
        capture_id = str(entry.get("id") or entry.get("capture_id") or entry.get("path")).strip()
        pcap_rel = entry.get("path") or entry.get("file_name") or entry.get("pcap")
        if pcap_rel is None:
            raise ValueError(f"Capture sans chemin PCAP dans la config : {entry}")
        pcap_path = _expand_capture_path(base_root, pcap_rel)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP introuvable pour {capture_id}: {pcap_path}")
        output_dir = output_root / capture_id
        try:
            manifests.append(
                run_zeek_capture(
                    pcap_path,
                    output_dir,
                    timeout=timeout,
                    zeek_bin=zeek_bin,
                    zeek_version=zeek_version,
                )
            )
        except Exception as error:
            manifests.append(
                {
                    "capture_id": capture_id,
                    "pcap_path": str(pcap_path),
                    "output_dir": str(output_dir),
                    "status": "failed",
                    "error": str(error),
                }
            )
    return manifests


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Zeek against every PCAP declared in a capture registry.")
    parser.add_argument(
        "--config",
        default=str(REPO_ROOT / "configs" / "captures.yaml"),
        help="Path to the YAML capture registry.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPO_ROOT / "data" / "processed_zeek"),
        help="Directory where Zeek outputs are stored.",
    )
    parser.add_argument("--timeout", type=int, default=None, help="Timeout in seconds for each Zeek run.")
    args = parser.parse_args()

    config_path = Path(args.config).expanduser().resolve()
    output_root = Path(args.output_dir).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    try:
        manifests = run_batch(config_path, output_root, timeout=args.timeout)
    except Exception as exc:
        print(f"[ERREUR] {exc}", file=sys.stderr)
        return 2

    succeeded = sum(item.get("status") == "ok" for item in manifests)
    skipped = sum(item.get("status") == "ignored_unchanged" for item in manifests)
    failed = sum(item.get("status") == "failed" for item in manifests)
    print(
        f"[OK] Résumé Zeek : OK={succeeded}, ignorées inchangées={skipped}, "
        f"KO={failed}, total={len(manifests)}"
    )
    for manifest in manifests:
        print(
            f"  - {manifest['capture_id']}: {manifest['status']} -> "
            f"{manifest['output_dir']}"
            + (f" ({manifest['error']})" if manifest.get("error") else "")
        )
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
