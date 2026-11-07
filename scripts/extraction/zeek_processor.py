#!/usr/bin/env python3
"""
Zeek PCAP Processor
-------------------
Automatise l'extraction des logs réseau à partir de fichiers PCAP/PCAPNG.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def calculate_sha256(file_path):
    """Calcule l'empreinte SHA256 du fichier PCAP."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_zeek_version():
    """Récupère la version de Zeek."""
    result = subprocess.run(
        ["zeek", "--version"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        raise RuntimeError("Impossible de récupérer la version de Zeek.")
    return (result.stdout or result.stderr).strip()


def process_pcap(pcap_path, output_root, timeout=None):
    """Exécute Zeek et organise les logs générés."""
    pcap_path = Path(pcap_path).expanduser().resolve()
    output_root = Path(output_root).expanduser().resolve()

    if not pcap_path.exists() or not pcap_path.is_file():
        raise FileNotFoundError(f"Fichier introuvable : {pcap_path}")

    if pcap_path.suffix.lower() not in (".pcap", ".pcapng"):
        raise ValueError("Le fichier doit être au format .pcap ou .pcapng.")

    zeek_executable = shutil.which("zeek")
    if zeek_executable is None:
        raise RuntimeError("Zeek n'est pas installé ou n'est pas accessible dans PATH.")

    output_root.mkdir(parents=True, exist_ok=True)
    output_dir = output_root / pcap_path.stem
    counter = 1

    while output_dir.exists():
        output_dir = output_root / f"{pcap_path.stem}_{counter}"
        counter += 1

    output_dir.mkdir(parents=True)

    print("\n========== ZEEK PCAP PROCESSOR ==========")
    print(f"[INFO] Capture : {pcap_path}")
    print(f"[INFO] Sortie  : {output_dir}")

    zeek_version = get_zeek_version()
    pcap_hash = calculate_sha256(pcap_path)

    print(f"[INFO] Version Zeek : {zeek_version}")
    print(f"[INFO] SHA256 : {pcap_hash}")
    print("\n[INFO] Analyse de la capture en cours...")

    start_time = datetime.now(timezone.utc)

    try:
        result = subprocess.run(
            [zeek_executable, "-r", str(pcap_path)],
            cwd=output_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Temps limite dépassé ({timeout} secondes).")

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()

    if result.returncode != 0:
        print("\n[ERREUR] Zeek n'a pas terminé correctement.")
        print(result.stderr)
        raise RuntimeError(f"Échec de Zeek. Code de retour : {result.returncode}")

    log_files = sorted(output_dir.glob("*.log"))
    if not log_files:
        raise RuntimeError("Aucun fichier .log généré.")

    log_information = []
    print("\n========== LOGS GÉNÉRÉS ==========")
    for log_file in log_files:
        size = log_file.stat().st_size
        log_information.append({"filename": log_file.name, "size_bytes": size})
        print(f"[OK] {log_file.name:<20} {size:>10} bytes")

    manifest = {
        "input_file": str(pcap_path),
        "sha256": pcap_hash,
        "zeek_version": zeek_version,
        "start_time_utc": start_time.isoformat(),
        "end_time_utc": end_time.isoformat(),
        "processing_time_seconds": duration,
        "return_code": result.returncode,
        "logs": log_information
    }

    manifest_path = output_dir / "processing_metadata.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=4, ensure_ascii=False)

    print("\n========== RÉSULTAT ==========")
    print(f"[SUCCESS] Analyse terminée.")
    print(f"[INFO] Durée : {duration:.3f} secondes")
    print(f"[INFO] Nombre de logs : {len(log_files)}")
    print(f"[INFO] Dossier : {output_dir}")
    print(f"[INFO] Métadonnées : {manifest_path}")

    return output_dir


def main():
    parser = argparse.ArgumentParser(description="Automatisation de l'extraction Zeek.")
    parser.add_argument("pcap", help="Chemin du fichier .pcap ou .pcapng")
    parser.add_argument("-o", "--output", default="~/XD-IDS_Project/data/processed_zeek", help="Dossier de sortie")
    parser.add_argument("--timeout", type=int, default=None, help="Timeout en secondes")

    args = parser.parse_args()
    try:
        process_pcap(args.pcap, args.output, args.timeout)
    except Exception as error:
        print(f"\n[ERREUR] {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
