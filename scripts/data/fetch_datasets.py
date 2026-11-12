#!/usr/bin/env python3
"""Fetch only explicitly configured dataset files and verify their SHA-256."""

from __future__ import annotations

import argparse
import hashlib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_datasets(config_path: Path) -> list[dict]:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("datasets"), list):
        raise ValueError(f"Registre datasets invalide : {config_path}")
    return config["datasets"]


def _validate_direct_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ValueError("download_url doit être une URL HTTP(S) directe.")


def _download(url: str, destination: Path, expected_sha256: str) -> str:
    _validate_direct_url(url)
    if len(expected_sha256) != 64 or any(
        character not in "0123456789abcdefABCDEF" for character in expected_sha256
    ):
        raise ValueError("Un SHA-256 attendu valide est obligatoire avant téléchargement.")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = destination.with_name(destination.name + ".part")
    digest = hashlib.sha256()
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "XD-IDS dataset fetcher/1.0"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            with temporary_path.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
                    digest.update(chunk)
        actual = digest.hexdigest()
        if actual.lower() != expected_sha256.lower():
            raise ValueError(
                f"SHA-256 mismatch for {url}: expected {expected_sha256}, got {actual}"
            )
        temporary_path.replace(destination)
        return actual
    except (OSError, urllib.error.URLError, ValueError):
        temporary_path.unlink(missing_ok=True)
        raise


def write_manual_guide(datasets: list[dict], output_path: Path) -> None:
    lines = [
        "# Guide de téléchargement manuel",
        "",
        "Aucun fichier n'est téléchargé depuis une page d'information ou une source "
        "qui demande une authentification. Pour chaque entrée sans `download_url` "
        "direct et SHA-256 attendu, télécharger depuis le site source manuellement, "
        "vérifier licence/annotations, puis renseigner l'URL directe et le checksum "
        "dans `configs/datasets.yaml` avant de relancer le script.",
        "",
        "## Étapes",
        "",
        "1. Ouvrir la page source et vérifier les droits/licence.",
        "2. Télécharger le PCAP et son fichier d'annotations/manifeste sans "
        "renommer les originaux.",
        "3. Vérifier la correspondance label-capture dans la documentation de la "
        "version téléchargée.",
        "4. Calculer `sha256sum <fichier>` et enregistrer l'URL/version/checksum.",
        "5. Ajouter uniquement une URL de fichier directe et le checksum attendu "
        "dans le registre.",
        "6. Relancer `python scripts/data/fetch_datasets.py --dataset <id>`; "
        "un checksum différent empêche la publication du fichier.",
        "",
    ]
    for dataset in datasets:
        dataset_id = dataset.get("id", "ID NON DISPONIBLE")
        source = dataset.get("source_url", "NON DISPONIBLE")
        if not dataset.get("download_url") or not dataset.get("sha256"):
            lines.extend(
                [
                    f"## {dataset_id}",
                    f"- Source : {source}",
                    f"- Accès : {dataset.get('access', {}).get('details', 'NON DISPONIBLE')}",
                    "- Blocage : URL directe ou SHA-256 attendu NON DISPONIBLE.",
                    "- Après téléchargement, vérifier la licence, conserver le manifeste "
                    "source, calculer le SHA-256 et documenter le label/topologie.",
                    "",
                ]
            )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")


def fetch_datasets(
    datasets: list[dict],
    dataset_ids: set[str] | None,
    output_root: Path,
) -> tuple[list[dict], list[dict]]:
    succeeded = []
    skipped = []
    for dataset in datasets:
        dataset_id = str(dataset.get("id", ""))
        if dataset_ids is not None and dataset_id not in dataset_ids:
            continue
        url = dataset.get("download_url")
        expected = dataset.get("sha256")
        if not url or not expected:
            skipped.append(
                {
                    "dataset": dataset_id,
                    "reason": "download_url directe ou SHA-256 attendu NON DISPONIBLE",
                }
            )
            continue
        filename = dataset.get("download_filename") or Path(
            urllib.parse.urlparse(str(url)).path
        ).name
        if not filename or filename in {".", ".."}:
            raise ValueError(f"Nom de fichier de téléchargement invalide pour {dataset_id}")
        destination = output_root / dataset_id / filename
        digest = _download(str(url), destination, str(expected))
        succeeded.append(
            {
                "dataset": dataset_id,
                "path": str(destination),
                "sha256": digest,
            }
        )
    return succeeded, skipped


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Télécharge seulement des URL directes préconfigurées et vérifie leur SHA-256."
    )
    parser.add_argument(
        "--config",
        default=str(REPO_ROOT / "configs" / "datasets.yaml"),
        help="Registre de datasets.",
    )
    parser.add_argument("--dataset", action="append", help="ID de dataset (répétable).")
    parser.add_argument(
        "--output-dir",
        default=str(REPO_ROOT / "data" / "raw_datasets"),
        help="Dossier de réception des fichiers vérifiés.",
    )
    parser.add_argument(
        "--manual-guide",
        default=str(REPO_ROOT / "docs" / "datasets" / "manual_download_guide.md"),
        help="Chemin du guide manuel généré.",
    )
    args = parser.parse_args()

    try:
        datasets = load_datasets(Path(args.config).expanduser().resolve())
        guide_path = Path(args.manual_guide).expanduser().resolve()
        write_manual_guide(datasets, guide_path)
        succeeded, skipped = fetch_datasets(
            datasets,
            set(args.dataset) if args.dataset else None,
            Path(args.output_dir).expanduser().resolve(),
        )
    except (OSError, ValueError, yaml.YAMLError, urllib.error.URLError) as error:
        parser.exit(2, f"[ERREUR] {error}\n")

    for item in succeeded:
        print(f"[OK] {item['dataset']}: {item['path']} (SHA-256 vérifié)")
    for item in skipped:
        print(f"[MANUEL] {item['dataset']}: {item['reason']}")
    print(f"[OK] Guide manuel : {guide_path}")
    print(
        f"[OK] Résumé : téléchargés={len(succeeded)}, "
        f"manuels/ignorés={len(skipped)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
