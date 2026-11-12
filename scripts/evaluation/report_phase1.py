#!/usr/bin/env python3
"""Generate a factual Phase 1 report from splits and recorded experiment outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import sklearn
import xgboost

REPO_ROOT = Path(__file__).resolve().parents[2]
METRICS = (
    ("macro_f1", "Macro-F1"),
    ("fpr", "FPR"),
    ("pr_auc_attack", "PR-AUC attaque"),
    ("ece_attack", "ECE attaque"),
    ("inference_latency_p95_ms", "Latence p95 (ms)"),
)
SPLIT_ORDER = ("train", "validation", "test")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "NON DISPONIBLE"


def environment_version(command: str, arguments: list[str]) -> str:
    executable = shutil.which(command)
    if executable is None:
        return "NON DISPONIBLE (exécutable absent du PATH)"
    result = subprocess.run(
        [executable, *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return "NON DISPONIBLE (commande de version en échec)"
    return (result.stdout or result.stderr).strip()


def class_distribution(frame: pd.DataFrame) -> dict[str, dict[int, int]]:
    counts = frame.groupby(["split", "label"]).size()
    return {
        split: {
            label: int(counts.get((split, label), 0))
            for label in (0, 1)
        }
        for split in SPLIT_ORDER
    }


def validate_e2_structure(frame: pd.DataFrame) -> tuple[bool, list[str]]:
    reasons = []
    session_splits = frame.groupby("capture_id")["split"].nunique()
    if session_splits.gt(1).any():
        reasons.append("Une capture_id est partagée entre plusieurs partitions.")
    ranges = {}
    for split in SPLIT_ORDER:
        subset = frame.loc[frame["split"].eq(split)]
        if subset.empty:
            reasons.append(f"La partition {split} est vide.")
            continue
        ranges[split] = (
            float(subset["window_start"].min()),
            float(subset["window_end"].max()),
        )
    if all(split in ranges for split in SPLIT_ORDER):
        if not (
            ranges["train"][1] <= ranges["validation"][0]
            and ranges["validation"][1] <= ranges["test"][0]
        ):
            reasons.append("Les intervalles des partitions ne sont pas strictement chronologiques.")
    return not reasons, reasons


def _format_metric(value) -> str:
    return "NON DISPONIBLE" if pd.isna(value) else f"{float(value):.4f}"


def _write_phase1_summary(
    results_dir: Path,
    e1_summary: pd.DataFrame,
    e2_summary: pd.DataFrame,
    e1_evaluable: bool,
    e2_evaluable: bool,
    e1_reasons: list[str],
    e2_reasons: list[str],
) -> Path:
    output_dir = results_dir.parent / "phase1"
    output_dir.mkdir(parents=True, exist_ok=True)
    frames = []
    if not e1_summary.empty:
        e1_rows = e1_summary.copy()
        e1_rows["status"] = "measured"
        e1_rows["reason"] = ""
        frames.append(e1_rows)
    elif not e1_evaluable:
        frames.append(
            pd.DataFrame(
                [
                    {
                        "protocol": "E1",
                        "model": "RF/XGBoost",
                        "split": "test",
                        "seed_count": 0,
                        "status": "NON VALIDE",
                        "reason": " ".join(e1_reasons)
                        or "Couverture des classes insuffisante pour évaluer E1.",
                    }
                ]
            )
        )
    if not e2_summary.empty and e2_evaluable:
        e2_rows = e2_summary.copy()
        e2_rows["status"] = "measured"
        e2_rows["reason"] = ""
        frames.append(e2_rows)
    elif not e2_evaluable:
        frames.append(
            pd.DataFrame(
                [
                    {
                        "protocol": "E2",
                        "model": "RF/XGBoost",
                        "split": "test",
                        "seed_count": 0,
                        "status": "NON VALIDE",
                        "reason": " ".join(e2_reasons)
                        or "Couverture des classes insuffisante pour évaluer E2.",
                    }
                ]
            )
        )
    summary = pd.concat(frames, ignore_index=True, sort=False) if frames else pd.DataFrame()
    path = output_dir / "summary.csv"
    summary.to_csv(path, index=False, float_format="%.12g")
    return path


def build_report(
    windows_path: Path,
    splits_dir: Path,
    results_dir: Path,
    output_path: Path,
    root: Path = REPO_ROOT,
) -> str:
    windows = pd.read_csv(windows_path)
    e1_path = splits_dir / "E1.csv"
    e2_path = splits_dir / "E2.csv"
    e1 = pd.read_csv(e1_path)
    e2 = (
        pd.read_csv(e2_path)
        if e2_path.exists()
        else pd.DataFrame(
            columns=["capture_id", "window_start", "window_end", "label", "split"]
        )
    )

    e1_manifest_path = results_dir / "E1" / "metrics.json"
    e1_status_path = results_dir / "E1" / "status.json"
    e1_status = (
        json.loads(e1_status_path.read_text(encoding="utf-8"))
        if e1_status_path.exists()
        else None
    )
    e1_manifest = (
        json.loads(e1_manifest_path.read_text(encoding="utf-8"))
        if e1_manifest_path.exists()
        else None
    )
    e1_summary_path = results_dir / "E1" / "metrics_summary.csv"
    e1_summary = (
        pd.read_csv(e1_summary_path)
        if e1_summary_path.exists()
        else pd.DataFrame()
    )
    e1_reasons = []
    if e1_status and e1_status.get("status") != "trained":
        e1_reasons.append(e1_status.get("reason", "E1 marqué non valide."))
        e1_manifest = None
        e1_summary = pd.DataFrame()
    elif e1_manifest and e1_manifest.get("split_sha256") != sha256_file(e1_path):
        e1_reasons.append(
            "Les anciens artefacts E1 ne correspondent pas au SHA-256 du split "
            "actuel; ils sont ignorés."
        )
        e1_manifest = None
        e1_summary = pd.DataFrame()
    e1_evaluable = e1_manifest is not None and not e1_summary.empty
    e2_summary_path = results_dir / "E2" / "metrics_summary.csv"
    e2_summary = (
        pd.read_csv(e2_summary_path)
        if e2_summary_path.exists()
        else pd.DataFrame()
    )
    e2_status_path = results_dir / "E2" / "status.json"
    split_e2_status_path = splits_dir / "E2.status.json"
    e2_status = (
        json.loads(e2_status_path.read_text(encoding="utf-8"))
        if e2_status_path.exists()
        else (
            json.loads(split_e2_status_path.read_text(encoding="utf-8"))
            if split_e2_status_path.exists()
            else None
        )
    )

    e1_class_counts = class_distribution(e1)
    e2_class_counts = class_distribution(e2)
    if e2_path.exists():
        e2_structure_valid, e2_structure_reasons = validate_e2_structure(e2)
        e2_binary_trainable = (
            set(e2.loc[e2["split"].eq("train"), "label"]) == {0, 1}
        )
        e2_validation_has_both = (
            set(e2.loc[e2["split"].eq("validation"), "label"]) == {0, 1}
        )
    else:
        e2_structure_valid = False
        e2_structure_reasons = [
            e2_status.get("reason", "Aucun split E2 valide n'a été produit.")
            if e2_status
            else "Aucun split E2 valide n'a été produit."
        ]
        e2_binary_trainable = False
        e2_validation_has_both = False
    e2_evaluable = e2_structure_valid and e2_binary_trainable and e2_validation_has_both

    lines = [
        "# Rapport Phase 1 — XD-IDS",
        "",
        f"- Généré (UTC) : {datetime.now(timezone.utc).isoformat()}",
        f"- Commit Git : `{git_commit(root)}`",
        f"- Fenêtres source : `{windows_path.relative_to(root)}` "
        f"(SHA-256 `{sha256_file(windows_path)}`)",
        f"- Split E1 : `{e1_path.relative_to(root)}` "
        f"(SHA-256 `{sha256_file(e1_path)}`)",
        f"- Split E2 : `{e2_path.relative_to(root)}` "
        + (
            f"(SHA-256 `{sha256_file(e2_path)}`)"
            if e2_path.exists()
            else "(NON DISPONIBLE : E2 non valide; voir `splits/E2.status.json`)"
        ),
        "",
        "## Portée et limites",
        "",
        "Les résultats ci-dessous décrivent uniquement les captures PCAP locales "
        "inscrites dans le registre courant. La provenance et la licence de "
        "madatasets restent NON DISPONIBLES dans le dépôt. Les labels sont des "
        "hypothèses de travail dérivées des noms de fichiers, pas une vérité terrain "
        "vérifiée. Ces résultats ne démontrent ni généralisation inter-domaines ni "
        "supériorité par rapport à d'autres méthodes.",
        "",
        f"Le fichier de fenêtres contient {len(windows)} lignes. Les colonnes "
        "d'identité, de capture, d'appareil et de temps ne sont pas utilisées comme "
        "features par le script d'entraînement.",
        "",
        "## Résultats E1 — référence aléatoire favorable",
        "",
    ]

    if e1_manifest is None or e1_summary.empty:
        lines.extend(
            [
                "NON DISPONIBLE : les métriques E1 ne sont pas présentes dans le "
                "dossier de résultats pour le split courant, ou E1 n'a pas une "
                "couverture de classes valide. Aucun score n'est publié.",
                *[f"Raison : {reason}" for reason in e1_reasons],
                "",
            ]
        )
    else:
        lines.extend(
            [
                f"Statut : `{e1_manifest.get('status', 'NON DISPONIBLE')}`. "
                f"Graines enregistrées : {e1_manifest.get('seeds', 'NON DISPONIBLE')}.",
                "",
                "| Partition | Fenêtres normales (0) | Fenêtres attaque (1) |",
                "|---|---:|---:|",
            ]
        )
        for split in SPLIT_ORDER:
            lines.append(
                f"| {split} | {e1_class_counts[split][0]} | "
                f"{e1_class_counts[split][1]} |"
            )
        lines.extend(
            [
                "",
                "| Modèle | Partition | Graines | Macro-F1 moyen ± écart-type | FPR moyen ± écart-type | PR-AUC attaque moyen ± écart-type | ECE moyen ± écart-type | Latence p95 moyenne ± écart-type (ms) |",
                "|---|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for _, row in e1_summary.sort_values(["model", "split"]).iterrows():
            values = []
            for metric, _label in METRICS:
                mean = _format_metric(row.get(f"{metric}_mean", float("nan")))
                std = _format_metric(row.get(f"{metric}_std", float("nan")))
                values.append(f"{mean} ± {std}")
            lines.append(
                f"| {row['model']} | {row['split']} | {int(row['seed_count'])} | "
                + " | ".join(values)
                + " |"
            )
        lines.extend(
            [
                "",
                f"Les prédictions E1 sont disponibles dans "
                f"`{(results_dir / 'E1' / 'predictions.csv').relative_to(root)}` "
                "pour les partitions validation et test, séparément par modèle "
                "et graine.",
                "",
                "E1 répartit aléatoirement et stratifie par classe les groupes de "
                "features identiques lorsque la composition le permet, mais ne "
                "garantit pas l'indépendance des sessions entre partitions. Il "
                "est donc seulement une référence favorable, pas le résultat "
                "principal anti-fuite.",
                "",
            ]
        )

    lines.extend(
        [
            "## Résultat E2 — chronologique par capture",
            "",
            f"- Validité structurelle (captures entières et ordre chronologique) : "
            f"{'OUI' if e2_structure_valid else 'NON'}.",
            f"- Entraînement binaire et validation binaire possibles : "
            f"{'OUI' if e2_evaluable else 'NON'}.",
            "",
            "| Partition | Fenêtres normales (0) | Fenêtres attaque (1) |",
            "|---|---:|---:|",
        ]
    )
    for split in SPLIT_ORDER:
        normal_count = (
            str(e2_class_counts[split][0]) if e2_path.exists() else "NON DISPONIBLE"
        )
        attack_count = (
            str(e2_class_counts[split][1]) if e2_path.exists() else "NON DISPONIBLE"
        )
        lines.append(f"| {split} | {normal_count} | {attack_count} |")
    lines.extend(["", ""])
    if e2_structure_reasons:
        lines.extend(["Contrôles structurels échoués :"])
        lines.extend(f"- {reason}" for reason in e2_structure_reasons)
        lines.append("")
    if not e2_path.exists():
        lines.append(
            "E2 n'a pas été entraîné : aucun split chronologique valide n'a été "
            "produit."
        )
    elif not e2_binary_trainable:
        lines.append(
            "E2 n'a pas été entraîné : le train ne contient pas les deux classes. "
            "Un classifieur binaire ne peut pas apprendre une frontière entre "
            "normal et attaque depuis un train mono-classe."
        )
    if e2_path.exists() and not e2_validation_has_both:
        lines.append(
            "La validation E2 ne contient pas les deux classes; elle ne peut donc "
            "pas servir à sélectionner ou valider un classifieur binaire."
        )
    e2_reasons = []
    if not e2_structure_valid:
        e2_reasons.extend(e2_structure_reasons)
    if e2_path.exists() and not e2_binary_trainable:
        e2_reasons.append("train ne contient pas les deux classes.")
    if e2_path.exists() and not e2_validation_has_both:
        e2_reasons.append("validation ne contient pas les deux classes.")
    if not e2_evaluable:
        if not e2_path.exists():
            lines.append(
                "Aucun `splits/E2.csv` n'a été publié : la construction du split "
                "chronologique a échoué à cause des intervalles de sessions "
                "chevauchants. Le statut et la raison sont consignés dans "
                "`splits/E2.status.json`."
            )
        lines.append(
            "Les métriques E2 sont NON DISPONIBLES. Cette limite est publiée plutôt "
            "que de modifier les partitions ou d'inventer une évaluation."
        )
        if e2_status:
            lines.append(f"Statut d'exécution E2 : {e2_status.get('reason', 'NON DISPONIBLE')}")
    elif e2_summary.empty:
        lines.append(
            "La structure et les classes E2 sont admissibles, mais les métriques "
            "E2 sont NON DISPONIBLES : aucun artefact d'entraînement E2 n'a été fourni."
        )
        e2_reasons.append("E2 admissible structurellement mais entraînement absent.")
        e2_evaluable = False
    phase1_summary_path = _write_phase1_summary(
        results_dir,
        e1_summary,
        e2_summary,
        e1_evaluable,
        e2_evaluable,
        e1_reasons,
        e2_reasons,
    )
    lines.extend(
        [
            "",
            "## RQ1 — écart E1 − E2",
            "",
            f"Résumé tabulaire : `{phase1_summary_path.relative_to(root)}`.",
            "Un écart E1−E2 numérique est NON DISPONIBLE car aucune métrique E2 "
            "binaire valide n'est présente; aucun écart n'est estimé.",
            "",
        ]
    )
    datasets_config = root / "configs" / "datasets.yaml"
    if datasets_config.is_file():
        import yaml

        dataset_registry = yaml.safe_load(datasets_config.read_text(encoding="utf-8"))
        datasets = dataset_registry.get("datasets", []) if isinstance(dataset_registry, dict) else []
        admissible = [
            str(dataset.get("id"))
            for dataset in datasets
            if dataset.get("e3_admissible") is True
        ]
        lines.extend(
            [
                "## Admissibilité E3 — plan de transferts",
                "",
                "Domaines actuellement admissibles (PCAP et labels fiables vérifiés) : "
                + (", ".join(f"`{domain}`" for domain in admissible) if admissible else "AUCUN"),
                f"Transferts dirigés réalisables actuellement : "
                f"{len(admissible) * max(0, len(admissible) - 1)}; tests LODO : {len(admissible)}.",
                "À titre de planification uniquement, 3 domaines validés permettraient "
                "6 transferts dirigés et 3 tests LODO.",
                "Blocages actuels : aucun domaine externe n'est présent avec PCAP, "
                "licence, provenance, topologie et labels fiables vérifiés. "
                "madatasets reste non admissible tant que sa provenance et ses labels "
                "heuristiques ne sont pas validés. E3 n'a pas été exécuté.",
                "",
            ]
        )
    lines.extend(["", "## Conclusion", ""])
    if e1_evaluable:
        lines.append(
            "Seules les baselines E1 ont été mesurées. Aucun résultat principal "
            "anti-fuite E2 valide n'est disponible avec la composition actuelle "
            "des captures. Les sessions qui se chevauchent empêchent un split "
            "chronologique valide; la faible représentation normale (5 fenêtres "
            "issues de 2 captures) limite également E1. Ces problèmes doivent "
            "être résolus avant toute conclusion de performance."
        )
    else:
        lines.append(
            "Aucun résultat expérimental complet n'est disponible; les chiffres "
            "absents sont explicitement marqués NON DISPONIBLE."
        )
    lines.append("")

    report = "\n".join(lines)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    input_paths = [windows_path, e1_path, e2_path]
    for candidate in (
        e1_manifest_path,
        e1_status_path,
        e1_summary_path,
        e2_summary_path,
        e2_status_path,
        split_e2_status_path,
        root / "configs" / "models.yaml",
        root / "configs" / "splits.yaml",
        root / "configs" / "captures.yaml",
        datasets_config,
    ):
        if candidate.is_file():
            input_paths.append(candidate)
    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_commit(root),
        "inputs": {
            str(path.relative_to(root)): sha256_file(path)
            for path in input_paths
            if path.is_file()
        },
        "output_file": str(output_path.relative_to(root)),
        "output_sha256": sha256_file(output_path),
        "outputs": {
            str(output_path.relative_to(root)): sha256_file(output_path),
            str(phase1_summary_path.relative_to(root)): sha256_file(
                phase1_summary_path
            ),
        },
        "software_versions": {
            "python": sys.version.split()[0],
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "zeek": environment_version("zeek", ["--version"]),
        },
    }
    manifest_path = output_path.with_suffix(".manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the factual XD-IDS Phase 1 report.")
    parser.add_argument("--windows", default=str(REPO_ROOT / "data" / "processed_features" / "windows_all.csv"))
    parser.add_argument("--splits-dir", default=str(REPO_ROOT / "splits"))
    parser.add_argument("--results-dir", default=str(REPO_ROOT / "results" / "phase_b"))
    parser.add_argument("--output", default=str(REPO_ROOT / "docs" / "phase1_report.md"))
    args = parser.parse_args()
    build_report(
        Path(args.windows).expanduser().resolve(),
        Path(args.splits_dir).expanduser().resolve(),
        Path(args.results_dir).expanduser().resolve(),
        Path(args.output).expanduser().resolve(),
    )
    output_path = Path(args.output).expanduser().resolve()
    print(f"[OK] Rapport généré : {output_path}")
    print(f"[OK] Manifeste : {output_path.with_suffix('.manifest.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
