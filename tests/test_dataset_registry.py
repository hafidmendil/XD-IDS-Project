"""Ensure the dataset registry remains parseable and documentation exists."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_dataset_registry_entries_have_source_cards_and_e3_decision():
    registry = yaml.safe_load(
        (ROOT / "configs" / "datasets.yaml").read_text(encoding="utf-8")
    )
    datasets = registry["datasets"]
    ids = {dataset["id"] for dataset in datasets}

    assert ids == {
        "MQTT-IoTIDS2020",
        "Bot-IoT",
        "ToN_IoT",
        "CICIoT2023",
        "CIC-IDS2017",
        "madatasets",
    }
    for dataset in datasets:
        assert dataset["source_url"]
        assert "e3_admissible" in dataset
        assert dataset.get("download_url") is None
        assert (
            ROOT / "docs" / "datasets" / f"{dataset['id']}.md"
        ).is_file() or dataset["id"] == "madatasets" and (
            ROOT / "docs" / "datasets" / "madatasets.md"
        ).is_file()


def test_labels_taxonomy_exists():
    assert (ROOT / "docs" / "labels_taxonomy.md").is_file()
