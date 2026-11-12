`PYTHON ?= python
RUFF ?= ruff
DATASET_ROOT ?= madatasets
CAPTURE_CONFIG ?= configs/captures.yaml
DATASETS_CONFIG ?= configs/datasets.yaml
WINDOW_SECONDS ?= 60
DEVICE_SIDE ?= orig
NEAR_TOLERANCE ?= 0.01

.PHONY: all phase1 audit zeek windows train report fetch-datasets test lint acceptance

all: phase1

phase1: report

audit:
	$(PYTHON) scripts/data/audit_pcaps.py $(DATASET_ROOT) \
		--csv-output data/metadata/captures.csv \
		--config-output $(CAPTURE_CONFIG) \
		--docs-output docs/data_card_madatasets.md

zeek: audit
	$(PYTHON) scripts/extraction/run_zeek_batch.py \
		--config $(CAPTURE_CONFIG) \
		--output-dir data/processed_zeek

windows: zeek
	$(PYTHON) scripts/preprocessing/build_dataset.py \
		--capture-config $(CAPTURE_CONFIG) \
		--output-dir data/processed_features \
		--windows-output data/processed_features/windows_all.csv \
		--splits-dir splits \
		--window-seconds $(WINDOW_SECONDS) \
		--device-side $(DEVICE_SIDE) \
		--near-tolerance $(NEAR_TOLERANCE) \
		--splits-config configs/splits.yaml

train: windows
	$(PYTHON) scripts/evaluation/train_phase1.py \
		--splits-dir splits \
		--config configs/models.yaml \
		--results-dir results/phase_b

report: train
	$(PYTHON) scripts/evaluation/report_phase1.py \
		--windows data/processed_features/windows_all.csv \
		--splits-dir splits \
		--results-dir results/phase_b \
		--output docs/phase1_report.md

fetch-datasets:
	$(PYTHON) scripts/data/fetch_datasets.py --config $(DATASETS_CONFIG)

test:
	$(PYTHON) -m pytest -q

lint:
	$(RUFF) check .

acceptance: phase1 test lint
