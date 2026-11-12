"""Tests du batch Zeek avec un mock de subprocess."""

import json
from pathlib import Path

from scripts.extraction.run_zeek_batch import run_batch


class DummyResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_batch_runs_zeek_on_each_capture(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    (root / "data" / "raw").mkdir(parents=True)
    pcap_a = root / "data" / "raw" / "capture_a.pcap"
    pcap_b = root / "data" / "raw" / "capture_b.pcap"
    pcap_a.write_bytes(b"pcap-a")
    pcap_b.write_bytes(b"pcap-b")

    config = root / "configs" / "captures.yaml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        json.dumps(
            {
                "captures": [
                    {"id": "capture_a", "path": "data/raw/capture_a.pcap"},
                    {"id": "capture_b", "path": "data/raw/capture_b.pcap"},
                ]
            }
        ),
        encoding="utf-8",
    )

    calls = []

    def fake_run(
        cmd, cwd=None, capture_output=True, text=True, timeout=None, check=False
    ):
        if cmd[1] == "--version":
            return DummyResult(stdout="zeek version test")
        out_dir = Path(cwd)
        (out_dir / "conn.log").write_text("#fields\tts\n1\tfoo\n", encoding="utf-8")
        calls.append((cmd[2], cwd))
        return DummyResult(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("scripts.extraction.run_zeek_batch.subprocess.run", fake_run)
    monkeypatch.setattr("scripts.extraction.run_zeek_batch.shutil.which", lambda name: "/usr/bin/zeek")

    manifests = run_batch(config, root / "data" / "processed_zeek")

    assert len(manifests) == 2
    assert {entry["capture_id"] for entry in manifests} == {"capture_a", "capture_b"}
    assert len(calls) == 2
    for manifest in manifests:
        assert (Path(manifest["output_dir"]) / "conn.log").exists()
        assert (Path(manifest["output_dir"]) / "processing_metadata.json").exists()

    skipped = run_batch(config, root / "data" / "processed_zeek")
    assert len(calls) == 2
    assert {entry["status"] for entry in skipped} == {"ignored_unchanged"}
