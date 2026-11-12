"""Unit tests for direct dataset downloads and checksum validation."""

import hashlib
import io

import pytest

from scripts.data.fetch_datasets import _download, fetch_datasets, write_manual_guide


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_fetch_datasets_skips_unavailable_sources_and_writes_guide(tmp_path):
    datasets = [
        {
            "id": "manual",
            "source_url": "https://example.test/dataset",
            "download_url": None,
            "sha256": "NON DISPONIBLE",
        }
    ]
    guide = tmp_path / "manual.md"

    write_manual_guide(datasets, guide)
    downloaded, skipped = fetch_datasets(datasets, None, tmp_path / "raw")

    assert downloaded == []
    assert skipped[0]["dataset"] == "manual"
    assert "URL directe ou SHA-256 attendu" in guide.read_text(encoding="utf-8")


def test_download_checks_sha256_before_publishing(tmp_path, monkeypatch):
    content = b"small public test fixture"
    expected = hashlib.sha256(content).hexdigest()
    monkeypatch.setattr(
        "scripts.data.fetch_datasets.urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(content),
    )

    destination = tmp_path / "dataset" / "fixture.bin"
    actual = _download("https://example.test/fixture.bin", destination, expected)

    assert actual == expected
    assert destination.read_bytes() == content
    assert not destination.with_name("fixture.bin.part").exists()


def test_download_rejects_checksum_mismatch_without_publishing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "scripts.data.fetch_datasets.urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(b"not the expected content"),
    )
    destination = tmp_path / "dataset" / "fixture.bin"

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        _download("https://example.test/fixture.bin", destination, "0" * 64)

    assert not destination.exists()
    assert not destination.with_name("fixture.bin.part").exists()


def test_download_refuses_non_http_direct_sources(tmp_path):
    with pytest.raises(ValueError, match="HTTP"):
        _download("file:///etc/passwd", tmp_path / "out", "0" * 64)
