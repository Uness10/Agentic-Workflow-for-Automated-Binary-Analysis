from __future__ import annotations

from pathlib import Path

import pytest

from core.models import BinaryFormat
from core.utils import detect_format, shannon_entropy, validate_file


def test_detect_format_pe() -> None:
    assert detect_format(b"MZ" + b"\x00" * 10) == BinaryFormat.PE


def test_detect_format_elf() -> None:
    assert detect_format(b"\x7fELF" + b"\x00" * 10) == BinaryFormat.ELF


def test_entropy_bounds() -> None:
    low = shannon_entropy(b"A" * 256)
    high = shannon_entropy(bytes(range(256)))
    assert 0.0 <= low <= 8.0
    assert 0.0 <= high <= 8.0
    assert high > low


def test_validate_file_rejects_missing() -> None:
    with pytest.raises(FileNotFoundError):
        validate_file("does-not-exist.bin")


def test_validate_file_accepts_existing(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")
    resolved = validate_file(str(sample))
    assert resolved.exists()
